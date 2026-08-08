//! Cross-platform ICMP echo ping for host discovery.
//!
//! - On Windows we call `IcmpSendEcho` from iphlpapi, which needs no
//!   privileges and works for IPv4.
//! - On Unix we use a raw ICMP socket (`SOCK_DGRAM` + `IPPROTO_ICMP`), which
//!   needs root / `CAP_NET_RAW`; when that is unavailable the function simply
//!   reports the host as not pingable and discovery falls back to TCP probes.
//!
//! IPv6 is not supported by either path; IPv6 targets are skipped here and
//! covered by the TCP probes in `discover.rs`.

use std::net::IpAddr;
use std::time::Duration;

/// The result of a successful ICMP echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingReply {
    pub rtt_ms: u32,
    /// TTL of the reply packet, when the platform exposes it. Used for OS
    /// fingerprinting (Windows ~128, Linux/macOS ~64, network gear ~255).
    pub ttl: Option<u8>,
}

/// Ping `ip` and return the round-trip time in milliseconds, or `None` when
/// the host does not answer, the address is IPv6, or ICMP is not available
/// to this process.
pub async fn ping(ip: IpAddr, timeout: Duration) -> Option<u32> {
    ping_ttl(ip, timeout).await.map(|r| r.rtt_ms)
}

/// Ping `ip` and return the full reply (RTT + TTL when available).
pub async fn ping_ttl(ip: IpAddr, timeout: Duration) -> Option<PingReply> {
    tokio::task::spawn_blocking(move || imp::icmp_ping(ip, timeout).map(|(rtt, ttl)| PingReply { rtt_ms: rtt, ttl }))
        .await
        .ok()
        .flatten()
}

#[cfg(target_os = "windows")]
mod imp {
    use std::ffi::c_void;
    use std::net::IpAddr;
    use std::time::Duration;

    type Dword = u32;
    type Bool = i32;
    type Handle = *mut c_void;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> Handle;
        fn IcmpCloseHandle(icmp_handle: Handle) -> Bool;
        fn IcmpSendEcho(
            icmp_handle: Handle,
            destination_address: Dword,
            request_data: *const u8,
            request_size: u16,
            request_options: *const c_void,
            reply_buffer: *mut u8,
            reply_size: Dword,
            timeout: Dword,
        ) -> Dword;
    }

    /// Returns `(rtt_ms, ttl)`. `ttl` is read from the ICMP_ECHO_REPLY options
    /// field (the TTL byte at a pointer-size-dependent offset), when present.
    pub(super) fn icmp_ping(ip: IpAddr, timeout: Duration) -> Option<(u32, Option<u8>)> {
        let IpAddr::V4(v4) = ip else {
            return None;
        };
        let handle = unsafe { IcmpCreateFile() };
        if handle.is_null() {
            return None;
        }

        // ICMP_ECHO_REPLY layout: Address(4) Status(4) RoundTripTime(4)
        // DataSize(2) Reserved(2) Data(ptr) Options(ICMP_ECHO_REPLY_OPTIONS),
        // where Options starts with a TTL byte. On x64 the Data pointer is
        // 8 bytes, so Options begins at 4+4+4+2+2+8 = 24; on x86 at 20.
        // We use a 64-byte buffer so a single reply plus payload always fits.
        const REPLY_SIZE: usize = 64;
        let mut reply = [0u8; REPLY_SIZE];
        let dest: Dword = u32::from(v4).to_be(); // network byte order
        let payload = *b"VAJRA-PING-PROBE\0\0";
        let replies = unsafe {
            IcmpSendEcho(
                handle,
                dest,
                payload.as_ptr(),
                payload.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr(),
                REPLY_SIZE as Dword,
                timeout.as_millis().min(u32::MAX as u128) as Dword,
            )
        };
        unsafe { IcmpCloseHandle(handle) };

        if replies == 0 {
            return None;
        }
        let status = u32::from_le_bytes(reply[4..8].try_into().ok()?);
        let rtt = u32::from_le_bytes(reply[8..12].try_into().ok()?);
        if status != 0 {
            return None;
        }
        let options_off = 4 + 4 + 4 + 2 + 2 + std::mem::size_of::<usize>();
        // The first ICMP_ECHO_REPLY_OPTIONS byte is the TTL (1 = IP_OPTION_TTL
        // means TTL is present in OptionsData; when OptionsData is null the
        // OS still fills TTL for the first reply in practice). Guard the read.
        let ttl = (options_off < reply.len()).then(|| reply[options_off]);
        Some((rtt, ttl))
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    use std::mem::MaybeUninit;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    /// Returns `(rtt_ms, ttl)`. TTL is captured via the `IP_RECVTTL` socket
    /// option and the recvmsg ancillary data; when the platform or privileges
    /// do not expose it, `ttl` is `None` (OS fingerprinting degrades to
    /// banner/port heuristics only).
    pub(super) fn icmp_ping(ip: IpAddr, timeout: Duration) -> Option<(u32, Option<u8>)> {
        let IpAddr::V4(v4) = ip else {
            return None;
        };

        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
        if sock < 0 {
            return None; // raw ICMP requires root / CAP_NET_RAW
        }

        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        // Ask the kernel to deliver the incoming IP TTL as control data.
        #[allow(unused_unsafe)]
        unsafe {
            libc::setsockopt(
                sock,
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                &1i32 as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }

        let id = (std::process::id() & 0xffff) as u16;
        let mut pkt = [0u8; 64];
        pkt[0] = 8; // ICMP echo request
        pkt[1] = 0;
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        pkt[6..8].copy_from_slice(&1u16.to_be_bytes());
        pkt[8..].fill(0x41);

        let dst = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: u32::from(v4).to_be() },
            sin_zero: [0; 8],
        };
        let sent = unsafe {
            libc::sendto(
                sock,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &dst as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            unsafe { libc::close(sock) };
            return None;
        }

        let start = Instant::now();
        let mut buf = [0u8; 512];
        let mut cmsg_buf = [0u8; 128];
        let mut src: libc::sockaddr_in = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msghdr = libc::msghdr {
            msg_name: &mut src as *mut libc::sockaddr_in as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buf.len(),
            msg_flags: 0,
        };
        let n = unsafe { libc::recvmsg(sock, &mut msghdr, 0) };
        unsafe { libc::close(sock) };

        if n < 8 {
            return None;
        }
        // SOCK_DGRAM + IPPROTO_ICMP delivers the ICMP header itself:
        // type 0 is an echo reply.
        if buf[0] != 0 || buf[4..6] != id.to_be_bytes() {
            return None;
        }

        // Extract the TTL from the IP_RECVTTL control message, if delivered.
        // The kernel delivers the TTL as a full `int` (Linux and BSDs), so
        // read a c_int and truncate — reading a single byte would be wrong
        // on big-endian hosts.
        let ttl = unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msghdr);
            let mut found: Option<u8> = None;
            while !cmsg.is_null() {
                let len = (*cmsg).cmsg_len as usize;
                // Reject malformed lengths before advancing with CMSG_NXTHDR
                // (which derives the next offset from this length).
                if len < std::mem::size_of::<libc::cmsghdr>() {
                    break;
                }
                let level = (*cmsg).cmsg_level;
                let ctype = (*cmsg).cmsg_type;
                if level == libc::IPPROTO_IP && ctype == libc::IP_RECVTTL {
                    let data = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                    found = Some(std::ptr::read(data) as u8);
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
            }
            found
        };
        Some((start.elapsed().as_millis() as u32, ttl))
    }
}
