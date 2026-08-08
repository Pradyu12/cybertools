//! UDP port scanning.
//!
//! UDP has no connect handshake, so detection relies on application probes:
//! for each port we send a protocol-appropriate request and wait for a reply.
//! A reply means the port is *open*; silence usually means *open|filtered*
//! (we cannot tell "no listener" apart from "packets dropped" without a raw
//! socket that can read ICMP port-unreachable messages, which Windows does
//! not deliver to unprivileged processes). This mirrors nmap's behaviour when
//! run without privileges.
//!
//! Every well-known port gets a purpose-built payload (DNS query, NTP
//! request, SSDP M-SEARCH, SNMP GET, ...) and a response classifier;
//! user-specified ports outside the table are probed with a generic payload.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use indicatif::ProgressBar;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::dashboard::{DashboardEvent, DashboardHub};
use crate::target::ResolvedHost;

/// Result of probing a single UDP port.
#[derive(Debug, Clone)]
pub struct UdpResult {
    pub port: u16,
    pub state: UdpState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// How a UDP probe ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    /// Got a response (port is open).
    Open,
    /// No response: open or filtered, indistinguishable without ICMP.
    OpenFiltered,
}

impl UdpState {
    pub fn label(&self) -> &'static str {
        match self {
            UdpState::Open => "open",
            UdpState::OpenFiltered => "open|filtered",
        }
    }
}

// ---- Application payloads -----------------------------------------------

/// NetBIOS name encoding: 32 nibble-encoded bytes preceded by 0x20.
fn encode_nb_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.push(0x20);
    let mut bytes: Vec<u8> = name.as_bytes().to_vec();
    bytes.resize(15, b' ');
    bytes.push(0x00); // suffix: workstation service
    for b in bytes {
        out.push(0x41 + (b >> 4));
        out.push(0x41 + (b & 0x0f));
    }
    out
}

fn dns_query() -> Vec<u8> {
    let mut v = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    v.extend_from_slice(b"\x07example\x03com\x00");
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    v
}

const NTP_REQUEST: [u8; 48] = {
    let mut a = [0u8; 48];
    a[0] = 0x1b; // LI=0, VN=3, mode=3 (client)
    a
};

fn mdns_query() -> Vec<u8> {
    let mut v = vec![0u8; 12];
    v[2] = 0x00;
    v[3] = 0x01; // QDCOUNT = 1
    v.extend_from_slice(b"\x09_services\x07_dns-sd\x04_udp\x05local\x00");
    v.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // PTR, IN
    v
}

fn llmnr_query() -> Vec<u8> {
    let mut v = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    v.extend_from_slice(b"\x05vajra\x05local\x00");
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    v
}

fn tftp_rrq() -> Vec<u8> {
    let mut v = vec![0x00, 0x01];
    v.extend_from_slice(b"vajra\x00octet\x00");
    v
}

fn snmp_get() -> Vec<u8> {
    // SNMPv1 GET of sysDescr (1.3.6.1.2.1.1.1.0), community "public".
    vec![
        0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x1c,
        0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
        0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ]
}

fn isakmp_probe() -> Vec<u8> {
    // IKE v1 header (28 bytes): initiator cookie + empty responder cookie.
    let mut v = vec![0u8; 28];
    v[0..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
    v[8] = 1; // next payload: SA
    v[9] = 0x10; // version 1.0
    v[10] = 2; // exchange type: identity protection
    v[24..26].copy_from_slice(&28u16.to_be_bytes());
    v[26] = 0x04;
    v[27] = 0x04;
    v
}

fn memcached_stats() -> Vec<u8> {
    let mut v = vec![0u8; 24];
    v[0] = 0x80; // binary protocol magic (request)
    v[1] = 0x10; // opcode STAT
    v[8..12].copy_from_slice(&0x12345678u32.to_be_bytes()); // opaque
    v
}

fn openvpn_probe() -> Vec<u8> {
    let mut v = vec![0x38]; // P_CONTROL_HARD_RESET_CLIENT_V2
    v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
    v.resize(32, 0x00);
    v
}

fn wireguard_probe() -> Vec<u8> {
    let mut v = vec![0x01, 0x00, 0x00, 0x00]; // handshake initiation (type 1)
    v.extend_from_slice(&0x12345678u32.to_be_bytes()); // sender index
    v.resize(148, 0);
    v
}

fn ssdp_msearch() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
        .to_vec()
}

fn wsd_probe() -> Vec<u8> {
    br#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"><soap:Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"><Types>wsdp:Device</Types></Probe></soap:Body></soap:Envelope>"#
        .to_vec()
}

fn sip_options() -> Vec<u8> {
    b"OPTIONS sip:vajra@localhost SIP/2.0\r\n\
      Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-0001\r\n\
      From: <sip:probe@localhost>;tag=1\r\n\
      To: <sip:vajra@localhost>\r\n\
      Call-ID: vajra-0001\r\n\
      CSeq: 1 OPTIONS\r\n\
      Content-Length: 0\r\n\r\n"
        .to_vec()
}

/// Purpose-built payload for a known UDP port, if we have one.
fn payload_for(port: u16) -> Option<Vec<u8>> {
    let v = match port {
        53 => dns_query(),
        69 => tftp_rrq(),
        123 => NTP_REQUEST.to_vec(),
        137 => {
            let mut v = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            v.extend_from_slice(&encode_nb_name("VAJRA"));
            v.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]); // NB, IN
            v
        }
        161 | 162 => snmp_get(),
        500 => isakmp_probe(),
        5060 | 5061 => sip_options(),
        5353 => mdns_query(),
        5355 => llmnr_query(),
        11211 => memcached_stats(),
        1194 => openvpn_probe(),
        1900 => ssdp_msearch(),
        3702 => wsd_probe(),
        4500 => vec![0xff], // NAT-T keepalive
        51820 => wireguard_probe(),
        7 => b"vajra".to_vec(),
        9 => b"data".to_vec(),
        13 | 17 | 19 | 37 => vec![0x00, 0x00, 0x00, 0x00],
        623 => vec![0x06, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0x00], // ASF-RMCP presence ping
        _ => return None,
    };
    Some(v)
}

/// Human service name for a UDP port, used on open|filtered rows.
fn udp_service(port: u16) -> Option<String> {
    let s = match port {
        53 => "domain",
        69 => "tftp",
        123 => "ntp",
        135 => "msrpc",
        137..=139 => "netbios",
        161 | 162 => "snmp",
        445 => "microsoft-ds",
        500 => "isakmp",
        514 => "syslog",
        520 => "rip",
        623 => "ipmi",
        631 => "ipp",
        1434 => "ms-sql-m",
        1701 => "l2tp",
        1900 => "ssdp",
        2049 => "nfs",
        3702 => "ws-discovery",
        4500 => "ipsec-natt",
        5060 | 5061 => "sip",
        5353 => "mdns",
        5355 => "llmnr",
        11211 => "memcached",
        1194 => "openvpn",
        51820 => "wireguard",
        _ => return None,
    };
    Some(s.into())
}

// ---- Response classification --------------------------------------------

/// Reduce a raw response to printable text for banners.
fn sanitize(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            s.push(b as char);
        } else if b == b'\n' || b == b'\r' || b == b'\t' {
            s.push(' ');
        } else {
            s.push('.');
        }
    }
    let mut out = String::new();
    let mut prev_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    let out = out.trim().to_string();
    if out.chars().count() > 200 {
        out.chars().take(200).collect::<String>() + "…"
    } else {
        out
    }
}

/// Classify a probe response: `(service, version, banner)`.
fn classify_response(port: u16, resp: &[u8]) -> (String, Option<String>, Option<String>) {
    let txt = sanitize(resp);
    let lower = txt.to_ascii_lowercase();
    let (service, version, banner): (&str, Option<String>, Option<String>) = match port {
        53 if resp.len() >= 12 && resp[0] == 0x12 && resp[1] == 0x34 && resp[2] & 0x80 != 0 => {
            ("domain", None, Some(txt))
        }
        123 if resp.len() >= 48 && resp[0] >> 6 <= 3 => {
            let vn = (resp[0] >> 3) & 0x07;
            ("ntp", Some(format!("NTP v{vn}")), Some(txt))
        }
        137 if resp.len() >= 12 && resp[0] == 0x12 && resp[1] == 0x34 && resp[2] & 0x80 != 0 => {
            ("netbios-ns", None, Some(txt))
        }
        161 | 162 if resp.first() == Some(&0x30) && resp.windows(6).any(|w| w == b"public") => {
            ("snmp", None, Some(txt))
        }
        69 if resp.len() >= 4 && (resp[0], resp[1]) == (0x00, 0x03) => ("tftp", None, Some(txt)),
        1900 if lower.contains("http/1.1 200") || lower.contains("notify") => {
            let server = lower
                .split("server:")
                .nth(1)
                .and_then(|s| s.lines().next())
                .map(|s| s.trim().to_string());
            ("ssdp", None, server.or(Some(txt)))
        }
        5353 if resp.len() >= 12 && resp[2] & 0x80 != 0 => ("mdns", None, Some(txt)),
        5355 if resp.len() >= 12 && resp[2] & 0x80 != 0 => ("llmnr", None, Some(txt)),
        500 if resp.len() >= 28 && resp[8..16].iter().any(|&b| b != 0) => {
            let vn = format!("IKE v{}.{}", (resp[9] >> 4) & 0x0f, resp[9] & 0x0f);
            ("isakmp", Some(vn), Some(txt))
        }
        4500 if resp.first() == Some(&0xff) => ("ipsec-natt", None, Some(txt)),
        11211 if resp.first() == Some(&0x81) => ("memcached", None, Some(txt)),
        1194 if resp.first().is_some_and(|b| (b >> 3) == 0x40) => ("openvpn", None, Some(txt)),
        51820 if matches!(resp.first(), Some(2..=4)) => ("wireguard", None, Some(txt)),
        5060 | 5061 if lower.contains("sip/2.0") => ("sip", None, Some(txt)),
        3702 if lower.contains("ws-discovery") || lower.contains("schemas.xmlsoap.org") => {
            ("ws-discovery", None, Some(txt))
        }
        7 if txt.starts_with("vajra") => ("echo", None, Some(txt)),
        9 => ("discard", None, Some(txt)),
        13 => ("daytime", None, Some(txt)),
        17 => ("qotd", None, Some(txt)),
        19 => ("chargen", None, Some(txt)),
        37 => ("time", None, Some(txt)),
        623 if resp.first() == Some(&0x06) => ("ipmi", None, Some(txt)),
        _ => ("unknown-udp", None, Some(txt)),
    };
    (service.into(), version, banner)
}

// ---- Probing ------------------------------------------------------------

/// Probe one (host, port) over UDP.
async fn probe_udp(ip: IpAddr, port: u16, timeout: Duration) -> UdpResult {
    let payload = payload_for(port).unwrap_or_else(|| vec![0x00, 0x00, 0x00, 0x00]);
    let filtered = || UdpResult {
        port,
        state: UdpState::OpenFiltered,
        service: udp_service(port),
        version: None,
        banner: None,
    };

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return filtered(),
    };
    if socket.connect(SocketAddr::new(ip, port)).await.is_err() {
        return filtered();
    }
    let _ = socket.send(&payload).await;

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let (service, version, banner) = classify_response(port, &buf[..n]);
            UdpResult { port, state: UdpState::Open, service: Some(service), version, banner }
        }
        _ => filtered(),
    }
}

const UDP_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Scan every (host, port) pair over UDP and stream results to the dashboard.
/// Returns the results plus whether the scan was interrupted by Ctrl+C.
pub async fn scan_udp(
    hosts: &[ResolvedHost],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
    pb: Option<&ProgressBar>,
    hub: Option<&DashboardHub>,
) -> (BTreeMap<IpAddr, Vec<UdpResult>>, bool) {
    let started = Instant::now();
    let mut jobs: Vec<(IpAddr, u16)> = Vec::with_capacity(hosts.len() * ports.len());
    for h in hosts {
        for p in ports {
            jobs.push((h.ip, *p));
        }
    }

    let mut tasks = JoinSet::new();
    let mut next = 0usize;
    let mut done: u64 = 0;
    let mut interrupted = false;
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());
    let mut last_progress = Instant::now();
    let mut out: BTreeMap<IpAddr, Vec<UdpResult>> = BTreeMap::new();

    loop {
        while next < jobs.len() && tasks.len() < concurrency {
            let (ip, port) = jobs[next];
            tasks.spawn(async move {
                let r = probe_udp(ip, port, timeout).await;
                (ip, r)
            });
            next += 1;
        }

        if let Some(pb) = pb {
            pb.set_position(done);
            pb.set_message(format!("UDP scan (concurrency {})", tasks.len()));
        }
        if let Some(hub) = hub {
            if last_progress.elapsed() >= UDP_PROGRESS_INTERVAL && done > 0 {
                hub.emit(DashboardEvent::Progress {
                    done,
                    total: jobs.len() as u64,
                    concurrency,
                    elapsed_ms: started.elapsed().as_millis(),
                    proto: "udp".into(),
                });
                last_progress = Instant::now();
            }
        }

        if next >= jobs.len() && tasks.is_empty() {
            break;
        }

        tokio::select! {
            r = tasks.join_next() => match r {
                Some(Ok((ip, res))) => {
                    done += 1;
                    if let Some(hub) = hub {
                        hub.emit(DashboardEvent::PortOpen {
                            ip: ip.to_string(),
                            port: res.port,
                            service: res.service.clone(),
                            version: res.version.clone(),
                            banner: res.banner.clone(),
                            proto: "udp".into(),
                            state: res.state.label().into(),
                        });
                    }
                    out.entry(ip).or_default().push(res);
                }
                Some(Err(_)) => done += 1,
                None => break,
            },
            _ = &mut ctrl_c => {
                interrupted = true;
                break;
            }
        }
    }

    if interrupted {
        tasks.shutdown().await;
    }
    if let Some(hub) = hub {
        hub.emit(DashboardEvent::Progress {
            done,
            total: jobs.len() as u64,
            concurrency,
            elapsed_ms: started.elapsed().as_millis(),
            proto: "udp".into(),
        });
    }
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    for v in out.values_mut() {
        v.sort_by_key(|r| r.port);
    }
    (out, interrupted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_udp_ports_are_unique() {
        let mut set = std::collections::HashSet::new();
        for p in crate::ports::TOP_UDP_PORTS {
            assert!(set.insert(*p), "duplicate UDP port {p}");
        }
    }

    #[test]
    fn common_ports_have_purpose_built_payloads() {
        // These get protocol-specific probes; everything else falls back to
        // the generic probe, which is a deliberate strategy.
        for p in [53, 69, 123, 137, 161, 500, 623, 1900, 3702, 4500, 5060, 5353, 5355, 11211, 1194, 51820] {
            assert!(payload_for(p).is_some(), "port {p} should have a payload");
        }
    }

    #[test]
    fn dns_payload_is_valid_query() {
        let q = dns_query();
        assert_eq!(&q[..12], &[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn classifies_dns_response() {
        let mut resp = vec![0x12, 0x34];
        resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01");
        let (svc, _, banner) = classify_response(53, &resp);
        assert_eq!(svc, "domain");
        assert!(banner.is_some());
    }

    #[test]
    fn classifies_ntp_response() {
        let mut resp = vec![0u8; 48];
        resp[0] = 0x1c; // LI=0, VN=3, mode=4 (server)
        resp[1] = 1; // stratum 1
        let (svc, version, _) = classify_response(123, &resp);
        assert_eq!(svc, "ntp");
        assert_eq!(version.as_deref(), Some("NTP v3"));
    }

    #[test]
    fn classifies_tftp_data() {
        let resp = [0x00, 0x03, 0x00, 0x01, b'v', b'a'];
        let (svc, _, _) = classify_response(69, &resp);
        assert_eq!(svc, "tftp");
    }

    #[test]
    fn classifies_snmp_response() {
        let mut resp = vec![0x30, 0x2a];
        resp.extend_from_slice(b"\x02\x01\x00\x04\x06public");
        let (svc, _, _) = classify_response(161, &resp);
        assert_eq!(svc, "snmp");
    }

    #[test]
    fn unknown_port_response_is_unknown_udp() {
        let resp = b"hello from the void";
        let (svc, _, banner) = classify_response(49152, resp);
        assert_eq!(svc, "unknown-udp");
        assert!(banner.as_deref().unwrap().contains("hello"));
    }

    #[test]
    fn netbios_name_encoding_is_33_bytes() {
        // 1 length byte + 16 source bytes x 2 nibbles each.
        let enc = encode_nb_name("VAJRA");
        assert_eq!(enc.len(), 33);
        assert_eq!(enc[0], 0x20);
        for b in &enc[1..] {
            assert!((0x41..=0x50).contains(b), "nibble out of range: {b:#x}");
        }
    }
}
