//! Network device discovery + OS fingerprinting.
//!
//! Sweeps a target range, pings every address (capturing the reply TTL),
//! probes common service ports on live hosts, grabs banners, then combines
//! the evidence — TTL (Windows ~128, Linux/macOS ~64, network gear ~255),
//! banner content (SSH / HTTP server headers), and port patterns (SMB/RDP =
//! Windows, AirTunes = Apple) — into an OS guess with a confidence score.
//! MAC addresses come from the local ARP/neighbour table, and the vendor is
//! looked up from the OUI prefix.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use indicatif::ProgressBar;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::banner::{grab_banner, OpenPort};
use crate::ping;
use crate::target::ResolvedHost;

/// Ports probed on every live host to build an OS fingerprint. Cheap and
/// spread across Windows / Unix / Apple / IoT signatures.
pub const FINGERPRINT_PORTS: &[u16] = &[
    22,    // ssh — Unix signature; banner names the distro
    80,    // http — server header names the OS
    443,   // https — IIS / nginx / Apache
    135,   // msrpc — Windows
    139,   // netbios — Windows
    445,   // smb — Windows (or Samba on Unix)
    3389,  // rdp — Windows
    62078, // AirTunes — Apple
    5353,  // mdns — Apple (also used for discovery)
    8080,  // http-alt
];

/// A device found on the network with its best OS guess.
#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub os: String,
    pub confidence: u8,
    pub ttl: Option<u8>,
    pub rtt_ms: Option<u32>,
    /// Evidence that drove the OS guess, e.g. `["ttl=128", "445/smb open"]`.
    pub signals: Vec<String>,
    pub open_ports: Vec<u16>,
}

/// One row of the discovery sweep.
#[derive(Clone, Copy)]
struct PingHit {
    ip: IpAddr,
    rtt_ms: u32,
    ttl: Option<u8>,
}

/// Sweep every address with ICMP, collecting replies (with TTL) in parallel.
async fn sweep_ping(ips: &[IpAddr], timeout: Duration, concurrency: usize, pb: Option<&ProgressBar>) -> Vec<PingHit> {
    let mut tasks = JoinSet::new();
    let mut next = 0usize;
    let mut hits = Vec::new();
    loop {
        while next < ips.len() && tasks.len() < concurrency {
            let ip = ips[next];
            tasks.spawn(async move { (ip, ping::ping_ttl(ip, timeout).await) });
            next += 1;
        }
        if next >= ips.len() && tasks.is_empty() {
            break;
        }
        if let Some(result) = tasks.join_next().await {
            // Count every completed probe so the bar tracks the full sweep,
            // not just the live hosts.
            if let Some(pb) = pb {
                pb.inc(1);
            }
            if let Ok((ip, Some(rep))) = result {
                hits.push(PingHit { ip, rtt_ms: rep.rtt_ms, ttl: rep.ttl });
            }
        }
    }
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    hits
}

/// TCP-connect to one port; true when it accepts.
async fn tcp_open(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Fingerprint one host: probe signature ports, grab banners on the open
/// ones, and combine everything into an OS guess.
async fn fingerprint_host(
    hit: PingHit,
    timeout: Duration,
    banner_timeout: Duration,
) -> Device {
    let mut signals: Vec<String> = Vec::new();
    if let Some(ttl) = hit.ttl {
        signals.push(format!("ttl={ttl}"));
    }

    // Probe all signature ports concurrently.
    let mut ports_tasks = JoinSet::new();
    let mut next = 0usize;
    let mut open_ports = Vec::new();
    loop {
        while next < FINGERPRINT_PORTS.len() && ports_tasks.len() < FINGERPRINT_PORTS.len() {
            let ip = hit.ip;
            let port = FINGERPRINT_PORTS[next];
            let t = timeout;
            ports_tasks.spawn(async move { (port, tcp_open(ip, port, t).await) });
            next += 1;
        }
        if next >= FINGERPRINT_PORTS.len() && ports_tasks.is_empty() {
            break;
        }
        if let Some(Ok((port, true))) = ports_tasks.join_next().await {
            open_ports.push(port);
        }
    }
    open_ports.sort_unstable();

    // Grab banners on open ports (bounded set).
    let mut banners: Vec<OpenPort> = Vec::new();
    let mut banner_tasks = JoinSet::new();
    for &port in open_ports.iter().take(6) {
        banner_tasks.spawn(grab_banner(hit.ip, port, banner_timeout));
    }
    while let Some(Ok((_, op))) = banner_tasks.join_next().await {
        if op.banner.is_some() {
            banners.push(op);
        }
    }

    for p in &open_ports {
        signals.push(format!("{p}/{} open", crate::banner::service_for_port(*p).unwrap_or_else(|| "?".into())));
    }
    let (os, confidence) = fingerprint_os(hit.ttl, &open_ports, &banners, &mut signals);

    Device {
        ip: hit.ip,
        mac: None,
        vendor: None,
        os,
        confidence,
        ttl: hit.ttl,
        rtt_ms: Some(hit.rtt_ms),
        signals,
        open_ports,
    }
}

/// Combine TTL, open ports, and banner content into an OS guess with a
/// 0-100 confidence score.
fn fingerprint_os(
    ttl: Option<u8>,
    open_ports: &[u16],
    banners: &[OpenPort],
    signals: &mut Vec<String>,
) -> (String, u8) {
    let mut confidence: u8 = 0;
    let mut guess: Option<(&str, u8)> = None;

    // ---- Banner evidence (strongest) -----------------------------------
    let banner_text: String = banners
        .iter()
        .filter_map(|b| b.banner.clone())
        .collect::<Vec<_>>()
        .join(" ");
    let lower = banner_text.to_ascii_lowercase();

    if lower.contains("microsoft-iis") {
        guess = Some(("Windows (IIS)", 92));
        signals.push("banner: Microsoft-IIS".into());
    } else if lower.contains("openssh") {
        // SSH banner names the platform.
        if lower.contains("ubuntu") {
            guess = Some(("Linux (Ubuntu)", 95));
            signals.push("banner: OpenSSH/Ubuntu".into());
        } else if lower.contains("debian") {
            guess = Some(("Linux (Debian)", 95));
            signals.push("banner: OpenSSH/Debian".into());
        } else if lower.contains("raspbian") {
            guess = Some(("Linux (Raspberry Pi OS)", 95));
            signals.push("banner: OpenSSH/Raspbian".into());
        } else if lower.contains("freebsd") {
            guess = Some(("FreeBSD", 92));
            signals.push("banner: OpenSSH/FreeBSD".into());
        } else if lower.contains("cisco") {
            guess = Some(("Cisco IOS", 90));
            signals.push("banner: Cisco SSH".into());
        } else {
            guess = Some(("Linux/Unix (SSH)", 70));
            signals.push("banner: SSH".into());
        }
    } else if lower.contains("samba") {
        guess = Some(("Linux (Samba)", 90));
        signals.push("banner: Samba".into());
    } else if lower.contains("microsoft httpapi") || lower.contains("microsoft-ds") {
        guess = Some(("Windows", 88));
        signals.push("banner: Microsoft service".into());
    } else if lower.contains("nginx") {
        guess = Some(("Linux (nginx)", 82));
        signals.push("banner: nginx".into());
    } else if lower.contains("apache") {
        guess = Some(("Linux (Apache)", 80));
        signals.push("banner: Apache".into());
    }

    // ---- Port-pattern evidence -----------------------------------------
    if guess.is_none() {
        let has_smb = open_ports.iter().any(|p| matches!(p, 139 | 445));
        let has_rdp = open_ports.contains(&3389);
        let has_msrpc = open_ports.contains(&135);
        let has_ssh = open_ports.contains(&22);
        let has_airtunes = open_ports.contains(&62078);
        let has_mdns = open_ports.contains(&5353);

        if has_smb && (has_rdp || has_msrpc) {
            guess = Some(("Windows", 78));
            signals.push("ports: SMB+RDP/MSRPC".into());
        } else if has_smb {
            guess = Some(("Windows (or Samba)", 60));
            signals.push("ports: SMB".into());
        } else if has_rdp {
            guess = Some(("Windows (RDP)", 68));
            signals.push("ports: RDP".into());
        } else if has_airtunes && has_mdns {
            guess = Some(("Apple (iOS/macOS)", 80));
            signals.push("ports: AirTunes+mDNS".into());
        } else if has_airtunes {
            guess = Some(("Apple", 65));
            signals.push("ports: AirTunes".into());
        } else if has_ssh {
            guess = Some(("Linux/Unix", 45));
            signals.push("ports: SSH".into());
        }
    }

    // ---- TTL evidence (weakest, tiebreaker) -----------------------------
    if let Some(t) = ttl {
        confidence = match guess {
            Some((_, c)) => c,
            None => match t {
                124..=131 => {
                    guess = Some(("Windows", 45));
                    signals.push("ttl≈128 → Windows".into());
                    45
                }
                55..=70 => {
                    guess = Some(("Linux/macOS/Android", 40));
                    signals.push("ttl≈64 → Unix".into());
                    40
                }
                248..=255 => {
                    guess = Some(("Network device", 55));
                    signals.push("ttl≈255 → network gear".into());
                    55
                }
                _ => 0,
            },
        };
    }

    // `confidence` already holds the guess's score in every path (banner/port
    // evidence, or the TTL branch sets both at once), so just report it.
    match guess {
        Some((os, conf)) => (os.to_string(), confidence.max(conf)),
        None => ("Unknown".to_string(), 0),
    }
}

/// Look up a MAC address (any separator/case) and return the vendor from a
/// curated OUI table.
pub fn vendor_from_mac(mac: &str) -> Option<String> {
    let normalized: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if normalized.len() < 6 {
        return None;
    }
    let prefix = &normalized[..6];
    vendor_for_prefix(prefix).map(|s| s.to_string())
}

/// Curated OUI → vendor prefixes (common consumer/enterprise hardware).
/// First 6 hex digits of the MAC (uppercase).
static OUI_TABLE: &[(&str, &str)] = &[
    // Apple
    ("3C22FB", "Apple"), ("001788", "Apple"), ("F01898", "Apple"), ("000393", "Apple"),
    ("ACBC32", "Apple"), ("5CE9E1", "Apple"), ("A4B197", "Apple"),
    // Intel (incl. Wi-Fi/Bluetooth in many laptops)
    ("782B46", "Intel"), ("3C970E", "Intel"), ("001E64", "Intel"), ("40B076", "Intel"),
    ("A08869", "Intel"), ("18CF5E", "Intel"), ("8C1645", "Intel"), ("F8E71E", "Intel"),
    // Airtel (common ISP routers in South Asia)
    ("6C4F89", "Airtel"), ("DCB4C4", "Airtel"),
    // TP-Link
    ("50C7BF", "TP-Link"), ("78DB2F", "TP-Link"), ("14CC20", "TP-Link"), ("6032B1", "TP-Link"),
    ("30B49E", "TP-Link"), ("388345", "TP-Link"), ("CC32E5", "TP-Link"), ("A8D3F2", "TP-Link"),
    // Samsung
    ("0023D4", "Samsung"), ("3C8BFE", "Samsung"), ("001FCC", "Samsung"), ("0012FB", "Samsung"),
    ("F0F01C", "Samsung"), ("A4762F", "Samsung"),
    // Xiaomi
    ("7811DC", "Xiaomi"), ("640980", "Xiaomi"), ("8CDEF9", "Xiaomi"), ("D8C771", "Xiaomi"),
    // Dell
    ("001422", "Dell"), ("3417EB", "Dell"), ("001EC9", "Dell"), ("B82A44", "Dell"),
    ("48D705", "Dell"),
    // HP
    ("3CD92B", "HP"), ("001A4B", "HP"), ("705A0F", "HP"), ("9CB654", "HP"),
    // Cisco
    ("00000C", "Cisco"), ("000F66", "Cisco"), ("44D3CA", "Cisco"), ("001646", "Cisco"),
    ("001B2A", "Cisco"),
    // Netgear
    ("204E7F", "Netgear"), ("A040A0", "Netgear"), ("000FB5", "Netgear"), ("28C68E", "Netgear"),
    // ASUS
    ("001132", "ASUS"), ("04D9F5", "ASUS"), ("001BFC", "ASUS"), ("AC220B", "ASUS"),
    // Google
    ("001A11", "Google"), ("3C5AB4", "Google"), ("94EB2C", "Google"), ("F4F5D8", "Google"),
    // Amazon
    ("44650D", "Amazon"), ("F0272D", "Amazon"), ("747548", "Amazon"), ("F0E77E", "Amazon"),
    // Raspberry Pi
    ("B827EB", "Raspberry Pi"), ("DCA632", "Raspberry Pi"), ("E45F01", "Raspberry Pi"),
    // Sony
    ("00146C", "Sony"), ("001F90", "Sony"), ("3497F6", "Sony"),
    // Huawei / Honor
    ("00E0FC", "Huawei"), ("84A8E4", "Huawei"), ("20299B", "Huawei"), ("F4BBDC", "Huawei"),
    // OnePlus / Oppo / Realme (BBK)
    ("F0E4D2", "Oppo/OnePlus"), ("9C99A0", "Oppo/OnePlus"),
    // Motorola
    ("0015A2", "Motorola"), ("00246C", "Motorola"), ("D0E140", "Motorola"),
    // Nokia / Alcatel
    ("000F57", "Nokia"), ("00215A", "Nokia/Alcatel"),
    // Espressif (ESP32/ESP8266 IoT)
    ("240AC4", "Espressif"), ("30AEA4", "Espressif"), ("84CCA8", "Espressif"), ("246F28", "Espressif"),
    // Realtek (many dongles / smart TVs)
    ("00E04C", "Realtek"), ("525400", "Realtek"),
    // Linksys / Belkin
    ("001A2B", "Linksys"), ("001E58", "Linksys"), ("9432A9", "Linksys"),
    // MediaTek (broad spectrum)
    ("3C9C0F", "MediaTek"), ("18D6C7", "MediaTek"),
    // Raspberry Pi alternative / Rockchip
    ("001CC4", "Rockchip"),
    // D-Link
    ("0015E9", "D-Link"), ("286C07", "D-Link"), ("1C7EE5", "D-Link"),
    // MikroTik
    ("04818D", "MikroTik"), ("4C5E0C", "MikroTik"),
    // Ubiquiti
    ("F0963E", "Ubiquiti"), ("802AA8", "Ubiquiti"), ("78FC14", "Ubiquiti"),
    // Hisense / TCL / smart TVs
    ("001EE8", "Hisense"), ("3C84A6", "TCL"),
];

fn vendor_for_prefix(prefix: &str) -> Option<&'static str> {
    OUI_TABLE.iter().find(|(p, _)| *p == prefix).map(|(_, v)| *v)
}

/// Read the local ARP (Windows) or neighbour (Linux/macOS) table and return
/// IP → MAC mappings.
pub fn arp_table() -> HashMap<String, String> {
    let mut map = HashMap::new();
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = std::process::Command::new("arp").arg("-a").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                // Windows: "  192.168.1.5            78-2b-46-51-8e-48     dynamic"
                let mut parts = line.split_whitespace();
                if let (Some(ip), Some(mac)) = (parts.next(), parts.next()) {
                    if ip.parse::<std::net::Ipv4Addr>().is_ok()
                        && mac.matches('-').count() == 5
                    {
                        map.insert(ip.to_string(), mac.replace('-', ":").to_lowercase());
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Linux/macOS: `ip neigh` — "192.168.1.5 dev wlan0 lladdr 78:2b:... REACHABLE"
        if let Ok(out) = std::process::Command::new("ip").args(["neigh"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                if let Some(ip) = parts.next() {
                    if let Some(lladdr) = parts.find(|p| *p == "lladdr").and_then(|_| parts.next()) {
                        if ip.parse::<std::net::Ipv4Addr>().is_ok() && lladdr.matches(':').count() == 5 {
                            map.insert(ip.to_string(), lladdr.to_lowercase());
                        }
                    }
                }
            }
        }
    }
    map
}

/// Full device-scan orchestration: ping sweep with TTL, per-host fingerprint
/// probes, ARP/vendor enrichment. Returns devices sorted by IP.
pub async fn scan_devices(
    targets: &[ResolvedHost],
    timeout: Duration,
    pb: Option<&ProgressBar>,
) -> Vec<Device> {
    let ips: Vec<IpAddr> = targets.iter().map(|h| h.ip).collect();
    let hits = sweep_ping(&ips, timeout, 128, pb).await;

    // Enrich each live host in parallel, bounded like the ping sweep so a
    // huge subnet cannot spawn an unbounded number of fingerprint tasks
    // (each one probes 10 ports + banners concurrently).
    const FINGERPRINT_CONCURRENCY: usize = 64;
    let mut tasks = JoinSet::new();
    let mut next = 0usize;
    let mut devices: Vec<Device> = Vec::new();
    loop {
        while next < hits.len() && tasks.len() < FINGERPRINT_CONCURRENCY {
            let hit = hits[next];
            tasks.spawn(fingerprint_host(hit, timeout, Duration::from_millis(900)));
            next += 1;
        }
        if next >= hits.len() && tasks.is_empty() {
            break;
        }
        if let Some(Ok(dev)) = tasks.join_next().await {
            devices.push(dev);
        }
    }

    // Attach MAC + vendor from the local ARP/neighbour table.
    let arp = arp_table();
    for dev in &mut devices {
        if let Some(mac) = arp.get(&dev.ip.to_string()) {
            dev.mac = Some(mac.clone());
            dev.vendor = vendor_from_mac(mac);
        }
    }
    devices.sort_by_key(|d| d.ip);
    devices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oui_lookup() {
        assert_eq!(vendor_from_mac("3C:22:FB:12:34:56").as_deref(), Some("Apple"));
        assert_eq!(vendor_from_mac("78:2B:46:51:8E:48").as_deref(), Some("Intel"));
        assert_eq!(vendor_from_mac("B8:27:EB:00:00:01").as_deref(), Some("Raspberry Pi"));
        assert_eq!(vendor_from_mac("50:C7:BF:AA:BB:CC").as_deref(), Some("TP-Link"));
        assert_eq!(vendor_from_mac("00:11:22:33:44:55"), None);
        assert_eq!(vendor_from_mac("bogus"), None);
    }

    #[test]
    fn ttl_fingerprinting() {
        let mut s = Vec::new();
        let (os, _) = fingerprint_os(Some(128), &[], &[], &mut s);
        assert_eq!(os, "Windows");
        let mut s = Vec::new();
        let (os, _) = fingerprint_os(Some(64), &[], &[], &mut s);
        assert_eq!(os, "Linux/macOS/Android");
        let mut s = Vec::new();
        let (os, _) = fingerprint_os(Some(255), &[], &[], &mut s);
        assert_eq!(os, "Network device");
        let mut s = Vec::new();
        let (os, _) = fingerprint_os(None, &[], &[], &mut s);
        assert_eq!(os, "Unknown");
    }

    #[test]
    fn port_pattern_fingerprinting() {
        let mut s = Vec::new();
        let (os, c) = fingerprint_os(None, &[139, 445, 3389], &[], &mut s);
        assert_eq!(os, "Windows");
        assert!(c >= 78);
        let mut s = Vec::new();
        let (os, _) = fingerprint_os(None, &[62078, 5353], &[], &mut s);
        assert_eq!(os, "Apple (iOS/macOS)");
        let mut s = Vec::new();
        let (os, _) = fingerprint_os(None, &[22], &[], &mut s);
        assert_eq!(os, "Linux/Unix");
    }

    #[test]
    fn banner_fingerprinting() {
        let ssh = OpenPort {
            port: 22,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("ssh".into()),
            version: Some("8.9".into()),
            banner: Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".into()),
        };
        let mut s = Vec::new();
        let (os, c) = fingerprint_os(Some(64), &[22], &[ssh], &mut s);
        assert_eq!(os, "Linux (Ubuntu)");
        assert!(c >= 95);

        let iis = OpenPort {
            port: 80,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("http".into()),
            version: None,
            banner: Some("HTTP/1.1 200 OK\\nServer: Microsoft-IIS/10.0".into()),
        };
        let mut s = Vec::new();
        let (os, _) = fingerprint_os(Some(128), &[80], &[iis], &mut s);
        assert_eq!(os, "Windows (IIS)");
    }
}
