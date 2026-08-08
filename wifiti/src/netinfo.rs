//! Local network info for the connected Wi-Fi: our IPv4 address and the
//! gateway. Pulled from `ipconfig` on Windows (matching the wireless
//! adapter) and `ip` on Linux/macOS.

use serde::Serialize;
use std::process::Command;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct NetInfo {
    pub ipv4: Option<String>,
    pub gateway: Option<String>,
    pub subnet: Option<String>,
    /// Which network we are connected to (SSID).
    pub ssid: Option<String>,
}

impl NetInfo {
    pub fn is_some(&self) -> bool {
        self.ipv4.is_some() || self.gateway.is_some()
    }
}

/// Detect the local Wi-Fi network information.
pub fn detect() -> NetInfo {
    #[cfg(target_os = "windows")]
    {
        windows_detect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        unix_detect()
    }
}

#[cfg(target_os = "windows")]
fn windows_detect() -> NetInfo {
    let mut info = NetInfo::default();
    if let Ok(out) = Command::new("ipconfig").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        info = parse_ipconfig(&text);
    }
    // SSID from the wireless interface state.
    if let Ok(out) = Command::new("netsh").args(["wlan", "show", "interfaces"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("SSID") {
                if let Some((_, v)) = rest.split_once(':') {
                    let v = v.trim();
                    if !v.is_empty() {
                        info.ssid = Some(v.to_string());
                    }
                }
                break;
            }
        }
    }
    info
}

/// Parse `ipconfig` output for the wireless adapter block (the one that
/// contains a "Wireless LAN adapter" header and a connected IPv4 address).
fn parse_ipconfig(text: &str) -> NetInfo {
    let mut info = NetInfo::default();
    let mut in_wireless = false;
    let mut pending_gateway_continuation = false;

    for raw in text.lines() {
        let line = raw.trim();
        let had_cont = pending_gateway_continuation;
        pending_gateway_continuation = false;
        if line.to_lowercase().contains("wireless lan adapter") {
            in_wireless = !line.to_lowercase().contains("media disconnected");
            continue;
        }
        if in_wireless {
            if line.to_lowercase().contains("adapter") && !line.contains("Wireless LAN") {
                in_wireless = false;
                continue;
            }
            if had_cont && info.gateway.is_none() && line.contains('.') {
                // ipconfig wraps a long gateway onto the next indented line.
                info.gateway = Some(line.to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("IPv4 Address") {
                if let Some((_, v)) = rest.split_once(':') {
                    let v = v.trim();
                    if !v.is_empty() {
                        info.ipv4 = Some(v.to_string());
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Subnet Mask") {
                if let Some((_, v)) = rest.split_once(':') {
                    let v = v.trim();
                    if !v.is_empty() && v != "255.255.255.255" {
                        info.subnet = Some(v.to_string());
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Default Gateway") {
                if let Some((_, v)) = rest.split_once(':') {
                    let v = v.trim();
                    if v.contains('.') {
                        if info.gateway.is_none() {
                            info.gateway = Some(v.to_string());
                        }
                    } else {
                        // Link-local/IPv6 gateway — the IPv4 gateway may be
                        // on the next (indented) line.
                        pending_gateway_continuation = true;
                    }
                }
            }
        }
    }
    // If no wireless block matched (e.g. non-English Windows), fall back to
    // the first IPv4 address in the whole output.
    if info.ipv4.is_none() {
        for raw in text.lines() {
            let line = raw.trim();
            if let Some(rest) = line.strip_prefix("IPv4 Address") {
                if let Some((_, v)) = rest.split_once(':') {
                    let v = v.trim();
                    if !v.is_empty() {
                        info.ipv4 = Some(v.to_string());
                        break;
                    }
                }
            }
        }
    }
    info
}

#[cfg(not(target_os = "windows"))]
fn unix_detect() -> NetInfo {
    let mut info = NetInfo::default();
    // IPv4 of the default-route interface.
    if let Ok(out) = Command::new("sh")
        .args(["-c", "ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}'"])
        .output()
    {
        let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !ip.is_empty() {
            info.ipv4 = Some(ip);
        }
    }
    // Gateway from the default route.
    if let Ok(out) = Command::new("sh")
        .args(["-c", "ip -4 route show default 2>/dev/null | awk '{print $3; exit}'"])
        .output()
    {
        let gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !gw.is_empty() {
            info.gateway = Some(gw);
        }
    }
    // SSID from nmcli.
    if let Ok(out) = Command::new("nmcli")
        .args(["-t", "-f", "active,ssid", "dev", "wifi"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let mut parts = line.splitn(2, ':');
            if parts.next() == Some("yes") {
                if let Some(ssid) = parts.next() {
                    info.ssid = Some(ssid.trim().to_string());
                    break;
                }
            }
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipconfig_wireless_block() {
        let out = "\r\nWireless LAN adapter Wi-Fi:\r\n\r\n   Connection-specific DNS Suffix  . : \r\n   IPv4 Address. . . . . . . . . . . : 192.168.1.13\r\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . : 192.168.1.1\r\n\r\nEthernet adapter Ethernet:\r\n\r\n   IPv4 Address. . . . . . . . . . . : 10.0.0.5\r\n";
        let info = parse_ipconfig(out);
        assert_eq!(info.ipv4.as_deref(), Some("192.168.1.13"));
        assert_eq!(info.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(info.subnet.as_deref(), Some("255.255.255.0"));
    }

    #[test]
    fn ignores_disconnected_and_ipv6_gateway() {
        let out = "\r\nWireless LAN adapter Local Area Connection* 1:\r\n\r\n   Media State . . . . . . . . . . : Media disconnected\r\n\r\nWireless LAN adapter Wi-Fi:\r\n\r\n   IPv4 Address. . . . . . . . . . . : 192.168.1.13\r\n   Default Gateway . . . . . . . . . : fe80::6e4f:89ff:fe95:3cd8%19\r\n                                       192.168.1.1\r\n";
        let info = parse_ipconfig(out);
        assert_eq!(info.ipv4.as_deref(), Some("192.168.1.13"));
        // IPv6 link-local gateway must be ignored; IPv4 gateway picked up from
        // the continuation line.
        assert_eq!(info.gateway.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn fallback_first_ipv4() {
        let out = "Ethernet adapter Ethernet:\n   IPv4 Address. . . . . . . . . . . : 10.0.0.5\n";
        let info = parse_ipconfig(out);
        assert_eq!(info.ipv4.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn empty_when_nothing() {
        let info = parse_ipconfig("no addresses here");
        assert!(!info.is_some());
    }
}
