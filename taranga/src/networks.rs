//! Wi-Fi network data model + parsers for `netsh` (Windows), `nmcli` and
//! `iw` (Linux) scan output.

use serde::Serialize;
use std::collections::HashMap;

/// A single access point (one BSSID of one SSID).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AccessPoint {
    pub ssid: String,
    pub bssid: String,
    pub auth: String,   // e.g. "WPA2-Personal", "WPA3-Personal", "Open"
    pub cipher: String, // e.g. "CCMP", "GCMP"
    pub channel: u16,
    pub band: String, // "2.4 GHz" / "5 GHz" / "6 GHz"
    pub radio: String,
    pub signal_pct: u8,   // 0-100
    pub hidden: bool,
}

impl AccessPoint {
    /// Signal strength in dBm approximated from percentage (0-100 -> -100..-30).
    pub fn signal_dbm(&self) -> i32 {
        -100 + (self.signal_pct as i32 * 70 / 100)
    }

    /// Human security label; falls back to "(unknown)" when unset.
    pub fn security(&self) -> String {
        if self.auth.is_empty() {
            "(unknown)".to_string()
        } else {
            self.auth.clone()
        }
    }
}

/// Parse `netsh wlan show networks mode=bssid` output.
pub fn parse_netsh(text: &str) -> Vec<AccessPoint> {
    let mut aps = Vec::new();
    let mut current_ssid: Option<String> = None;
    let mut current_auth = String::new();
    let mut current_cipher = String::new();
    let mut hidden = false;
    let mut bssid: Option<String> = None;
    let mut signal: Option<u8> = None;
    let mut radio = String::new();
    let mut band = String::new();
    let mut channel: Option<u16> = None;

    let flush = |aps: &mut Vec<AccessPoint>,
                 ssid: &Option<String>,
                 auth: &str,
                 cipher: &str,
                 hidden: bool,
                 bssid: &Option<String>,
                 signal: Option<u8>,
                 radio: &str,
                 band: &str,
                 channel: Option<u16>| {
        if let (Some(ssid), Some(bssid)) = (ssid, bssid) {
            aps.push(AccessPoint {
                ssid: if ssid.trim().is_empty() {
                    "(hidden)".to_string()
                } else {
                    ssid.trim().to_string()
                },
                bssid: bssid.trim().to_uppercase(),
                auth: auth.trim().to_string(),
                cipher: cipher.trim().to_string(),
                channel: channel.unwrap_or(0),
                band: band.trim().to_string(),
                radio: radio.trim().to_string(),
                signal_pct: signal.unwrap_or(0),
                hidden,
            });
        }
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("SSID ") {
            // "SSID 1 : foo" -> new SSID block; flush any in-progress AP
            flush(
                &mut aps,
                &current_ssid,
                &current_auth,
                &current_cipher,
                hidden,
                &bssid,
                signal,
                &radio,
                &band,
                channel,
            );
            let name = rest
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            let trimmed = name.trim();
            current_ssid = Some(trimmed.to_string());
            hidden = trimmed.is_empty();
            current_auth.clear();
            current_cipher.clear();
            bssid = None;
            signal = None;
            radio.clear();
            band.clear();
            channel = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("Authentication") {
            current_auth = rest
                .split_once(':')
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            continue;
        }
        if let Some(rest) = line.strip_prefix("Encryption") {
            current_cipher = rest
                .split_once(':')
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            continue;
        }
        if let Some(rest) = line.strip_prefix("BSSID ") {
            // New BSSID under the current SSID; flush the previous one.
            flush(
                &mut aps,
                &current_ssid,
                &current_auth,
                &current_cipher,
                hidden,
                &bssid,
                signal,
                &radio,
                &band,
                channel,
            );
            bssid = rest
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .filter(|s| !s.is_empty());
            signal = None;
            radio.clear();
            band.clear();
            channel = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("Signal") {
            signal = rest
                .split_once(':')
                .and_then(|(_, v)| v.trim().trim_end_matches('%').parse().ok());
            continue;
        }
        if let Some(rest) = line.strip_prefix("Radio type") {
            radio = rest
                .split_once(':')
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            continue;
        }
        if let Some(rest) = line.strip_prefix("Band") {
            band = rest
                .split_once(':')
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            continue;
        }
        if let Some(rest) = line.strip_prefix("Channel") {
            channel = rest
                .split_once(':')
                .and_then(|(_, v)| v.trim().parse().ok());
            continue;
        }
    }
    flush(
        &mut aps,
        &current_ssid,
        &current_auth,
        &current_cipher,
        hidden,
        &bssid,
        signal,
        &radio,
        &band,
        channel,
    );
    aps
}

/// Parse `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY,IN-USE,RATE dev wifi list`
/// output (tab-separated, escaped values).
pub fn parse_nmcli(text: &str) -> Vec<AccessPoint> {
    let mut aps = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            continue;
        }
        let unesc = |s: &str| s.replace("\\:", ":").replace("\\\\", "\\");
        let ssid = unesc(parts[0]);
        let bssid = unesc(parts[1]);
        let channel: u16 = parts[2].parse().unwrap_or(0);
        let signal: u8 = parts[3].parse().unwrap_or(0);
        let security = if parts[4].is_empty() { "Open" } else { parts[4] };
        let mut hidden = false;
        let mut band = String::new();
        let mut radio = String::new();
        if parts.len() > 7 {
            band = parts[7].to_string();
            radio = parts[7].to_string();
        }
        if parts.len() > 8 {
            hidden = parts[8].to_lowercase().contains("yes");
        }
        aps.push(AccessPoint {
            ssid,
            bssid: bssid.to_uppercase(),
            auth: security.to_string(),
            cipher: String::new(),
            channel,
            band,
            radio,
            signal_pct: signal,
            hidden,
        });
    }
    aps
}

/// Parse `iw dev <if> scan` output (raw 802.11 survey dump).
pub fn parse_iw(text: &str) -> Vec<AccessPoint> {
    let mut aps = Vec::new();
    let mut cur: HashMap<String, String> = HashMap::new();
    let mut freq: Option<u32> = None;
    let mut signal_pct: u8 = 0;

    let flush = |cur: &mut HashMap<String, String>,
                     freq: &mut Option<u32>,
                     signal_pct: &mut u8,
                     aps: &mut Vec<AccessPoint>| {
        let ssid = cur.get("ssid").cloned().unwrap_or_default();
        if let Some(bssid) = cur.get("bssid").cloned() {
            let f = freq.take();
            let channel = freq_to_channel(f);
            aps.push(AccessPoint {
                ssid: if ssid.is_empty() { "(hidden)".into() } else { ssid.clone() },
                bssid: bssid.to_uppercase(),
                auth: cur.get("auth").cloned().unwrap_or_default(),
                cipher: cur.get("cipher").cloned().unwrap_or_default(),
                channel,
                band: f
                    .map(|f| {
                        if f >= 5925 {
                            "6 GHz".into()
                        } else if f >= 4900 {
                            "5 GHz".into()
                        } else {
                            "2.4 GHz".into()
                        }
                    })
                    .unwrap_or_default(),
                radio: cur.get("radio").cloned().unwrap_or_default(),
                signal_pct: std::mem::take(signal_pct),
                hidden: cur.get("ssid").map(|s| s.is_empty()).unwrap_or(false),
            });
        }
        cur.clear();
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("BSS ") {
            flush(&mut cur, &mut freq, &mut signal_pct, &mut aps);
            cur.insert(
                "bssid".to_string(),
                line.strip_prefix("BSS ")
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string(),
            );
        } else if line.starts_with("freq:") {
            freq = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok());
        } else if line.starts_with("signal:") {
            // "signal: -67.00 dBm"
            if let Some(s) = line.split_whitespace().nth(1) {
                if let Ok(dbm) = s.parse::<f64>() {
                    signal_pct = dbm_to_pct(dbm);
                }
            }
        } else if line.starts_with("SSID:") {
            cur.insert(
                "ssid".to_string(),
                line.trim_start_matches("SSID:").trim().to_string(),
            );
        } else if line.starts_with("RSN:") || line.starts_with("WPA:") {
            // WPA/WPA2/WPA3 indicated by RSN / WPA IE presence
            cur.insert("auth".to_string(), "WPA".to_string());
            cur.insert("cipher".to_string(), "CCMP".to_string());
        } else if line.starts_with("CIPHER") {
            cur.insert(
                "cipher".to_string(),
                line.split(':').next_back().unwrap_or("").trim().to_string(),
            );
        } else if line.starts_with("WPS:") {
            cur.insert("wps".to_string(), "yes".to_string());
        }
    }
    flush(&mut cur, &mut freq, &mut signal_pct, &mut aps);
    aps
}

pub fn freq_to_channel(freq: Option<u32>) -> u16 {
    match freq {
        Some(f) if (2412..=2484).contains(&f) => ((f - 2412) / 5 + 1) as u16,
        Some(f) if (5180..=5885).contains(&f) => ((f - 5180) / 5 + 36) as u16,
        Some(f) if (5955..=7115).contains(&f) => ((f - 5955) / 5 + 1) as u16,
        _ => 0,
    }
}

pub fn dbm_to_pct(dbm: f64) -> u8 {
    let pct = ((dbm + 100.0) / 70.0 * 100.0).clamp(0.0, 100.0);
    pct as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_netsh_with_multiple_bssids() {
        let out = "\r\nInterface name : Wi-Fi \r\nThere are 2 networks currently visible. \r\n\r\nSSID 1 : \r\n    Network type            : Infrastructure\r\n    Authentication          : WPA2-Personal\r\n    Encryption              : CCMP \r\n    BSSID 1                 : 6e:4f:89:95:3c:df\r\n         Signal             : 53%  \r\n         Radio type         : 802.11ax\r\n         Band               : 5 GHz\r\n         Channel            : 36 \r\n         Basic rates (Mbps) : 6 9 12 18 24\r\n\r\nSSID 2 : Airtel_venk_6990\r\n    Authentication          : WPA2-Personal\r\n    Encryption              : CCMP\r\n    BSSID 1                 : 6c:4f:89:95:3c:de\r\n         Signal             : 91%\r\n         Radio type         : 802.11ac\r\n         Band               : 2.4 GHz\r\n         Channel            : 6\r\n";
        let aps = parse_netsh(out);
        assert_eq!(aps.len(), 2);
        assert_eq!(aps[0].ssid, "(hidden)");
        assert!(aps[0].hidden);
        assert_eq!(aps[0].bssid, "6E:4F:89:95:3C:DF");
        assert_eq!(aps[0].channel, 36);
        assert_eq!(aps[0].signal_pct, 53);
        assert_eq!(aps[1].ssid, "Airtel_venk_6990");
        assert_eq!(aps[1].signal_pct, 91);
        assert_eq!(aps[1].channel, 6);
        assert_eq!(aps[1].auth, "WPA2-Personal");
    }

    #[test]
    fn parses_nmcli() {
        let out = "MyNet\tAA:BB:CC:DD:EE:FF\t6\t87\tWPA2\tno\t195 Mbit/s\t54 MHz\t\nOtherNet\t11:22:33:44:55:66\t149\t45\tWPA3\tno\t130 Mbit/s\t5.18 GHz\t\n";
        let aps = parse_nmcli(out);
        assert_eq!(aps.len(), 2);
        assert_eq!(aps[0].ssid, "MyNet");
        assert_eq!(aps[0].bssid, "AA:BB:CC:DD:EE:FF");
        assert_eq!(aps[0].channel, 6);
        assert_eq!(aps[0].signal_pct, 87);
        assert_eq!(aps[1].auth, "WPA3");
        assert_eq!(aps[1].channel, 149);
    }

    #[test]
    fn parses_iw_scan() {
        let out = "BSS 6e:4f:89:95:3c:df(on wlan0)\n\tfreq: 5180\n\tSSID: TestAP\n\tsignal: -67.00 dBm\n\tRSN:\n\t\tCIPHER:TKIP\nBSS 4a:43:dd:07:39:72(on wlan0)\n\tfreq: 2412\n\tsignal: -80.00 dBm\n";
        let aps = parse_iw(out);
        assert_eq!(aps.len(), 2);
        assert_eq!(aps[0].ssid, "TestAP");
        assert_eq!(aps[0].channel, 36);
        assert_eq!(aps[0].signal_pct, 47);
        assert_eq!(aps[0].auth, "WPA");
        assert_eq!(aps[1].ssid, "(hidden)");
        assert_eq!(aps[1].channel, 1);
    }

    #[test]
    fn channel_and_dbm_helpers() {
        assert_eq!(freq_to_channel(Some(2412)), 1);
        assert_eq!(freq_to_channel(Some(2447)), 8);
        assert_eq!(freq_to_channel(Some(5180)), 36);
        assert_eq!(freq_to_channel(Some(5955)), 1);
        assert_eq!(dbm_to_pct(-50.0), 71);
        assert_eq!(dbm_to_pct(-90.0), 14);
    }
}
