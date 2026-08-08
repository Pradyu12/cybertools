//! Output renderers: human table, JSON, and CSV.

use crate::networks::AccessPoint;
use std::io::Write;

/// Render a human-readable table, optionally with ANSI colour.
pub fn render_human(aps: &[AccessPoint], color: bool) -> String {
    let mut out = String::new();
    if aps.is_empty() {
        out.push_str("No networks found (are you connected to Wi-Fi? try `--iface`)\n");
        return out;
    }

    let sorted: Vec<&AccessPoint> = {
        let mut v: Vec<&AccessPoint> = aps.iter().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.signal_pct));
        v
    };

    let c = |s: &str| -> String {
        if color {
            format!("\x1b[1;32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };

    out.push_str(&format!(
        "{:<4} {:<19} {:<4} {:<5} {:<20} {}\n",
        "CH", "BSSID", "SIG%", "dBm", "SECURITY", "SSID"
    ));
    out.push_str(&format!(
        "{:<4} {:<19} {:<4} {:<5} {:<20} {}\n",
        "---", "-------------------", "----", "-----", "--------------------", "----"
    ));
    for ap in &sorted {
        let ssid = if ap.hidden {
            format!("({})", c("hidden"))
        } else {
            c(&ap.ssid)
        };
        let detail = if ap.band.is_empty() {
            String::new()
        } else {
            format!("[{} {}]", ap.band, ap.radio)
        };
        out.push_str(&format!(
            "{:<4} {:<19} {:<5} {:<6} {:<20} {}\n",
            ap.channel, c(&ap.bssid), ap.signal_pct, ap.signal_dbm(), ap.security(), ssid
        ));
        if !detail.is_empty() {
            out.push_str(&format!("    {:<19} {:<5} {:<6} {:<20} {}\n", "", "", "", "", detail));
        }
    }
    out
}

/// Render JSON.
pub fn render_json(aps: &[AccessPoint]) -> String {
    let mut out = String::new();
    out.push_str("[\n");
    for (i, ap) in aps.iter().enumerate() {
        out.push_str("  ");
        out.push_str(&serde_json::to_string_pretty(ap).unwrap_or_default().replace('\n', "\n  "));
        if i + 1 < aps.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

/// Render CSV (RFC4180-ish).
pub fn render_csv(aps: &[AccessPoint]) -> String {
    let mut out = String::new();
    out.push_str("ssid,bssid,channel,band,radio,signal_pct,signal_dbm,auth,cipher,hidden\n");
    for ap in aps {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&ap.ssid),
            ap.bssid,
            ap.channel,
            csv_escape(&ap.band),
            csv_escape(&ap.radio),
            ap.signal_pct,
            ap.signal_dbm(),
            csv_escape(&ap.auth),
            csv_escape(&ap.cipher),
            ap.hidden,
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Write output to a file if `-o` given, otherwise stdout.
pub fn emit(aps: &[AccessPoint], json: bool, csv: bool, output: Option<&str>, color: bool) -> Result<(), std::io::Error> {
    let body = if json {
        render_json(aps)
    } else if csv {
        render_csv(aps)
    } else {
        render_human(aps, color)
    };
    match output {
        Some(path) => {
            let mut f = std::fs::File::create(path)?;
            f.write_all(body.as_bytes())?;
            println!("[i] wrote {} AP(s) to {}", aps.len(), path);
        }
        None => {
            // Tolerate a closed pipe (e.g. `wifiti scan | head`).
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            if let Err(e) = lock.write_all(body.as_bytes()) {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::AccessPoint;

    fn ap() -> AccessPoint {
        AccessPoint {
            ssid: "TestNet".into(),
            bssid: "AA:BB:CC:DD:EE:FF".into(),
            auth: "WPA2-Personal".into(),
            cipher: "CCMP".into(),
            channel: 6,
            band: "2.4 GHz".into(),
            radio: "802.11n".into(),
            signal_pct: 87,
            hidden: false,
        }
    }

    #[test]
    fn human_table_has_header_and_row() {
        let t = render_human(&[ap()], false);
        assert!(t.contains("BSSID"));
        assert!(t.contains("AA:BB:CC:DD:EE:FF"));
        assert!(t.contains("WPA2-Personal"));
    }

    #[test]
    fn json_valid() {
        let j = render_json(&[ap()]);
        let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed[0]["ssid"], "TestNet");
        assert_eq!(parsed[0]["signal_pct"], 87);
    }

    #[test]
    fn csv_escapes_commas() {
        let mut a = ap();
        a.ssid = "Has,Comma".into();
        let c = render_csv(&[a]);
        assert!(c.contains("\"Has,Comma\""));
    }

    #[test]
    fn empty_is_graceful() {
        assert!(render_human(&[], false).contains("No networks found"));
    }
}
