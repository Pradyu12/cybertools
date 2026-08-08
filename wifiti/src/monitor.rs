//! Live monitoring: repeatedly rescan and render a live AP table, tracking
//! networks that appear / disappear / change signal strength (wifite-style).

use crate::backend::Backend;
use crate::networks::AccessPoint;
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct Tracked {
    ap: AccessPoint,
    prev_signal: i32,
}

/// Render a single AP row as a live-updating line.
pub fn render_live_row(ap: &AccessPoint, delta: Option<i32>) -> String {
    let bars = signal_bars(ap.signal_pct);
    let mut line = format!(
        "{:<4} {:<19} {} {:<3}%  {:<6} {:<20} {}",
        ap.channel,
        ap.bssid,
        bars,
        ap.signal_pct,
        format!("{:<4}", ap.signal_dbm()),
        if ap.hidden { "(hidden)".into() } else { ap.ssid.clone() },
        ap.auth,
    );
    if let Some(d) = delta {
        if d > 0 {
            line.push_str(&format!(" \x1b[1;32m▲{d}\x1b[0m"));
        } else if d < 0 {
            line.push_str(&format!(" \x1b[1;31m▼{}\x1b[0m", -d));
        }
    }
    line
}

fn signal_bars(pct: u8) -> String {
    let filled = (pct as f32 / 100.0 * 10.0).round() as usize;
    let mut s = String::new();
    s.push('[');
    for i in 0..10 {
        if i < filled {
            s.push('█');
        } else {
            s.push('░');
        }
    }
    s.push(']');
    s
}

/// Run the monitor loop. Returns when Ctrl+C (or an error) occurs.
pub fn run_monitor(backend: &Backend, interval: Duration) -> Result<(), crate::backend::BackendError> {
    let mut tracked: HashMap<String, Tracked> = HashMap::new();
    let mut cycle = 0u32;

    println!("\x1b[2J\x1b[H"); // clear screen
    println!("wifiti monitor — Ctrl+C to stop\n");

    loop {
        let started = Instant::now();
        let aps = backend.scan()?;

        let mut current: HashMap<String, AccessPoint> = HashMap::new();
        for ap in &aps {
            current.insert(ap.bssid.clone(), ap.clone());
        }

        // Detect new / gone APs.
        let new: Vec<&AccessPoint> = aps.iter().filter(|a| !tracked.contains_key(&a.bssid)).collect();
        let gone: Vec<String> = tracked
            .keys()
            .filter(|k| !current.contains_key(*k))
            .cloned()
            .collect();

        // Update tracked state (keep old APs that disappeared for one cycle).
        for k in &gone {
            tracked.remove(k);
        }
        for ap in &aps {
            let entry = tracked
                .entry(ap.bssid.clone())
                .or_insert_with(|| Tracked { ap: ap.clone(), prev_signal: -1 });
            entry.prev_signal = entry.ap.signal_pct as i32;
            entry.ap = ap.clone();
        }

        // Render header.
        println!("\x1b[1;32mcycle {cycle} · {} AP(s) · +{} new · -{} gone\x1b[0m", aps.len(), new.len(), gone.len());
        println!("{:<4} {:<19} {:<12} {:<5} {:<6} {:<20} SECURITY", "CH", "BSSID", "SIGNAL", "SIG%", "dBm", "SSID");

        // Sort by channel then signal.
        let mut rows: Vec<&AccessPoint> = aps.iter().collect();
        rows.sort_by(|a, b| a.channel.cmp(&b.channel).then(b.signal_pct.cmp(&a.signal_pct)));
        for ap in rows {
            let delta = tracked
                .get(&ap.bssid)
                .filter(|t| t.prev_signal >= 0 && t.prev_signal != ap.signal_pct as i32)
                .map(|t| ap.signal_pct as i32 - t.prev_signal);
            let mark = if new.iter().any(|n| n.bssid == ap.bssid) {
                " \x1b[1;33m[NEW]\x1b[0m"
            } else {
                ""
            };
            println!("{}{}", render_live_row(ap, delta), mark);
        }
        for g in &gone {
            println!("  \x1b[1;31m— gone: {g}\x1b[0m");
        }

        // Sleep for the remainder of the interval (unless a scan took longer).
        let elapsed = started.elapsed();
        if elapsed < interval {
            std::thread::sleep(interval - elapsed);
        }
        cycle += 1;
    }
}
