//! Post-scan nmap integration.
//!
//! Once Vajra knows which ports are open, it hands them to nmap so the
//! heavy lifting (`-sV`, `-sC`, `-A`, scripts, OS detection) only runs against
//! open ports. The nmap command is built as `nmap <user args> -p <ports>
//! <targets>` and inherits stdio so output streams straight to the user.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Command;

use crate::banner::OpenPort;

/// Run nmap against the open ports. Silently skips when nmap is unavailable.
///
/// TCP and UDP ports are handed over with per-protocol specs
/// (`-p T:80,443,U:53`) so nmap scans each port with the right transport.
pub fn run_nmap(ips: &[IpAddr], open: &BTreeMap<IpAddr, Vec<OpenPort>>, extra: &[String]) {
    let mut tcp: Vec<u16> = open
        .values()
        .flatten()
        .filter(|p| p.protocol == "tcp" && p.state == "open")
        .map(|p| p.port)
        .collect();
    let mut udp: Vec<u16> = open
        .values()
        .flatten()
        .filter(|p| p.protocol == "udp" && p.state == "open")
        .map(|p| p.port)
        .collect();
    tcp.sort_unstable();
    tcp.dedup();
    udp.sort_unstable();
    udp.dedup();
    if tcp.is_empty() && udp.is_empty() {
        println!("[*] No open ports found — skipping nmap.");
        return;
    }

    let mut spec = String::new();
    if !tcp.is_empty() {
        spec.push_str("T:");
        spec.push_str(&tcp.iter().map(u16::to_string).collect::<Vec<_>>().join(","));
    }
    if !udp.is_empty() {
        if !spec.is_empty() {
            spec.push(',');
        }
        spec.push_str("U:");
        spec.push_str(&udp.iter().map(u16::to_string).collect::<Vec<_>>().join(","));
    }

    let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    let mut cmd = Command::new("nmap");
    cmd.args(extra).arg("-p").arg(&spec);
    for ip in &ip_strs {
        cmd.arg(ip);
    }

    let display = format!("nmap {} -p {spec} {}", extra.join(" "), ip_strs.join(" "));
    println!("[*] Running: {display}");

    match cmd.spawn() {
        Ok(mut child) => {
            let _ = child.wait();
        }
        Err(e) => eprintln!(
            "[!] Failed to run nmap: {e}\n    Install nmap (https://nmap.org) or pass --no-nmap."
        ),
    }
}
