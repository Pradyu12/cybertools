//! taranga — a wifite-style Wi-Fi auditing toolkit in Rust.
//!
//! Subcommands:
//!   scan          one-shot AP scan (human / JSON / CSV)
//!   monitor       live rescan loop with signal tracking
//!   crack-pmkid   dictionary-crack a captured PMKID (pure Rust, offline)

mod backend;
mod crack;
mod dashboard;
mod monitor;
mod netinfo;
mod networks;
mod output;
mod web;

use clap::{Args, Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "taranga",
    version,
    about = "taranga — wifite-style Wi-Fi auditing: AP scanning, live monitoring, PMKID cracking",
    long_about = "taranga is a Rust re-imagining of wifite's core workflow: scan nearby access points \
                  (netsh on Windows, nmcli/iw on Linux), monitor them live as you move around, and \
                  dictionary-crack captured WPA/WPA2 PMKID hashes entirely offline in pure Rust."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// One-shot scan of nearby access points
    Scan(ScanArgs),
    /// Continuously rescan and show a live table
    Monitor(MonitorArgs),
    /// Dictionary-crack a captured PMKID hash (offline)
    CrackPmkid(CrackArgs),
}

#[derive(Args)]
struct ScanArgs {
    /// Linux only: wireless interface name (e.g. wlan0)
    #[arg(long)]
    iface: Option<String>,

    /// JSON output
    #[arg(long)]
    json: bool,

    /// CSV output
    #[arg(long)]
    csv: bool,

    /// Write output to a file
    #[arg(short, long)]
    output: Option<String>,

    /// Disable ANSI colours
    #[arg(long)]
    no_color: bool,

    /// Serve the live web dashboard while scanning
    #[arg(long)]
    web: bool,

    /// Port for the live web dashboard
    #[arg(long, default_value_t = 9334)]
    web_port: u16,

    /// Do not auto-open the dashboard in a browser
    #[arg(long)]
    no_open: bool,
}

#[derive(Args)]
struct MonitorArgs {
    /// Linux only: wireless interface name (e.g. wlan0)
    #[arg(long)]
    iface: Option<String>,

    /// Rescan interval in seconds
    #[arg(short, long, default_value_t = 5.0)]
    interval: f64,

    /// Serve the live web dashboard while monitoring
    #[arg(long)]
    web: bool,

    /// Port for the live web dashboard
    #[arg(long, default_value_t = 9334)]
    web_port: u16,

    /// Do not auto-open the dashboard in a browser
    #[arg(long)]
    no_open: bool,
}

#[derive(Args)]
struct CrackArgs {
    /// The captured PMKID as 32 hex characters
    #[arg(long)]
    pmkid: String,

    /// AP (access point) MAC address, e.g. 6c:4f:89:95:3c:de
    #[arg(long)]
    ap_mac: String,

    /// Client (station) MAC address from the capture
    #[arg(long)]
    client_mac: String,

    /// The network SSID
    #[arg(long)]
    essid: String,

    /// Wordlist file (one candidate passphrase per line)
    #[arg(short, long)]
    wordlist: String,

    /// Serve the live web dashboard while cracking
    #[arg(long)]
    web: bool,

    /// Port for the live web dashboard
    #[arg(long, default_value_t = 9334)]
    web_port: u16,

    /// Do not auto-open the dashboard in a browser
    #[arg(long)]
    no_open: bool,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scan(args) => cmd_scan(&args),
        Commands::Monitor(args) => cmd_monitor(&args),
        Commands::CrackPmkid(args) => cmd_crack(&args),
    };
    if let Err(e) = result {
        eprintln!("\x1b[1;31merror:\x1b[0m {e}");
        std::process::exit(1);
    }
}

fn cmd_scan(args: &ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    let backend = backend::Backend::detect(args.iface.as_deref())?;
    if args.web {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(web::run_scan_web(backend, args.web_port, args.no_open))?;
        return Ok(());
    }
    let aps = backend.scan()?;
    // Print local network info first (IP / gateway / SSID of the connected Wi-Fi).
    let net = netinfo::detect();
    if net.is_some() && !args.json && !args.csv {
        println!("[net] {}", net_line(&net));
    }
    let color = !args.no_color && std::io::IsTerminal::is_terminal(&std::io::stdout());
    output::emit(&aps, args.json, args.csv, args.output.as_deref(), color)?;
    Ok(())
}

fn net_line(net: &netinfo::NetInfo) -> String {
    let mut parts = Vec::new();
    if let Some(ip) = &net.ipv4 {
        parts.push(format!("ip {ip}"));
    }
    if let Some(gw) = &net.gateway {
        parts.push(format!("gw {gw}"));
    }
    if let Some(ssid) = &net.ssid {
        parts.push(format!("on \"{ssid}\""));
    }
    if parts.is_empty() {
        "no connected Wi-Fi".to_string()
    } else {
        parts.join(" · ")
    }
}

fn cmd_monitor(args: &MonitorArgs) -> Result<(), Box<dyn std::error::Error>> {
    let backend = backend::Backend::detect(args.iface.as_deref())?;
    let interval = Duration::from_secs_f64(args.interval.max(0.5));
    if args.web {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(web::run_monitor_web(backend, interval, args.web_port, args.no_open))?;
        return Ok(());
    }
    monitor::run_monitor(&backend, interval)?;
    Ok(())
}

fn cmd_crack(args: &CrackArgs) -> Result<(), Box<dyn std::error::Error>> {
    let target = crack::PmkidTarget::new(&args.pmkid, &args.ap_mac, &args.client_mac, &args.essid)?;
    if args.web {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(web::run_crack_web(target, args.wordlist.clone(), args.web_port, args.no_open))?;
        return Ok(());
    }
    use std::io::Write;

    let target = crack::PmkidTarget::new(&args.pmkid, &args.ap_mac, &args.client_mac, &args.essid)?;
    let pmkid_hex: String = target.pmkid.iter().map(|b| format!("{b:02x}")).collect();
    println!("[*] target: {:<28} essid: {}", target.ap_mac_hex(), target.essid);
    println!("[*] pmkid:  {pmkid_hex}");
    println!("[*] wordlist: {}", args.wordlist);
    println!();

    let start = std::time::Instant::now();
    let last_pct: std::cell::Cell<usize> = std::cell::Cell::new(0);
    let found = crack::crack_wordlist(&target, &args.wordlist, Some(&|bytes, total| {
        let pct = (bytes * 100).checked_div(total).unwrap_or(100);
        if pct != last_pct.get() && pct % 5 == 0 {
            last_pct.set(pct);
            print!("\r\x1b[K[ ] {pct}% ({bytes}/{total} bytes)…");
            let _ = std::io::stdout().flush();
        }
    }))?;

    match found {
        Some(pass) => {
            println!("\r\x1b[K\x1b[1;32m[+] CRACKED!\x1b[0m passphrase = \"{pass}\" in {:.2}s", start.elapsed().as_secs_f64());
            Ok(())
        }
        None => {
            println!("\r\x1b[K\x1b[1;31m[-]\x1b[0m passphrase not in wordlist ({:.2}s)", start.elapsed().as_secs_f64());
            Ok(())
        }
    }
}

