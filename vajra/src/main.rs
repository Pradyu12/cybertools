//! Vajra (वज्र) — the thunderbolt: ultra-fast async port scanner.
//!
//! Orchestrates target resolution -> host discovery -> TCP scan -> UDP scan
//! -> service detection -> output -> optional nmap hand-off, with a live web
//! dashboard when `--web` is set.

mod banner;
mod cli;
mod dashboard;
mod devices;
mod discover;
mod nmap;
mod output;
mod ping;
mod ports;
mod scan;
mod target;
mod udp;

use std::collections::{BTreeMap, HashSet};
use std::io::IsTerminal;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use thiserror::Error;
use tokio::task::JoinSet;

use crate::banner::{grab_banner, OpenPort};
use crate::cli::{Cli, DeviceCmd, ScanOrder};
use crate::dashboard::{DashboardEvent, DashboardHub};
use crate::output::{render, OutputFormat};
use crate::ports::{parse_ports, parse_ports_with, TOP_PORTS, TOP_UDP_PORTS};
use crate::scan::{scan_hosts, ScanOptions, ScanSummary};
use crate::target::expand_targets;

#[derive(Debug, Error)]
enum AppError {
    #[error(transparent)]
    Target(#[from] target::TargetError),
    #[error(transparent)]
    Port(#[from] ports::PortError),
    #[error("no targets could be resolved from the given addresses")]
    NoTargets,
    #[error("connection timeout must be greater than 0")]
    ZeroTimeout,
    #[error("failed to write output file `{0}`: {1}")]
    Write(PathBuf, std::io::Error),
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(DeviceCmd::Devices(args)) = &cli.command {
        return match run_devices(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        };
    }
    if cli.addresses.is_empty() {
        eprintln!("error: no targets given (use -a, e.g. -a 192.168.1.0/24, or run `vajra devices --help`)");
        return ExitCode::FAILURE;
    }
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn output_format(cli: &Cli) -> OutputFormat {
    if cli.json {
        OutputFormat::Json
    } else if cli.greppable {
        OutputFormat::Greppable
    } else {
        OutputFormat::Human
    }
}

/// Render the report, print it, and honor `-o` when given.
fn render_and_write(
    cli: &Cli,
    summary: &ScanSummary,
    targets: &[crate::target::ResolvedHost],
    open: &BTreeMap<IpAddr, Vec<OpenPort>>,
) -> Result<(), AppError> {
    let rendered = render(output_format(cli), summary, targets, open);
    if !rendered.is_empty() {
        print!("{rendered}");
    }
    if let Some(path) = &cli.output {
        std::fs::write(path, &rendered).map_err(|e| AppError::Write(path.clone(), e))?;
        if !cli.greppable && !cli.json {
            eprintln!("[i] wrote output to {}", path.display());
        }
    }
    Ok(())
}

fn make_bar(len: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {msg} {bar:40.cyan/blue} {pos}/{len} ({eta})")
            .expect("valid template")
            .progress_chars("=>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Emit the final scan_done event so the dashboard can mark the sweep closed.
fn emit_scan_done(hub: Option<&DashboardHub>, elapsed: Duration, interrupted: bool, hosts: usize, open: usize) {
    if let Some(hub) = hub {
        hub.emit(DashboardEvent::ScanDone {
            elapsed_ms: elapsed.as_millis(),
            interrupted,
            hosts,
            open_ports: open,
        });
    }
}

/// Keep the process alive so the dashboard stays browsable after the sweep.
async fn hold_dashboard(web: bool, up: bool, interrupted: bool, port: u16) {
    if web && up && !interrupted {
        eprintln!(
            "[*] Sweep finished — dashboard live at http://127.0.0.1:{}/ (Ctrl+C to exit)",
            port
        );
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn run(cli: Cli) -> Result<(), AppError> {
    let quiet = cli.greppable || cli.json;

    if cli.timeout == 0 {
        return Err(AppError::ZeroTimeout);
    }

    // ---- Resolve targets -------------------------------------------------
    let targets = expand_targets(&cli.addresses).await?;
    if targets.is_empty() {
        return Err(AppError::NoTargets);
    }

    let ports = parse_ports(&cli.ports)?;
    if let Some(n) = cli.ports.strip_prefix("top-") {
        if let Ok(n) = n.parse::<usize>() {
            if n > TOP_PORTS.len() && !quiet {
                eprintln!(
                    "[i] top-{n} requested, but the built-in list has {} ports; scanning those.",
                    TOP_PORTS.len()
                );
            }
        }
    }
    let udp_ports = if cli.udp {
        let p = parse_ports_with(&cli.udp_ports, TOP_UDP_PORTS)?;
        if let Some(n) = cli.udp_ports.strip_prefix("top-") {
            if let Ok(n) = n.parse::<usize>() {
                if n > TOP_UDP_PORTS.len() && !quiet {
                    eprintln!(
                        "[i] top-{n} UDP ports requested, but the built-in list has {}; scanning those.",
                        TOP_UDP_PORTS.len()
                    );
                }
            }
        }
        Some(p)
    } else {
        None
    };

    let discover = cli.discover && !cli.no_probe;
    if !quiet {
        let udp_note = udp_ports
            .as_ref()
            .map(|p| format!(" + {} UDP port(s)", p.len()))
            .unwrap_or_default();
        eprintln!(
            "[i] {} target(s) -> {} address(es), scanning {} TCP port(s) per host{}",
            cli.addresses.len(),
            targets.len(),
            ports.len(),
            udp_note
        );
        if discover {
            eprintln!("[i] host discovery enabled — only live hosts will be scanned");
        }
    }

    let tty = std::io::stderr().is_terminal() && !quiet;
    let started = Instant::now();

    // ---- Live web dashboard -------------------------------------------
    let (hub, dashboard_up): (Option<Arc<DashboardHub>>, bool) = if cli.web {
        let hub = Arc::new(DashboardHub::new(1024));
        // Bind first so we know the port is really free before opening the
        // browser / holding the process after the sweep.
        match hub.bind(cli.web_port).await {
            Ok(listener) => {
                let h = Arc::clone(&hub);
                tokio::spawn(async move {
                    if let Err(e) = h.serve_on(listener).await {
                        eprintln!("[!] dashboard server failed: {e}");
                    }
                });
                if !quiet {
                    eprintln!("[i] live dashboard: http://127.0.0.1:{}/", cli.web_port);
                }
                if !cli.no_open {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    open_browser(&format!("http://127.0.0.1:{}/", cli.web_port));
                }
                (Some(hub), true)
            }
            Err(e) => {
                eprintln!("[!] dashboard failed to bind port {}: {e}", cli.web_port);
                (None, false)
            }
        }
    } else {
        (None, false)
    };

    // Tell the dashboard about the campaign up front (targets + TCP plan).
    if let Some(hub) = hub.as_deref() {
        hub.emit(DashboardEvent::ScanStart {
            targets: targets.iter().map(|h| h.ip.to_string()).collect(),
            total_ports: ports.len(),
            total_jobs: (targets.len() * ports.len()) as u64,
        });
    }

    let mut open: BTreeMap<IpAddr, Vec<OpenPort>> = BTreeMap::new();

    // ---- Host discovery --------------------------------------------------
    let mut scan_targets: Vec<crate::target::ResolvedHost> = targets.clone();
    if discover {
        let ips: Vec<IpAddr> = targets.iter().map(|h| h.ip).collect();
        // Alive hosts answer fast by definition, so cap the probe timeout;
        // a subnet full of dead hosts should not stall the sweep.
        let probe_timeout = Duration::from_millis(cli.timeout.min(800));
        let dpb = tty.then(|| make_bar(ips.len() as u64, "Discovering hosts"));
        let (alive, d_interrupted) =
            discover::discover_hosts(&ips, probe_timeout, dpb.as_ref(), hub.as_deref()).await;
        if !quiet {
            eprintln!("[i] discovery: {} of {} host(s) alive", alive.len(), ips.len());
        }
        if d_interrupted {
            emit_scan_done(hub.as_deref(), started.elapsed(), true, 0, 0);
            hold_dashboard(cli.web, dashboard_up, true, cli.web_port).await;
            return Ok(());
        }
        if alive.is_empty() {
            if !quiet {
                eprintln!("[!] no hosts responded — nothing to scan (use --no-probe to force a scan anyway)");
            }
            let summary = ScanSummary {
                hosts: Vec::new(),
                elapsed: started.elapsed(),
                interrupted: false,
                final_concurrency: 0,
            };
            render_and_write(&cli, &summary, &targets, &open)?;
            emit_scan_done(hub.as_deref(), started.elapsed(), false, 0, 0);
            hold_dashboard(cli.web, dashboard_up, false, cli.web_port).await;
            return Ok(());
        }
        let alive_set: HashSet<IpAddr> = alive.into_iter().collect();
        scan_targets = targets
            .clone()
            .into_iter()
            .filter(|h| alive_set.contains(&h.ip))
            .collect();
    }

    // ---- Scan (TCP) ------------------------------------------------------
    // Concurrency of 0 would make the scan loop spin without doing anything;
    // keep the bounds sane and ordered (min <= initial <= max).
    let min_concurrency = cli.min_concurrency.max(1);
    let initial_concurrency = cli.concurrency.max(min_concurrency);
    let max_concurrency = cli.max_concurrency.max(initial_concurrency);

    let opts = ScanOptions {
        timeout: Duration::from_millis(cli.timeout),
        initial_concurrency,
        min_concurrency,
        max_concurrency,
        randomize: cli.scan_order == ScanOrder::Random,
    };

    let tcp_jobs = (scan_targets.len() * ports.len()) as u64;
    let pb = tty.then(|| make_bar(tcp_jobs, "Scanning"));

    if let Some(hub) = hub.as_deref() {
        hub.emit(DashboardEvent::Phase {
            phase: "tcp".into(),
            label: format!("{} target(s) x {} ports", scan_targets.len(), ports.len()),
        });
    }
    let mut summary = scan_hosts(&scan_targets, &ports, &opts, pb.as_ref(), hub.as_deref(), "tcp").await;
    let mut interrupted = summary.interrupted;

    // ---- UDP scan ---------------------------------------------------------
    if let Some(udp_ports) = &udp_ports {
        if !interrupted {
            if let Some(hub) = hub.as_deref() {
                hub.emit(DashboardEvent::Phase {
                    phase: "udp".into(),
                    label: format!("{} UDP port(s) x {} host(s)", udp_ports.len(), scan_targets.len()),
                });
            }
            let udp_jobs = (scan_targets.len() * udp_ports.len()) as u64;
            let udp_pb = tty.then(|| make_bar(udp_jobs, "UDP scan"));
            let udp_concurrency = cli.concurrency.clamp(1, 512);
            let (udp_results, udp_interrupted) =
                udp::scan_udp(&scan_targets, udp_ports, opts.timeout, udp_concurrency, udp_pb.as_ref(), hub.as_deref()).await;
            interrupted = interrupted || udp_interrupted;
            for (ip, results) in udp_results {
                let v = open.entry(ip).or_default();
                for r in results {
                    v.push(OpenPort {
                        port: r.port,
                        protocol: "udp".into(),
                        state: r.state.label().into(),
                        service: r.service.clone(),
                        version: r.version.clone(),
                        banner: r.banner.clone(),
                    });
                }
            }
        }
    }

    // ---- Service detection (TCP banners) ---------------------------------
    let jobs: Vec<(IpAddr, u16)> = summary
        .hosts
        .iter()
        .flat_map(|h| h.open_ports.iter().map(|p| (h.ip, *p)))
        .collect();

    if !cli.no_banner && !jobs.is_empty() && !interrupted {
        if let Some(hub) = hub.as_deref() {
            hub.emit(DashboardEvent::Phase {
                phase: "banner".into(),
                label: format!("fingerprinting {} open port(s)", jobs.len()),
            });
        }
        let banner_pb = tty.then(|| make_bar(jobs.len() as u64, "Detecting services"));
        let connect_timeout = Duration::from_millis(cli.timeout);
        let mut tasks = JoinSet::new();
        let mut next = 0usize;
        loop {
            while next < jobs.len() && tasks.len() < 64 {
                let (ip, port) = jobs[next];
                tasks.spawn(grab_banner(ip, port, connect_timeout));
                next += 1;
            }
            if next >= jobs.len() && tasks.is_empty() {
                break;
            }
            if let Some(r) = tasks.join_next().await {
                if let Some(pb) = banner_pb.as_ref() {
                    pb.inc(1);
                }
                if let Ok((ip, op)) = r {
                    if let Some(hub) = hub.as_deref() {
                        hub.emit(DashboardEvent::PortOpen {
                            ip: ip.to_string(),
                            port: op.port,
                            service: op.service.clone(),
                            version: op.version.clone(),
                            banner: op.banner.clone(),
                            proto: "tcp".into(),
                            state: "open".into(),
                        });
                    }
                    open.entry(ip).or_default().push(op);
                }
            }
        }
        if let Some(pb) = banner_pb.as_ref() {
            pb.finish_and_clear();
        }
    } else {
        for h in &summary.hosts {
            let v = open.entry(h.ip).or_default();
            for p in &h.open_ports {
                v.push(OpenPort::new(*p));
            }
        }
    }
    for v in open.values_mut() {
        v.sort_by_key(|p| p.port);
    }

    // ---- Output ----------------------------------------------------------
    summary.elapsed = started.elapsed(); // cover the whole campaign
    render_and_write(&cli, &summary, &targets, &open)?;

    // "Open port(s)" counts genuinely open findings; UDP open|filtered rows
    // (which may be filtered) are excluded so the totals stay honest.
    let open_total: usize = open
        .values()
        .flatten()
        .filter(|p| p.state == "open")
        .count();
    emit_scan_done(hub.as_deref(), started.elapsed(), interrupted, scan_targets.len(), open_total);

    // ---- nmap hand-off ---------------------------------------------------
    if !cli.no_nmap && !scan_targets.is_empty() {
        let ips: Vec<IpAddr> = scan_targets.iter().map(|h| h.ip).collect();
        nmap::run_nmap(&ips, &open, &cli.nmap_args);
    }

    // ---- Keep the dashboard alive for review ----------------------------
    hold_dashboard(cli.web, dashboard_up, interrupted, cli.web_port).await;

    Ok(())
}

/// Device-mode entry point: resolve targets, sweep with TTL, fingerprint OS,
/// render the device table (human or JSON), honor `-o`.
async fn run_devices(args: &cli::DevicesArgs) -> Result<(), AppError> {
    if args.timeout == 0 {
        return Err(AppError::ZeroTimeout);
    }
    let targets = expand_targets(&args.addresses).await?;
    if targets.is_empty() {
        return Err(AppError::NoTargets);
    }
    let tty = std::io::stderr().is_terminal() && !args.json;
    eprintln!(
        "[i] {} target(s) -> {} address(es), fingerprinting live hosts…",
        args.addresses.len(),
        targets.len()
    );

    let started = Instant::now();
    let pb = tty.then(|| make_bar(targets.len() as u64, "Probing hosts"));
    let devices = devices::scan_devices(&targets, Duration::from_millis(args.timeout), pb.as_ref()).await;

    let rendered = if args.json {
        serde_json::to_string_pretty(&devices).unwrap_or_else(|_| "[]".to_string())
    } else {
        render_devices(&devices, !args.no_color)
    };
    print!("{rendered}");
    if let Some(path) = &args.output {
        std::fs::write(path, &rendered).map_err(|e| AppError::Write(path.clone(), e))?;
        if !args.json {
            eprintln!("[i] wrote output to {}", path.display());
        }
    }
    eprintln!(
        "[i] {} device(s) found in {:.2}s",
        devices.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Render the device table for the terminal.
fn render_devices(devices: &[devices::Device], color: bool) -> String {
    use std::fmt::Write as _;

    let c = |s: &str| -> String {
        if color {
            format!("\x1b[1;32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let amber = |s: &str| -> String {
        if color {
            format!("\x1b[1;33m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mut out = String::new();
    if devices.is_empty() {
        out.push_str("No devices responded (try a wider range or a longer -T).\n");
        return out;
    }
    let _ = writeln!(
        out,
        "{:<16} {:<19} {:<14} {:<22} {:<6} {:<5} OPEN PORTS",
        "IP", "MAC", "VENDOR", "OS", "CONF", "TTL"
    );
    let _ = writeln!(
        out,
        "{:<16} {:<19} {:<14} {:<22} {:<6} {:<5} -----------",
        "----------------", "-------------------", "--------------", "----------------------", "-----", "----"
    );
    for d in devices {
        let _ = writeln!(
            out,
            "{:<16} {:<19} {:<14} {:<22} {:<6} {:<5} {}",
            c(&d.ip.to_string()),
            d.mac.as_deref().unwrap_or("—"),
            d.vendor.as_deref().unwrap_or("—"),
            amber(&d.os),
            format!("{}%", d.confidence),
            d.ttl.map(|t| t.to_string()).unwrap_or_else(|| "—".into()),
            d.open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        if color {
            let _ = writeln!(out, "  \x1b[2m{}\x1b[0m", d.signals.join(" · "));
        }
    }
    out
}

/// Open the dashboard in the default browser.
#[cfg(target_os = "windows")]
fn open_browser(url: &str) {
    let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn();
}

#[cfg(target_os = "macos")]
fn open_browser(url: &str) {
    let _ = std::process::Command::new("open").arg(url).spawn();
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn open_browser(url: &str) {
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}
