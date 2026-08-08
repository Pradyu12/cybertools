//! Command-line interface definition (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ScanOrder {
    Serial,
    #[default]
    Random,
}

#[derive(Parser, Debug)]
#[command(
    name = "vajra",
    version,
    about = "Ultra-fast async port scanner with host discovery, UDP scanning, service detection, a live dashboard, and nmap integration",
    long_about = "Vajra (वज्र) — the thunderbolt — is an ultra-fast port scanner written in Rust. It \
discovers which hosts are up (ICMP + TCP probes), asynchronously sweeps every port at very \
high concurrency, identifies services via banner grabbing, scans UDP with application probes, \
hands open ports to nmap for deep scanning, streams progress to a live web dashboard, and \
emits clean human, greppable, or JSON output.",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Target IPs, hostnames, CIDR blocks (e.g. 192.168.1.0/24), IP ranges
    /// (e.g. 192.168.1.5-20), or a file of targets prefixed with '@'
    #[arg(short = 'a', long = "addresses", value_name = "TARGETS")]
    pub addresses: Vec<String>,

    /// Device-mode subcommand: scan a network and fingerprint each host's OS
    #[command(subcommand)]
    pub command: Option<DeviceCmd>,

    /// Ports to scan, e.g. "80,443", "1-1000" or "top-1000"
    #[arg(short = 'p', long, value_name = "PORTS", default_value = "top-1000")]
    pub ports: String,

    /// Per-connection timeout in milliseconds (raise it on firewalled or
    /// slow networks, e.g. -T 2500)
    #[arg(short = 'T', long, value_name = "MS", default_value_t = 2500)]
    pub timeout: u64,

    /// Initial scan concurrency (auto-tunes between --min-concurrency and
    /// --max-concurrency)
    #[arg(short = 'c', long, value_name = "N", default_value_t = 4000)]
    pub concurrency: usize,

    /// Floor for adaptive concurrency
    #[arg(long, value_name = "N", default_value_t = 128)]
    pub min_concurrency: usize,

    /// Ceiling for adaptive concurrency
    #[arg(long, value_name = "N", default_value_t = 65535)]
    pub max_concurrency: usize,

    /// Port scan order: serial or random
    #[arg(long, value_enum, default_value_t = ScanOrder::Random)]
    pub scan_order: ScanOrder,

    /// Host discovery: ICMP ping + TCP probe each target and only scan the
    /// hosts that are up (streams live to the dashboard)
    #[arg(short = 'd', long)]
    pub discover: bool,

    /// Skip host discovery entirely and scan every target regardless (the
    /// nmap -Pn equivalent)
    #[arg(long)]
    pub no_probe: bool,

    /// Also scan UDP ports using application probes. Silent ports are
    /// reported as open|filtered (no ICMP unreachable detection without
    /// privileges)
    #[arg(short = 'u', long)]
    pub udp: bool,

    /// UDP ports to scan, e.g. "53,123,161" or "top-100"
    #[arg(long, value_name = "PORTS", default_value = "top-100")]
    pub udp_ports: String,

    /// Greppable output: one `ip:port:open[:service]` line per open port
    #[arg(short = 'g', long)]
    pub greppable: bool,

    /// JSON output
    #[arg(long)]
    pub json: bool,

    /// Write output to a file
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Skip banner/service detection (faster, less information)
    #[arg(long)]
    pub no_banner: bool,

    /// Do not run nmap after the scan
    #[arg(short = 'n', long)]
    pub no_nmap: bool,

    /// Serve a live web dashboard while scanning (http://127.0.0.1:<port>)
    #[arg(short = 'w', long)]
    pub web: bool,

    /// Port for the live web dashboard
    #[arg(long, value_name = "PORT", default_value_t = 9333)]
    pub web_port: u16,

    /// Do not auto-open the dashboard in a browser
    #[arg(long)]
    pub no_open: bool,

    /// Extra arguments passed through to nmap (after `--`)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub nmap_args: Vec<String>,
}

/// Device-scan subcommand: discover every live host on a target range and
/// fingerprint its operating system.
#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    /// Discover live devices on the network and fingerprint their OS
    #[command(name = "devices")]
    Devices(DevicesArgs),
}

#[derive(Args, Debug)]
#[command(
    about = "Scan a network and identify devices + their operating systems",
    long_about = "Scans a target range (e.g. 192.168.1.0/24), pings every address to capture the reply \
TTL, probes common service ports on live hosts, grabs banners (SSH / HTTP), and combines the \
evidence into an OS fingerprint (Windows / Linux / macOS / network gear / Apple) with a \
confidence score. MAC addresses come from the local ARP table and are matched against a \
vendor OUI table."
)]
pub struct DevicesArgs {
    /// Target IPs, hostnames, CIDR blocks (e.g. 192.168.1.0/24), IP ranges,
    /// or a file of targets prefixed with '@'
    #[arg(short = 'a', long = "addresses", value_name = "TARGETS", required = true)]
    pub addresses: Vec<String>,

    /// Per-probe timeout in milliseconds
    #[arg(short = 'T', long, value_name = "MS", default_value_t = 1200)]
    pub timeout: u64,

    /// JSON output
    #[arg(long)]
    pub json: bool,

    /// Write output to a file
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Disable ANSI colours
    #[arg(long)]
    pub no_color: bool,
}
