//! Output rendering: human-readable tables, greppable lines, and JSON.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;

use crate::banner::OpenPort;
use crate::scan::ScanSummary;
use crate::target::ResolvedHost;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Greppable,
    Json,
}

pub fn render(
    format: OutputFormat,
    summary: &ScanSummary,
    targets: &[ResolvedHost],
    open: &BTreeMap<IpAddr, Vec<OpenPort>>,
) -> String {
    match format {
        OutputFormat::Human => render_human(summary, targets, open),
        OutputFormat::Greppable => render_greppable(open),
        OutputFormat::Json => render_json(summary, targets, open),
    }
}

fn hostname_for(targets: &[ResolvedHost], ip: IpAddr) -> Option<&str> {
    targets.iter().find(|h| h.ip == ip).and_then(|h| h.hostname.as_deref())
}

fn render_human(
    summary: &ScanSummary,
    targets: &[ResolvedHost],
    open: &BTreeMap<IpAddr, Vec<OpenPort>>,
) -> String {
    let mut out = String::new();
    // "Open port(s)" counts genuinely open findings; UDP open|filtered rows
    // (which may simply be filtered) are excluded so the totals stay honest.
    let open_total: usize = open
        .values()
        .flatten()
        .filter(|p| p.state == "open")
        .count();
    let scanned: u64 = summary
        .hosts
        .iter()
        .map(|h| h.open_ports.len() as u64 + h.closed + h.filtered)
        .sum();

    out.push_str(&format!(
        "Scan report: {} host(s), {} open port(s), {} probe(s) in {:.2}s (concurrency {}){}\n",
        summary.hosts.len(),
        open_total,
        scanned,
        summary.elapsed.as_secs_f64(),
        summary.final_concurrency,
        if summary.interrupted { " (interrupted)" } else { "" },
    ));

    if open_total == 0 {
        out.push_str("No open ports found.\n");
        return out;
    }

    for (ip, ports) in open {
        out.push_str(&format!(
            "Host {} ({})\n",
            ip,
            hostname_for(targets, *ip).unwrap_or("-")
        ));
        out.push_str("  PORT      SERVICE   VERSION   BANNER\n");
        for p in ports {
            let svc = p.service.as_deref().unwrap_or("unknown");
            let ver = p.version.as_deref().unwrap_or("-");
            let banner = p.banner.as_deref().unwrap_or("(no banner)");
            let state = if p.protocol == "udp" && p.state != "open" {
                format!(" ({})", p.state)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {:<11} {:<9} {:<9} {}{}\n",
                format!("{}/{}", p.port, p.protocol),
                svc,
                ver,
                state,
                banner
            ));
        }
        if let Some(h) = summary.hosts.iter().find(|h| h.ip == *ip) {
            out.push_str(&format!("  ({} closed, {} filtered)\n", h.closed, h.filtered));
        }
        out.push('\n');
    }
    out
}

fn render_greppable(open: &BTreeMap<IpAddr, Vec<OpenPort>>) -> String {
    let mut out = String::new();
    for (ip, ports) in open {
        for p in ports {
            // TCP keeps the classic `ip:port:open[:service]` shape; UDP rows
            // carry the protocol and state so they are unambiguous: e.g.
            // `1.2.3.4:53/udp:open|filtered:domain`.
            if p.protocol == "udp" {
                out.push_str(&format!("{}:{}/udp:{}", ip, p.port, p.state));
            } else {
                out.push_str(&format!("{}:{}:{}", ip, p.port, p.state));
            }
            if let Some(s) = &p.service {
                out.push(':');
                out.push_str(s);
            }
            out.push('\n');
        }
    }
    out
}

#[derive(Serialize)]
struct JsonHost {
    ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    ports: Vec<OpenPort>,
    closed: u64,
    filtered: u64,
}

#[derive(Serialize)]
struct JsonOutput {
    tool: &'static str,
    version: &'static str,
    duration_ms: u128,
    interrupted: bool,
    total_hosts: usize,
    total_open_ports: usize,
    hosts: Vec<JsonHost>,
}

fn render_json(
    summary: &ScanSummary,
    targets: &[ResolvedHost],
    open: &BTreeMap<IpAddr, Vec<OpenPort>>,
) -> String {
    let stats: BTreeMap<IpAddr, (u64, u64)> = summary
        .hosts
        .iter()
        .map(|h| (h.ip, (h.closed, h.filtered)))
        .collect();

    let hosts: Vec<JsonHost> = open
        .iter()
        .map(|(ip, ports)| JsonHost {
            ip: ip.to_string(),
            hostname: hostname_for(targets, *ip).map(str::to_string),
            ports: ports.clone(),
            closed: stats.get(ip).map(|s| s.0).unwrap_or(0),
            filtered: stats.get(ip).map(|s| s.1).unwrap_or(0),
        })
        .collect();

    serde_json::to_string_pretty(&JsonOutput {
        tool: "vajra",
        version: env!("CARGO_PKG_VERSION"),
        duration_ms: summary.elapsed.as_millis(),
        interrupted: summary.interrupted,
        total_hosts: summary.hosts.len(),
        total_open_ports: hosts.iter().map(|h| h.ports.len()).sum(),
        hosts,
    })
    .unwrap_or_else(|_| "{}".to_string())
}
