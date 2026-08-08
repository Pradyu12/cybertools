//! Host discovery: figure out which targets are alive before scanning them.
//!
//! Two privilege-free mechanisms are tried per host, in parallel:
//! - ICMP echo ping (via [`crate::ping`]) — works on Windows without
//!   privileges and on Unix with root;
//! - TCP connect probes to a handful of common service ports — works
//!   everywhere with no special permissions.
//!
//! A host is *up* as soon as either mechanism succeeds; the first success
//! wins, so a /24 sweep with mostly-dead hosts still finishes quickly. Every
//! live host is streamed to the dashboard the moment it is found, so a subnet
//! sweep shows hosts lighting up before any port is probed.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use indicatif::ProgressBar;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::dashboard::{DashboardEvent, DashboardHub};
use crate::ping;

/// Service ports probed to detect live hosts when ICMP is unavailable.
pub const DISCOVERY_PORTS: &[u16] = &[
    22, 80, 443, 445, 3389, 21, 25, 53, 110, 143, 993, 995, 23, 5900, 3306, 6379, 5432, 27017,
    8000, 8080, 8443, 8888, 9200, 11211, 1433, 1521,
];

/// How many hosts are probed concurrently.
const MAX_HOST_TASKS: usize = 128;
/// How many TCP probes a single host may run at once.
const MAX_PORTS_PER_HOST: usize = 12;
/// Global cap on in-flight TCP probes across all hosts.
const MAX_TCP_PROBES: usize = 256;

/// How a host was found alive.
#[derive(Debug, Clone)]
pub struct HostUp {
    pub ip: IpAddr,
    /// `"icmp"` or `"tcp/<port>"`.
    pub method: String,
    /// Round-trip time in milliseconds, when known.
    pub rtt_ms: Option<u32>,
}

/// Try to connect to one (host, port); true when the port accepts.
pub async fn tcp_probe(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);
    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Probe a single host; returns `Some` as soon as ICMP or any TCP probe hits.
async fn probe_host(ip: IpAddr, timeout: Duration, sem: Arc<Semaphore>) -> Option<HostUp> {
    if let Some(rtt) = ping::ping(ip, timeout).await {
        return Some(HostUp { ip, method: "icmp".into(), rtt_ms: Some(rtt) });
    }

    let mut tasks = JoinSet::new();
    let mut next = 0usize;
    loop {
        while next < DISCOVERY_PORTS.len() && tasks.len() < MAX_PORTS_PER_HOST {
            let port = DISCOVERY_PORTS[next];
            let sem = Arc::clone(&sem);
            let start = Instant::now();
            tasks.spawn(async move {
                let Ok(_permit) = sem.acquire().await else {
                    return (false, port, 0u32);
                };
                let ok = tcp_probe(ip, port, timeout).await;
                (ok, port, start.elapsed().as_millis() as u32)
            });
            next += 1;
        }
        if next >= DISCOVERY_PORTS.len() && tasks.is_empty() {
            break;
        }
        match tasks.join_next().await {
            Some(Ok((true, port, rtt))) => {
                tasks.shutdown().await;
                return Some(HostUp { ip, method: format!("tcp/{port}"), rtt_ms: Some(rtt) });
            }
            Some(Ok((false, _, _))) | Some(Err(_)) => {}
            None => break,
        }
    }
    None
}

/// Probe every host and return the ones that answered. Live hosts are
/// streamed to the dashboard as `host_up` events as soon as they are found.
/// Returns the alive hosts and whether Ctrl+C cut the probe short.
pub async fn discover_hosts(
    ips: &[IpAddr],
    timeout: Duration,
    pb: Option<&ProgressBar>,
    hub: Option<&DashboardHub>,
) -> (Vec<IpAddr>, bool) {
    if let Some(hub) = hub {
        hub.emit(DashboardEvent::Phase {
            phase: "discovery".into(),
            label: format!("probing {} host(s) for liveness", ips.len()),
        });
    }

    let sem = Arc::new(Semaphore::new(MAX_TCP_PROBES));
    let mut tasks = JoinSet::new();
    let mut next = 0usize;
    let mut done: u64 = 0;
    let mut alive: Vec<IpAddr> = Vec::new();
    let mut alive_set: HashSet<IpAddr> = HashSet::new();
    let started = Instant::now();
    let mut last_progress = Instant::now();
    let mut interrupted = false;
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

    loop {
        while next < ips.len() && tasks.len() < MAX_HOST_TASKS {
            let ip = ips[next];
            let sem = Arc::clone(&sem);
            tasks.spawn(probe_host(ip, timeout, sem));
            next += 1;
        }

        if let Some(pb) = pb {
            pb.set_position(done);
            pb.set_message(format!("Discovering hosts ({done}/{})", ips.len()));
        }
        if let Some(hub) = hub {
            if last_progress.elapsed() >= Duration::from_millis(100) {
                hub.emit(DashboardEvent::Progress {
                    done,
                    total: ips.len() as u64,
                    concurrency: tasks.len(),
                    elapsed_ms: started.elapsed().as_millis(),
                    proto: "discovery".into(),
                });
                last_progress = Instant::now();
            }
        }

        if next >= ips.len() && tasks.is_empty() {
            break;
        }

        tokio::select! {
            r = tasks.join_next() => match r {
                Some(Ok(Some(up))) => {
                    done += 1;
                    if let Some(hub) = hub {
                        hub.emit(DashboardEvent::HostUp {
                            ip: up.ip.to_string(),
                            method: up.method.clone(),
                            rtt_ms: up.rtt_ms,
                        });
                    }
                    if alive_set.insert(up.ip) {
                        alive.push(up.ip);
                    }
                }
                Some(Ok(None)) | Some(Err(_)) => done += 1,
                None => break,
            },
            _ = &mut ctrl_c => {
                interrupted = true;
                break;
            }
        }
    }

    if let Some(hub) = hub {
        hub.emit(DashboardEvent::Progress {
            done,
            total: ips.len() as u64,
            concurrency: 0,
            elapsed_ms: started.elapsed().as_millis(),
            proto: "discovery".into(),
        });
    }
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    alive.sort_unstable();
    (alive, interrupted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, d))
    }

    #[tokio::test]
    async fn tcp_probe_hits_listening_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        assert!(tcp_probe(v4(1), addr.port(), Duration::from_millis(500)).await);
    }

    #[tokio::test]
    async fn tcp_probe_misses_closed_port() {
        // Port 9 is closed on loopback; connect should fail or time out.
        assert!(!tcp_probe(v4(1), 9, Duration::from_millis(400)).await);
    }

    #[test]
    fn discovery_ports_nonempty_and_unique() {
        let mut set = HashSet::new();
        for p in DISCOVERY_PORTS {
            assert!(set.insert(*p), "duplicate discovery port {p}");
        }
        assert!(DISCOVERY_PORTS.len() >= 20);
    }
}
