//! The async scanning engine with adaptive concurrency.
//!
//! Every (host, port) pair is probed as an independent async task. A shared
//! `limit` controls how many tasks are in flight at once; a sliding window of
//! recent outcomes adapts that limit to the network: if timeouts dominate we
//! back off, if everything completes instantly we ramp up. This is the core
//! trick that lets a full 65,535-port sweep finish in seconds on a fast link.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use indicatif::ProgressBar;
use rand::seq::SliceRandom;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::dashboard::{DashboardEvent, DashboardHub};
use crate::target::ResolvedHost;

/// How many recent scan outcomes feed the adaptive-concurrency decision.
const WINDOW_SIZE: usize = 256;

/// Minimum completions before the time-based adaptation may fire.
const MIN_WINDOW: usize = 32;

/// How often the controller may re-evaluate, even with a partial window.
const ADAPT_INTERVAL: Duration = Duration::from_millis(200);

/// Tuning knobs for the scan engine.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Per-connection timeout; connections that exceed it count as "filtered".
    pub timeout: Duration,
    /// Concurrency the scan starts at.
    pub initial_concurrency: usize,
    /// Floor for adaptive concurrency.
    pub min_concurrency: usize,
    /// Ceiling for adaptive concurrency.
    pub max_concurrency: usize,
    /// Shuffle the probe order to avoid tripping naive firewall detection.
    pub randomize: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1500),
            initial_concurrency: 4000,
            min_concurrency: 128,
            max_concurrency: 65535,
            randomize: true,
        }
    }
}

/// Aggregated scan results for a single host.
#[derive(Debug, Clone)]
pub struct HostOutcome {
    pub ip: IpAddr,
    pub open_ports: Vec<u16>,
    /// Ports that actively refused the connection.
    pub closed: u64,
    /// Ports that timed out (likely filtered by a firewall).
    pub filtered: u64,
}

/// Overall scan results.
#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub hosts: Vec<HostOutcome>,
    pub elapsed: Duration,
    /// True if the scan was cut short by Ctrl+C.
    pub interrupted: bool,
    /// The concurrency the adaptive controller settled on.
    pub final_concurrency: usize,
}

#[derive(Clone, Copy)]
struct Job {
    ip: IpAddr,
    port: u16,
}

struct TaskOutcome {
    ip: IpAddr,
    timed_out: bool,
    open: Option<u16>,
}

/// Sliding window of recent outcomes plus when it was last cleared.
struct WindowState {
    q: VecDeque<bool>,
    since: Instant,
}

async fn scan_one(job: Job, timeout: Duration) -> TaskOutcome {
    let addr = SocketAddr::new(job.ip, job.port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            TaskOutcome { ip: job.ip, timed_out: false, open: Some(job.port) }
        }
        Ok(Err(_)) => TaskOutcome { ip: job.ip, timed_out: false, open: None },
        Err(_) => TaskOutcome { ip: job.ip, timed_out: true, open: None },
    }
}

/// Adjust `limit` based on the ratio of timeouts in the recent window.
/// Fires when the window is full, or every `ADAPT_INTERVAL` once enough
/// completions have been seen, so small scans adapt too.
fn adapt(limit: &mut usize, window: &mut WindowState, opts: &ScanOptions) {
    let elapsed = window.since.elapsed();
    let full = window.q.len() >= WINDOW_SIZE;
    if !full && (window.q.len() < MIN_WINDOW || elapsed < ADAPT_INTERVAL) {
        return;
    }
    let timeouts = window.q.iter().filter(|t| **t).count();
    let ratio = timeouts as f64 / window.q.len() as f64;
    // Only ramp up on a full window of fast completions; back off aggressively
    // (even on partial windows) as soon as timeouts dominate.
    let next = if ratio > 0.5 {
        (*limit / 2).max(opts.min_concurrency)
    } else if ratio < 0.08 && full {
        (*limit * 2).min(opts.max_concurrency)
    } else {
        *limit
    };
    *limit = next;
    window.q.clear();
    window.since = Instant::now();
}

/// How often the dashboard receives a progress update.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Probe every (host, port) pair and aggregate the results. When a dashboard
/// hub is given, live events (progress, open ports) are streamed to it as the
/// scan runs. `proto` labels the events ("tcp" today; the UDP scanner emits
/// its own).
pub async fn scan_hosts(
    hosts: &[ResolvedHost],
    ports: &[u16],
    opts: &ScanOptions,
    pb: Option<&ProgressBar>,
    hub: Option<&DashboardHub>,
    proto: &'static str,
) -> ScanSummary {
    let started = Instant::now();

    let mut jobs: Vec<Job> = Vec::with_capacity(hosts.len() * ports.len());
    for h in hosts {
        for p in ports {
            jobs.push(Job { ip: h.ip, port: *p });
        }
    }
    if opts.randomize {
        jobs.shuffle(&mut rand::thread_rng());
    }


    // All shared state below lives on this task; outcomes are collected from
    // the JoinSet directly, so no locks are needed and results cannot be lost.
    let mut limit = opts.initial_concurrency;
    let mut done: u64 = 0;
    let mut window = WindowState { q: VecDeque::new(), since: Instant::now() };
    let mut outcomes: Vec<TaskOutcome> = Vec::new();

    let mut tasks = JoinSet::new();
    let mut next = 0usize;
    let mut interrupted = false;
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());
    let mut last_progress = Instant::now();

    loop {
        // Top up in-flight tasks up to the current adaptive limit.
        while next < jobs.len() && tasks.len() < limit {
            tasks.spawn(scan_one(jobs[next], opts.timeout));
            next += 1;
        }

        if let Some(pb) = pb {
            pb.set_position(done);
            pb.set_message(format!("Scanning (concurrency {limit})"));
        }
        if let Some(hub) = hub {
            if (last_progress.elapsed() >= PROGRESS_INTERVAL || done as usize >= jobs.len()) && done > 0 {
                hub.emit(DashboardEvent::Progress {
                    done,
                    total: jobs.len() as u64,
                    concurrency: limit,
                    elapsed_ms: started.elapsed().as_millis(),
                    proto: proto.to_string(),
                });
                last_progress = Instant::now();
            }
        }

        if next >= jobs.len() && tasks.is_empty() {
            break;
        }

        adapt(&mut limit, &mut window, opts);

        tokio::select! {
            r = tasks.join_next() => match r {
                Some(Ok(o)) => {
                    done += 1;
                    window.q.push_back(o.timed_out);
                    if window.q.len() > WINDOW_SIZE {
                        window.q.pop_front();
                    }
                    if let Some(port) = o.open {
                        if let Some(hub) = hub {
                            hub.emit(DashboardEvent::PortOpen {
                                ip: o.ip.to_string(),
                                port,
                                service: None,
                                version: None,
                                banner: None,
                                proto: proto.to_string(),
                                state: "open".to_string(),
                            });
                        }
                    }
                    outcomes.push(o);
                }
                // A panicked probe must not stall the scan; count it and move on.
                Some(Err(_)) => done += 1,
                None => break,
            },
            _ = &mut ctrl_c => {
                interrupted = true;
                break;
            }
        }
    }

    if interrupted {
        // Abort in-flight probes so we return promptly with partial results.
        tasks.shutdown().await;
    }

    let final_concurrency = limit;
    if let Some(pb) = pb {
        pb.set_position(done);
        pb.finish_and_clear();
    }

    let mut map: BTreeMap<IpAddr, HostOutcome> = BTreeMap::new();
    for o in outcomes {
        let entry = map.entry(o.ip).or_insert(HostOutcome {
            ip: o.ip,
            open_ports: Vec::new(),
            closed: 0,
            filtered: 0,
        });
        match o.open {
            Some(p) => entry.open_ports.push(p),
            None if o.timed_out => entry.filtered += 1,
            None => entry.closed += 1,
        }
    }
    for e in map.values_mut() {
        e.open_ports.sort_unstable();
    }


    ScanSummary {
        hosts: map.into_values().collect(),
        elapsed: started.elapsed(),
        interrupted,
        final_concurrency,
    }
}
