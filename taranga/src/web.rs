//! Web mode: embed the dashboard server and drive the scan/monitor/crack
//! engines while streaming JSON events over WebSocket. The process holds
//! after finishing so the final state stays viewable in the browser.

use crate::backend::Backend;
use crate::dashboard::{ApEvent, DashboardEvent, DashboardHub};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("dashboard bind failed on port {0}: {1}")]
    Bind(u16, String),
    #[error("{0}")]
    Backend(#[from] crate::backend::BackendError),
    #[error("{0}")]
    Crack(#[from] crate::crack::CrackError),
    #[error("{0}")]
    Io(String),
}

/// Spawn the dashboard server (bind-then-serve, no race), open the browser
/// unless `--no-open`, and return the runtime-scoped hub.
async fn start_server(
    hub: Arc<DashboardHub>,
    port: u16,
    no_open: bool,
) -> Result<(), WebError> {
    let listener = hub
        .bind(port)
        .await
        .map_err(|e| WebError::Bind(port, e.to_string()))?;
    let url = format!("http://127.0.0.1:{port}/");
    if !no_open {
        open_browser(&url);
    }
    println!("[i] live dashboard: {url}");
    let server_hub = hub.clone();
    tokio::spawn(async move {
        let _ = server_hub.serve_on(listener).await;
    });
    Ok(())
}

/// Open the default browser on the current platform.
fn open_browser(url: &str) {
    let cmd = if cfg!(target_os = "windows") {
        ("cmd", vec!["/C", "start", "", url])
    } else if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else {
        ("xdg-open", vec![url])
    };
    let _ = std::process::Command::new(cmd.0).args(&cmd.1).spawn();
}

/// Run a one-shot scan with the dashboard.
pub async fn run_scan_web(
    backend: Backend,
    port: u16,
    no_open: bool,
) -> Result<(), WebError> {
    let hub = Arc::new(DashboardHub::new(512));
    start_server(hub.clone(), port, no_open).await?;

    let started = Instant::now();
    hub.emit(DashboardEvent::Start {
        mode: "scan".into(),
        label: "one-shot AP scan".into(),
        net: Some(crate::netinfo::detect()),
    });
    let aps = backend.scan()?;
    let events: Vec<ApEvent> = aps.iter().map(ApEvent::from).collect();
    hub.emit(DashboardEvent::ScanResult { aps: events, elapsed_ms: started.elapsed().as_millis() });
    hub.emit(DashboardEvent::Done { mode: "scan".into(), elapsed_ms: started.elapsed().as_millis() });

    hold_until_ctrl_c().await;
    Ok(())
}

/// Run the continuous monitor loop with the dashboard.
pub async fn run_monitor_web(
    backend: Backend,
    interval: Duration,
    port: u16,
    no_open: bool,
) -> Result<(), WebError> {
    let hub = Arc::new(DashboardHub::new(1024));
    start_server(hub.clone(), port, no_open).await?;

    let started = Instant::now();
    let mut cycle = 0u64;
    let mut prev_bssids: std::collections::HashSet<String> = std::collections::HashSet::new();
    hub.emit(DashboardEvent::Start {
        mode: "monitor".into(),
        label: format!("rescan every {}s", interval.as_secs_f64()),
        net: Some(crate::netinfo::detect()),
    });

    loop {
        let cycle_start = Instant::now();
        // netsh/nmcli/iw are blocking subprocess calls (1-5s); run them off
        // the async worker so WebSocket handlers never stall.
        let scan_backend = backend.clone();
        let aps = tokio::task::spawn_blocking(move || scan_backend.scan())
            .await
            .map_err(|e| WebError::Io(e.to_string()))??;
        let events: Vec<ApEvent> = aps.iter().map(ApEvent::from).collect();
        let now: std::collections::HashSet<String> =
            events.iter().map(|a| a.bssid.clone()).collect();
        let new = now.difference(&prev_bssids).count();
        let gone = prev_bssids.difference(&now).count();
        prev_bssids = now;

        hub.emit(DashboardEvent::ScanResult {
            aps: events,
            elapsed_ms: started.elapsed().as_millis(),
        });
        hub.emit(DashboardEvent::Cycle {
            cycle,
            new,
            gone,
            elapsed_ms: started.elapsed().as_millis(),
        });
        cycle += 1;

        let elapsed = cycle_start.elapsed();
        let wait = interval.saturating_sub(elapsed);
        if wait > Duration::ZERO {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Run a PMKID dictionary crack with the dashboard.
pub async fn run_crack_web(
    target: crate::crack::PmkidTarget,
    wordlist: String,
    port: u16,
    no_open: bool,
) -> Result<(), WebError> {
    let hub = Arc::new(DashboardHub::new(512));
    start_server(hub.clone(), port, no_open).await?;

    let started = Instant::now();
    hub.emit(DashboardEvent::Start {
        mode: "crack".into(),
        label: format!("pmkid on \"{}\"", target.essid),
        net: Some(crate::netinfo::detect()),
    });

    let last_pct: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let hub2 = hub.clone();
    let found = tokio::task::spawn_blocking(move || {
        crate::crack::crack_wordlist(&target, &wordlist, Some(&|bytes, total| {
            let pct = (bytes * 100).checked_div(total).unwrap_or(100);
            let prev = last_pct.load(std::sync::atomic::Ordering::Relaxed);
            // Throttle to whole percents, but always report the tail so short
            // wordlists still animate and finish on 100%.
            if pct > prev && (pct % 5 == 0 || pct == 100) {
                last_pct.store(pct, std::sync::atomic::Ordering::Relaxed);
                hub2.emit(DashboardEvent::CrackProgress { pct, tried: bytes });
            }
        }))
    })
    .await
    .map_err(|e| WebError::Io(e.to_string()))?;

    match found? {
        Some(pass) => {
            hub.emit(DashboardEvent::CrackFound {
                passphrase: pass,
                elapsed_ms: started.elapsed().as_millis(),
            });
        }
        None => {
            hub.emit(DashboardEvent::CrackMiss {
                elapsed_ms: started.elapsed().as_millis(),
            });
        }
    }
    hub.emit(DashboardEvent::Done { mode: "crack".into(), elapsed_ms: started.elapsed().as_millis() });

    hold_until_ctrl_c().await;
    Ok(())
}

/// Wait until Ctrl+C (the process is held so the dashboard can be reviewed).
async fn hold_until_ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}
