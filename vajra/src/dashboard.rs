//! Live web dashboard.
//!
//! With `--web`, the scanner embeds a tiny HTTP + WebSocket server on
//! `127.0.0.1:<port>`. The scan engine pushes JSON events through a broadcast
//! channel; every connected browser tab renders them in real time, and
//! late-joining tabs receive a full snapshot of the scan so far.

use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use tokio::sync::broadcast;

/// The dashboard page served at `/`.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Events streamed from the scan engine to every connected dashboard client.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DashboardEvent {
    ScanStart {
        targets: Vec<String>,
        total_ports: usize,
        total_jobs: u64,
    },
    /// The scanner moved to a new phase: "discovery", "tcp", "udp", "banner".
    Phase {
        phase: String,
        label: String,
    },
    Progress {
        done: u64,
        total: u64,
        concurrency: usize,
        elapsed_ms: u128,
        /// Which phase this progress belongs to ("discovery", "tcp", "udp").
        proto: String,
    },
    /// A host answered discovery (ICMP ping or a TCP probe).
    HostUp {
        ip: String,
        method: String,
        rtt_ms: Option<u32>,
    },
    PortOpen {
        ip: String,
        port: u16,
        service: Option<String>,
        version: Option<String>,
        banner: Option<String>,
        /// "tcp" or "udp".
        proto: String,
        /// "open", "open|filtered", ...
        state: String,
    },
    ScanDone {
        elapsed_ms: u128,
        interrupted: bool,
        hosts: usize,
        open_ports: usize,
    },
}

/// Serialisable current state, sent to clients that connect mid-scan.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Snapshot {
    started: bool,
    finished: bool,
    interrupted: bool,
    targets: Vec<String>,
    total_ports: usize,
    total_jobs: u64,
    done: u64,
    concurrency: usize,
    elapsed_ms: u128,
    /// Current phase: "", "discovery", "tcp", "udp", "banner".
    phase: String,
    /// Hosts confirmed alive by discovery.
    hosts_up: Vec<SnapshotHostUp>,
    /// Hosts with open ports (grouped tables).
    hosts: Vec<SnapshotHost>,
    open_ports: usize,
}

#[derive(Debug, Clone, Serialize)]
struct SnapshotHostUp {
    ip: String,
    method: String,
    rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct SnapshotHost {
    ip: String,
    ports: Vec<SnapshotPort>,
}

#[derive(Debug, Clone, Serialize)]
struct SnapshotPort {
    port: u16,
    proto: String,
    state: String,
    service: Option<String>,
    version: Option<String>,
    banner: Option<String>,
}

/// Shared hub: keeps the snapshot and broadcasts events to WebSocket clients.
pub struct DashboardHub {
    tx: broadcast::Sender<String>,
    state: Mutex<Snapshot>,
}

impl DashboardHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx, state: Mutex::new(Snapshot::default()) }
    }

    /// Apply an event to the snapshot and broadcast it to every client.
    pub fn emit(&self, ev: DashboardEvent) {
        {
            let mut s = self.state.lock().unwrap();
            apply(&mut s, &ev);
        }
        if let Ok(json) = serde_json::to_string(&ev) {
            let _ = self.tx.send(json);
        }
    }

    fn snapshot_json(&self) -> String {
        let s = self.state.lock().unwrap();
        serde_json::json!({ "type": "snapshot", "snapshot": &*s }).to_string()
    }

    /// Bind the dashboard listener. Callers use the returned listener to
    /// confirm the port is actually bound before opening a browser.
    pub async fn bind(&self, port: u16) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(("127.0.0.1", port)).await
    }

    /// Run the HTTP + WebSocket server on an already-bound listener until the
    /// process exits.
    pub async fn serve_on(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
    ) -> std::io::Result<()> {
        let app = Router::new()
            .route("/", get(index))
            .route("/ws", get(ws_handler))
            .with_state(self);
        axum::serve(listener, app)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

fn apply(state: &mut Snapshot, ev: &DashboardEvent) {
    match ev {
        DashboardEvent::ScanStart { targets, total_ports, total_jobs } => {
            state.started = true;
            state.targets = targets.clone();
            state.total_ports = *total_ports;
            state.total_jobs = *total_jobs;
        }
        DashboardEvent::Progress { done, total, concurrency, elapsed_ms, proto: _ } => {
            state.done = *done;
            state.total_jobs = *total;
            state.concurrency = *concurrency;
            state.elapsed_ms = *elapsed_ms;
        }
        DashboardEvent::Phase { phase, .. } => {
            state.phase = phase.clone();
        }
        DashboardEvent::HostUp { ip, method, rtt_ms } => {
            if let Some(h) = state.hosts_up.iter_mut().find(|h| h.ip == *ip) {
                let better = match (h.rtt_ms, *rtt_ms) {
                    (Some(old), Some(new)) => new < old,
                    (None, Some(_)) => true,
                    _ => false,
                };
                if better {
                    h.rtt_ms = *rtt_ms;
                }
            } else {
                state.hosts_up.push(SnapshotHostUp {
                    ip: ip.clone(),
                    method: method.clone(),
                    rtt_ms: *rtt_ms,
                });
            }
        }
        DashboardEvent::PortOpen { ip, port, service, version, banner, proto, state: st } => {
            let host_idx = match state.hosts.iter().position(|h| h.ip == *ip) {
                Some(i) => i,
                None => {
                    state.hosts.push(SnapshotHost { ip: ip.clone(), ports: Vec::new() });
                    state.hosts.len() - 1
                }
            };
            let host = &mut state.hosts[host_idx];
            let port_idx = match host.ports.iter().position(|p| p.port == *port) {
                Some(i) => i,
                None => {
                    host.ports.push(SnapshotPort {
                        port: *port,
                        proto: proto.clone(),
                        state: st.clone(),
                        service: None,
                        version: None,
                        banner: None,
                    });
                    host.ports.len() - 1
                }
            };
            let p = &mut host.ports[port_idx];
            p.proto = proto.clone();
            p.state = st.clone();
            if service.is_some() {
                p.service = service.clone();
            }
            if version.is_some() {
                p.version = version.clone();
            }
            if banner.is_some() {
                p.banner = banner.clone();
            }
            // Count genuinely open findings; UDP open|filtered rows are not
            // "open" (they may simply be filtered) so totals stay honest.
            state.open_ports = state
                .hosts
                .iter()
                .flat_map(|h| h.ports.iter())
                .filter(|p| p.state == "open")
                .count();
        }
        DashboardEvent::ScanDone { elapsed_ms, interrupted, .. } => {
            state.finished = true;
            state.interrupted = *interrupted;
            state.elapsed_ms = *elapsed_ms;
        }
    }
}

async fn index() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn ws_handler(ws: WebSocketUpgrade, State(hub): State<Arc<DashboardHub>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, hub))
}

async fn handle_socket(socket: WebSocket, hub: Arc<DashboardHub>) {
    use futures::{SinkExt, StreamExt};

    let (mut sink, mut stream) = socket.split();

    // Send the current state first so mid-scan joins render something.
    if sink.send(Message::Text(hub.snapshot_json())).await.is_err() {
        return;
    }

    let mut rx = hub.tx.subscribe();
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(text) => {
                    if sink.send(Message::Text(text)).await.is_err() {
                        return;
                    }
                }
                // Slow client missed events — resend the current snapshot so
                // it converges on the true state before resuming the stream.
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if sink.send(Message::Text(hub.snapshot_json())).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            msg = stream.next() => match msg {
                Some(Ok(Message::Close(_))) | None => return,
                Some(Ok(_)) => {}
                Some(Err(_)) => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_with_type_tag() {
        let ev = DashboardEvent::PortOpen {
            ip: "192.168.1.5".into(),
            port: 80,
            service: Some("http".into()),
            version: None,
            banner: Some("HTTP/1.1 200 OK".into()),
            proto: "tcp".into(),
            state: "open".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"type\":\"port_open\""));
        assert!(json.contains("\"port\":80"));
        assert!(json.contains("\"ip\":\"192.168.1.5\""));
        assert!(json.contains("\"proto\":\"tcp\""));
    }

    #[test]
    fn host_up_applies_to_snapshot() {
        let mut snap = Snapshot::default();
        apply(&mut snap, &DashboardEvent::Phase { phase: "discovery".into(), label: "probe".into() });
        apply(
            &mut snap,
            &DashboardEvent::HostUp { ip: "10.0.0.2".into(), method: "icmp".into(), rtt_ms: Some(3) },
        );
        assert_eq!(snap.phase, "discovery");
        assert_eq!(snap.hosts_up.len(), 1);
        assert_eq!(snap.hosts_up[0].method, "icmp");
        assert_eq!(snap.hosts_up[0].rtt_ms, Some(3));
    }

    #[test]
    fn snapshot_tracks_udp_port_state() {
        let mut snap = Snapshot::default();
        apply(
            &mut snap,
            &DashboardEvent::PortOpen {
                ip: "10.0.0.1".into(),
                port: 53,
                service: Some("domain".into()),
                version: None,
                banner: None,
                proto: "udp".into(),
                state: "open|filtered".into(),
            },
        );
        assert_eq!(snap.hosts[0].ports[0].proto, "udp");
        assert_eq!(snap.hosts[0].ports[0].state, "open|filtered");
        // open|filtered rows are not counted as genuinely open.
        assert_eq!(snap.open_ports, 0);
        apply(
            &mut snap,
            &DashboardEvent::PortOpen {
                ip: "10.0.0.1".into(),
                port: 5353,
                service: Some("mdns".into()),
                version: None,
                banner: None,
                proto: "udp".into(),
                state: "open".into(),
            },
        );
        assert_eq!(snap.hosts[0].ports.len(), 2);
        assert_eq!(snap.open_ports, 1);
    }

    #[test]
    fn snapshot_tracks_port_updates() {
        let mut snap = Snapshot::default();
        apply(
            &mut snap,
            &DashboardEvent::ScanStart {
                targets: vec!["10.0.0.1".into()],
                total_ports: 1000,
                total_jobs: 1000,
            },
        );
        apply(
            &mut snap,
            &DashboardEvent::PortOpen {
                ip: "10.0.0.1".into(),
                port: 22,
                service: Some("ssh".into()),
                version: None,
                banner: None,
                proto: "tcp".into(),
                state: "open".into(),
            },
        );
        apply(
            &mut snap,
            &DashboardEvent::PortOpen {
                ip: "10.0.0.1".into(),
                port: 22,
                service: Some("ssh".into()),
                version: Some("9.0".into()),
                banner: Some("SSH-2.0".into()),
                proto: "tcp".into(),
                state: "open".into(),
            },
        );
        assert_eq!(snap.hosts.len(), 1);
        assert_eq!(snap.hosts[0].ports.len(), 1);
        assert_eq!(snap.hosts[0].ports[0].version.as_deref(), Some("9.0"));
        assert_eq!(snap.open_ports, 1);
    }
}
