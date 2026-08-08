//! Live web dashboard.
//!
//! With `--web`, taranga embeds a tiny HTTP + WebSocket server on
//! `127.0.0.1:<port>`. The scan/monitor/crack engine pushes JSON events
//! through a broadcast channel; every connected browser tab renders them in
//! real time, and late-joining tabs receive a full snapshot of the state so
//! far (the current AP list, or the crack result).

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

/// Events streamed from the engine to every connected dashboard client.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DashboardEvent {
    /// The engine began: `mode` is "scan", "monitor" or "crack".
    Start {
        mode: String,
        label: String,
        /// Local network info for the connected Wi-Fi (IP, gateway, SSID).
        net: Option<crate::netinfo::NetInfo>,
    },
    /// A full AP-list refresh (scan mode: once; monitor mode: every cycle).
    ScanResult {
        aps: Vec<ApEvent>,
        elapsed_ms: u128,
    },
    /// A monitor cycle completed (kept lightweight; the AP list follows).
    Cycle {
        cycle: u64,
        new: usize,
        gone: usize,
        elapsed_ms: u128,
    },
    /// Cracking progress (throttled to whole percents).
    CrackProgress {
        pct: usize,
        tried: usize,
    },
    /// The passphrase was found.
    CrackFound {
        passphrase: String,
        elapsed_ms: u128,
    },
    /// Cracking finished without a hit.
    CrackMiss {
        elapsed_ms: u128,
    },
    /// Everything is done; the process holds so the dashboard can be read.
    Done {
        mode: String,
        elapsed_ms: u128,
    },
}

/// One access point as seen by the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct ApEvent {
    pub ssid: String,
    pub bssid: String,
    pub channel: u16,
    pub band: String,
    pub radio: String,
    pub signal_pct: u8,
    pub signal_dbm: i32,
    pub auth: String,
    pub hidden: bool,
}

impl From<&crate::networks::AccessPoint> for ApEvent {
    fn from(ap: &crate::networks::AccessPoint) -> Self {
        ApEvent {
            ssid: ap.ssid.clone(),
            bssid: ap.bssid.clone(),
            channel: ap.channel,
            band: ap.band.clone(),
            radio: ap.radio.clone(),
            signal_pct: ap.signal_pct,
            signal_dbm: ap.signal_dbm(),
            auth: ap.security(),
            hidden: ap.hidden,
        }
    }
}

/// Serialisable current state, sent to clients that connect mid-run.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Snapshot {
    started: bool,
    finished: bool,
    mode: String,
    label: String,
    net: Option<crate::netinfo::NetInfo>,
    aps: Vec<ApEvent>,
    cycle: u64,
    /// Current crack progress percent (0-100) or None when not cracking.
    crack_pct: Option<usize>,
    crack_tried: usize,
    cracked: bool,
    passphrase: Option<String>,
    elapsed_ms: u128,
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
        DashboardEvent::Start { mode, label, net } => {
            state.started = true;
            state.finished = false;
            state.mode = mode.clone();
            state.label = label.clone();
            state.net = net.clone();
            state.aps.clear();
            state.cycle = 0;
            state.crack_pct = None;
            state.cracked = false;
            state.passphrase = None;
            state.elapsed_ms = 0;
        }
        DashboardEvent::ScanResult { aps, elapsed_ms } => {
            state.aps = aps.clone();
            state.elapsed_ms = *elapsed_ms;
        }
        DashboardEvent::Cycle { cycle, .. } => {
            state.cycle = *cycle;
        }
        DashboardEvent::CrackProgress { pct, tried } => {
            state.crack_pct = Some(*pct);
            state.crack_tried = *tried;
        }
        DashboardEvent::CrackFound { passphrase, elapsed_ms } => {
            state.cracked = true;
            state.passphrase = Some(passphrase.clone());
            state.crack_pct = Some(100);
            state.elapsed_ms = *elapsed_ms;
            state.finished = true;
        }
        DashboardEvent::CrackMiss { elapsed_ms } => {
            state.crack_pct = Some(100);
            state.elapsed_ms = *elapsed_ms;
            state.finished = true;
        }
        DashboardEvent::Done { elapsed_ms, .. } => {
            state.finished = true;
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

    // Send the current state first so mid-run joins render something.
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
                // Slow client missed events — resend the snapshot so it
                // converges on the true state before resuming the stream.
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
        let ev = DashboardEvent::CrackFound {
            passphrase: "letmein".into(),
            elapsed_ms: 42,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"type\":\"crack_found\""));
        assert!(json.contains("\"passphrase\":\"letmein\""));
    }

    #[test]
    fn scan_result_updates_snapshot() {
        let mut snap = Snapshot::default();
        apply(
            &mut snap,
            &DashboardEvent::Start { mode: "scan".into(), label: "scan".into(), net: None },
        );
        apply(
            &mut snap,
            &DashboardEvent::ScanResult {
                aps: vec![ApEvent {
                    ssid: "MyNet".into(),
                    bssid: "AA:BB:CC:DD:EE:FF".into(),
                    channel: 6,
                    band: "2.4 GHz".into(),
                    radio: "802.11n".into(),
                    signal_pct: 87,
                    signal_dbm: -41,
                    auth: "WPA2-Personal".into(),
                    hidden: false,
                }],
                elapsed_ms: 500,
            },
        );
        assert_eq!(snap.aps.len(), 1);
        assert_eq!(snap.aps[0].ssid, "MyNet");
        assert_eq!(snap.elapsed_ms, 500);
    }

    #[test]
    fn crack_found_marks_finished() {
        let mut snap = Snapshot::default();
        apply(
            &mut snap,
            &DashboardEvent::CrackProgress { pct: 50, tried: 5 },
        );
        assert_eq!(snap.crack_pct, Some(50));
        assert!(!snap.finished);
        apply(
            &mut snap,
            &DashboardEvent::CrackFound { passphrase: "hunter2".into(), elapsed_ms: 99 },
        );
        assert!(snap.finished);
        assert!(snap.cracked);
        assert_eq!(snap.passphrase.as_deref(), Some("hunter2"));
        assert_eq!(snap.crack_pct, Some(100));
    }
}
