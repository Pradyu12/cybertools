//! Platform backend dispatch: run a scan using the native tool available on
//! the current OS and parse the result.

use crate::networks::{parse_iw, parse_nmcli, parse_netsh, AccessPoint};
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("no supported scan backend found: {0}")]
    NoBackend(String),
    #[error("scan command failed: {0}")]
    CommandFailed(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// A scan backend: how to invoke it, and how to parse its output.
#[cfg_attr(target_os = "windows", allow(dead_code))]
#[derive(Clone)]
pub enum Backend {
    Netsh,
    Nmcli,
    Iw { iface: String },
}

impl Backend {
    /// Pick the best backend for the current platform.
    pub fn detect(iface: Option<&str>) -> Result<Backend, BackendError> {
        #[cfg(target_os = "windows")]
        {
            let _ = iface;
            if which("netsh").is_ok() {
                return Ok(Backend::Netsh);
            }
            Err(BackendError::NoBackend("netsh not found".into()))
        }
        #[cfg(not(target_os = "windows"))]
        {
            if let Some(i) = iface {
                if which("iw").is_ok() {
                    return Ok(Backend::Iw { iface: i.to_string() });
                }
            }
            if which("nmcli").is_ok() {
                return Ok(Backend::Nmcli);
            }
            if let Ok(i) = default_iw_iface() {
                if which("iw").is_ok() {
                    return Ok(Backend::Iw { iface: i });
                }
            }
            Err(BackendError::NoBackend(
                "install nmcli (NetworkManager) or iw, or pass --iface".into(),
            ))
        }
    }

    pub fn scan(&self) -> Result<Vec<AccessPoint>, BackendError> {
        let raw = match self {
            Backend::Netsh => {
                let out = Command::new("netsh")
                    .args(["wlan", "show", "networks", "mode=bssid"])
                    .output()?;
                String::from_utf8_lossy(&out.stdout).into_owned()
            }
            Backend::Nmcli => {
                let out = Command::new("nmcli")
                    .args([
                        "-t",
                        "-f",
                        "SSID,BSSID,CHAN,SIGNAL,SECURITY,IN-USE,RATE,BAND",
                        "dev",
                        "wifi",
                        "list",
                    ])
                    .output()?;
                String::from_utf8_lossy(&out.stdout).into_owned()
            }
            Backend::Iw { iface } => {
                let out = Command::new("iw")
                    .args(["dev", iface.as_str(), "scan"])
                    .output()?;
                if !out.status.success() {
                    return Err(BackendError::CommandFailed(
                        "iw scan needs root (try: sudo)".into(),
                    ));
                }
                String::from_utf8_lossy(&out.stdout).into_owned()
            }
        };

        let mut aps = match self {
            Backend::Netsh => parse_netsh(&raw),
            Backend::Nmcli => parse_nmcli(&raw),
            Backend::Iw { .. } => parse_iw(&raw),
        };
        dedup_and_sort(&mut aps);
        Ok(aps)
    }
}

/// Merge BSSIDs from the same radio/SSID seen in both bands and sort by
/// signal strength (strongest first).
pub fn dedup_and_sort(aps: &mut Vec<AccessPoint>) {
    let mut seen = std::collections::HashSet::new();
    aps.retain(|ap| seen.insert((ap.ssid.clone(), ap.bssid.clone())));
    aps.sort_by_key(|a| std::cmp::Reverse(a.signal_pct));
}

fn which(cmd: &str) -> Result<(), std::io::Error> {
    // Minimal PATH lookup, Windows-aware (checks PATHEXT).
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let exe = dir.join(cmd);
        if exe.is_file() {
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        {
            let exe_exe = dir.join(format!("{cmd}.exe"));
            if exe_exe.is_file() {
                return Ok(());
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{cmd} not found on PATH"),
    ))
}

#[cfg(not(target_os = "windows"))]
fn default_iw_iface() -> Result<String, BackendError> {
    let out = Command::new("iw").args(["dev"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Interface") {
            if let Some((_, name)) = rest.split_once(':') {
                return Ok(name.trim().to_string());
            }
        }
    }
    Err(BackendError::NoBackend("no wireless interface found".into()))
}
