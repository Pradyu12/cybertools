//! Vajra (वज्र, the thunderbolt): an ultra-fast async port scanner.
//!
//! The crate is organised so every subsystem is unit-testable:
//! - [`ports`]: port specification parsing and the built-in top-ports list
//! - [`target`]: target expansion (IPs, hostnames, CIDR, ranges, `@files`)
//! - [`scan`]: the async TCP scanning engine with adaptive concurrency
//! - [`discover`]: host discovery (ICMP + TCP probes, streamed live)
//! - [`udp`]: UDP scanning with application probes
//! - [`ping`]: cross-platform ICMP echo
//! - [`banner`]: banner grabbing and service/version identification
//! - [`dashboard`]: live web dashboard (HTTP + WebSocket hub)
//! - [`output`]: human, greppable and JSON renderers
//! - [`nmap`]: post-scan nmap integration
//! - [`cli`]: command-line interface definition

pub mod banner;
pub mod cli;
pub mod dashboard;
pub mod discover;
pub mod nmap;
pub mod output;
pub mod ping;
pub mod ports;
pub mod scan;
pub mod target;
pub mod udp;
