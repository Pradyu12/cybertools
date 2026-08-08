# Vajra · वज्र

**The thunderbolt** — an ultra-fast async port scanner written in Rust. Vajra
discovers which hosts are up (ICMP ping + TCP probes), asynchronously sweeps
every TCP port on your targets at very high concurrency (adaptive
concurrency), scans UDP with application probes, fingerprints services via
banner grabbing, streams everything to a **live web dashboard**, hands open
ports to `nmap` for deep scanning, and emits clean human, greppable, or JSON
output.

## Install — one-liner, compiles from source (feroxbuster style)

**Already have Rust?** It's a single `cargo install` straight from this
repo — cargo downloads the source and compiles it for you, exactly like
`cargo install feroxbuster` (no crates.io needed):

```bash
cargo install --git https://github.com/Pradyu12/cybertools vajra-rs
```

**No Rust installed? No setup needed — this one-liner installs Rust if
missing, then compiles + installs:**

```bash
# Linux / macOS / WSL
curl -sSL https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.ps1 | iex
```

The binaries land in `~/.cargo/bin` (`vajra`, plus `taranga` if you install
the full kit). Add `~/.cargo/bin` to your `PATH` if needed.

```
Scan report: 1 host(s), 13 open port(s), 194 probe(s) in 3.35s (concurrency 2000)
Host 127.0.0.1 (-)
  PORT      SERVICE   VERSION   BANNER
  135/tcp   msrpc     -         (no banner)
  53/udp    domain    -         (open|filtered)
  5678/udp  unknown-udp -       ....
  (0 closed, 190 filtered)
```

## Features

- **Full 65,535-port sweep in seconds** — every `(host, port)` pair is an async
  task; a sliding-window controller adapts concurrency to the network, backing
  off when timeouts dominate and ramping up when everything completes fast.
- **Host discovery** (`-d`) — before scanning, every target is probed with
  ICMP echo (via `IcmpSendEcho` on Windows, raw ICMP on Unix) **and** TCP
  connects to common service ports; only live hosts get scanned. Live hosts
  stream to the dashboard the moment they answer — a subnet sweep shows hosts
  lighting up before a single port is probed. `--no-probe` forces scanning
  everything regardless (nmap `-Pn`).
- **UDP scanning** (`-u`) — every UDP port gets a purpose-built application
  probe (DNS query, NTP request, SNMP GET, SSDP M-SEARCH, mDNS/LLMNR queries,
  TFTP RRQ, ISAKMP, memcached, OpenVPN, WireGuard, SIP OPTIONS, ...) with a
  response classifier. A reply means *open*; silence means *open|filtered*
  (indistinguishable without a raw ICMP socket — same as unprivileged nmap).
- **Live web dashboard** (`-w`) — a self-contained hacker/CRT-styled page
  (matrix rain, scanlines, phosphor green) streams the phase (discovery → TCP
  sweep → UDP sweep → banner grab), progress, ETA, host chips lighting up, and
  open ports over a WebSocket in real time. Auto-opens in your browser and
  stays alive after the sweep so you can review results. Late joiners receive
  a full snapshot of the scan so far.
- **Service detection** — banner grabbing with HTTP, TLS ClientHello, greeting
  and newline probes; fingerprints service + version with a port-based fallback
  table.
- **Flexible targets** — single IPs, hostnames, CIDR blocks (`192.168.1.0/24`),
  IP ranges (`192.168.1.5-192.168.1.20`), octet ranges (`192.168.1.5-20`),
  IPv6, and `@file` target lists with `#` comments.
- **Flexible ports** — `80,443`, `1-1000`, `top-1000` (clamped to the built-in
  top-ports list), plus a built-in top-UDP list for `--udp-ports`.
- **nmap integration** — open ports are handed to `nmap -p <ports> <hosts>`
  automatically; pass extra flags after `--`.
- **Three output formats** — human tables, greppable
  (`ip:port:open[:service]`; UDP rows carry `/udp` and state), and JSON
  (per-port `protocol` + `state`); write to a file with `-o`.
- **Device scan** (`devices`) — sweep a range, capture each reply's ICMP
  TTL, probe signature ports (SSH/SMB/RDP/AirTunes/mDNS), grab banners, and
  combine the evidence into an OS fingerprint (Windows / Linux / macOS /
  Apple / network gear) with a confidence score. MACs come from the local
  ARP table and are matched against a vendor OUI table.
- **Ctrl+C safe** — aborts in-flight probes and still prints partial results.
- **Randomized scan order** by default to avoid tripping naive firewalls.

## Prerequisites & dependencies

| Tool | Required? | Notes |
| --- | --- | --- |
| **Rust toolchain** (stable, via [rustup](https://rustup.rs)) | ✅ yes | Everything is pure-Rust; `cargo build` fetches all crates below automatically |
| **nmap** | ⚠️ optional | Only needed for the automatic post-scan hand-off (`vajra ... -- -sV -sC`). Install from [nmap.org](https://nmap.org) or `apt install nmap`; skip with `--no-nmap` |
| **root / `CAP_NET_RAW`** | ⚠️ Linux only | Required for raw ICMP discovery (`-d`). Without it, discovery falls back to TCP probes automatically |
| **Windows admin** | ❌ not needed | Ping uses `IcmpSendEcho` (no admin); UDP `open\|filtered` is reported the same as unprivileged nmap |

Cargo crates (fetched automatically): `tokio`, `axum`, `clap`, `indicatif`, `serde`, `rand`, `ipnet`, `thiserror`, `libc`. The live dashboard is a single self-contained HTML file — no Node, no CDN, no browser extensions.

## Build

```bash
cargo build --release        # binary at target/release/vajra(.exe)
cargo test                   # 44 unit tests
```

## Usage

```bash
# Scan the top-1000 ports of one host (default), with service detection
vajra -a 192.168.1.5

# Full port sweep, all 65,535 ports
vajra -a 192.168.1.5 -p 1-65535

# Subnet sweep: discover live hosts, then scan only them (watch it live)
vajra -a 192.168.1.0/24 -d -w

# TCP + UDP sweep
vajra -a 192.168.1.5 -u -p 1-1000 --udp-ports 53,123,161

# Scan a CIDR block and an octet range on specific ports, greppable
vajra -a 192.168.1.0/24 -a 10.0.0.5-20 -p 80,443,8000-8100 -g

# Discover every live device on your LAN and fingerprint its OS
vajra devices -a 192.168.1.0/24

# Device sweep with JSON output (for scripts / dashboards)
vajra devices -a 192.168.1.0/24 --json -o devices.json

# Hostname + target file, JSON output to a file
vajra -a example.com -a @targets.txt -p top-100 --json -o scan.json

# Feed open ports into nmap with extra flags
vajra -a 192.168.1.5 -p 1-1000 -- -sV -sC

# Tune the scan
vajra -a 192.168.1.5 -T 2500 -c 4000 --scan-order serial --no-banner
```

### Options

| Flag | Meaning | Default |
| --- | --- | --- |
| `-a, --addresses` | targets: IPs, hostnames, CIDR, ranges, `@file` | (required) |
| `-p, --ports` | TCP port spec: `80,443`, `1-1000`, `top-1000` | `top-1000` |
| `-d, --discover` | host discovery (ICMP + TCP probes) before scanning | off |
| `--no-probe` | scan all targets even if discovery finds none (nmap `-Pn`) | off |
| `-u, --udp` | also scan UDP ports with application probes | off |
| `--udp-ports` | UDP port spec (built-in top-UDP list) | `top-100` |
| `-T, --timeout` | per-connection timeout in ms | `2500` |
| `-c, --concurrency` | initial scan concurrency | `4000` |
| `--min-concurrency` / `--max-concurrency` | adaptive bounds | `128` / `65535` |
| `--scan-order` | `serial` or `random` | `random` |
| `-w, --web` | serve the live web dashboard | off |
| `--web-port` | dashboard port | `9333` |
| `--no-open` | don't auto-open the dashboard in a browser | off |
| `-g, --greppable` | `ip:port:open[:service]` per line | off |
| `--json` | JSON output | off |
| `-o, --output` | write output to a file | — |
| `--no-banner` | skip service detection | off |
| `-n, --no-nmap` | don't run nmap afterwards | off |
| `--` | extra arguments passed to nmap | — |

### The dashboard

`vajra -a <targets> -w` starts an embedded HTTP + WebSocket server on
`127.0.0.1:9333` (override with `--web-port`), opens it in your default
browser, and streams JSON events over `/ws` as the campaign runs:

- `scan_start`, `phase` (discovery / tcp / udp / banner), `progress`
  (throttled to ~10/s, tagged with the phase), `host_up` (with method + RTT),
  `port_open` (with `proto` and `state`), `scan_done`
- `snapshot` — sent to any client that connects mid-scan so it can catch up,
  including the discovered-host fleet

The process holds after the sweep so you can review the final state in the
browser; Ctrl+C exits. The dashboard is a single self-contained HTML file
(`src/dashboard.html`) — no external assets or CDNs.

### Notes

- **Closed vs filtered**: a TCP port that times out is reported as `filtered`.
  On healthy networks closed ports are refused instantly; if you see many
  `filtered` ports on a machine that shouldn't be firewalled, raise
  `-T` (some environments take >1.5s to deliver a refusal).
- **UDP `open|filtered`**: UDP has no handshake. A port that replies is
  `open`; a silent port is `open|filtered` — only a raw ICMP socket could
  distinguish a closed port, and Windows does not deliver ICMP
  port-unreachable messages to unprivileged processes.
- **ICMP on Unix**: requires root / `CAP_NET_RAW`; otherwise discovery falls
  back to TCP probes automatically (works everywhere).
- **`top-N` ports**: the built-in TCP list is curated (~180 common ports). If
  you need the full nmap top-1000, pass the range explicitly.
- **nmap**: install [nmap](https://nmap.org) to enable the automatic hand-off,
  or pass `--no-nmap` to skip it.

## Project layout

```
src/
  main.rs      entry point + orchestration (targets -> discovery -> TCP -> UDP -> banners -> output -> nmap)
  cli.rs       clap CLI definition
  target.rs    target expansion: IPs, hostnames, CIDR, ranges, @files
  ports.rs     port spec parsing + built-in top-ports lists (TCP + UDP)
  scan.rs      async TCP engine with adaptive concurrency
  discover.rs  host discovery: ICMP ping + TCP probes, streamed live
  ping.rs      cross-platform ICMP echo (IcmpSendEcho / raw socket)
  devices.rs   device discovery + OS fingerprinting (TTL + banners + OUI)
  udp.rs       UDP scanning with application payloads + classifiers
  banner.rs    banner grabbing + service/version fingerprinting
  dashboard.rs WebSocket hub + embedded HTTP server
  dashboard.html  self-contained live dashboard page
  output.rs    human / greppable / JSON renderers
  nmap.rs      post-scan nmap integration
```

## Roadmap ideas

- Rate limiting (`--rate`) and jitter
- `~/.vajra.toml` config file support
- Full nmap top-1000 port list
- TCP SYN "half-open" scanning (needs privileges)
- Multi-scan session history in the dashboard
