# cybertools · सायबर-साधन

A collection of **cyber security tools written in pure Rust** — installable
with a single one-liner, no setup, straight from this repo (no crates.io, no
package manager, no Python, no system dependencies):

| Tool | Sanskrit | What it does | Install |
| --- | --- | --- | --- |
| **vajra** | वज्र (thunderbolt) | Ultra-fast async port scanner — TCP/UDP sweeps, host discovery, banner grabbing, live web dashboard, nmap integration | `cargo install --git https://github.com/Pradyu12/cybertools vajra-rs` |
| **taranga** | तरंग (wave) | Wifite-style Wi-Fi auditing — AP scanning, live signal monitoring, pure-Rust PMKID cracking | `cargo install --git https://github.com/Pradyu12/cybertools taranga` |

Both install as standalone binaries into `~/.cargo/bin` (`vajra` and
`taranga`).

## Install — one-liner, compiles from source (feroxbuster style)

**Already have Rust?** One command downloads the source from this repo and
compiles it — exactly like `cargo install feroxbuster`:

```bash
cargo install --git https://github.com/Pradyu12/cybertools vajra-rs   # scanner
cargo install --git https://github.com/Pradyu12/cybertools taranga    # Wi-Fi kit
```

**No Rust installed? No setup needed — this one-liner installs Rust if
missing, then compiles + installs both tools:**

```bash
# Linux / macOS / WSL
curl -sSL https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.ps1 | iex
```

Add `~/.cargo/bin` to your `PATH` if needed.

## The tools

### [vajra](vajra/) · वज्र — port scanner

Full 65,535-port sweeps in seconds with adaptive async concurrency; ICMP +
TCP host discovery; UDP probing with application payloads; banner grabbing
and service fingerprinting; a live web dashboard streaming the campaign in
real time; automatic `nmap` hand-off; device discovery with OS fingerprinting
(TTL + banners + OUI); human / greppable / JSON output.

```bash
vajra -a 192.168.1.5                       # top-1000 ports of one host
vajra -a 192.168.1.0/24 -d -w              # discover live hosts, watch live
vajra -a 192.168.1.5 -u -p 1-1000          # TCP + UDP sweep
vajra devices -a 192.168.1.0/24 --json     # fingerprint every device's OS
```

### [taranga](taranga/) · तरंग — Wi-Fi auditing toolkit

Wifite-style wardriving in pure Rust: scan nearby APs (Windows `netsh`, Linux
`nmcli`/`iw`, no admin needed on Windows), monitor them live with
new/lost/signal-change detection, and crack captured WPA/WPA2 **PMKID**
hashes offline — pure Rust, no Python, no aircrack, no GPU.

```bash
taranga scan                                  # one-shot AP scan
taranga monitor -i 3                          # live wardriving
taranga crack-pmkid --pmkid <hash> --ap-mac <mac> --client-mac <mac> --essid <ssid> -w wordlist.txt
```

## Building from source

```bash
cargo build --release        # builds both vajra and taranga
cargo test                   # runs all tests for the whole workspace
```

## Project layout

```
vajra/      the port scanner (crate name vajra-rs, binary `vajra`)
taranga/    the Wi-Fi toolkit (crate name taranga, binary `taranga`)
install.sh      one-liner installer for Linux / macOS / WSL
install.ps1     one-liner installer for Windows
```

## License

MIT. Use responsibly — only against networks you own or have explicit
permission to test.
