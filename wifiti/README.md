# wifiti

A **wifite-style Wi-Fi auditing toolkit written in Rust**: scan nearby access
points, monitor them live, and dictionary-crack captured WPA/WPA2 **PMKID**
hashes entirely offline in pure Rust (no Python, no aircrack, no GPU).

```
CH   BSSID               SIG% dBm   SECURITY             SSID
---  ------------------- ---- ----- -------------------- ----
36   4A:43:DD:07:39:72   90   -37   WPA2-Personal        (hidden)
11   6C:4F:89:95:3C:DE   85   -41   WPA2-Personal        Airtel_venk_6990
36   6E:4F:89:95:3C:DF   29   -80   WPA2-Personal        (hidden)
0    10:27:F5:EC:17:56   26   -82   WPA2-Personal        TP-Link_1756
```

## Features

- **AP scanning** — lists every visible access point with SSID, BSSID,
  channel, band, radio type (802.11ax/ac/n), signal strength (percent + dBm),
  and security mode. Hidden-SSID networks are detected and marked.
  - Windows: `netsh wlan show networks mode=bssid` (no admin needed)
  - Linux: `nmcli` or `iw` (root for `iw scan`)
- **Live web dashboard** (`--web`) — a self-contained hacker/CRT-styled page
  (matrix rain, scanlines, phosphor green) streams the airspace in real time
  over WebSocket: AP cards with signal bars, a **channel-occupancy
  histogram**, per-cycle new/lost/signal-change events in an activity log, and
  a **crack progress bar** that turns amber and flashes "CRACKED!" when the
  passphrase is found. Late joiners receive a full snapshot. Auto-opens in
  your browser and holds after the run (Ctrl+C exits).
- **Live monitoring** (`monitor`) — rescans on an interval and renders a live
  table with signal bars, highlighting **new APs**, **vanished APs**, and
  **signal-strength changes** (▲/▼) as they happen — wifite-style wardriving.
- **PMKID cracking** (`crack-pmkid`) — pure-Rust offline dictionary attack:
  `PMK = PBKDF2-HMAC-SHA1(pass, ssid, 4096)`, then
  `PMKID = HMAC-SHA1(PMK, "PMK Name" ‖ AP_MAC ‖ Client_MAC)[0..16]`.
  No external tools, no GPU — just a wordlist.
- **Three output formats** — human table, JSON, and CSV; write to a file with
  `-o`.

## Build & test

```bash
cargo build --release        # binary at target/release/wifiti(.exe)
cargo test                   # 12 unit tests (parsers + PMKID vectors)
```

## Usage

```bash
# One-shot scan of everything nearby
wifiti scan

# Machine-readable output
wifiti scan --json
wifiti scan --csv
wifiti scan --json -o scan.json

# Live monitoring (rescan every 3s, watch APs appear/disappear)
wifiti monitor -i 3

# Live web dashboard (auto-opens in your browser; Ctrl+C to exit)
wifiti monitor -i 4 --web
wifiti scan --web --json -o scan.json
wifiti crack-pmkid ... --web

# Dashboard on another port / don't auto-open the browser
wifiti monitor -i 4 --web --web-port 9090 --no-open

# Linux: choose the wireless interface
wifiti scan --iface wlan0
wifiti monitor --iface wlan0
```

### Cracking a PMKID

Capturing the PMKID itself requires a monitor-mode adapter (e.g.
`hcxdumptool`/`hcxtools` on Linux). Once you have the 32-hex-digit hash:

```bash
wifiti crack-pmkid \
  --pmkid a2c30e23df4e38ddfc45746ab3fdf6d4 \
  --ap-mac 6c:4f:89:95:3c:de \
  --client-mac 78:2b:46:51:8e:48 \
  --essid Airtel_venk_6990 \
  --wordlist rockyou.txt
```

```
[*] target: 6c:4f:89:95:3c:de     essid: Airtel_venk_6990
[*] pmkid:  a2c30e23df4e38ddfc45746ab3fdf6d4
[+] CRACKED! passphrase = "wifi-password-42" in 0.00s
```

The PMKID algorithm is validated against an independently computed reference
vector in the test suite, so a hit is a real hit.

## Roadmap

- WPA/WPA2 **handshake** (EAPOL) capture + offline cracking from PCAP
- Client/station enumeration in the dashboard
- History of past scans in the dashboard
- WPS PIN attacks (online brute force + pixie-dust-style offline)
- Deauthentication support (Linux, needs monitor mode)
- Client/station enumeration
- Rate limiting and channel hopping (needs monitor mode)

## Legal

Wi-Fi auditing is only lawful against networks you own or are explicitly
authorized to test. The cracking feature exists for auditing your own
infrastructure and for research.
