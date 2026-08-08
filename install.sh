#!/usr/bin/env bash
# cybertools installer — vajra-rs (port scanner) + taranga (Wi-Fi toolkit)
# No setup required: installs Rust if missing, then compiles from crates.io.
#
#   curl -sSL https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.sh | bash
set -euo pipefail

say()  { printf '\033[1;36m[cybertools]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[cybertools] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

TOOLS="${1:-vajra-rs taranga}"   # `install.sh vajra-rs` installs just the scanner

# --- 1. Rust toolchain ------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
    say "Rust not found — installing via rustup (no setup needed)..."
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal
    else
        die "need curl or wget to install Rust"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
    command -v cargo >/dev/null 2>&1 || die "cargo still missing after rustup install — open a new shell and retry"
fi
say "Using cargo $(cargo --version | awk '{print $2}')"

# --- 2. Compile + install from crates.io -------------------------------------
for t in $TOOLS; do
    say "Installing $t (compiling from source)..."
    cargo install "$t" || die "cargo install $t failed"
done

say "Done! Binaries are in ~/.cargo/bin:"
for t in $TOOLS; do
    bin="${t%-rs}"   # vajra-rs installs as `vajra`
    [ -f "$HOME/.cargo/bin/$bin" ] || bin="$t"
    say "  $bin — $HOME/.cargo/bin/$bin"
    # shellcheck disable=SC2015
    case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) echo "    (add $HOME/.cargo/bin to your PATH)";; esac
done
