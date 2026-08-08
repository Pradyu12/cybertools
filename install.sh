#!/usr/bin/env bash
# cybertools installer — vajra-rs (port scanner) + taranga (Wi-Fi toolkit)
# No setup required: installs Rust if missing, then compiles from this repo.
#
#   curl -sSL https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.sh | bash
set -euo pipefail

say()  { printf '\033[1;36m[cybertools]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[cybertools] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

REPO="https://github.com/Pradyu12/cybertools"
# which tools to install; vajra-rs -> ./vajra, taranga -> ./taranga
TOOLS="${1:-vajra-rs taranga}"

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

# --- 2. Clone + compile + install from this repo (no crates.io) --------------
command -v git >/dev/null 2>&1 || die "git is required — install it first (e.g. apt install git)"
say "Cloning $REPO..."
git clone --depth 1 "$REPO" "$TMP/cybertools" >/dev/null 2>&1 || die "could not clone $REPO"
cd "$TMP/cybertools" || die "clone failed"

for t in $TOOLS; do
    dir="$t"
    [ "$t" = "vajra-rs" ] && dir="vajra"
    say "Installing $t (compiling from source)..."
    cargo install --path "$dir" --root "$HOME/.cargo" || die "cargo install $t failed"
done

say "Done! Binaries are in ~/.cargo/bin:"
for b in vajra taranga; do
    if [ -x "$HOME/.cargo/bin/$b" ]; then
        say "  $b — $HOME/.cargo/bin/$b"
        case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) echo "    (add $HOME/.cargo/bin to your PATH)";; esac
    fi
done
