# cybertools installer — vajra-rs (port scanner) + taranga (Wi-Fi toolkit)
# No setup required: installs Rust if missing, then compiles from crates.io.
#
#   irm https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'

function Say($msg) { Write-Host "[cybertools] $msg" -ForegroundColor Cyan }

# --- 1. Rust toolchain ------------------------------------------------------
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Say "Rust not found - installing via rustup (no setup needed)..."
    $rustup = Join-Path $env:TEMP 'rustup-init.exe'
    Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $rustup
    Start-Process -FilePath $rustup -ArgumentList '-y', '--profile', 'minimal' -Wait -NoNewWindow
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo still missing after rustup install - open a new terminal and retry"
    }
}
Say "Using cargo $(cargo --version | ForEach-Object { $_.Split(' ')[1] })"

# --- 2. Compile + install from crates.io -------------------------------------
foreach ($tool in @('vajra-rs', 'taranga')) {
    Say "Installing $tool (compiling from source)..."
    cargo install $tool
    if ($LASTEXITCODE -ne 0) { throw "cargo install $tool failed" }
}

Say "Done! Binaries are in ~\.cargo\bin: vajra and taranga"
Say "Open a NEW terminal so PATH picks up ~\.cargo\bin"
