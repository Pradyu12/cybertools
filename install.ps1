# cybertools installer — vajra-rs (port scanner) + taranga (Wi-Fi toolkit)
# No setup required: installs Rust if missing, then compiles from this repo.
#
#   irm https://raw.githubusercontent.com/Pradyu12/cybertools/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'

function Say($msg) { Write-Host "[cybertools] $msg" -ForegroundColor Cyan }

$Repo = 'https://github.com/Pradyu12/cybertools'
$CargoBin = "$env:USERPROFILE\.cargo\bin"

# --- 1. Rust toolchain ------------------------------------------------------
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Say "Rust not found - installing via rustup (no setup needed)..."
    $rustup = Join-Path $env:TEMP 'rustup-init.exe'
    Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $rustup
    Start-Process -FilePath $rustup -ArgumentList '-y', '--profile', 'minimal' -Wait -NoNewWindow
    $env:PATH = "$CargoBin;$env:PATH"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo still missing after rustup install - open a new terminal and retry"
    }
}
Say "Using cargo $(cargo --version | ForEach-Object { $_.Split(' ')[1] })"

# --- 2. Clone + compile + install from this repo (no crates.io) --------------
Say "Cloning $Repo ..."
$tmp = Join-Path $env:TEMP "cybertools-install-$([guid]::NewGuid().ToString('N'))"
git clone --depth 1 $Repo $tmp | Out-Null
if ($LASTEXITCODE -ne 0) { throw "could not clone $Repo" }

foreach ($tool in @(@{ name = 'vajra-rs'; dir = 'vajra' }, @{ name = 'taranga'; dir = 'taranga' })) {
    Say "Installing $($tool.name) (compiling from source)..."
    Push-Location (Join-Path $tmp $tool.dir)
    try { cargo install --path . --root "$env:USERPROFILE\.cargo" }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "cargo install $($tool.name) failed" }
}

Say "Done! Binaries are in ~\.cargo\bin: vajra and taranga"
Say "Open a NEW terminal so PATH picks up ~\.cargo\bin"
