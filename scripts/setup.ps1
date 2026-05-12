# setup.ps1 — Ramen CVE development environment bootstrapper (Windows 11 Pro)
#
# Usage (from PowerShell in the repo root):
#   .\setup.ps1
#
# If you get an execution policy error, allow scripts for this session only:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\setup.ps1
#
# What this does:
#   1. Verifies Python 3.10+ is installed.
#   2. Creates a .venv virtualenv at the repo root.
#   3. Installs runtime + dev dependencies.
#   4. Bootstraps .env from .env.example if .env is missing.
#   5. Initializes the tasks/ directory if missing.
#   6. Prints next steps.
#
# Re-running is safe — every step is idempotent.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

function Write-Info  { param($msg) Write-Host "[info] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[ok]   $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[warn] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[fail] $msg" -ForegroundColor Red; exit 1 }

Write-Info "Ramen CVE setup - Windows"
Write-Info "Repo root: $RepoRoot"

# ----- Step 1: Find a usable Python interpreter -----
# Windows ships the 'py' launcher with Python.org installs; prefer it.
$python = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $python = "py -3"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $python = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $python = "python3"
} else {
    Write-Fail "No Python found. Install Python 3.10+ from https://www.python.org/downloads/ or 'winget install Python.Python.3.12'"
}

# Check version
$pyVersionOutput = & cmd /c "$python -c `"import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')`" 2>&1"
$pyMajor = & cmd /c "$python -c `"import sys; print(sys.version_info.major)`" 2>&1"
$pyMinor = & cmd /c "$python -c `"import sys; print(sys.version_info.minor)`" 2>&1"

if ([int]$pyMajor -lt 3 -or ([int]$pyMajor -eq 3 -and [int]$pyMinor -lt 10)) {
    Write-Fail "Python 3.10+ required. Found: $pyVersionOutput"
}
Write-Ok "Python $pyVersionOutput detected (using: $python)"

# ----- Step 2: Create venv -----
if (-not (Test-Path ".venv")) {
    Write-Info "Creating virtualenv at .venv/"
    & cmd /c "$python -m venv .venv"
    if ($LASTEXITCODE -ne 0) { Write-Fail "venv creation failed" }
    Write-Ok "Virtualenv created"
} else {
    Write-Ok "Virtualenv already exists at .venv/"
}

# Path to the venv's Python and pip
$venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$venvPip = Join-Path $RepoRoot ".venv\Scripts\pip.exe"

if (-not (Test-Path $venvPython)) {
    Write-Fail "Expected venv Python at $venvPython but it's missing. Try deleting .venv and re-running."
}

# ----- Step 3: Upgrade pip + install deps -----
Write-Info "Upgrading pip"
& $venvPython -m pip install --quiet --upgrade pip
if ($LASTEXITCODE -ne 0) { Write-Fail "pip upgrade failed" }

if (Test-Path "requirements.txt") {
    Write-Info "Installing runtime dependencies from requirements.txt"
    & $venvPip install --quiet -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Fail "Runtime deps install failed" }
    Write-Ok "Runtime dependencies installed"
} else {
    Write-Warn "requirements.txt not found - skipping runtime deps (Phase 0 hasn't run yet)"
}

if (Test-Path "requirements-dev.txt") {
    Write-Info "Installing dev dependencies from requirements-dev.txt"
    & $venvPip install --quiet -r requirements-dev.txt
    if ($LASTEXITCODE -ne 0) { Write-Fail "Dev deps install failed" }
    Write-Ok "Dev dependencies installed"
} else {
    Write-Warn "requirements-dev.txt not found - skipping dev deps (Phase 0 hasn't run yet)"
}

# ----- Step 4: Bootstrap .env from .env.example -----
if (Test-Path ".env.example") {
    if (-not (Test-Path ".env")) {
        Copy-Item ".env.example" ".env"
        Write-Ok "Created .env from .env.example - edit it and paste your NVD API key"
    } else {
        Write-Ok ".env already exists (preserved as-is)"
    }
} else {
    Write-Warn ".env.example not found - Phase 0 Slice 0.1 hasn't created it yet"
}

# ----- Step 5: Ensure tasks/ exists with stub lessons.md -----
if (-not (Test-Path "tasks")) {
    New-Item -ItemType Directory -Path "tasks" | Out-Null
}
if (-not (Test-Path "tasks\lessons.md")) {
    @"
# Lessons learned

Append entries here after every user correction or postmortem.
Format: short failure mode + detection signal + prevention rule.

(Empty until something is learned.)
"@ | Set-Content -Path "tasks\lessons.md" -Encoding UTF8
    Write-Ok "Stubbed tasks/lessons.md"
}

# ----- Step 6: Sanity check Claude Code config -----
if (Test-Path ".claude\settings.json") {
    try {
        Get-Content ".claude\settings.json" -Raw | ConvertFrom-Json | Out-Null
        Write-Ok ".claude/settings.json is valid JSON"
    } catch {
        Write-Warn ".claude/settings.json exists but does not parse as JSON"
    }
} else {
    Write-Warn ".claude/settings.json not found"
}

if (Test-Path "CLAUDE.md") {
    Write-Ok "CLAUDE.md present at repo root"
} else {
    Write-Warn "CLAUDE.md not found at repo root - Claude Code won't auto-load project context"
}

# ----- Done -----
Write-Host ""
Write-Ok "Setup complete."
Write-Host ""
Write-Info "Next steps:"
Write-Host "  1. Activate the venv:    .\.venv\Scripts\Activate.ps1"
Write-Host "  2. Edit .env and paste your NVD_API_KEY"
Write-Host "  3. Open this repo in Claude Code and use the kickoff prompt"
Write-Host ""
Write-Info "Verify the environment any time with:"
Write-Host "  python --version    # should show 3.10+"
Write-Host "  python -c `"import requests, feedparser, dotenv; print('deps ok')`""
Write-Host ""
