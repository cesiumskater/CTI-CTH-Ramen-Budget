# ----------------------------------------------------------------------------
# ramen-cve bootstrap - Windows PowerShell
# ----------------------------------------------------------------------------
# Creates a project-local virtualenv, installs runtime + dev dependencies,
# and copies config\env.example -> .env on first run. Idempotent: re-run any
# time after pulling new commits.
#
# Usage (from PowerShell):
#   .\scripts\setup.ps1
#
# If you hit an execution-policy error, allow scripts for this session only:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\scripts\setup.ps1
# ----------------------------------------------------------------------------

$ErrorActionPreference = "Stop"

# Walk one directory up from the script's location so the same invocation
# works whether the user calls scripts\setup.ps1 from the repo root or from
# inside scripts\.
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

function Write-Info { param($msg) Write-Host "[info] $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "[ok]   $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[warn] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "[fail] $msg" -ForegroundColor Red; exit 1 }

Write-Info "ramen-cve setup - repo root: $RepoRoot"

# --- Python 3.10+ check ----------------------------------------------------
$python = $null
foreach ($candidate in @("python", "py")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $python = $candidate; break }
}
if (-not $python) {
    Write-Fail "python not found. Install Python 3.10+ from https://www.python.org/downloads/ and re-run."
}
$pyVer = & $python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
$pyMaj = [int](& $python -c 'import sys; print(sys.version_info.major)')
$pyMin = [int](& $python -c 'import sys; print(sys.version_info.minor)')
if ($pyMaj -lt 3 -or ($pyMaj -eq 3 -and $pyMin -lt 10)) {
    Write-Fail "Python 3.10+ required. Found $pyVer."
}
Write-Ok "Python $pyVer detected"

# --- venv -------------------------------------------------------------------
if (-not (Test-Path ".venv")) {
    Write-Info "Creating virtualenv at .venv\"
    & $python -m venv .venv
    Write-Ok "Virtualenv created"
} else {
    Write-Ok "Virtualenv already exists at .venv\"
}
& ".\.venv\Scripts\Activate.ps1"

# --- Dependencies ----------------------------------------------------------
python -m pip install --quiet --upgrade pip
# Editable install picks up the pyproject [project] block AND installs the
# `ramen-cve` console script.
pip install --quiet -e ".[dev]"
Write-Ok "Runtime + dev dependencies installed (editable mode, console script: ramen-cve)"

# --- First-run .env --------------------------------------------------------
if ((Test-Path "config\env.example") -and -not (Test-Path ".env")) {
    Copy-Item "config\env.example" ".env"
    Write-Ok "Created .env from config\env.example - paste your NVD_API_KEY there"
} elseif (Test-Path ".env") {
    Write-Ok ".env already exists (preserved)"
}

Write-Host ""
Write-Ok "Setup complete. Next steps:"
Write-Host "  1. .\.venv\Scripts\Activate.ps1"
Write-Host "  2. notepad .env  (paste your NVD_API_KEY)"
Write-Host "  3. python ramen.py            # launches the wizard"
Write-Host "     ramen-cve --help          # console entry installed by pip"
