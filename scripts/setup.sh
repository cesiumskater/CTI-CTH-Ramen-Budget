#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# ramen-cve bootstrap — Linux / macOS
# ----------------------------------------------------------------------------
# Creates a project-local virtualenv, installs runtime + dev dependencies,
# and copies config/env.example -> .env on first run. Idempotent: re-run any
# time after pulling new commits.
#
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh
# ----------------------------------------------------------------------------

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; CYAN=''; RESET=''
fi
info()  { printf "${CYAN}[info]${RESET} %s\n" "$1"; }
ok()    { printf "${GREEN}[ok]${RESET}   %s\n" "$1"; }
warn()  { printf "${YELLOW}[warn]${RESET} %s\n" "$1"; }
fail()  { printf "${RED}[fail]${RESET} %s\n" "$1" >&2; exit 1; }

info "ramen-cve setup — repo root: $REPO_ROOT"

# --- Python 3.10+ check -----------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 not found. On Debian/Ubuntu: sudo apt install python3 python3-venv python3-pip"
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
  fail "Python 3.10+ required. Found $PY_VERSION."
fi
ok "Python $PY_VERSION detected"

# --- venv -------------------------------------------------------------------
if [ ! -d ".venv" ]; then
  info "Creating virtualenv at .venv/"
  python3 -m venv .venv
  ok "Virtualenv created"
else
  ok "Virtualenv already exists at .venv/"
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# --- Dependencies -----------------------------------------------------------
python -m pip install --quiet --upgrade pip
# Prefer the editable install — it picks up the [project] block in
# pyproject.toml AND exposes the `ramen-cve` console script.
pip install --quiet -e ".[dev]"
ok "Runtime + dev dependencies installed (editable mode, console script: ramen-cve)"

# --- First-run .env ---------------------------------------------------------
if [ -f "config/env.example" ] && [ ! -f ".env" ]; then
  cp config/env.example .env
  ok "Created .env from config/env.example — paste your NVD_API_KEY there"
elif [ -f ".env" ]; then
  ok ".env already exists (preserved)"
fi

echo ""
ok "Setup complete. Next steps:"
echo "  1. source .venv/bin/activate"
echo "  2. edit .env and paste your NVD_API_KEY"
echo "  3. python ramen.py            # launches the wizard"
echo "     ramen-cve --help          # console entry installed by pip"
