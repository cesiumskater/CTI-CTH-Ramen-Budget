#!/usr/bin/env bash
# setup.sh — Ramen CVE development environment bootstrapper (Linux / Kubuntu)
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
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

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ----- Colors (degrade cleanly if not a TTY) -----
if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; CYAN=''; RESET=''
fi

info()  { printf "${CYAN}[info]${RESET} %s\n" "$1"; }
ok()    { printf "${GREEN}[ok]${RESET}   %s\n" "$1"; }
warn()  { printf "${YELLOW}[warn]${RESET} %s\n" "$1"; }
fail()  { printf "${RED}[fail]${RESET} %s\n" "$1" >&2; exit 1; }

info "Ramen CVE setup — Linux"
info "Repo root: $REPO_ROOT"

# ----- Step 1: Python version check -----
if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 not found. Install with: sudo apt install python3 python3-venv python3-pip"
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
  fail "Python 3.10+ required. Found: $PY_VERSION. Install with: sudo apt install python3.12 python3.12-venv"
fi
ok "Python $PY_VERSION detected"

# ----- Step 2: Verify python3-venv is available -----
if ! python3 -c "import venv" >/dev/null 2>&1; then
  fail "python3-venv not installed. Run: sudo apt install python3-venv"
fi

# ----- Step 3: Create venv -----
if [ ! -d ".venv" ]; then
  info "Creating virtualenv at .venv/"
  python3 -m venv .venv
  ok "Virtualenv created"
else
  ok "Virtualenv already exists at .venv/"
fi

# Activate the venv for this script's remaining steps
# shellcheck disable=SC1091
source .venv/bin/activate

# ----- Step 4: Upgrade pip + install deps -----
info "Upgrading pip"
python -m pip install --quiet --upgrade pip

if [ -f "requirements.txt" ]; then
  info "Installing runtime dependencies from requirements.txt"
  pip install --quiet -r requirements.txt
  ok "Runtime dependencies installed"
else
  warn "requirements.txt not found — skipping runtime deps (Phase 0 hasn't run yet)"
fi

if [ -f "requirements-dev.txt" ]; then
  info "Installing dev dependencies from requirements-dev.txt"
  pip install --quiet -r requirements-dev.txt
  ok "Dev dependencies installed"
else
  warn "requirements-dev.txt not found — skipping dev deps (Phase 0 hasn't run yet)"
fi

# ----- Step 5: Bootstrap .env from .env.example -----
if [ -f ".env.example" ]; then
  if [ ! -f ".env" ]; then
    cp .env.example .env
    ok "Created .env from .env.example — edit it and paste your NVD API key"
  else
    ok ".env already exists (preserved as-is)"
  fi
else
  warn ".env.example not found — Phase 0 Slice 0.1 hasn't created it yet"
fi

# ----- Step 6: Ensure tasks/ exists with stub lessons.md -----
mkdir -p tasks
if [ ! -f "tasks/lessons.md" ]; then
  cat > tasks/lessons.md << 'EOF'
# Lessons learned

Append entries here after every user correction or postmortem.
Format: short failure mode + detection signal + prevention rule.

(Empty until something is learned.)
EOF
  ok "Stubbed tasks/lessons.md"
fi

# ----- Step 7: Sanity check Claude Code config -----
if [ -f ".claude/settings.json" ]; then
  if python -c "import json; json.load(open('.claude/settings.json'))" >/dev/null 2>&1; then
    ok ".claude/settings.json is valid JSON"
  else
    warn ".claude/settings.json exists but does not parse as JSON"
  fi
else
  warn ".claude/settings.json not found"
fi

if [ -f "CLAUDE.md" ]; then
  ok "CLAUDE.md present at repo root"
else
  warn "CLAUDE.md not found at repo root — Claude Code won't auto-load project context"
fi

# ----- Done -----
echo ""
ok "Setup complete."
echo ""
info "Next steps:"
echo "  1. Activate the venv:    source .venv/bin/activate"
echo "  2. Edit .env and paste your NVD_API_KEY"
echo "  3. Open this repo in Claude Code and use the kickoff prompt"
echo ""
info "Verify the environment any time with:"
echo "  python --version    # should show 3.10+"
echo "  python -c 'import requests, feedparser, dotenv; print(\"deps ok\")'"
echo ""
