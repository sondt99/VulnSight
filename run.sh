#!/usr/bin/env bash
# Bootstrap venv, install deps, and launch VulnSight.
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
if [ ! -d "$VENV" ]; then
  echo "==> Creating virtualenv"
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Installing dependencies"
pip install -q --upgrade pip >/dev/null
pip install -q -r requirements.txt

# Preflight checks
if ! command -v gh >/dev/null 2>&1; then
  echo "!! gh CLI not found. Install it: https://cli.github.com/"
elif ! gh auth status >/dev/null 2>&1; then
  echo "!! gh not authenticated. Run: gh auth login"
fi

if [ ! -f .env ]; then
  echo "!! No .env found — copy .env.example and add your AI_TOKEN for AI."
fi

echo "==> Starting server on http://127.0.0.1:${PORT:-5000}"
exec python app.py "$@"
