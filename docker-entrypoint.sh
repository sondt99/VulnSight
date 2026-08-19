#!/bin/sh
set -eu

data_dir="${VULNSIGHT_DATA_DIR:-/data}"
mkdir -p "${data_dir}/osv_cache"

if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
  echo "==> gh: using token from the environment"
elif gh auth status >/dev/null 2>&1; then
  echo "==> gh: already authenticated"
else
  echo "!! gh not authenticated — GHSA searches will fail."
  echo "   Host login is stored in the OS keyring, so the container cannot reuse it."
  echo "   Pass a token:  GH_TOKEN=\$(gh auth token) docker compose up --build"
  echo "   or set GH_TOKEN in .env"
fi

exec "$@"
