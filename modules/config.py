"""Environment helpers: minimal .env loader (no external dependency)."""

from __future__ import annotations

import os

# Project root (one level above the modules/ package): .env lives here.
# advisories.db and osv_cache/ default to the same directory; Docker sets
# VULNSIGHT_DATA_DIR so they persist on a volume instead.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.abspath(os.environ.get("VULNSIGHT_DATA_DIR") or BASE_DIR)


def load_dotenv(path: str | None = None) -> None:
    """Load KEY=VALUE lines from a .env file (default: BASE_DIR/.env)."""
    if path is None:
        path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            # Do not clobber values already set in the real environment.
            os.environ.setdefault(key, val)
