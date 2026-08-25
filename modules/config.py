"""Environment helpers: minimal .env loader (no external dependency)."""

from __future__ import annotations

import os

# Project root (one level above the modules/ package): .env lives here.
# advisories.db and osv_cache/ default to the same directory; Docker sets
# VULNSIGHT_DATA_DIR so they persist on a volume instead.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


# Loaded here, at import, rather than left to the application entry point.
#
# Several modules derive a constant from the environment while *they* are being
# imported — cache.DB_PATH, osv_client.CACHE_DIR, ai_classifier's timeout,
# max-tokens and thinking flags. app.py imported those modules and only then
# called load_dotenv(), so every one of those constants was computed against an
# environment the .env had not reached yet. Verified before this change, with
# `AI_THINKING=on` and `AI_CLASSIFY_TIMEOUT=999` in .env: the variables were set
# afterwards, but THINKING_ENABLED stayed False and CLASSIFY_TIMEOUT stayed 45.
# AI_CLASSIFY_WORKERS worked, because it happens to be read at call time — so
# the behaviour differed knob by knob, which is worse than a knob that plainly
# does not exist.
#
# The import side effect is the cost. It buys every documented setting actually
# taking effect regardless of import order, which the explicit call could not.
# load_dotenv uses setdefault, so a real environment variable still wins and
# calling it again later is harmless.
load_dotenv()

DATA_DIR = os.path.abspath(os.environ.get("VULNSIGHT_DATA_DIR") or BASE_DIR)
