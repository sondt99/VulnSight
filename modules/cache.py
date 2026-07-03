"""Tiny SQLite cache for advisories and AI classifications.

Two tables:
  advisories        - normalized GHSA record (raw JSON), keyed by ghsa_id
  ai_classification - AI verdict per (ghsa_id, category), so re-running a
                      search does not re-spend AI tokens on the same advisory.

The cache is optional: the app works without it, it just re-fetches. Keeping
it makes the UI snappy and the AI pass cheap on repeat searches.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager

from .config import BASE_DIR

DB_PATH = os.path.join(BASE_DIR, "advisories.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    ghsa_id     TEXT PRIMARY KEY,
    cve_id      TEXT,
    severity    TEXT,
    data        TEXT NOT NULL,          -- normalized record as JSON
    fetched_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_classification (
    ghsa_id     TEXT NOT NULL,
    category    TEXT NOT NULL,
    is_match    INTEGER NOT NULL,       -- 0/1
    confidence  REAL NOT NULL,          -- 0..1
    vuln_type   TEXT,
    reason      TEXT,
    model       TEXT,
    created_at  REAL NOT NULL,
    PRIMARY KEY (ghsa_id, category)
);
CREATE INDEX IF NOT EXISTS idx_adv_cve ON advisories(cve_id);
"""


def _connect(path: str | None = None) -> sqlite3.Connection:
    # Resolve the module global at CALL time (not def time) so tests / callers
    # can repoint cache.DB_PATH and have every function honour it.
    conn = sqlite3.connect(path or DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


@contextmanager
def _db(path: str | None = None):
    """Connection scope: commit on success, rollback on error, always close.

    sqlite3.Connection's own context manager only manages the transaction —
    it never closes the connection — so this wrapper owns the full lifecycle.
    """
    conn = _connect(path)
    try:
        with conn:          # transaction scope (commit/rollback)
            yield conn
    finally:
        conn.close()


def init_db(path: str | None = None) -> None:
    with _db(path) as conn:
        conn.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# Advisories
# ---------------------------------------------------------------------------

def upsert_advisories(records: list[dict], path: str | None = None) -> None:
    if not records:
        return
    now = time.time()
    with _db(path) as conn:
        conn.executemany(
            """INSERT INTO advisories (ghsa_id, cve_id, severity, data, fetched_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(ghsa_id) DO UPDATE SET
                 cve_id=excluded.cve_id,
                 severity=excluded.severity,
                 data=excluded.data,
                 fetched_at=excluded.fetched_at""",
            [
                (
                    r.get("ghsa_id"),
                    r.get("cve_id"),
                    r.get("severity"),
                    json.dumps(r, ensure_ascii=False),
                    now,
                )
                for r in records
                if r.get("ghsa_id")
            ],
        )


def get_advisory(ghsa_id: str, path: str | None = None) -> dict | None:
    with _db(path) as conn:
        row = conn.execute(
            "SELECT data FROM advisories WHERE ghsa_id=?", (ghsa_id,)
        ).fetchone()
    return json.loads(row["data"]) if row else None


def count_advisories(path: str | None = None) -> int:
    with _db(path) as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM advisories").fetchone()["c"]


# ---------------------------------------------------------------------------
# AI classifications
# ---------------------------------------------------------------------------

def save_classification(
    ghsa_id: str,
    category: str,
    verdict: dict,
    model: str,
    path: str | None = None,
) -> None:
    with _db(path) as conn:
        conn.execute(
            """INSERT INTO ai_classification
               (ghsa_id, category, is_match, confidence, vuln_type, reason, model, created_at)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(ghsa_id, category) DO UPDATE SET
                 is_match=excluded.is_match,
                 confidence=excluded.confidence,
                 vuln_type=excluded.vuln_type,
                 reason=excluded.reason,
                 model=excluded.model,
                 created_at=excluded.created_at""",
            (
                ghsa_id,
                category,
                1 if verdict.get("is_match") else 0,
                float(verdict.get("confidence", 0.0)),
                verdict.get("vuln_type"),
                verdict.get("reason"),
                model,
                time.time(),
            ),
        )


def get_classifications(
    ghsa_ids: list[str], category: str, path: str | None = None
) -> dict[str, dict]:
    if not ghsa_ids:
        return {}
    placeholders = ",".join("?" * len(ghsa_ids))
    with _db(path) as conn:
        rows = conn.execute(
            f"""SELECT * FROM ai_classification
                WHERE category=? AND ghsa_id IN ({placeholders})""",
            [category, *ghsa_ids],
        ).fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        out[r["ghsa_id"]] = {
            "is_match": bool(r["is_match"]),
            "confidence": r["confidence"],
            "vuln_type": r["vuln_type"],
            "reason": r["reason"],
            "model": r["model"],
            "cached": True,
        }
    return out
