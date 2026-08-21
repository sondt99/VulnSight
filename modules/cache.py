"""Tiny SQLite cache for advisories and AI classifications.

Two tables:
  advisories        - normalized advisory record (raw JSON), keyed by advisory_id
  ai_classification - AI verdict per (advisory_id, category), so re-running a
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

from .config import DATA_DIR

DB_PATH = os.path.join(DATA_DIR, "advisories.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    cve_id      TEXT,
    severity    TEXT,
    data        TEXT NOT NULL,          -- normalized record as JSON
    fetched_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_classification (
    advisory_id TEXT NOT NULL,
    category    TEXT NOT NULL,
    is_match    INTEGER NOT NULL,       -- 0/1
    confidence  REAL NOT NULL,          -- 0..1
    vuln_type   TEXT,
    reason      TEXT,
    model       TEXT,
    fingerprint TEXT,
    created_at  REAL NOT NULL,
    PRIMARY KEY (advisory_id, category)
);
CREATE INDEX IF NOT EXISTS idx_adv_cve ON advisories(cve_id);
"""

# ---------------------------------------------------------------------------
# Schema migrations — append-only list of (version, sql) tuples.
# Each sql string may contain multiple semicolon-separated statements.
# ---------------------------------------------------------------------------
_MIGRATIONS = [
    # v1: base schema (advisories + ai_classification + indexes)
    (1, _SCHEMA),
    # v2: add fingerprint column to ai_classification
    (2, "ALTER TABLE ai_classification ADD COLUMN fingerprint TEXT"),
    # v3: rename ghsa_id -> advisory_id (source-neutral primary key)
    (3, "ALTER TABLE advisories RENAME COLUMN ghsa_id TO advisory_id;"
        "ALTER TABLE ai_classification RENAME COLUMN ghsa_id TO advisory_id"),
    # v4: v3 renamed the *column* but left the stored JSON alone, so rows written
    # before it carry no advisory_id inside `data`. Anything that reads a cached
    # record back — the AI batch in particular — then has no id to key the result
    # by. Backfill from the primary key, which is authoritative. Idempotent.
    (4, "UPDATE advisories"
        "   SET data = json_set(data, '$.advisory_id', advisory_id)"
        " WHERE json_valid(data)"
        "   AND COALESCE(json_extract(data, '$.advisory_id'), '') = ''"),
]


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
    """Create / migrate the database to the latest schema version."""
    db_path = path or DB_PATH
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with _db(db_path) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version ("
            "    version INTEGER NOT NULL"
            ")"
        )
        row = conn.execute(
            "SELECT MAX(version) AS v FROM schema_version"
        ).fetchone()
        current = row["v"] if row["v"] is not None else 0

        for version, sql in _MIGRATIONS:
            if version <= current:
                continue
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if not stmt:
                    continue
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    # e.g. ALTER TABLE ADD COLUMN when column already exists
                    pass
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (version,),
            )


# ---------------------------------------------------------------------------
# Advisories
# ---------------------------------------------------------------------------

def upsert_advisories(records: list[dict], path: str | None = None) -> None:
    if not records:
        return
    now = time.time()
    with _db(path) as conn:
        conn.executemany(
            """INSERT INTO advisories (advisory_id, cve_id, severity, data, fetched_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(advisory_id) DO UPDATE SET
                 cve_id=excluded.cve_id,
                 severity=excluded.severity,
                 data=excluded.data,
                 fetched_at=excluded.fetched_at""",
            [
                (
                    r.get("advisory_id"),
                    r.get("cve_id"),
                    r.get("severity"),
                    json.dumps(r, ensure_ascii=False),
                    now,
                )
                for r in records
                if r.get("advisory_id")
            ],
        )


def get_advisory(advisory_id: str, path: str | None = None) -> dict | None:
    with _db(path) as conn:
        row = conn.execute(
            "SELECT data FROM advisories WHERE advisory_id=?", (advisory_id,)
        ).fetchone()
    return json.loads(row["data"]) if row else None


def count_advisories(path: str | None = None) -> int:
    with _db(path) as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM advisories").fetchone()["c"]


# ---------------------------------------------------------------------------
# AI classifications
# ---------------------------------------------------------------------------

def save_classification(
    advisory_id: str,
    category: str,
    verdict: dict,
    model: str,
    path: str | None = None,
    *,
    fingerprint: str | None = None,
) -> None:
    with _db(path) as conn:
        conn.execute(
            """INSERT INTO ai_classification
               (advisory_id, category, is_match, confidence, vuln_type, reason, model,
                fingerprint, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(advisory_id, category) DO UPDATE SET
                 is_match=excluded.is_match,
                 confidence=excluded.confidence,
                 vuln_type=excluded.vuln_type,
                 reason=excluded.reason,
                 model=excluded.model,
                 fingerprint=excluded.fingerprint,
                 created_at=excluded.created_at""",
            (
                advisory_id,
                category,
                1 if verdict.get("is_match") else 0,
                float(verdict.get("confidence", 0.0)),
                verdict.get("vuln_type"),
                verdict.get("reason"),
                model,
                fingerprint,
                time.time(),
            ),
        )


def get_classifications(
    advisory_ids: list[str],
    category: str,
    path: str | None = None,
    *,
    expected_fingerprints: dict[str, str] | None = None,
) -> dict[str, dict]:
    if not advisory_ids:
        return {}
    placeholders = ",".join("?" * len(advisory_ids))
    with _db(path) as conn:
        rows = conn.execute(
            f"""SELECT * FROM ai_classification
                WHERE category=? AND advisory_id IN ({placeholders})""",
            [category, *advisory_ids],
        ).fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        if expected_fingerprints is not None:
            expected = expected_fingerprints.get(r["advisory_id"])
            if not expected or r["fingerprint"] != expected:
                continue
        out[r["advisory_id"]] = {
            "is_match": bool(r["is_match"]),
            "confidence": r["confidence"],
            "vuln_type": r["vuln_type"],
            "reason": r["reason"],
            "model": r["model"],
            "cached": True,
        }
    return out
