"""OSV.dev source (bulk-download + local CWE filter).

Why bulk and not the API: the OSV REST API is *package-centric* — you can only
query by package/commit/purl/id. It has NO CWE filter and no "list everything in
an ecosystem" browse (POST /v1/query with {"cwe":...} returns "Invalid query").
So to browse by bug class / CWE the way this tool does, we download OSV's
per-ecosystem bulk export (a small zip, ~10 MB) and filter locally.

Bulk export layout:
  https://osv-vulnerabilities.storage.googleapis.com/{Ecosystem}/all.zip
  -> a zip of one JSON file per vulnerability (OSV schema).

We normalise each record to the SAME shape as ghsa_client.normalize() so the
cache, AI layer, and UI treat GHSA and OSV records identically.

OSV records for maven/npm/pip/Go/crates are largely mirrored from GHSA (their id
is GHSA-...), so merging dedupes heavily; the genuine additions are source-native
records (GO-..., RUSTSEC-..., PYSEC-..., etc.).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.request
import zipfile

from .config import BASE_DIR
from .cvss import base_score, severity_from_score
from .cwe_categories import category_keywords, normalize_cwe_id

logger = logging.getLogger(__name__)

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
CACHE_DIR = os.path.join(BASE_DIR, "osv_cache")
DEFAULT_MAX_AGE = 24 * 3600  # re-download the bulk zip at most once a day
USER_AGENT = "vulnsight/1.0 (+osv bulk)"

# GHSA ecosystem name  ->  OSV ecosystem name (OSV uses different casing/labels).
ECOSYSTEM_MAP: dict[str, str] = {
    "maven": "Maven",
    "go": "Go",
    "npm": "npm",
    "pip": "PyPI",
    "composer": "Packagist",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "rust": "crates.io",
    "pub": "Pub",
    "swift": "SwiftURL",
    "erlang": "Hex",
    "actions": "GitHub Actions",
}

# In-process cache of parsed+normalized records, keyed by GHSA ecosystem name.
_MEM: dict[str, list[dict]] = {}


class OsvError(RuntimeError):
    pass


def supported_ecosystem(ghsa_ecosystem: str) -> bool:
    return ghsa_ecosystem in ECOSYSTEM_MAP


# ---------------------------------------------------------------------------
# Download + cache the bulk zip
# ---------------------------------------------------------------------------

def _zip_path(osv_eco: str) -> str:
    safe = osv_eco.replace("/", "_").replace(" ", "_")
    return os.path.join(CACHE_DIR, f"{safe}.zip")


def download_ecosystem(osv_eco: str, force: bool = False,
                       max_age: int = DEFAULT_MAX_AGE, timeout: int = 120) -> str:
    """Ensure the ecosystem's all.zip is cached locally; return its path."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = _zip_path(osv_eco)
    if (not force and os.path.exists(path)
            and (time.time() - os.path.getmtime(path)) < max_age
            and os.path.getsize(path) > 0):
        return path

    url = f"{OSV_BASE}/{osv_eco}/all.zip"
    req = urllib.request.Request(url, headers={"user-agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except Exception as e:  # noqa: BLE001 - surface a clean message to the UI
        raise OsvError(f"could not download OSV bulk for {osv_eco}: {e}") from e

    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    return path


_QUAL_MAP = {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium",
             "HIGH": "high", "CRITICAL": "critical"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_GHSA_RE = re.compile(r"^GHSA-", re.I)


# ---------------------------------------------------------------------------
# Normalise one OSV record -> the shared advisory shape
# ---------------------------------------------------------------------------

def normalize_osv(rec: dict) -> dict:
    osv_id = rec.get("id", "")
    aliases = rec.get("aliases") or []
    ghsa_id = osv_id if _GHSA_RE.match(osv_id) else next(
        (a for a in aliases if _GHSA_RE.match(a)), osv_id)
    cve_id = next((a for a in aliases if _CVE_RE.match(a)), None)
    if not cve_id and _CVE_RE.match(osv_id):
        cve_id = osv_id

    cwes = list((rec.get("database_specific") or {}).get("cwe_ids") or [])

    # severity: prefer qualitative from database_specific, else compute CVSS.
    ds_sev = (rec.get("database_specific") or {}).get("severity")
    cvss_score = None
    for s in rec.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            cvss_score = base_score(s.get("score", ""))
            if cvss_score is not None:
                break
    if ds_sev and str(ds_sev).upper() in _QUAL_MAP:
        severity = _QUAL_MAP[str(ds_sev).upper()]
    else:
        severity = severity_from_score(cvss_score)

    packages = []
    ecos = set()
    for aff in rec.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        name = pkg.get("name")
        if not name:
            continue
        first_patched = None
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    first_patched = ev["fixed"]
        eco = pkg.get("ecosystem")
        if eco:
            ecos.add(eco)
        packages.append({
            "ecosystem": eco,
            "name": name,
            "vulnerable_version_range": None,
            "first_patched_version": first_patched,
        })

    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": rec.get("summary") or (rec.get("details") or "")[:120],
        "description": rec.get("details") or "",
        "severity": severity,
        "cvss_score": cvss_score,
        "cwes": cwes,
        "packages": packages,
        "ecosystems": sorted(ecos),
        "html_url": f"https://osv.dev/vulnerability/{osv_id}",
        "references": [r.get("url") for r in (rec.get("references") or []) if r.get("url")],
        "published_at": rec.get("published"),
        "updated_at": rec.get("modified"),
        "type": "osv",
        "source": "osv",
        "osv_id": osv_id,
        "aliases": aliases,
    }


# ---------------------------------------------------------------------------
# Load + filter
# ---------------------------------------------------------------------------

def _load_records(ghsa_ecosystem: str, force: bool = False) -> list[dict]:
    """Return all normalized OSV records for an ecosystem (memoised)."""
    if not force and ghsa_ecosystem in _MEM:
        return _MEM[ghsa_ecosystem]
    osv_eco = ECOSYSTEM_MAP.get(ghsa_ecosystem)
    if not osv_eco:
        raise OsvError(f"ecosystem '{ghsa_ecosystem}' not supported by OSV bulk mode")
    path = download_ecosystem(osv_eco, force=force)
    records: list[dict] = []
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                rec = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                logger.debug("skipping unparsable OSV record %s in %s", name, path)
                continue
            if rec.get("withdrawn"):
                continue
            records.append(normalize_osv(rec))
    _MEM[ghsa_ecosystem] = records
    return records


def fetch_osv(ecosystem: str, cwes: list[str], affects: str | None = None,
              severity: str | None = None, max_results: int = 200,
              force_refresh: bool = False) -> list[dict]:
    """Filter the ecosystem's OSV records by CWE set (+ optional package/severity).

    Records with none of the target CWEs are dropped. Sorted newest-first.
    """
    if ecosystem in (None, "", "any"):
        raise OsvError("OSV bulk mode needs a specific ecosystem (not 'any')")
    want = {normalize_cwe_id(c) for c in cwes}
    records = _load_records(ecosystem, force=force_refresh)

    out = []
    for r in records:
        rec_cwes = {normalize_cwe_id(c) for c in r.get("cwes") or []}
        if not (rec_cwes & want):
            continue
        if severity and severity != "any" and r.get("severity") != severity:
            continue
        if affects:
            names = [p.get("name", "") for p in r.get("packages") or []]
            if not any(affects.lower() == n.lower() or affects.lower() in n.lower()
                       for n in names):
                continue
        out.append(r)

    out.sort(key=lambda r: (r.get("published_at") or ""), reverse=True)
    return out[:max_results]


def fetch_osv_native(ecosystem: str, categories: list[str], max_results: int = 100,
                     force_refresh: bool = False) -> list[dict]:
    """Return source-native OSV records (GO-/RUSTSEC-/PYSEC-…) that CWE filtering
    can never reach, narrowed by bug-class keywords so the AI has a sane pool.

    These carry no CWE tag, so the caller is expected to run the AI classifier on
    them to decide which are genuinely BAC / injection / etc.
    """
    if ecosystem in (None, "", "any"):
        raise OsvError("OSV native mode needs a specific ecosystem (not 'any')")
    kws = category_keywords(categories)
    records = _load_records(ecosystem, force=force_refresh)

    out = []
    for r in records:
        if str(r.get("ghsa_id", "")).startswith("GHSA"):
            continue  # GHSA-sourced -> already covered by the CWE path
        if r.get("cwes"):
            continue  # CWE-tagged -> already reachable via the CWE filter
        if kws:
            text = (r.get("summary", "") + " " + r.get("description", "")).lower()
            if not any(k in text for k in kws):
                continue
        out.append(dict(r, native=True))

    out.sort(key=lambda r: (r.get("published_at") or ""), reverse=True)
    return out[:max_results]


def cache_status() -> list[dict]:
    """For the UI: which ecosystems are downloaded and how old."""
    status = []
    for ghsa_eco, osv_eco in ECOSYSTEM_MAP.items():
        p = _zip_path(osv_eco)
        if os.path.exists(p):
            status.append({
                "ecosystem": ghsa_eco,
                "size_mb": round(os.path.getsize(p) / 1e6, 1),
                "age_hours": round((time.time() - os.path.getmtime(p)) / 3600, 1),
            })
    return status
