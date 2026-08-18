"""FIRST EPSS (Exploit Prediction Scoring System) client.

Fetches EPSS scores from the FIRST API to augment vulnerability results with
exploit-likelihood data.  No authentication required.

Endpoint: https://api.first.org/data/v1/epss
Docs:     https://www.first.org/epss/api

Rate limits:
  - Max 100 CVEs per request (batch query)
  - No published per-minute cap, but be courteous

Uses stdlib ``urllib`` only (consistent with the rest of the codebase).
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

EPSS_BASE = "https://api.first.org/data/v1/epss"
USER_AGENT = "vulnsight/1.0 (+epss)"
BATCH_SIZE = 100  # API-imposed maximum CVEs per request


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for a list of CVE IDs.

    Returns ``{cve_id: {"epss": float, "percentile": float}}`` for every CVE
    the API returned data for.  CVEs without EPSS data are silently omitted.

    On network or parsing errors the function logs a warning and returns an
    empty dict -- callers should never crash because EPSS enrichment failed.
    """
    if not cve_ids:
        return {}

    # Deduplicate while preserving a deterministic order for testing.
    unique: list[str] = list(dict.fromkeys(cve_ids))

    results: dict[str, dict] = {}
    for batch in _batches(unique, BATCH_SIZE):
        try:
            batch_results = _fetch_batch(batch)
            results.update(batch_results)
        except Exception:
            logger.warning("EPSS batch request failed for %d CVEs", len(batch), exc_info=True)

    return results


def _batches(items: list[str], size: int):
    """Yield successive chunks of *size* from *items*."""
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _fetch_batch(cve_ids: list[str], timeout: int = 30) -> dict[str, dict]:
    """Query the FIRST EPSS API for up to 100 CVEs and return parsed scores."""
    params = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    url = f"{EPSS_BASE}?{params}"

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except urllib.error.HTTPError as exc:
        logger.warning("EPSS API HTTP %d: %s", exc.code, exc.reason)
        return {}
    except Exception as exc:
        logger.warning("EPSS API request failed: %s", exc)
        return {}

    try:
        body = json.loads(data)
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse EPSS response: %s", exc)
        return {}

    results: dict[str, dict] = {}
    for entry in body.get("data") or []:
        cve = entry.get("cve")
        if not cve:
            continue
        try:
            results[cve] = {
                "epss": float(entry["epss"]),
                "percentile": float(entry["percentile"]),
            }
        except (KeyError, TypeError, ValueError):
            continue

    return results
