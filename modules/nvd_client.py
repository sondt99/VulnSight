"""NIST National Vulnerability Database (NVD) API v2 client.

Fetches CVEs from the NVD REST API filtered by CWE, severity, date range,
and keyword. The NVD API only accepts ONE cweId per request, so we iterate
over the requested CWEs, deduplicate, and normalize to the shared advisory
shape used by ghsa_client / osv_client.

Docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  - Without API key: 5 requests per 30-second window  (~6s between calls)
  - With API key:   50 requests per 30-second window  (~0.6s between calls)

Set NVD_API_KEY in .env for faster queries (free, get one at
https://nvd.nist.gov/developers/request-an-api-key).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .cwe_categories import normalize_cwe_id

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "vulnsight/1.0 (+nvd)"


class NvdError(RuntimeError):
    """Raised on NVD API failures."""


_SEVERITY_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def _api_key() -> str | None:
    return os.environ.get("NVD_API_KEY", "").strip() or None


def _request_delay() -> float:
    return 0.7 if _api_key() else 6.5


@dataclass
class NvdSearchParams:
    cwes: list[str] = field(default_factory=list)
    keyword: str | None = None
    severity: str | None = None
    published_range: str | None = None
    max_results: int = 200
    results_per_page: int = 200


def _build_date_params(published: str | None) -> dict[str, str]:
    """Convert a GHSA-style published filter (e.g. '>=2024-01-01') to NVD
    pubStartDate/pubEndDate params. NVD limits date ranges to 120 days, so
    for ranges longer than that we just set the start date."""
    if not published:
        return {}
    raw = published.lstrip(">= ")
    try:
        start = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return {}
    end = datetime.now(tz=timezone.utc)
    if (end - start) > timedelta(days=120):
        start = end - timedelta(days=120)
    return {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
    }


def _fetch_page(params: dict[str, str], timeout: int = 60) -> dict:
    """Make a single NVD API GET request and return parsed JSON."""
    qs = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                  for k, v in params.items())
    url = f"{NVD_BASE}?{qs}"

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    key = _api_key()
    if key:
        headers["apiKey"] = key

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise NvdError("NVD rate limit hit (HTTP 403). Try again in 30s or set NVD_API_KEY.") from e
        raise NvdError(f"NVD API HTTP {e.code}: {e.reason}") from e
    except Exception as e:
        raise NvdError(f"NVD API request failed: {e}") from e

    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise NvdError(f"Could not parse NVD response: {e}") from e


def _fetch_cves_for_cwe(cwe: str, params: NvdSearchParams) -> list[dict]:
    """Fetch all CVEs matching a single CWE, paginating as needed."""
    base_q: dict[str, str] = {
        "cweId": f"CWE-{normalize_cwe_id(cwe)}",
        "resultsPerPage": str(min(params.results_per_page, 2000)),
        "noRejected": "",
    }
    if params.severity and params.severity != "any":
        nvd_sev = params.severity.upper()
        if nvd_sev in _SEVERITY_MAP.values():
            nvd_sev = {v: k for k, v in _SEVERITY_MAP.items()}[nvd_sev]
        base_q["cvssV3Severity"] = nvd_sev

    if params.keyword:
        base_q["keywordSearch"] = params.keyword

    base_q.update(_build_date_params(params.published_range))

    results: list[dict] = []
    start_index = 0
    delay = _request_delay()

    while len(results) < params.max_results:
        q = dict(base_q, startIndex=str(start_index))
        body = _fetch_page(q)

        vulns = body.get("vulnerabilities") or []
        if not vulns:
            break

        results.extend(vulns)
        total = body.get("totalResults", 0)
        start_index += len(vulns)

        if start_index >= total or start_index >= params.max_results:
            break
        time.sleep(delay)

    return results[:params.max_results]


def fetch_nvd(params: NvdSearchParams) -> list[dict]:
    """Fetch CVEs for all requested CWEs, deduplicate, and normalize."""
    if not params.cwes:
        return []

    seen_ids: set[str] = set()
    raw_all: list[dict] = []
    delay = _request_delay()

    for i, cwe in enumerate(params.cwes):
        if len(raw_all) >= params.max_results:
            break
        if i > 0:
            time.sleep(delay)

        remaining = params.max_results - len(raw_all)
        per_cwe = NvdSearchParams(
            cwes=[cwe],
            keyword=params.keyword,
            severity=params.severity,
            published_range=params.published_range,
            max_results=remaining,
            results_per_page=min(remaining, 200),
        )
        try:
            batch = _fetch_cves_for_cwe(cwe, per_cwe)
        except NvdError as e:
            logger.warning("NVD fetch for CWE-%s failed: %s", cwe, e)
            continue

        for vuln in batch:
            cve_id = (vuln.get("cve") or {}).get("id", "")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                raw_all.append(vuln)

    return [normalize(v) for v in raw_all[:params.max_results]]


# ---------------------------------------------------------------------------
# Normalization: NVD CVE -> shared advisory dict
# ---------------------------------------------------------------------------

def _extract_cwes(cve: dict) -> list[str]:
    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = d.get("value", "")
            if val.startswith("CWE-") and val not in ("CWE-noinfo", "CWE-Other"):
                bare = normalize_cwe_id(val)
                if bare not in cwes:
                    cwes.append(bare)
    return cwes


def _extract_cvss(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        for entry in metrics.get(key) or []:
            cvss_data = entry.get("cvssData") or {}
            score = cvss_data.get("baseScore")
            sev = (cvss_data.get("baseSeverity") or "").upper()
            if score is not None:
                return float(score), _SEVERITY_MAP.get(sev, "unknown")
    for entry in metrics.get("cvssMetricV2") or []:
        cvss_data = entry.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        sev = (entry.get("baseSeverity") or "").upper()
        if score is not None:
            return float(score), _SEVERITY_MAP.get(sev, "unknown")
    return None, "unknown"


def _extract_packages(cve: dict) -> list[dict]:
    packages: list[dict] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3] if len(parts) > 3 else ""
                    product = parts[4] if len(parts) > 4 else ""
                    version_end = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                    packages.append({
                        "ecosystem": "nvd",
                        "name": f"{vendor}:{product}" if vendor else product,
                        "vulnerable_version_range": f"< {version_end}" if version_end else None,
                        "first_patched_version": version_end,
                    })
    return packages


def _extract_description(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    descs = cve.get("descriptions") or []
    return descs[0].get("value", "") if descs else ""


def normalize(vuln: dict) -> dict:
    cve = vuln.get("cve") or {}
    cve_id = cve.get("id", "")
    desc = _extract_description(cve)
    cwes = _extract_cwes(cve)
    cvss_score, severity = _extract_cvss(cve)
    packages = _extract_packages(cve)
    refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]

    kev_date = cve.get("cisaExploitAdd")
    aliases = [cve_id] if cve_id else []

    return {
        "ghsa_id": cve_id,
        "cve_id": cve_id,
        "summary": (desc[:120] + "…") if len(desc) > 120 else desc,
        "description": desc,
        "severity": severity,
        "cvss_score": cvss_score,
        "cwes": cwes,
        "packages": packages,
        "ecosystems": sorted({p["ecosystem"] for p in packages if p.get("ecosystem")}),
        "html_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        "references": refs,
        "published_at": cve.get("published", ""),
        "updated_at": cve.get("lastModified", ""),
        "type": "nvd",
        "source": "nvd",
        "aliases": aliases,
        "nvd_status": cve.get("vulnStatus", ""),
        "kev": bool(kev_date),
    }
