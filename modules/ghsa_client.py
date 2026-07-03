"""GitHub Security Advisory (GHSA) client.

Fetches advisories from the global GitHub Advisory Database via the
authenticated `gh` CLI (`gh api /advisories`). Using `gh` means we reuse the
user's existing credentials and rate limits without handling tokens ourselves.

Docs: https://docs.github.com/rest/security-advisories/global-advisories

Supported server-side filters we use:
  ecosystem, cwes (comma list), affects (package), severity, type,
  published/updated (date ranges), sort, direction.

Pagination is cursor based via the `Link` response header; we follow `rel=next`
until we hit `max_results` so the caller can bound cost.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from .cwe_categories import normalize_cwe_id


class GhCliError(RuntimeError):
    """Raised when the gh CLI is missing, unauthenticated, or errors out."""


_LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


def gh_available() -> bool:
    return shutil.which("gh") is not None


def gh_auth_ok() -> bool:
    if not gh_available():
        return False
    try:
        r = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return r.returncode == 0
    except Exception:
        return False


@dataclass
class SearchParams:
    ecosystem: str | None = None
    cwes: list[str] = field(default_factory=list)      # bare numeric ids
    affects: str | None = None                         # package name
    severity: str | None = None                        # low|medium|high|critical
    type: str = "reviewed"                             # reviewed|unreviewed|malware
    published: str | None = None                       # e.g. ">=2024-01-01"
    updated: str | None = None
    sort: str = "published"                            # published|updated|cve_id
    direction: str = "desc"
    per_page: int = 100                                # GHSA max is 100
    max_results: int = 200                             # hard cap for our fetch

    def to_query(self) -> dict[str, str]:
        """Build the querystring pieces (excluding pagination cursor)."""
        q: dict[str, str] = {
            "type": self.type,
            "sort": self.sort,
            "direction": self.direction,
            "per_page": str(min(self.per_page, 100)),
        }
        if self.ecosystem and self.ecosystem != "any":
            q["ecosystem"] = self.ecosystem
        if self.cwes:
            # API accepts comma separated; normalise to bare numeric.
            q["cwes"] = ",".join(normalize_cwe_id(c) for c in self.cwes)
        if self.affects:
            q["affects"] = self.affects
        if self.severity and self.severity != "any":
            q["severity"] = self.severity
        if self.published:
            q["published"] = self.published
        if self.updated:
            q["updated"] = self.updated
        return q


def _run_gh_api(path_with_query: str, timeout: int = 60) -> tuple[list | dict, str | None]:
    """Call `gh api -i <path>` and return (json_body, next_url).

    json_body is a list for /advisories, a dict for /advisories/{id}, or []
    on an empty body. `-i` includes response headers so we can read the Link
    header for the pagination cursor.
    """
    cmd = ["gh", "api", "-i", "-X", "GET", path_with_query,
           "-H", "Accept: application/vnd.github+json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise GhCliError("gh CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise GhCliError(f"gh api timed out after {timeout}s") from e

    if proc.returncode != 0:
        raise GhCliError(
            f"gh api failed (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )

    raw = proc.stdout
    # Split headers from body: headers end at the first blank line, which may
    # be \n\n or \r\n\r\n depending on how gh emits the response.
    parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    header_blob = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    next_url = None
    for line in header_blob.splitlines():
        if line.lower().startswith("link:"):
            m = _LINK_NEXT_RE.search(line)
            if m:
                next_url = m.group(1)
            break

    body = body.strip()
    if not body:
        return [], next_url
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        raise GhCliError(f"could not parse gh api response: {e}") from e

    if isinstance(data, dict) and "message" in data and "documentation_url" in data:
        raise GhCliError(f"GitHub API error: {data['message']}")
    # data is a list for /advisories, a dict for /advisories/{id}; callers decide.
    return data, next_url


def fetch_advisories(params: SearchParams) -> list[dict]:
    """Fetch advisories following pagination up to params.max_results."""
    q = params.to_query()
    path = "/advisories?" + urlencode(q)

    results: list[dict] = []
    guard = 0
    while path and len(results) < params.max_results:
        guard += 1
        if guard > 50:  # safety: never loop forever
            break
        batch, next_url = _run_gh_api(path)
        if not isinstance(batch, list):
            raise GhCliError("unexpected GHSA response shape (expected a list)")
        results.extend(batch)
        if not next_url:
            break
        # next_url is a full https URL; gh api accepts a full URL too, but we
        # strip to the path+query for consistency.
        path = _strip_to_path(next_url)

    return results[: params.max_results]


def _strip_to_path(url: str) -> str:
    parts = urlsplit(url)
    if parts.query:
        return f"{parts.path}?{parts.query}"
    return parts.path


# ---------------------------------------------------------------------------
# Normalisation: turn a raw GHSA record into a compact, UI-friendly dict.
# ---------------------------------------------------------------------------

def normalize(adv: dict) -> dict:
    cwes = [c.get("cwe_id") for c in adv.get("cwes") or [] if c.get("cwe_id")]
    packages = []
    for v in adv.get("vulnerabilities") or []:
        pkg = (v or {}).get("package") or {}
        name = pkg.get("name")
        if not name:
            continue
        packages.append({
            "ecosystem": pkg.get("ecosystem"),
            "name": name,
            "vulnerable_version_range": v.get("vulnerable_version_range"),
            "first_patched_version": v.get("first_patched_version"),
        })
    return {
        "ghsa_id": adv.get("ghsa_id"),
        "cve_id": adv.get("cve_id"),
        "summary": adv.get("summary") or "",
        "description": adv.get("description") or "",
        "severity": (adv.get("severity") or "unknown").lower(),
        "cvss_score": ((adv.get("cvss") or {}).get("score")),
        "cwes": cwes,
        "packages": packages,
        "ecosystems": sorted({p["ecosystem"] for p in packages if p.get("ecosystem")}),
        "html_url": adv.get("html_url"),
        "references": [r for r in (adv.get("references") or []) if isinstance(r, str)],
        "published_at": adv.get("published_at"),
        "updated_at": adv.get("updated_at"),
        "type": adv.get("type"),
        "source": "ghsa",
        "aliases": [i.get("value") for i in (adv.get("identifiers") or []) if i.get("value")],
    }
