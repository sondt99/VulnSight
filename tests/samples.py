"""Shared offline fixtures + helpers for the test suite.

Pure stdlib, no prod imports and no sys.path bootstrap here: each test file
sets up sys.path itself (so every file also runs standalone) and then does
`from samples import ...`.
"""

import io
import json
import zipfile

# --- sample raw advisory as returned by GHSA -------------------------------
SAMPLE = {
    "ghsa_id": "GHSA-h3m5-97jq-qjrf",
    "cve_id": "CVE-2026-57168",
    "summary": "OpenRemote Manager cross-realm IDOR",
    "description": "removeAlarms lets a user delete alarms in other realms.",
    "severity": "high",
    "html_url": "https://github.com/advisories/GHSA-h3m5-97jq-qjrf",
    "published_at": "2026-06-25T17:07:58Z",
    "updated_at": "2026-06-26T00:00:00Z",
    "type": "reviewed",
    "cvss": {"score": 7.5},
    "cwes": [{"cwe_id": "CWE-639", "name": "Authorization Bypass"}],
    "references": ["https://example.com/a", {"bad": "obj"}],
    "vulnerabilities": [
        {
            "package": {"ecosystem": "maven", "name": "org.openremote:manager"},
            "vulnerable_version_range": "< 1.2.3",
            "first_patched_version": "1.2.3",
        },
        {"package": {}},  # malformed -> skipped
    ],
}

# --- sample raw OSV records --------------------------------------------------
OSV_GHSA = {
    "id": "GHSA-xr65-5cpm-g36x",
    "summary": "Rancher Fleet cross-namespace secret access",
    "details": "A crafted GitRepo reaches secrets in other namespaces.",
    "aliases": ["CVE-2026-11122"],
    "published": "2026-06-20T00:00:00Z", "modified": "2026-06-21T00:00:00Z",
    "database_specific": {"cwe_ids": ["CWE-863"], "severity": "CRITICAL"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{"package": {"ecosystem": "Go", "name": "github.com/rancher/fleet"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.9.5"}]}]}],
    "references": [{"type": "WEB", "url": "http://example.com/x"}],
}
OSV_NATIVE = {  # source-native (Go DB), no CWE tag
    "id": "GO-2023-1737",
    "summary": "gin improper input", "details": "d", "aliases": ["CVE-2023-29401"],
    "published": "2023-05-01T00:00:00Z", "modified": "2023-05-02T00:00:00Z",
    "database_specific": {},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"}],
    "affected": [{"package": {"ecosystem": "Go", "name": "github.com/gin-gonic/gin"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.9.1"}]}]}],
}


def make_osv_zip(records):
    """Build an in-memory OSV bulk `all.zip` (one `<id>.json` per record) -> bytes.

    Replaces the removed osv_client.bytes_to_records helper: tests unzip these
    bytes themselves and feed each JSON through osv_client.normalize_osv.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for idx, rec in enumerate(records):
            name = "{}.json".format(rec.get("id") or f"record-{idx}")
            zf.writestr(name, json.dumps(rec))
    return buf.getvalue()


# --- sortable GHSA raw records for the /api/search sort-fix regression ------
# The three orderings all differ so a wrong sort field is always detectable:
#   published desc : A, C, B          updated desc : B, C, A
#   cve_id    desc : B, A, C          (asc = each reversed)
SORT_A = "GHSA-aaaa-aaaa-aaaa"
SORT_B = "GHSA-bbbb-bbbb-bbbb"
SORT_C = "GHSA-cccc-cccc-cccc"


def make_sortable_raw():
    """Three fresh raw GHSA records with interleaved published/updated/cve_id."""
    def _rec(gid, cve, pub, upd):
        return dict(SAMPLE, ghsa_id=gid, cve_id=cve, published_at=pub, updated_at=upd)

    return [
        _rec(SORT_A, "CVE-2026-0002", "2026-01-03T00:00:00Z", "2026-02-01T00:00:00Z"),
        _rec(SORT_B, "CVE-2026-0003", "2026-01-01T00:00:00Z", "2026-02-03T00:00:00Z"),
        _rec(SORT_C, "CVE-2026-0001", "2026-01-02T00:00:00Z", "2026-02-02T00:00:00Z"),
    ]
