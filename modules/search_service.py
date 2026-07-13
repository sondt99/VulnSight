"""Search orchestration: parse request → fetch sources → merge/dedupe → sort → enrich."""

from __future__ import annotations

from dataclasses import dataclass

from . import cache
from . import ghsa_client as ghsa
from . import nvd_client
from . import osv_client
from .cwe_categories import cwe_label, normalize_cwe_id, resolve_cwes

VALID_SORTS = ("published", "updated", "cve_id")
VALID_DIRECTIONS = ("asc", "desc")
_SORT_FIELD = {"published": "published_at", "updated": "updated_at", "cve_id": "cve_id"}


class SearchError(RuntimeError):
    """Search failure that maps to an HTTP response."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass
class SearchQuery:
    categories: list[str]
    include_extended: bool
    ecosystem: str
    affects: str | None
    severity: str
    published: str | None
    adv_type: str
    sort: str
    direction: str
    max_results: int
    sources: list[str]
    refresh_osv: bool
    cwes: list[str]


@dataclass
class SearchOutcome:
    results: list[dict]
    warnings: list[str]
    per_source: dict[str, int]


def parse_str_list(val) -> list[str]:
    """Accept a JSON list or a comma-separated string; return clean strings."""
    if isinstance(val, list):
        return [str(x) for x in val if str(x).strip()]
    if isinstance(val, str) and val.strip():
        return [x for x in (p.strip() for p in val.split(",")) if x]
    return []


def parse_search_query(body: dict) -> SearchQuery:
    """Validate a raw /api/search JSON body into a SearchQuery."""
    categories = parse_str_list(body.get("categories")) or ["bac"]
    include_extended = bool(body.get("include_extended", True))
    ecosystem = (body.get("ecosystem") or "any").strip()
    affects = (body.get("affects") or "").strip() or None
    severity = (body.get("severity") or "any").strip()
    published = (body.get("published") or "").strip() or None
    adv_type = (body.get("type") or "reviewed").strip()
    sort = (body.get("sort") or "published").strip()
    if sort not in VALID_SORTS:
        sort = "published"
    direction = (body.get("direction") or "desc").strip()
    if direction not in VALID_DIRECTIONS:
        direction = "desc"
    try:
        max_results = max(1, min(500, int(body.get("max_results", 100))))
    except (TypeError, ValueError):
        max_results = 100

    cwes = resolve_cwes(categories, include_extended)
    for c in parse_str_list(body.get("extra_cwes")):
        c = normalize_cwe_id(c)
        if c and c not in cwes:
            cwes.append(c)

    if not cwes:
        raise SearchError("No CWEs resolved from the selected categories.", 400)

    sources = parse_str_list(body.get("sources")) or ["ghsa"]
    refresh_osv = bool(body.get("refresh_osv", False))

    return SearchQuery(
        categories=categories,
        include_extended=include_extended,
        ecosystem=ecosystem,
        affects=affects,
        severity=severity,
        published=published,
        adv_type=adv_type,
        sort=sort,
        direction=direction,
        max_results=max_results,
        sources=sources,
        refresh_osv=refresh_osv,
        cwes=cwes,
    )


def merge_advisories(collected: list[dict]) -> list[dict]:
    """Dedupe across sources (key by CVE, else GHSA id, else OSV id).

    Unions the "sources" field and prefers the GHSA record as the base
    (richer metadata). Records keep first-seen order.
    """
    merged: dict[str, dict] = {}
    order: list[str] = []
    for rec in collected:
        key = ((rec.get("cve_id") or "").upper()
               or (rec.get("ghsa_id") or "").upper()
               or (rec.get("osv_id") or "").upper())
        if not key:
            key = rec.get("ghsa_id") or rec.get("osv_id") or str(len(order))
        src = rec.get("source", "?")
        if key in merged:
            ex = merged[key]
            srcs = set(ex.get("sources", [ex.get("source")]))
            srcs.add(src)
            # Prefer the GHSA record as the base (richer metadata).
            if ex.get("source") != "ghsa" and src == "ghsa":
                rec["sources"] = sorted(srcs)
                merged[key] = rec
            else:
                ex["sources"] = sorted(srcs)
        else:
            rec["sources"] = [src]
            merged[key] = rec
            order.append(key)
    return [merged[k] for k in order]


def run_search(q: SearchQuery) -> SearchOutcome:
    """Fetch from each requested source, then merge, sort, cache and enrich."""
    warnings: list[str] = []
    per_source: dict[str, int] = {}
    collected: list[dict] = []

    # --- GHSA (server-side CWE filter) ---
    if "ghsa" in q.sources:
        params = ghsa.SearchParams(
            ecosystem=q.ecosystem, cwes=q.cwes, affects=q.affects, severity=q.severity,
            type=q.adv_type, published=q.published, sort=q.sort, direction=q.direction,
            max_results=q.max_results, per_page=100,
        )
        try:
            raw = ghsa.fetch_advisories(params)
            g = [ghsa.normalize(a) for a in raw]
            collected += g
            per_source["ghsa"] = len(g)
        except ghsa.GhCliError as e:
            if q.sources == ["ghsa"]:
                raise SearchError(f"GHSA fetch failed: {e}", 502)
            warnings.append(f"GHSA fetch failed: {e}")

    # --- OSV (local CWE filter over the bulk export) ---
    if "osv" in q.sources:
        if not osv_client.supported_ecosystem(q.ecosystem):
            warnings.append(
                f"OSV bulk mode needs a specific supported ecosystem; "
                f"'{q.ecosystem}' skipped. Supported: {', '.join(osv_client.ECOSYSTEM_MAP)}."
            )
        else:
            try:
                o = osv_client.fetch_osv(q.ecosystem, q.cwes, affects=q.affects,
                                         severity=q.severity, max_results=q.max_results,
                                         force_refresh=q.refresh_osv)
                collected += o
                per_source["osv"] = len(o)
            except osv_client.OsvError as e:
                warnings.append(f"OSV fetch failed: {e}")

    # --- NVD (server-side CWE filter via NIST API v2) ---
    if "nvd" in q.sources:
        nvd_params = nvd_client.NvdSearchParams(
            cwes=q.cwes,
            keyword=q.affects,
            severity=q.severity,
            published_range=q.published,
            max_results=q.max_results,
        )
        try:
            n = nvd_client.fetch_nvd(nvd_params)
            collected += n
            per_source["nvd"] = len(n)
        except nvd_client.NvdError as e:
            if q.sources == ["nvd"]:
                raise SearchError(f"NVD fetch failed: {e}", 502)
            warnings.append(f"NVD fetch failed: {e}")

    # --- OSV native (no CWE) — needs the AI pass to be useful ---
    if "osv-native" in q.sources:
        if not osv_client.supported_ecosystem(q.ecosystem):
            warnings.append(
                f"OSV native mode needs a specific supported ecosystem; "
                f"'{q.ecosystem}' skipped."
            )
        else:
            try:
                on = osv_client.fetch_osv_native(q.ecosystem, q.categories,
                                                 max_results=q.max_results,
                                                 force_refresh=q.refresh_osv)
                collected += on
                per_source["osv-native"] = len(on)
                if on:
                    warnings.append(
                        f"{len(on)} OSV native records have no CWE — click "
                        f"'Refine with AI' to classify them."
                    )
            except osv_client.OsvError as e:
                warnings.append(f"OSV native fetch failed: {e}")

    results = merge_advisories(collected)

    # Sort by the requested field. (Fixes the old behaviour of always sorting
    # by published_at even when sort=updated or sort=cve_id was requested.)
    field = _SORT_FIELD[q.sort]
    results.sort(key=lambda r: (r.get(field) or ""), reverse=(q.direction != "asc"))
    results = results[:q.max_results]

    cache.upsert_advisories(results)

    # Attach CWE labels for the UI.
    for rec in results:
        rec["cwe_labels"] = [{"id": c, "label": cwe_label(c)} for c in rec.get("cwes", [])]

    # Merge any cached AI verdicts for the primary category.
    primary = q.categories[0]
    cached_ai = cache.get_classifications([rec["ghsa_id"] for rec in results], primary)
    for rec in results:
        if rec["ghsa_id"] in cached_ai:
            rec["ai"] = cached_ai[rec["ghsa_id"]]

    return SearchOutcome(results=results, warnings=warnings, per_source=per_source)
