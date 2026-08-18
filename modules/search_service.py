"""Search orchestration: parse request → fetch sources → merge/dedupe → sort → enrich."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass

from . import ai_classifier
from . import cache
from . import epss_client
from . import ghsa_client as ghsa
from . import nvd_client
from . import osv_client
from .cwe_categories import CATEGORIES, ECOSYSTEMS, SEVERITIES, cwe_label, normalize_cwe_id, resolve_cwes
from .query_filters import matches_common_filters, valid_published_filter

VALID_SORTS = ("published", "updated", "cve_id", "epss_percentage", "epss_percentile")
VALID_DIRECTIONS = ("asc", "desc")
VALID_SOURCES = ("ghsa", "nvd", "osv", "osv-native")
VALID_TYPES = ("reviewed", "unreviewed", "malware")
_SORT_FIELD = {
    "published": "published_at",
    "updated": "updated_at",
    "cve_id": "cve_id",
    "epss_percentage": "epss_percentage",
    "epss_percentile": "epss_percentile",
}
MAX_CATEGORY_INPUTS = 100
MAX_EXTRA_CWES = 100
MAX_CWE_ID_DIGITS = 7
_EXTRA_CWE_RE = re.compile(rf"(?:CWE-)?([0-9]{{1,{MAX_CWE_ID_DIGITS}}})", re.IGNORECASE)


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


def parse_str_list(
    val,
    *,
    field_name: str = "values",
    max_items: int = 100,
    max_item_length: int = 300,
) -> list[str]:
    """Accept a bounded JSON string list or comma-separated string."""
    if val is None or val == "":
        return []
    if isinstance(val, list):
        if len(val) > max_items:
            raise SearchError(
                f"Too many {field_name}; maximum is {max_items}.", 400
            )
        raw_values = val
    elif isinstance(val, str):
        if len(val) > max_items * (max_item_length + 1):
            raise SearchError(f"{field_name} is too long.", 400)
        raw_values = val.split(",")
    else:
        raise SearchError(f"{field_name} must be a list or comma-separated string.", 400)

    out: list[str] = []
    for item in raw_values:
        if not isinstance(item, str):
            raise SearchError(f"{field_name} entries must be strings.", 400)
        text = item.strip()
        if not text:
            continue
        if len(text) > max_item_length:
            raise SearchError(
                f"{field_name} entries may not exceed {max_item_length} characters.",
                400,
            )
        out.append(text)
        if len(out) > max_items:
            raise SearchError(
                f"Too many {field_name}; maximum is {max_items}.", 400
            )
    return out


def parse_bool(value, default: bool = False) -> bool:
    """Parse JSON booleans without treating the string "false" as truthy."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "1", "yes"):
            return True
        if normalized in ("false", "0", "no"):
            return False
    raise SearchError(f"Invalid boolean value: {value!r}", 400)


def parse_text(value, default: str, field_name: str) -> str:
    if value is None or value == "":
        return default
    if not isinstance(value, str):
        raise SearchError(f"{field_name} must be a string.", 400)
    return value.strip() or default


def _parse_extra_cwes(value) -> list[str]:
    """Parse a bounded list of canonical positive CWE identifiers."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        raw_values = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, list):
        if len(value) > MAX_EXTRA_CWES:
            raise SearchError(
                f"Too many extra CWEs; maximum is {MAX_EXTRA_CWES}.", 400
            )
        raw_values = []
        for item in value:
            if isinstance(item, bool) or not isinstance(item, (str, int)):
                raise SearchError("extra_cwes entries must be strings or integers.", 400)
            text = str(item).strip()
            if text:
                raw_values.append(text)
    else:
        raise SearchError("extra_cwes must be a list or comma-separated string.", 400)

    if len(raw_values) > MAX_EXTRA_CWES:
        raise SearchError(
            f"Too many extra CWEs; maximum is {MAX_EXTRA_CWES}.", 400
        )

    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        match = _EXTRA_CWE_RE.fullmatch(raw)
        if not match or int(match.group(1)) == 0:
            display = raw if len(raw) <= 32 else raw[:29] + "..."
            raise SearchError(f"Invalid CWE identifier: {display}", 400)
        cwe = str(int(match.group(1)))
        if cwe not in seen:
            seen.add(cwe)
            out.append(cwe)
    return out


def parse_search_query(body: dict) -> SearchQuery:
    """Validate a raw /api/search JSON body into a SearchQuery."""
    category_inputs = parse_str_list(
        body.get("categories"),
        field_name="categories",
        max_items=MAX_CATEGORY_INPUTS,
        max_item_length=64,
    )
    if not category_inputs:
        raise SearchError("Select at least one vulnerability category.", 400)
    categories = list(dict.fromkeys(category_inputs))
    include_extended = parse_bool(body.get("include_extended"), True)
    ecosystem = parse_text(body.get("ecosystem"), "any", "ecosystem")
    affects = parse_text(body.get("affects"), "", "affects") or None
    severity = parse_text(body.get("severity"), "any", "severity")
    published = parse_text(body.get("published"), "", "published") or None
    adv_type = parse_text(body.get("type"), "reviewed", "type")
    sort = parse_text(body.get("sort"), "published", "sort")
    if sort not in VALID_SORTS:
        sort = "published"
    direction = parse_text(body.get("direction"), "desc", "direction")
    if direction not in VALID_DIRECTIONS:
        direction = "desc"
    try:
        max_results = max(1, min(500, int(body.get("max_results", 100))))
    except (TypeError, ValueError):
        max_results = 100

    unknown_categories = [category for category in categories if category not in CATEGORIES]
    if unknown_categories:
        raise SearchError(f"Unsupported categories: {', '.join(unknown_categories)}", 400)

    cwes = resolve_cwes(categories, include_extended)
    seen_cwes = set(cwes)
    for cwe in _parse_extra_cwes(body.get("extra_cwes")):
        if cwe not in seen_cwes:
            seen_cwes.add(cwe)
            cwes.append(cwe)

    if not cwes:
        raise SearchError("No CWEs resolved from the selected categories.", 400)

    if ecosystem not in ("any", *ECOSYSTEMS):
        raise SearchError(f"Unsupported ecosystem: {ecosystem}", 400)
    if severity not in ("any", *SEVERITIES):
        raise SearchError(f"Unsupported severity: {severity}", 400)
    if adv_type not in VALID_TYPES:
        raise SearchError(f"Unsupported advisory type: {adv_type}", 400)
    if not valid_published_filter(published):
        raise SearchError(f"Invalid published filter: {published}", 400)
    if affects and len(affects) > 300:
        raise SearchError("affects is too long (maximum 300 characters).", 400)

    sources = parse_str_list(
        body.get("sources"),
        field_name="sources",
        max_items=len(VALID_SOURCES),
        max_item_length=32,
    ) or ["ghsa"]
    sources = list(dict.fromkeys(sources))
    invalid_sources = [source for source in sources if source not in VALID_SOURCES]
    if invalid_sources:
        raise SearchError(f"Unsupported data source(s): {', '.join(invalid_sources)}", 400)
    refresh_osv = parse_bool(body.get("refresh_osv"), False)

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


_SOURCE_PRIORITY = {"ghsa": 0, "osv": 1, "nvd": 2}
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _record_identifier_values(record: dict) -> list[str]:
    values = [record.get("advisory_id"), record.get("cve_id"), record.get("ghsa_id"), record.get("osv_id")]
    values.extend(record.get("aliases") or [])
    return [str(value).strip() for value in values if str(value or "").strip()]


def _record_identifiers(record: dict) -> set[str]:
    return {value.upper() for value in _record_identifier_values(record)}


def _unique_dicts(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen:
            seen.add(key)
            out.append(copy.deepcopy(item))
    return out


def _merge_group(records: list[dict]) -> dict:
    base = min(records, key=lambda item: _SOURCE_PRIORITY.get(item.get("source"), 99))
    merged = copy.deepcopy(base)
    sources = sorted({record.get("source", "?") for record in records})
    merged["sources"] = sources

    source_records: dict[str, list[dict]] = {}
    for record in records:
        source = record.get("source", "?")
        snapshot = {
            key: copy.deepcopy(value)
            for key, value in record.items()
            if key not in ("source_records", "cwe_labels", "ai")
        }
        source_records.setdefault(source, []).append(snapshot)
    merged["source_records"] = source_records

    identifiers = set().union(*(_record_identifiers(record) for record in records))
    merged["aliases"] = sorted(identifiers)
    identifier_values = [
        identifier
        for record in records
        for identifier in _record_identifier_values(record)
    ]
    ghsa_ids = sorted(
        (identifier for identifier in identifier_values if identifier.upper().startswith("GHSA-")),
        key=str.upper,
    )
    cve_ids = sorted(
        (identifier for identifier in identifier_values if identifier.upper().startswith("CVE-")),
        key=str.upper,
    )
    if ghsa_ids:
        base_id = str(base.get("ghsa_id") or "")
        merged["ghsa_id"] = base_id if base_id.upper().startswith("GHSA-") else ghsa_ids[0]
    elif cve_ids:
        merged["ghsa_id"] = cve_ids[0]
    # advisory_id: prefer the base record's advisory_id; fall back to best
    # GHSA or CVE identifier so the merged record always has a stable key.
    if not merged.get("advisory_id"):
        merged["advisory_id"] = merged.get("ghsa_id") or (cve_ids[0] if cve_ids else "")
    if cve_ids:
        base_cve = str(base.get("cve_id") or "")
        merged["cve_id"] = base_cve if base_cve.upper().startswith("CVE-") else cve_ids[0]

    cwes: dict[str, str] = {}
    for record in records:
        for cwe in record.get("cwes") or []:
            normalized = normalize_cwe_id(str(cwe))
            if normalized:
                cwes.setdefault(normalized, normalized)
    merged["cwes"] = list(cwes.values())

    merged["references"] = list(dict.fromkeys(
        reference
        for record in records
        for reference in (record.get("references") or [])
        if reference
    ))
    merged["packages"] = _unique_dicts([
        package
        for record in records
        for package in (record.get("packages") or [])
        if isinstance(package, dict)
    ])
    merged["ecosystems"] = sorted({
        ecosystem
        for record in records
        for ecosystem in (record.get("ecosystems") or [])
        if ecosystem
    })

    severity_by_source = {
        record.get("source", "?"): record.get("severity", "unknown")
        for record in records
    }
    cvss_by_source = {
        record.get("source", "?"): record.get("cvss_score")
        for record in records
        if record.get("cvss_score") is not None
    }
    merged["severity_by_source"] = severity_by_source
    merged["cvss_by_source"] = cvss_by_source
    merged["severity"] = max(
        severity_by_source.values(), key=lambda value: _SEVERITY_RANK.get(value, 0)
    )
    if cvss_by_source:
        merged["cvss_score"] = max(cvss_by_source.values())

    published = [record.get("published_at") for record in records if record.get("published_at")]
    updated = [record.get("updated_at") for record in records if record.get("updated_at")]
    withdrawn = [record.get("withdrawn_at") for record in records if record.get("withdrawn_at")]
    merged["published_at"] = min(published) if published else None
    merged["updated_at"] = max(updated) if updated else None
    merged["withdrawn_at"] = max(withdrawn) if withdrawn else None
    merged["kev"] = any(bool(record.get("kev")) for record in records)
    merged["native"] = any(bool(record.get("native")) for record in records)
    for field in ("nvd_status", "osv_id"):
        value = next((record.get(field) for record in records if record.get(field)), None)
        if value is not None:
            merged[field] = value
    return merged


def merge_advisories(collected: list[dict]) -> list[dict]:
    """Dedupe by the full alias graph and preserve source-specific metadata."""
    if not collected:
        return []

    parents = list(range(len(collected)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    owner: dict[str, int] = {}
    for index, record in enumerate(collected):
        for identifier in _record_identifiers(record):
            if identifier in owner:
                union(index, owner[identifier])
            else:
                owner[identifier] = index

    groups: dict[int, list[dict]] = {}
    order: list[int] = []
    for index, record in enumerate(collected):
        root = find(index)
        if root not in groups:
            groups[root] = []
            order.append(root)
        groups[root].append(record)
    return [_merge_group(groups[root]) for root in order]


def run_search(q: SearchQuery) -> SearchOutcome:
    """Fetch from each requested source, then merge, sort, cache and enrich."""
    warnings: list[str] = []
    per_source: dict[str, int] = {}
    collected: list[dict] = []

    # --- GHSA (server-side CWE filter) ---
    if "ghsa" in q.sources:
        ghsa_sort = q.sort if q.sort in ("published", "updated") else "published"
        params = ghsa.SearchParams(
            ecosystem=q.ecosystem, cwes=q.cwes, affects=q.affects, severity=q.severity,
            type=q.adv_type, published=q.published, sort=ghsa_sort, direction=q.direction,
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
                                         force_refresh=q.refresh_osv,
                                         published=q.published)
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
                                                 force_refresh=q.refresh_osv,
                                                 affects=q.affects,
                                                 severity=q.severity,
                                                 published=q.published)
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
    results = [
        record for record in results
        if matches_common_filters(
            record,
            published=q.published,
            affects=q.affects,
            severity=q.severity,
        )
    ]

    # Enrich with EPSS scores before sorting so epss_percentage / epss_percentile
    # sort modes work correctly.
    cve_ids = [r["cve_id"] for r in results if r.get("cve_id")]
    if cve_ids:
        epss_scores = epss_client.fetch_epss(cve_ids)
        for rec in results:
            score = epss_scores.get(rec.get("cve_id", ""))
            if score:
                rec["epss_percentage"] = score["epss"]
                rec["epss_percentile"] = score["percentile"]

    # Sort by the requested field. (Fixes the old behaviour of always sorting
    # by published_at even when sort=updated or sort=cve_id was requested.)
    field = _SORT_FIELD[q.sort]
    results.sort(key=lambda r: (r.get(field) or ""), reverse=(q.direction != "asc"))
    results = results[:q.max_results]

    cache.upsert_advisories(results)

    # Attach CWE labels for the UI.
    for rec in results:
        rec["cwe_labels"] = [{"id": c, "label": cwe_label(c)} for c in rec.get("cwes", [])]

    # Attach cached AI only when every requested category has a fresh verdict.
    # Partial cache hits are completed by /api/ai/classify, never presented as a
    # finished multi-category decision.
    cfg = ai_classifier.load_config()
    ai_categories = [category for category in q.categories if category in CATEGORIES]
    if cfg.configured and ai_categories:
        cached_by_category: dict[str, dict[str, dict]] = {}
        for category in ai_categories:
            fingerprints = {
                rec["advisory_id"]: ai_classifier.classification_fingerprint(
                    cfg, rec, category
                )
                for rec in results
            }
            cached_by_category[category] = cache.get_classifications(
                list(fingerprints),
                category,
                expected_fingerprints=fingerprints,
            )
        for rec in results:
            aid = rec["advisory_id"]
            category_verdicts = {
                category: cached_by_category[category][aid]
                for category in ai_categories
                if aid in cached_by_category[category]
            }
            if len(category_verdicts) == len(ai_categories):
                rec["ai"] = ai_classifier.aggregate_category_verdicts(
                    category_verdicts
                )

    return SearchOutcome(results=results, warnings=warnings, per_source=per_source)
