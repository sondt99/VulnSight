# HTTP API

The UI is a client of this API and uses nothing private. Everything below works
from `curl` or a script.

## Conventions

- `POST` bodies must be a **JSON object** with `Content-Type: application/json`.
  Anything else is `415` / `400` — this is deliberate, since it blocks
  cross-origin `text/plain` form posts.
- Errors are always `{"error": "<operator-facing message>"}`. Exception strings
  and tracebacks are never returned.
- `POST` is subject to a same-origin check and to
  [rate limiting](configuration.md#rate-limiting).
- If `VULNSIGHT_API_TOKEN` is set, every mutating `/api/*` call needs
  `X-VulnSight-Token: <token>` (or `Authorization: Bearer <token>`). `GET`
  endpoints are unauthenticated — they expose only public reference data.

---

## `GET /`

The application shell. Server data is injected into `window.BOOT`: popular
packages, the curated classes (key, code, group, label, description, core,
extended, terms), OSV-supported ecosystems, whether AI is configured, the AI call
budget, and whether auth is required.

## `GET /api/meta`

Reference data for the curated taxonomy.

```json
{
  "categories": {
    "bac": {"code": "BAC", "label": "…", "description": "…",
            "core": ["284", "285", "…"], "extended": ["269", "…"]}
  },
  "ecosystems": ["maven", "go", "npm", "…"],
  "severities": ["low", "medium", "high", "critical"],
  "gh_ok": true,
  "ai_configured": true
}
```

## `GET /api/cwes`

The full MITRE catalog, column-oriented to keep it small (~66 KB).

```json
{
  "version": "4.20",
  "columns": ["id", "label", "aliases", "level"],
  "rows": [["639", "Authorization Bypass Through User-Controlled Key",
            "Insecure Direct Object Reference|IDOR|…", "Base"]]
}
```

Sent with a version `ETag` and `Cache-Control: private, max-age=86400`; a
conditional request with `If-None-Match` returns `304`. `aliases` is
pipe-separated and may be empty. Deprecated CWEs are excluded.

## `GET /api/osv/status`

Which OSV bulk exports are on disk, and how stale.

```json
{
  "supported": ["maven", "go", "npm", "…"],
  "cached": [{"ecosystem": "maven", "size_mb": 10.1, "age_hours": 3.6}]
}
```

---

## `POST /api/search`

```jsonc
{
  "categories": ["bac", "cwe:1321"],   // required: classes and/or cwe:<id>
  "include_extended": true,            // default true
  "ecosystem": "maven",                // "any" or a supported ecosystem
  "affects": "org.apache.tomcat:tomcat", // exact package match
  "severity": "high",                  // any|low|medium|high|critical
  "published": ">=2026-01-01",         // or "" for any time
  "type": "reviewed",                  // reviewed|unreviewed|malware
  "sort": "published",                 // published|updated|cve_id|epss_percentage|epss_percentile
  "direction": "desc",                 // asc|desc
  "max_results": 100,                  // clamped to 1..500
  "sources": ["ghsa", "osv-native"],   // ghsa|nvd|osv|osv-native
  "refresh_osv": false
}
```

Response:

```jsonc
{
  "count": 25,
  "query": {
    "categories": ["cwe:1321", "bac"],   // canonicalised and de-duplicated
    "cwes": ["1321", "284", "…"],        // what was actually filtered on
    "ecosystem": "maven", "severity": "any", "affects": null,
    "max_results": 100, "sources": ["ghsa"],
    "per_source": {"ghsa": 25}           // counted BEFORE merge/filter/truncate
  },
  "warnings": ["…"],
  "results": [ /* normalized advisories */ ]
}
```

Each result carries `advisory_id`, `ghsa_id`, `cve_id`, `aliases`, `sources`,
`source_records`, `severity` and `severity_by_source`, `cvss_score` and
`cvss_by_source`, `cwes`, `cwe_labels`, `packages`, `ecosystems`, `published_at`,
`updated_at`, `withdrawn_at`, `kev`, `epss_percentage`, `epss_percentile`,
`html_url`, `summary`, `description`, and `ai` when a fresh cached verdict exists
for **every** requested category.

`per_source` counts are pre-merge, so they will not sum to `count`.

Errors: `Select at least one bug class or CWE.` ·
`Unsupported categories: cwe:99999999` · `Unsupported ecosystem: …` ·
`Invalid published filter: …` · `GHSA fetch failed.` (502, only when it was the
sole source).

## `POST /api/ai/classify`

```jsonc
{
  "categories": ["bac", "cwe:1321"],   // classes and/or cwe:<id>
  "advisory_ids": ["GHSA-…", "…"],     // max 100; must be in the advisory cache
  "force": false                        // ignore cached verdicts
}
```

```jsonc
{
  "categories": ["bac", "cwe:1321"],
  "verdicts":    { "GHSA-…": { /* aggregated verdict */ } },
  "by_category": { "bac": {"GHSA-…": {…}}, "cwe:1321": {…} },
  "missing":     ["GHSA-notcached"]
}
```

Advisories must already be in the cache — run a search first. Unknown ids come
back in `missing` rather than failing the request.

**Cost:** `len(categories) × len(advisory_ids)` model calls, capped at **500**
per request. Over it you get `400` naming both factors. See
[AI classification](ai-classification.md#what-a-pass-costs).

Errors: `AI not configured. Set AI_* in .env.` · `No advisories to classify.` ·
`Too many advisories; maximum batch size is 100.` ·
`Request would issue N AI calls …`

## `POST /api/ai/test`

Empty body. Sends one trivial prompt to confirm the endpoint is reachable
without classifying anything.

```json
{"ok": true, "model": "glm-4", "reply": "…"}
```

---

## Using the modules directly

The search pipeline does not need Flask:

```python
from modules import config, search_service
config.load_dotenv()

query = search_service.parse_search_query({
    "categories": ["bac", "cwe:1321"],
    "ecosystem": "go",
    "max_results": 50,
})
outcome = search_service.run_search(query)
print(len(outcome.results), outcome.warnings, outcome.per_source)
```

Or a single source:

```python
from modules import ghsa_client as g
from modules.cwe_categories import resolve_cwes

params = g.SearchParams(ecosystem="go", cwes=resolve_cwes(["bac"]), max_results=50)
advisories = [g.normalize(a) for a in g.fetch_advisories(params)]

resolve_cwes(["cwe:1321"])      # -> ['1321']
```
