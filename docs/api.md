# HTTP API

The UI is a client of this API and uses nothing private. Everything below works
from `curl` or a script.

## Versioning

Every endpoint answers on two paths: a versioned one under `/api/v1/`, and the
original unversioned one. **Scripts should use `/api/v1/`** — that is the path
whose response shape is held stable.

The unversioned aliases — `/api/meta`, `/api/cwes`, `/api/osv/status`,
`/api/search`, `/api/jobs`, `/api/jobs/<job_id>`, `/api/ai/classify`,
`/api/ai/test`, `/api/openapi.json` — are kept indefinitely, with no
deprecation planned. The UI
still uses them. Both spellings hit the same handler, share the same rate-limit
bucket, and return byte-identical payloads.

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
  endpoints are unauthenticated — they expose only public reference data — with
  one exception: [`GET /api/v1/jobs/<job_id>`](#get-apiv1jobsjob_id) is guarded,
  because a job result is your query's output rather than reference data.
- Every `/api/` failure is JSON, including ones no handler produced: a wrong
  path is `404 {"error": "No such endpoint."}`, not a Werkzeug HTML page. Pages
  outside `/api/` still render HTML, since a browser is not a script.

## Machine-readable description

`GET /api/v1/openapi.json` (alias `/api/openapi.json`) serves an OpenAPI 3.1
document covering every endpoint, request schema and response schema. Load it
into Swagger Editor, Postman, Insomnia, or a client generator:

```bash
curl -s localhost:5000/api/v1/openapi.json > vulnsight.json
openapi-generator generate -i vulnsight.json -g python -o ./client
```

It is served with an ETag, so `If-None-Match` gets a `304`.

`GET /api/docs` renders that document as a browsable reference page.

The document is written by hand and verified by machine, which is the only way
it stays true: `tests/test_openapi.py` fails the build if a route exists with no
description, if a description exists for no route, if the methods disagree — and,
most usefully, if a **real response from the app** does not validate against the
schema the document claims for it. A description a generator believes but the
server does not honour is worse than no description at all.

Deliberately **not** Swagger UI. Vendoring it means ~1.4 MB of minified
third-party JavaScript inside a tool whose stated constraint is that an operator
can read it end to end before pointing it at their credentials, plus relaxing
`style-src` to `'unsafe-inline'` for the styles it injects at runtime. For eight
endpoints, neither trade is worth it — and the spec itself is the interoperable
artefact, so nothing is lost.

---

## `GET /`

The application shell. Server data is injected into `window.BOOT`: popular
packages, the curated classes (key, code, group, label, description, core,
extended, terms), OSV-supported ecosystems, whether AI is configured, the AI call
budget, and whether auth is required.

## `GET /api/v1/meta`

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

## `GET /api/v1/cwes`

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

## `GET /api/v1/osv/status`

Which OSV bulk exports are on disk, and how stale.

```json
{
  "supported": ["maven", "go", "npm", "…"],
  "cached": [{"ecosystem": "maven", "size_mb": 10.1, "age_hours": 3.6}]
}
```

---

## `POST /api/v1/search`

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
    "published": ">=2026-01-01", "type": "reviewed",
    "sort": "published", "direction": "desc", "include_extended": true,
    "max_results": 100, "sources": ["ghsa"],
    "per_source": {"ghsa": 25}           // counted BEFORE merge/filter/truncate
  },
  "stats": {
    "fetched_per_source": {"ghsa": 25},  // same numbers as query.per_source
    "fetched_total": 25,                 // rows that arrived from all sources
    "after_merge": 22,                   // 3 were the same advisory twice
    "after_filter": 20,                  // 2 failed a local filter
    "returned": 20,                      // == count == len(results)
    "truncated": false                   // true when max_results cut the list
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

`per_source` counts are pre-merge, so they will not sum to `count`. That gap
used to be unexplainable from the response — a smaller `count` could mean rows
were de-duplicated, filtered, or cut by `max_results`, and a script had no way
to tell which. `stats` names each stage, so a client can distinguish "these were
the same advisory reported by two sources" (`after_merge < fetched_total`) from
"a local filter rejected them" (`after_filter < after_merge`).

**`truncated` means the *local* pipeline dropped rows to honour `max_results`.
It does not mean the upstream source has no more.** Each source truncates to
`max_results` on its own before the merge — GHSA does it server-side — so a
single-source search almost always reports `truncated: false` even when the
source holds thousands more. It becomes informative when several sources
contribute together. There is no cursor: to widen a search, raise `max_results`
(ceiling 500) or narrow the query by ecosystem, severity or date.

Errors: `Select at least one bug class or CWE.` ·
`Unsupported categories: cwe:99999999` · `Unsupported ecosystem: …` ·
`Invalid published filter: …` · `GHSA fetch failed.` (502, only when it was the
sole source).

## `POST /api/v1/jobs`

Runs the same search off the request thread. Takes **exactly** the body
`/api/v1/search` takes, so moving a slow query across is a URL change and
nothing else.

Use it when the query includes NVD. NVD without an API key costs ~6.5 s per CWE
in rate-limit sleeps, and a class with extended CWEs enabled resolves to well
over a hundred — minutes of wall clock, past the default timeout of most HTTP
clients. The query is not slow so much as un-completable over one connection.

```
202 Accepted
Location: /api/v1/jobs/9f3c1ab2e4d5c6b7a8f90123
```
```json
{"job_id": "9f3c1ab2e4d5c6b7a8f90123", "kind": "search",
 "status": "queued", "poll": "/api/v1/jobs/9f3c1ab2e4d5c6b7a8f90123"}
```

The query is validated before the job is created, so a malformed request is a
`400` you get now rather than a job that fails a minute later. Submitting spends
the **same** rate-limit bucket as `/api/v1/search` — queueing a search costs the
same upstream budget as running one.

## `GET /api/v1/jobs/<job_id>`

```jsonc
{
  "job_id": "9f3c1ab2e4d5c6b7a8f90123",
  "kind": "search",
  "status": "queued",        // queued | running | done | failed
  "created_at": 1756000000.0,
  "started_at": 1756000001.2,
  "finished_at": 1756000118.9,
  "result": { /* identical to a POST /api/v1/search response */ },
  "error": "GHSA fetch failed."   // present only when status is "failed"
}
```

`result` appears only on `done`, `error` only on `failed` — there are no partial
results to poll for. The payload under `result` is byte-identical to what the
synchronous endpoint returns, so a client never parses two shapes.

Unlike every other `GET`, this one **requires the token when one is configured**.
The other read endpoints serve public reference data; a job result is the output
of your own query, and a 96-bit id should not be the only thing protecting it.

Unknown or malformed ids return `404 {"error": "No such job."}`.

### Limits worth knowing before you build on this

- **No cancellation.** Python cannot interrupt a thread parked in `time.sleep`,
  and the fetch loop has no cancellation points. A running job runs to
  completion or until the process exits.
- **Execution is pinned to the process that accepted the job.** The worker pool
  is in-process; job rows are shared, so polling works from any worker, but with
  gunicorn `--workers` above 1 the work only runs where it was submitted. The
  shipped `Dockerfile` uses one worker, so this is only a concern if you change it.
- **A restart fails in-flight jobs.** They are marked `failed` with
  `Server restarted while this job was in flight; resubmit it.` rather than left
  in `running` forever, because nothing is executing them any more.
- **One worker by default** (`VULNSIGHT_JOB_WORKERS`). The sources are rate
  limited per account, not per request, so running searches concurrently spends
  the same GitHub and NVD budget faster without finishing any job sooner.
- **Finished jobs are pruned** after `VULNSIGHT_JOB_RETENTION` seconds
  (default 24 h). Unfinished jobs are never pruned.

## `POST /api/v1/ai/classify`

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

## `POST /api/v1/ai/test`

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
