# Architecture

Flask, the standard library, and no frontend build step. `requirements.txt` is
Flask and click; everything else — HTTP clients, JSON, SQLite, threading — is
stdlib. That is a deliberate constraint: this is a tool an operator should be
able to read end to end before pointing it at their credentials.

## Module map

```
app.py                449   Flask routes, request guards, response headers. No logic.
modules/
  config.py            29   minimal .env loader; BASE_DIR / DATA_DIR
  search_service.py   572   the pipeline: parse → fetch → merge → sort → enrich
  cwe_categories.py   691   bug classes, labels, cwe:<id> ad-hoc classes, keywords
  cwe_catalog.py     1123   GENERATED — full MITRE names/aliases (tools/)
  ghsa_client.py      210   `gh api /advisories`, cursor pagination, normalize()
  nvd_client.py       338   NVD API v2, 120-day windowing, rate-limit sleeps
  osv_client.py       336   bulk export download, parse, CWE + keyword filters
  epss_client.py      100   FIRST EPSS scores, batched
  cvss.py             138   CVSS v3.0/3.1 base score from vector (spec rounding)
  cache.py            244   SQLite: advisories + verdicts, schema migrations
  ai_classifier.py    835   provider client, prompt, verdict cache, key rotation
  security.py         320   bind/exposure checks, CSRF origin check, rate limiter
templates/index.html  410   page shell — HTML and Jinja only
static/app.js        1476   all UI logic; server data arrives via window.BOOT
static/style.css     1733   design tokens + components, light and dark
tools/                184   generate_cwe_catalog.py
tests/                      291 tests (270 offline + 21 optional browser)
```

Every module is importable without Flask. `search_service.run_search()` is the
whole product, callable from a script — see [API](api.md#using-the-modules-directly).

## Request lifecycle

Guards run before every request, in this order:

1. **CSRF** — mutating methods must look same-origin (`Origin` / `Referer` /
   `Sec-Fetch-Site`, plus `VULNSIGHT_PUBLIC_HOST` for proxies).
2. **Rate limit** — per client address, per endpoint class.
3. **Auth** — `VULNSIGHT_API_TOKEN` on mutating `/api/*` when configured,
   compared with a constant-time check.
4. **CSP nonce** — a fresh nonce per response for the one inline bootstrap script.

Responses carry `Content-Security-Policy` (`default-src 'self'`, nonce'd scripts,
no inline styles, `object-src 'none'`, `frame-ancestors 'none'`),
`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`
and a restrictive `Permissions-Policy`.

The CSP has a practical consequence for anyone extending the UI: an injected
`<style>` tag is silently dropped, and inline `style="…"` attributes do not
apply. All styling must go through `static/style.css`.

## The search pipeline

`modules/search_service.py`, in order:

1. **Parse and validate** (`parse_search_query`). Bounded string lists, canonical
   `cwe:<id>` folding, ecosystem/severity/type/date validation. A category is
   either a curated class or a CWE that MITRE actually defines.
2. **Resolve CWEs** — union of each target's `core` (+ `extended`), de-duplicated,
   order preserved.
3. **Fetch, sequentially per source** — GHSA → OSV → NVD → OSV-native. Sources
   run one after another; wall-clock is the sum. Each truncates to `max_results`
   internally, so up to `4 × max_results` records reach the merge.
4. **Merge** (`merge_advisories`) — union-find over the full identifier set
   (`advisory_id`, `cve_id`, `ghsa_id`, `osv_id`, `aliases`). GHSA wins as the
   base record; every source's snapshot is kept under `source_records`, severity
   and CVSS are kept per source, and the highest of each is promoted.
5. **Re-filter** — `published` / `affects` / `severity` are enforced again on the
   normalized records, so a fuzzier server-side filter cannot leak rows through.
6. **Sort, truncate, enrich** — in that order for non-EPSS sorts, which keeps
   EPSS to one batched request instead of one per 100 pre-truncation records.
   Sorting *by* EPSS necessarily enriches before sorting.
7. **Persist and label** — upsert into the advisory cache, attach CWE labels, and
   attach a cached AI verdict **only if every requested category has a fresh
   one**. A partial cache hit is never presented as a finished decision.

## Frontend

No framework, no build. `templates/index.html` is a static shell; server data
arrives once in `window.BOOT`; `static/app.js` owns all behaviour.

State lives in four places, each with one owner:

| State | Owner |
|---|---|
| Selected classes | the checkboxes themselves |
| Selected CWEs | a `Set` of bare ids, rendered as chips |
| Result set + verdicts | `LAST` / `AI`, plus `AI_CATS` recording *which selection* the verdicts answer |
| Recent searches | `localStorage`, keyed by a query signature |

`AI_CATS` is the interesting one: it is what lets the UI notice that verdicts on
screen no longer answer the current query and refuse to filter with them.

## Storage

`advisories.db` (SQLite, WAL) with a versioned migration chain in `cache.py`:

| v | Change |
|---|---|
| 1 | base schema: `advisories`, `ai_classification`, indexes |
| 2 | `ai_classification.fingerprint` |
| 3 | rename `ghsa_id` → `advisory_id` on both tables |
| 4 | backfill `advisory_id` **into the stored JSON**, which v3 left untouched |

Migration 4 exists because of a real defect: v3 renamed the column but not the
blob, so a record read back had no id, and the AI batch keyed its results by
`""` — where the last verdict silently overwrote the others. Adding a migration
is cheaper than defending against every downstream consumer of a malformed row.

## Known limits

Written down rather than discovered later:

- **Sources are fetched sequentially.** Wall-clock is the sum, and NVD without an
  API key dominates it (~6.5 s per CWE).
- **Truncation is per source, before the merge.** So sorting by a field the
  sources do not support server-side (EPSS, CVE ID) ranks the page you fetched,
  not the corpus; and "oldest first" is honoured by GHSA but ignored by OSV/NVD.
- **AI-confirmed rows are pinned to the top** of the client-side ordering,
  regardless of the chosen sort. Convenient during triage, but it means the
  visible order is not purely the sort you selected.
- **The bug-class taxonomy is a judgement call.** Umbrella CWEs in `core` buy
  recall at the cost of precision; that trade is what the AI pass compensates
  for. See [Bug classes](bug-classes.md#reading-the-tables-honestly).
- **`static/app.js` is 1476 lines with no module system.** It is covered by the
  browser suite rather than unit tests, because its behaviour only exists in a
  document.
