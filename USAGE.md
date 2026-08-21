# VulnSight

Browse the **GitHub Advisory Database** filtered by **bug class → CWE**, scoped
by **ecosystem/package**, and optionally **refined by an LLM** to cut through
the noise of imperfect CWE tagging and inconsistent advisory titles.

Built for the workflow in `README.md`: find BAC (BOLA/BFLA/IDOR) advisories in
Java (maven) and Go, then expand to injection classes (SQLi/XSS/SSTI/…).

## Why CWE-based filtering

Many GHSA entries don't say "BOLA" or "BFLA" anywhere in the title, so keyword
search misses them. Every reviewed advisory *is* tagged with CWEs, so we filter
on the CWE set that defines each bug class (see `modules/cwe_categories.py`). The AI pass
then reads each advisory and confirms whether the root cause really matches —
useful because umbrella CWEs like `CWE-284` are often too vague.

## Quick start

```bash
cd VulnSight
cp .env.example .env      # then put YOUR own AI token in .env (never commit it)
./run.sh                  # creates venv, installs Flask, launches
# open http://127.0.0.1:5000
```

Requirements:
- `gh` CLI installed and authenticated (`gh auth login`) — used for all GHSA fetches.
- Python 3.9+.
- (Optional) AI creds in `.env` for the "Refine with AI" button.

## How to use the UI

1. **Find a bug** — type into the search box at the top of the left rail. It
   matches the **whole MITRE CWE catalog** (944 weaknesses, CWE 4.20) plus the
   curated bug classes, by:
   - **code** — `639`, `CWE-639`, or a prefix like `13` ;
   - **official MITRE name** — "authorization bypass", "prototype pollution" ;
   - **community alias** — `IDOR`, `BOLA`, `BFLA`, `SSRF`, `XXE`, `SSTI`, `SQLi`.

   `↑`/`↓` to move, `Enter` to add. Picking a **class** ticks its checkbox;
   picking a **CWE** adds a chip. Both appear under **Query targets**. Search is
   local (the catalog is fetched once and cached), so it never round-trips.
2. **Pick bug classes** in the grouped list below (BAC preselected). 29 classes
   across 7 groups; the **filter box** narrows them by label, description, group
   or community term (`toctou`, `__proto__`, `md5`, `webshell`). A class you have
   already selected is never hidden by the filter. Each maps to a CWE set, and a
   single CWE you pick becomes its own ad-hoc class: it is filtered on *and*
   scored by the AI pass, using that CWE's real MITRE definition.
3. **Include extended CWEs** — on = higher recall (more results, more noise),
   off = only high-precision core CWEs. Only affects curated classes; a CWE you
   picked yourself is always used exactly as-is.
4. Set **ecosystem** (`maven` = Java, `go` = Golang), optional **package**,
   **severity**, **published** filter (e.g. `>=2024-01-01`), and **max results**.
5. Click **Search** → advisories load, sorted by severity then date. The query
   lands in **Recent searches** at the top of the rail; click one to restore
   every filter and re-run it, `×` to forget it. History is kept in
   `localStorage` (last 12, deduplicated), so it survives a reload but never
   leaves the browser.
6. Click **✨ Refine with AI** → each advisory is sent to the LLM which returns
   `is_match / confidence / vuln_type / reason`. Toggle **Only AI matches** to
   hide the false positives. Verdicts are cached in SQLite so re-runs are free.
   **Do not skip this for BAC:** umbrella CWEs like `CWE-284` also tag SSRF,
   ReDoS, crypto bugs, and header issues. A live pass of 272 newest BAC-tagged
   advisories dropped 25 that were not access control.
7. **⚡ Test AI** pill (top-right) checks the endpoint is reachable.
8. **⬇ Export** the current (filtered) list as **CSV**, **JSON**, or **CSV — AI
   matches only**. CSV is Excel-friendly (UTF-8 BOM, RFC-4180 quoting) and
   includes the AI verdict columns.

### When AI calls fail

The provider's `PRO` model is a *reasoning* model, so a call can occasionally
truncate its JSON or return an empty answer, and shared endpoints sometimes rate
limit. The tool handles this at three levels:

- **Backend retry** — each classification retries up to 3× with exponential
  backoff on transient failures (HTTP 429/5xx/timeouts *and* truncated/empty
  replies). `max_tokens` is set high (2000) so the reasoning + JSON both fit.
- **Auto-retry** — after **Refine with AI**, any advisories still erroring are
  retried automatically for up to 3 more rounds.
- **↻ Retry failed (N)** — a button that re-runs only the ones still failing,
  on demand. Successful verdicts are cached, so retries never re-spend tokens on
  advisories that already succeeded.

## Data sources (GHSA + NVD + OSV.dev)

Pick one or more sources in the **DATA SOURCES** panel. Results are merged and
de-duplicated across sources (by CVE → GHSA id → OSV id); a record found in more
than one source is tagged e.g. `GHSA+OSV`.

- **GHSA** — GitHub Advisory Database via `gh`. Filters by CWE **server-side**;
  works for any ecosystem. This is the primary browse engine.
- **NVD** — NIST CVE API v2. Long published-date searches are split into
  API-compatible 120-day windows, then merged with the other sources by aliases.
- **OSV.dev** — the OSV bulk export (`{ecosystem}/all.zip`, ~10 MB, cached daily
  under `osv_cache/`). Filtered by CWE **locally**. Needs a specific ecosystem.
- **OSV native** — source-native records (`GO-`, `RUSTSEC-`, `PYSEC-`, …) that
  carry **no CWE tag** and are therefore invisible to every CWE filter. They are
  keyword-prefiltered by the selected bug class and then **classified by the AI**
  (click *Refine with AI*). Cards show a `no CWE · AI` badge.

### Honest note on coverage

For **maven/Go/npm/pip/crates**, OSV's CWE-tagged records are almost entirely
mirrored from GHSA (same `GHSA-…` id), so `GHSA` alone and `GHSA+OSV` return
nearly the same set — OSV's own scan showed **0 extra CWE-tagged records** beyond
GHSA for those ecosystems, and Maven is ~100% GHSA. The genuine win is **OSV
native**: e.g. 230 Go / 11.7k PyPI / 347 Rust records have no CWE and only
surface via the AI path (a live test found 5 real XSS in Go native records that
CWE filtering shows zero of). OSV's other big populations (Debian/Ubuntu/Alpine/
kernel/Android) are outside these package ecosystems and mostly not app-level
BAC/injection.

## Bug classes shipped

29 curated classes in 7 groups. Each maps to a **core** CWE set (high precision)
plus an **extended** set (higher recall), and carries the community terms people
actually type — so the class list filter matches `__proto__`, `toctou`,
`samesite`, `md5`, `dll hijack`, `webshell` and friends, not just the label.

| Key | Code | Class | Core CWEs |
|-----|------|-------|-----------|
| **Injection** | | | |
| `sqli` | SQLI | SQL Injection | 89 |
| `xss` | XSS | Cross-Site Scripting (XSS) | 79 |
| `ssti` | SSTI | Server-Side Template Injection / Code Injection | 1336, 94 |
| `cmdi` | CMDI | OS / Command Injection | 77, 78 |
| `deserialization` | DESER | Insecure Deserialization | 502 |
| `xxe` | XXE | XML External Entity (XXE) | 611 |
| `queryinj` | QINJ | LDAP / XPath / XQuery Injection | 643, 90 |
| `crlf` | CRLF | CRLF / Header Injection & Request Smuggling | 93, 113 |
| `protopollution` | PROTO | Prototype Pollution | 1321 |
| **Access control & auth** | | | |
| `bac` | BAC | Broken Access Control (BAC / BOLA / BFLA / IDOR) | 284, 285, 639, 862, 863, 732, 306, 287 |
| `csrf` | CSRF | Cross-Site Request Forgery (CSRF) | 352 |
| `cors` | CORS | CORS / Origin Validation Failure | 942 |
| `session` | SESS | Session Management Flaws | 384 |
| `hardcodedcreds` | CREDS | Hard-coded / Default Credentials | 798 |
| `clickjacking` | CLICK | Clickjacking / UI Redressing | 1021 |
| **Files & server-side requests** | | | |
| `ssrf` | SSRF | Server-Side Request Forgery (SSRF) | 918 |
| `pathtraversal` | PATH | Path Traversal / File Disclosure | 22 |
| `openredirect` | OPRED | Open Redirect | 601 |
| `upload` | UPLD | Unrestricted File Upload | 434 |
| `searchpath` | SPATH | Untrusted Search Path / Library Hijack | 426, 427 |
| **Crypto & secrets** | | | |
| `crypto` | CRYPT | Broken Cryptography & Verification | 327, 347, 295 |
| `randomness` | RAND | Insufficient Randomness | 330, 338 |
| `infoleak` | INFO | Sensitive Information Disclosure | 200 |
| **Memory & concurrency** | | | |
| `memory` | MEM | Memory Safety (OOB / UAF / Double Free) | 787, 125, 416, 415, 476 |
| `intoverflow` | INT | Integer Overflow / Wraparound | 190 |
| `race` | RACE | Race Condition / TOCTOU | 362, 367 |
| **Availability** | | | |
| `redos` | REDOS | Regular Expression DoS (ReDoS) | 1333 |
| `dos` | DOS | Denial of Service / Resource Exhaustion | 400, 770 |
| **Broad / umbrella** | | | |
| `inputval` | INPUT | Improper Input Validation (umbrella) | 20 |

Add or tune classes in [`modules/cwe_categories.py`](modules/cwe_categories.py).
`tests/test_cwe_categories.py` enforces the invariants a new class must satisfy:
a short unique code, a group, a description long enough to serve as the AI
prompt's definition, a non-empty core set, keyword prefilters, canonical bare
CWE ids that all exist in the MITRE catalog, and no core/extended overlap.

Anything outside this table is still reachable: pass a **single CWE as its own
class** with the `cwe:<id>` key. It is filtered on server-side and scored by the
AI pass against that CWE's real MITRE name and aliases.

```jsonc
// POST /api/search
{"categories": ["bac", "cwe:1321"], "ecosystem": "npm"}
```

The catalog behind the picker is generated from MITRE's official XML:

```bash
python tools/generate_cwe_catalog.py     # refreshes modules/cwe_catalog.py
```

## CLI / programmatic use

Everything is importable without Flask:

```python
from modules import ghsa_client as g
from modules.cwe_categories import resolve_cwes

p = g.SearchParams(ecosystem="go", cwes=resolve_cwes(["bac"]), max_results=50)
advs = [g.normalize(a) for a in g.fetch_advisories(p)]

# A single CWE works as an ad-hoc class, with no curated entry needed:
resolve_cwes(["cwe:1321"])          # -> ['1321']
```

## Architecture

```
app.py                thin Flask routes: /, /api/search, /api/ai/classify, …
modules/
  config.py           minimal .env loader; BASE_DIR = project root
  search_service.py   search orchestration: parse → fetch sources → merge/dedupe
                      → sort → enrich (usable without Flask)
  cwe_categories.py   bug-class → CWE mapping, labels, cwe:<id> ad-hoc classes
  cwe_catalog.py      GENERATED: full MITRE CWE names + aliases (see tools/)
  ghsa_client.py      gh api /advisories wrapper, cursor pagination, normalize()
  osv_client.py       OSV.dev bulk export: download, normalize, CWE/keyword filter
  cvss.py             CVSS v3.0/3.1 base score from vector (spec-exact rounding)
  cache.py            SQLite: advisories + AI verdicts (advisories.db at root)
  ai_classifier.py    Anthropic-compatible client (stdlib urllib), concurrent
templates/index.html  page shell (HTML + Jinja only)
static/style.css      styles
static/app.js         UI logic (server data injected via window.BOOT)
tests/                per-module unit tests (offline; GHSA/OSV/AI mocked)
```

## Tests

```bash
cd VulnSight
.venv/bin/python -m unittest discover -s tests -v   # full suite, offline
.venv/bin/python tests/test_app.py                  # or any single file
```

The frontend helpers lifted out of `static/app.js` (CSV escaping, CWE-finder
ranking, history sanitisation) are tested in `tests/test_frontend_*.js` and run
inside the Python suite via `tests/test_frontend_js.py` — skipped automatically
when `node` is unavailable.

## Notes & limits

- The GHSA REST API caps `per_page` at 100; we follow the `Link` cursor up to
  your **max results** so cost stays bounded.
- `affects` (package) is an **exact** match, e.g. `org.apache.tomcat:tomcat`.
- AI calls run 6-wide concurrently; verdicts persist per `(advisory, category)`.
- The token lives only in `.env` (git-ignored). `./run.sh` chmods `.env` to
  `0600`. The AI request goes to the `AI_BASE_URL` you configure — nowhere else.
- Docker publishes `127.0.0.1:5000` only. A non-loopback bind with credentials
  and no `VULNSIGHT_API_TOKEN` generates `.vulnsight_api_token` and the UI
  asks for it. Set `VULNSIGHT_API_TOKEN` yourself to pick the value.
