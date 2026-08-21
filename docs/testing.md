# Testing

```bash
.venv/bin/python -m unittest discover -s tests        # 270 offline tests
.venv/bin/python -m unittest discover -s tests -v     # with names
.venv/bin/python -m pytest tests/ -q                  # if you prefer pytest
.venv/bin/python tests/test_app.py                    # a single file
```

The offline suite needs **no network, no credentials and no browser**. GHSA, NVD,
OSV and the AI provider are all mocked.

## What is covered

| File | Tests | Covers |
|---|---|---|
| `test_app.py` | 49 | routes, guards, DOM contract, page weight, AI cost cap |
| `test_ai_classifier.py` | 37 | prompt, verdict aggregation, key rotation, cooldowns |
| `test_search_service.py` | 36 | query parsing, merge/dedupe, sort, filters |
| `test_cwe_categories.py` | 30 | taxonomy invariants, `cwe:<id>`, picker catalog |
| `test_security.py` | 27 | bind/exposure rules, CSRF origin check, rate limiter |
| `test_nvd_client.py` | 21 | date windowing, normalisation, rate-limit handling |
| `test_ui_e2e.py` | 21 | the real UI in a browser — *optional*, see below |
| `test_cvss.py` | 13 | v3.0/3.1 base scores against spec vectors |
| `test_epss_client.py` | 12 | batching, malformed responses |
| `test_osv_client.py` | 11 | zip parsing, CWE and keyword filters |
| `test_cache.py` | 9 | SQLite lifecycle, migrations, the v4 id backfill |
| `test_docs.py` | 11 | doc/code agreement: quoted numbers, routes, env vars, links |
| `test_ghsa_client.py` | 9 | `gh` invocation, cursor pagination |
| `test_query_filters.py` | 4 | shared published/affects/severity predicates |
| `test_frontend_js.py` | 1 | runs every `tests/*.js` under node |

## Frontend helper tests (node)

Pure helpers are lifted straight out of `static/app.js` and executed, so the
tested source is always the shipped source:

- `test_frontend_security.js` — CSV escaping, including formula-injection
  neutralisation.
- `test_frontend_finder.js` — CWE-finder ranking, history sanitisation,
  `stateSignature` dedupe, `relativeTime`, `publishedWindow`.

`test_frontend_js.py` discovers and runs them inside the Python suite, and skips
if `node` is unavailable. They earn their keep: the finder tests caught a null
timestamp rendering as *"20685d ago"*.

## Browser tests (optional)

`tests/test_ui_e2e.py` drives the real UI. It is the only part of the suite with
a third-party dependency and it **skips itself** unless both pieces are present:

```bash
pip install -r requirements-dev.txt
playwright install chromium          # or rely on a system Chrome
.venv/bin/python -m unittest discover -s tests    # the 21 e2e tests join in
```

Verified: with Playwright absent the suite reports `270 passed, 21 skipped`, and
`unittest discover` reports `OK (skipped=21)`.

It exists because `static/app.js` decides what the user *believes* — which
advisories are hidden, which verdict belongs to which advisory, and when real
budget is spent — and none of that is reachable from a Python unit test. Each
test corresponds to a defect that actually shipped:

| Group | Asserts |
|---|---|
| `TestCweFinder` | alias → CWE with its full official name, exact-id ranking, `Enter` adds without searching, popup closes on `Tab` |
| `TestClassFilter` | the filter hides rows **on screen**, a selected class is never hidden, community terms match, group headings track their contents |
| `TestAiSpendRequiresConsent` | `⌘↵` runs the free search, `Confirmed only` asks first and reverts on cancel, a failed pass restores the raw queue |
| `TestVerdictsFollowTheQuery` | changing the class flags verdicts stale and blocks the filter; the summary reports the visible count |
| `TestFailureStates` | a source-less search keeps the previous view; missing EPSS is not rendered as `0.00%` |
| `TestRecentSearches` | no duplicate entries, signature-keyed rows, restore reapplies filters |
| `TestAccessibility` | exactly one `<h1>`, labelled containers expose their label, the mobile panel takes and traps focus |

### Assert on what is rendered

These tests check `getComputedStyle(el).display`, never `el.hidden`. That is not
style preference. A `.cat { display: grid }` rule beat the UA stylesheet's
`[hidden] { display: none }`, so the class filter set `hidden` on every row and
**changed nothing on screen** — while a property-based assertion stayed green.
Delete `.taxonomy-item[hidden] { display: none }` from the stylesheet and two of
these tests fail, which is the point.

Also useful: each test declares expected console noise via
`self.tolerated_errors`; anything else fails the test, so a stray JS exception
cannot hide inside a passing run.

## Verifying a change

Type checking is not configured in this repo, so "it imports" is not evidence.
For anything touching behaviour:

```bash
python -m pytest tests/ -q                  # everything
python -m ruff check .                      # lint
node --check static/app.js                  # JS parses
python -c "import app; app.create_app()"    # the app actually builds
```

Then **exercise the thing you changed**. If it has a UI surface, add or extend a
case in `test_ui_e2e.py` rather than reasoning about it: several defects in this
codebase looked correct in the source and were only visible in a rendered page.

If you fix a bug, first write the assertion that fails, then fix it, then confirm
that removing the fix makes it fail again. Two findings in this repo's history
were measurement artifacts that would have been committed as facts without that
last step.
