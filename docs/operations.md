# Operations

## Exposure

Default: loopback only. The tool is built for one operator on `localhost`, and it
holds live credentials (`gh` token, AI keys), so the defaults refuse to be
casually widened.

| Situation | Behaviour |
|---|---|
| `HOST=127.0.0.1` (default) | runs normally |
| Non-loopback `HOST`, credentials loaded, no `VULNSIGHT_EXPOSE=1` | **refuses to start** |
| Non-loopback `HOST`, `VULNSIGHT_EXPOSE=1`, no `VULNSIGHT_API_TOKEN` | **refuses to start** |
| `--debug` off loopback | **refuses** — Werkzeug's debugger is remote code execution |
| Docker / gunicorn binding `0.0.0.0` with credentials | requires a token; generates `.vulnsight_api_token` if you did not set one |

Set `VULNSIGHT_API_TOKEN` yourself if you want to choose the value. The UI
prompts for it and keeps it in `sessionStorage` (per tab, not persisted).

Behind a reverse proxy, add its hostname to `VULNSIGHT_PUBLIC_HOST` or the
same-origin check will reject your `POST`s.

Read [SECURITY.md](../SECURITY.md) before publishing the port.

## Caches and disk

| Path | What | Size | Lifetime |
|---|---|---|---|
| `advisories.db` | advisory cache + AI verdicts | ~7 MB per ~1 000 advisories | forever, until you delete it |
| `osv_cache/` | OSV bulk exports | 10 MB maven, 11 MB go, **220 MB npm** | 24 h freshness check |
| `.ai_key_cooldown.json` | which API keys are rate-limited | bytes | until the stated reset |
| `.vulnsight_api_token` | generated API token | bytes | until deleted |

All are git-ignored. `VULNSIGHT_DATA_DIR` relocates them (Docker points it at the
`vulnsight-data` volume so a rebuild does not re-download 220 MB).

Safe to delete at any time — everything is regenerable. Deleting
`advisories.db` also discards cached AI verdicts, which costs real money to
rebuild.

Useful queries:

```bash
sqlite3 advisories.db "SELECT COUNT(*) FROM advisories"
sqlite3 advisories.db "SELECT model, COUNT(*), SUM(fingerprint IS NULL)
                         FROM ai_classification GROUP BY model"
du -sh osv_cache/*
```

## AI quota

With several comma-separated keys, an exhausted key is put in cooldown and
skipped rather than retried. Cooldowns survive a restart
(`.ai_key_cooldown.json`, storing only key hashes).

Expect **one** wasted call per newly-exhausted key — a key cannot be known
exhausted until it refuses once. After that it costs nothing until its stated
reset. Details and the measurements:
[AI classification → multi-key rotation](ai-classification.md#multi-key-rotation).

To see the current state, watch the log at startup — restored cooldowns are
logged as `API key #N still cooling down for Ns`.

## Cost control

| Lever | Where |
|---|---|
| `max_results` | the UI; caps how many advisories a pass can touch |
| Number of selected targets | multiplies the pass — `N targets = N calls per advisory` |
| `MAX_AI_CALLS_PER_REQUEST` (500) | server-side hard cap per request |
| `VULNSIGHT_AI_RATE` (20/min) | request-rate cap |
| `NVD_API_KEY` | not money, but ~10× wall-clock on NVD queries |

The UI states the cost of a pass before running it, and every control that spends
budget asks first. If you want a dry run, search without the AI pass — that is
always free.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Header shows `GH OFFLINE` | `gh` not authenticated, or unavailable | `gh auth login`; in Docker pass `GH_TOKEN` |
| Header shows `AI OFF` | no token / base URL / model | see [Configuration](configuration.md#ai-provider) |
| `GHSA fetch failed.` | `gh` error, network, or rate limit | run `gh api /advisories --paginate` manually to see the real error |
| Search returns far fewer than `max_results` | per-source truncation then exact re-filtering, most visible with NVD + `affects` | widen `max_results`, or drop the package filter |
| NVD takes minutes | ~6.5 s per CWE without a key | set `NVD_API_KEY`, or select fewer CWEs |
| First OSV search hangs | downloading the export (220 MB for npm) | wait once; it is cached for 24 h |
| `429 Too many requests` | local rate limiter, not the upstream | raise `VULNSIGHT_SEARCH_RATE` / `VULNSIGHT_AI_RATE`, or wait |
| `AI quota exhausted` | all keys in cooldown | add keys, or wait for the stated reset |
| AI verdicts never come from cache | the fingerprint changed (model, prompt or class description), or old rows have a `NULL` fingerprint | expected — see [the verdict cache](ai-classification.md#the-verdict-cache) |
| Verdicts look wrong after changing the query | they were scored for the previous selection | the banner is telling you exactly that; re-run the pass |
| Advisories with `NO CWE · AI` and no verdicts | OSV-native records need the AI pass | run *Refine with AI*, or deselect that source |
| A cached advisory cannot be classified | it is not in `advisories.db` | run a search first; `missing` in the response lists them |

## Upgrading

1. `git pull`
2. `./run.sh` — re-installs dependencies if they changed
3. Migrations run automatically at startup (`cache.init_db()`), are idempotent,
   and are safe to re-run.
4. If MITRE published a new CWE release, refresh the catalog:
   `python tools/generate_cwe_catalog.py && python -m pytest tests/test_cwe_categories.py`

Nothing in the upgrade path deletes your caches.
