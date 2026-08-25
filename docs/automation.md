# Scripting and CI

Driving VulnSight from a cron job or a pipeline, without the UI.

[HTTP API](api.md) is the reference for every endpoint. This page is the
narrower thing: what a script has to get right, and what will bite it.

---

## The short version

```bash
TOKEN=$(cat .vulnsight_api_token)      # or however you inject secrets
BASE=http://127.0.0.1:5000/api/v1

# Fast query (GHSA only) — answers in seconds, run it synchronously.
curl -sS -X POST "$BASE/search" \
  -H 'Content-Type: application/json' \
  -H "X-VulnSight-Token: $TOKEN" \
  -d '{"categories":["bac"],"ecosystem":"maven","published":">=2026-01-01"}'
```

Everything the UI does is here; it is a client of this API and uses nothing
private. `curl` is not a second-class caller — the same-origin check has a
deliberate escape hatch for requests with no `Origin` header, so a script passes
it without pretending to be a browser.

## Authentication

Set `VULNSIGHT_API_TOKEN` and send it as `X-VulnSight-Token` or
`Authorization: Bearer`. Comparison is constant-time.

It is required on every mutating call, plus `GET /api/v1/jobs/<id>`. It is *not*
required for `/meta`, `/cwes`, `/osv/status` or `/openapi.json`, which serve
public reference data.

If you bind anything other than loopback while credentials are loaded — an AI
key, `GH_TOKEN`, or simply a logged-in `gh` CLI — the process refuses to start
without a token, and generates one at `$VULNSIGHT_DATA_DIR/.vulnsight_api_token`
(mode 0600) for the container case. Read
[Operations](operations.md) before exposing the port.

## Choose sync or async by whether NVD is in the query

This is the single decision that determines whether your script works.

| Sources | Typical wall clock | Use |
|---|---|---|
| `ghsa` | seconds | `POST /api/v1/search` |
| `osv`, `osv-native` | seconds, minutes on a cold cache | `POST /api/v1/search` |
| anything including `nvd` | **minutes to hours** | `POST /api/v1/jobs` |

NVD without an API key requires ~6.5 s between requests, and the client issues
one request per CWE — before any HTTP time. With `include_extended` left at its
default (measured): the median class resolves to 4 CWEs, the widest — `bac` —
to 15, and selecting all 29 gives 139.

| Selection | CWEs | Sleep alone, no API key |
|---|---|---|
| median class | 4 | ~26 s |
| `bac` | 15 | ~1.6 min |
| all 29 classes | 139 | **~15 min** |

Setting `NVD_API_KEY` cuts the gap to 0.7 s — roughly 9× better, and still
minutes for a wide sweep. Note this is *only* the mandated sleeping; each CWE
also costs one or more real requests on top.

There is no server-side deadline. A synchronous request that outlives your
client's timeout keeps running to completion on the server; you just never see
the answer.

### The polling loop

```bash
JOB=$(curl -sS -X POST "$BASE/jobs" \
  -H 'Content-Type: application/json' -H "X-VulnSight-Token: $TOKEN" \
  -d '{"categories":["bac"],"sources":["ghsa","nvd"],"ecosystem":"maven"}' \
  | jq -r .job_id)

while :; do
  BODY=$(curl -sS -H "X-VulnSight-Token: $TOKEN" "$BASE/jobs/$JOB")
  case "$(jq -r .status <<<"$BODY")" in
    done)   jq .result <<<"$BODY" > results.json; break ;;
    failed) jq -r .error <<<"$BODY" >&2; exit 1 ;;
    *)      sleep 5 ;;
  esac
done
```

Poll every few seconds, not every few milliseconds — polling is cheap but it is
still a request. `result` is byte-identical to a synchronous response, so the
rest of your script does not care which path produced it.

In Python, without any dependency beyond the standard library:

```python
import json, time, urllib.request

BASE, TOKEN = "http://127.0.0.1:5000/api/v1", "…"

def call(path, body=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-VulnSight-Token": TOKEN},
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

job = call("/jobs", {"categories": ["bac"], "sources": ["ghsa", "nvd"]})
while True:
    state = call(f"/jobs/{job['job_id']}")
    if state["status"] == "done":
        results = state["result"]["results"]
        break
    if state["status"] == "failed":
        raise SystemExit(state["error"])
    time.sleep(5)
```

## Reading the response honestly

Three things a script gets wrong if it only looks at `count`.

**An all-sources failure is a 200.** If every source fails, you get HTTP 200
with `count: 0` and the reasons in `warnings`. "Nothing matched" and "everything
is broken" are the same status code. Always check `warnings`:

```bash
jq -e '.warnings | length == 0' results.json || echo "degraded run" >&2
```

**`count` does not tell you whether more exist.** Use `stats`:

```jsonc
"stats": {
  "fetched_per_source": {"ghsa": 25, "nvd": 4},
  "fetched_total": 29,   // rows that arrived
  "after_merge": 26,     // 3 were the same advisory from two sources
  "after_filter": 24,    // 2 failed a local filter
  "returned": 24,        // == count
  "truncated": false
}
```

**`truncated` is about the local pipeline, not the source.** Each source
truncates to `max_results` on its own *before* the merge — GHSA does it
server-side — so a single-source query reports `false` even when thousands more
exist upstream. There is no cursor. To widen a sweep, raise `max_results`
(ceiling 500) or split the query by ecosystem, severity or date window:

```bash
for month in 01 02 03 04 05 06; do
  curl -sS -X POST "$BASE/search" -H 'Content-Type: application/json' \
    -H "X-VulnSight-Token: $TOKEN" \
    -d "{\"categories\":[\"bac\"],\"published\":\"2026-$month-01..2026-$month-28\"}"
done
```

Date bounds are UTC, including for records from sources that send no timezone.

## Rate limits

Default 30 `POST /search` (and `/jobs` — they share one bucket) and 20 AI calls
per 60 s, per client address. Over it you get `429` with `Retry-After`.

Rate limiting runs *after* authentication, so a script sending a bad token
cannot exhaust the operator's budget — but it also means your own retries count.
Respect `Retry-After` rather than looping.

Behind a reverse proxy every client shares the proxy's address unless you set
`VULNSIGHT_TRUST_PROXY=1`, which makes the limiter read the first entry of
`X-Forwarded-For`. Only turn that on where the header is set by a proxy you
control — it is client-supplied otherwise, and one caller can mint unlimited
buckets with it.

## Spending money on purpose

`POST /api/v1/ai/classify` costs `len(categories) × len(advisory_ids)` model
calls, capped at 500 per request and 100 advisories per batch. Advisories must
already be in the cache, so run a search first.

For a scheduled job, decide the budget in the script rather than discovering it:

```python
ids = [r["advisory_id"] for r in results][:100]      # one batch
verdicts = call("/ai/classify", {"categories": ["bac"], "advisory_ids": ids})
confirmed = [a for a, v in verdicts["verdicts"].items() if v.get("is_match")]
```

Verdicts are cached against a fingerprint of the exact prompt, so re-running the
same query the next day costs nothing. Changing the model, the class definition,
or the set of sources changes the fingerprint and re-spends — see
[AI classification](ai-classification.md).

`force: true` bypasses the cache. There is no second guard on it; do not put it
in a cron job.

## Error handling

Every `/api/` failure is JSON, including ones no handler produced:

| Status | Meaning |
|---|---|
| `400` | Bad query. The message names the field. |
| `401` | Missing or wrong token. |
| `404` | No such job, or no such endpoint. |
| `405` | Wrong method for that path. |
| `413` | Body over `MAX_REQUEST_BYTES`. |
| `415` | Missing `Content-Type: application/json`. |
| `429` | Rate limited; honour `Retry-After`. |
| `502` | The only requested source failed. |
| `500` | Unexpected. The reason is in the server log, not the response. |

Messages are operator-facing by construction — exception strings, stack traces
and provider responses stay in the log. That is deliberate, and it means your
script should log the status and the message but not try to parse detail out of
it.

## A cron recipe

```bash
#!/usr/bin/env bash
set -euo pipefail
BASE=http://127.0.0.1:5000/api/v1
TOKEN=$(cat /etc/vulnsight/token)
OUT=/var/lib/vulnsight/$(date -u +%F).json

JOB=$(curl -sSf -X POST "$BASE/jobs" \
  -H 'Content-Type: application/json' -H "X-VulnSight-Token: $TOKEN" \
  -d '{"categories":["bac","sqli"],"sources":["ghsa","nvd"],
       "ecosystem":"maven","published":">='"$(date -u -d '7 days ago' +%F)"'",
       "max_results":500}' | jq -r .job_id)

for _ in $(seq 1 720); do          # 720 x 5 s = one hour
  BODY=$(curl -sSf -H "X-VulnSight-Token: $TOKEN" "$BASE/jobs/$JOB")
  STATUS=$(jq -r .status <<<"$BODY")
  [[ $STATUS == running || $STATUS == queued ]] || break
  sleep 5
done

[[ $STATUS == done ]] || { jq -r '.error // "timed out"' <<<"$BODY" >&2; exit 1; }
jq .result <<<"$BODY" > "$OUT"
jq -e '.warnings | length == 0' "$OUT" >/dev/null \
  || echo "vulnsight: degraded run, see $OUT" >&2
jq -r '.results[] | [.advisory_id, .severity, .summary] | @tsv' "$OUT"
```

Point `VULNSIGHT_DATA_DIR` at persistent storage so the advisory cache and AI
verdicts survive restarts — otherwise every scheduled run re-fetches and, if you
classify, re-spends.

## Generating a client

```bash
curl -sS "$BASE/openapi.json" > vulnsight.json
openapi-generator generate -i vulnsight.json -g python -o ./client
```

The document is verified against real responses in CI (`tests/test_openapi.py`),
so a generated client matches what the server sends rather than what the docs
once claimed. `GET /api/docs` renders the same document as a reference page.

## Limits to design around

- **No cancellation.** A running job finishes or the process exits. Do not
  submit a job you might not want.
- **Jobs are pinned to the process that accepted them.** With gunicorn
  `--workers` above 1, polling works from any worker but the work only runs
  where it was submitted. The shipped `Dockerfile` uses one worker.
- **A restart fails in-flight jobs** with a message telling you to resubmit,
  rather than leaving them `running` forever.
- **Finished jobs are pruned** after `VULNSIGHT_JOB_RETENTION` (default 24 h).
- **One job at a time by default** (`VULNSIGHT_JOB_WORKERS`). The sources are
  rate limited per account, not per request, so concurrency spends the same
  GitHub and NVD budget faster without finishing anything sooner.
- **CWE tagging is imperfect**, which is what the AI pass is for. A sweep that
  filters on umbrella CWEs alone will contain unrelated bugs — see
  [Bug classes](bug-classes.md) and [Data sources](data-sources.md).
