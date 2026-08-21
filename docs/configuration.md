# Configuration

Everything is read from the environment. `modules/config.py` loads `.env` from
the project root at startup with `os.environ.setdefault`, so **a real
environment variable always wins over `.env`** — handy for overriding a single
value on one run without editing the file.

`.env` is git-ignored. `.env.example` is the template; it ships with no
credentials in it.

## AI provider

Each provider reads its own prefixed variable and falls back to the generic
`AI_*` name, so an Anthropic and a GLM configuration can coexist in one `.env`.

| Variable | Default | Meaning |
|---|---|---|
| `CVE_AI_PROVIDER` | `anthropic` | `anthropic` (Messages shape) or `glm` (OpenAI chat-completions shape) |
| `<PREFIX>_TOKEN` / `AI_TOKEN` | — | API key. **Comma-separated for [multi-key rotation](ai-classification.md#multi-key-rotation)** |
| `<PREFIX>_BASE_URL` / `AI_BASE_URL` | `glm` → BigModel v4; otherwise none | endpoint root |
| `<PREFIX>_MODEL` / `AI_MODEL` | — | model id |

`<PREFIX>` is `ANTHROPIC` or `GLM`. Without a token, model and base URL the AI
pass reports itself unconfigured and the UI header shows `AI OFF`.

### AI tuning

| Variable | Default | Meaning |
|---|---|---|
| `AI_THINKING` | `false` | Enable the provider's reasoning mode. Slower; also raises the default timeout |
| `AI_CLASSIFY_TIMEOUT` | `45` s (`180` if thinking) | Per-call HTTP timeout |
| `AI_CLASSIFY_MAX_TOKENS` | see `modules/ai_classifier.py` | Response budget; must fit reasoning **plus** the JSON verdict |
| `AI_CLASSIFY_WORKERS` | derived from key count | Concurrency of the classify batch |

## Data sources

| Variable | Default | Meaning |
|---|---|---|
| `GH_TOKEN` / `GITHUB_TOKEN` | — | Used by `gh`. Required inside Docker, where the host keyring is unreachable |
| `NVD_API_KEY` | — | Without it NVD sleeps ~6.5 s between requests instead of ~0.7 s. [Free key](https://nvd.nist.gov/developers/request-an-api-key) |

## Server and exposure

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. A non-loopback bind is refused while credentials are loaded unless you also set `VULNSIGHT_EXPOSE=1` **and** `VULNSIGHT_API_TOKEN` |
| `PORT` | `5000` | |
| `VULNSIGHT_EXPOSE` | `0` | Acknowledge that you mean to listen off loopback |
| `VULNSIGHT_API_TOKEN` | — | When set, every mutating `/api/*` call must present it via `X-VulnSight-Token` or `Authorization`. The UI prompts for it and keeps it in `sessionStorage` |
| `VULNSIGHT_PUBLIC_HOST` | — | Extra hostnames to accept as same-origin for the CSRF check (reverse proxies) |
| `VULNSIGHT_DATA_DIR` | project root | Where `advisories.db`, `osv_cache/` and the API-token file live. Docker points this at a volume |
| `MAX_REQUEST_BYTES` | `1048576` | Request body cap; floors at 1 KiB |

`--debug` is refused off loopback: Werkzeug's debugger is remote code execution.

## Rate limiting

Applies to `POST` only, per client address.

| Variable | Default | Meaning |
|---|---|---|
| `VULNSIGHT_RATE_LIMIT` | `on` | `0`/`off`/`false`/`no` disables limiting entirely |
| `VULNSIGHT_RATE_WINDOW` | `60` s | Window length |
| `VULNSIGHT_SEARCH_RATE` | `30` | `/api/search` calls per window |
| `VULNSIGHT_AI_RATE` | `20` | `/api/ai/classify` and `/api/ai/test` calls per window |

A throttled request gets `429` with `Retry-After`.

## Fixed limits (code, not environment)

These are deliberate ceilings rather than knobs, because raising them changes
cost or correctness rather than convenience:

| Constant | Value | Where | Why |
|---|---|---|---|
| `MAX_AI_CALLS_PER_REQUEST` | `500` | `app.py` | One classify request costs `categories × advisories` model calls. Capping the *product* is the only cap that reflects the real bill |
| `MAX_AI_BATCH` | `100` | `app.py` | Advisories per classify request |
| `MAX_CATEGORY_INPUTS` | `100` | `modules/search_service.py` | Query targets per search |
| `MAX_CWE_ID_DIGITS` | `7` | `modules/cwe_categories.py` | Bounds the `cwe:<id>` form |
| `max_results` | `1`–`500` | `modules/search_service.py` | Clamped from the request |

The UI reads `MAX_AI_CALLS_PER_REQUEST` out of the bootstrap payload and sizes
its batches from it, so it never trips the server cap.

## Files the tool writes

| Path | Contents | Git |
|---|---|---|
| `advisories.db` | SQLite: advisory cache + AI verdicts | ignored |
| `osv_cache/` | OSV bulk exports per ecosystem | ignored |
| `.ai_key_cooldown.json` | Which API keys are in quota cooldown, as **SHA-256 prefixes — never the keys** | ignored |
| `.vulnsight_api_token` | Auto-generated token when exposing the port without setting one | ignored |
