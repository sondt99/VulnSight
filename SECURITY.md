# Security policy

VulnSight is a **local research UI** for querying GHSA, NVD, and OSV by bug
class. It is not a multi-user SaaS. The process holds the operator's AI keys,
GitHub token, and optional NVD key, and will spend them on `/api/search` and
`/api/ai/*`.

The supported deployment is loopback-only (`http://127.0.0.1:5000`) with
credentials in a git-ignored `.env`. Anything beyond that is an explicit
opt-in and needs a shared secret.

## Supported versions

There are no numbered releases. Security fixes land on `main` and apply to the
latest commit only. Older snapshots are unsupported.

## Reporting a vulnerability

**Do not open a public GitHub issue** for an exploitable finding (auth bypass,
CSRF that spends keys, secret leakage, RCE, SSRF, and similar).

1. Use [GitHub private vulnerability reporting](https://github.com/sondt99/VulnSight/security/advisories/new)
   on this repository.
2. If that form is unavailable, email the maintainer at the address on
   [sondt99's GitHub profile](https://github.com/sondt99). Put `VulnSight`
   in the subject.

Include:

- affected commit SHA (or `main` as of a date)
- impact (who can exploit it, and what they gain)
- reproduction steps or a proof of concept
- whether you have already disclosed it elsewhere

You should get an acknowledgement within **7 days**, and a decision
(fix / won't-fix / not a vulnerability) within **30 days**. Please give at
least **90 days** after a fix is on `main` before public write-ups, unless we
agree otherwise.

Public issues are fine for hardening ideas, docs gaps, and non-exploitable
bugs.

## Threat model

| In scope | Out of scope |
| --- | --- |
| Unauthenticated or CSRF use of `/api/search`, `/api/ai/test`, `/api/ai/classify` that spends API keys or GitHub credentials | A local operator attacking their own loopback instance |
| Secret leakage in HTTP responses, HTML, logs shipped to clients, or committed files | Prompt injection that only skews AI *verdicts* (advisory text is untrusted evidence by design) |
| XSS, HTML injection, or CSV formula injection in the UI / export | Findings that require `--debug`, a world-readable `.env` the operator created, or a compromised `gh` login |
| Path traversal, zip-slip, SSRF, SQLi, command injection in this codebase | Vulnerabilities in GHSA / NVD / OSV / the configured AI provider |
| Bind/auth bypass that exposes the UI beyond loopback without `VULNSIGHT_API_TOKEN` | Dependency CVEs with no reachable path in VulnSight (report them upstream too) |

## Operator requirements

Follow these if you load real credentials:

- Keep `.env` out of git (it is git-ignored). Never commit `GLM_TOKEN`,
  `AI_TOKEN`, `ANTHROPIC_TOKEN`, `GH_TOKEN`, `NVD_API_KEY`, or
  `VULNSIGHT_API_TOKEN`. `./run.sh` sets `.env` to mode `0600`.
- Prefer `./run.sh` or `docker compose` as documented. Compose publishes
  **`127.0.0.1:5000` only**.
- Do **not** run `docker run -p 5000:5000 …`. That maps the port on all
  interfaces. Gunicorn inside the image listens on `0.0.0.0`; the host publish
  is what keeps it private.
- If you bind beyond loopback (`HOST=0.0.0.0`, a LAN compose port, a reverse
  proxy): set a long random `VULNSIGHT_API_TOKEN`, set
  `VULNSIGHT_PUBLIC_HOST` to the DNS name the browser uses, and do not use
  `python app.py --debug`.
- `python app.py` refuses a non-loopback bind while credentials are loaded
  unless **both** `VULNSIGHT_EXPOSE=1` and `VULNSIGHT_API_TOKEN` are set.

Relevant knobs (see `.env.example`):

| Variable | Role |
| --- | --- |
| `VULNSIGHT_API_TOKEN` | Required on `POST /api/*` (`X-VulnSight-Token` or `Authorization: Bearer`) |
| `VULNSIGHT_EXPOSE` | Opt-in for `python app.py` on a non-loopback `HOST` |
| `VULNSIGHT_PUBLIC_HOST` | Extra CSRF Origin hosts (comma-separated DNS names) |
| `VULNSIGHT_SEARCH_RATE` / `VULNSIGHT_AI_RATE` | Per-IP limits (default 30 / 20 per 60s) |

## What the app already enforces

- JSON `Content-Type` on mutating APIs (rejects simple form CSRF).
- Origin/Referer parsed with `urlsplit` (not a prefix match); `Sec-Fetch-Site: cross-site` is blocked.
- Generic client errors for AI provider HTTP bodies and `gh` stderr; raw detail stays in server logs.
- CSP (`script-src 'self'` + per-response nonce), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
- CSV export prefixes formula-like cells with `'`.

## Secrets and data

| Item | Handling |
| --- | --- |
| `.env` | Git-ignored. Placeholders only in `.env.example`. |
| `advisories.db` / `osv_cache/` | Local cache of public advisory data plus AI verdicts. Git-ignored. Not a secrets store, but do not publish the files if they contain internal notes you added. |
| UI token prompt | `VULNSIGHT_API_TOKEN` is never rendered into HTML; the tab stores it in `sessionStorage` only. |

## Safe harbor

Good-faith research against your own checkout, or a loopback instance you
control, is welcome. Do not use findings to access other people's keys,
GitHub accounts, or AI quotas.
