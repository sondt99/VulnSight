# VulnSight

**Browse the vulnerability advisory databases by *bug class*, not by keyword.**

VulnSight queries the [GitHub Advisory Database](https://github.com/advisories)
(GHSA) and [OSV.dev](https://osv.dev), filters advisories by the **CWE set that
defines each bug class** (Broken Access Control, SQL injection, XSS, SSTI, …),
scopes them by **ecosystem and package**, and optionally runs an **LLM pass** to
confirm each advisory really matches the class you asked for.

It grew out of a concrete need: *find BAC / BOLA / BFLA / IDOR advisories in Java
(Maven) and Go, then expand to injection classes* — without drowning in the
noise of advisories that never say "BOLA" in their title.

## Why not just search by title?

Advisory titles are inconsistent — many real Broken Access Control bugs never
contain the words "BOLA", "BFLA", or "IDOR", so keyword search silently misses
them. But every reviewed advisory *is* tagged with one or more **CWE** IDs, so
VulnSight filters on the CWE set that characterises each bug class instead. See
[`modules/cwe_categories.py`](modules/cwe_categories.py) for the mappings.

CWE tagging is still imperfect (umbrella CWEs like `CWE-284` are vague, and
source-native records often carry no CWE at all). That's what the **AI refinement
pass** is for: it reads each advisory and returns a structured verdict
(`is_match / confidence / vuln_type / reason`) you can filter and sort on.

## Features

- **Bug-class → CWE filtering** across GHSA + NVD + OSV.dev, merged through
  the full CVE/GHSA/OSV alias graph without discarding source metadata.
- **Scope by** ecosystem (Maven/Go/npm/pip/…), package, severity, publish date.
- **AI refinement** — confirm true matches across every selected bug class and surface source-native records
  (`GO-`, `RUSTSEC-`, `PYSEC-`) that carry no CWE tag at all.
- **Consistent filters** — publish date, package and severity are enforced on
  normalized records from every source; long NVD date ranges are split safely.
- **SQLite cache** — advisories and AI verdicts persist, so repeat searches are
  fast and never re-spend AI tokens on an advisory already classified.
- **Export** the filtered list as CSV or JSON.
- **Offline test suite** — 120+ unit tests, no network or credentials required.

## Quick start

```bash
cd VulnSight
cp .env.example .env      # then set AI_TOKEN for the AI pass (optional)
./run.sh                  # creates a venv, installs Flask, launches
# open http://127.0.0.1:5000
```

**Docker**

```bash
cp .env.example .env                          # optional AI / NVD keys
GH_TOKEN=$(gh auth token) docker compose up --build
# open http://127.0.0.1:5000
```

Compose publishes the port on **loopback only** (`127.0.0.1:5000`). The
container cannot reuse a host `gh auth login` (the token lives in the OS
keyring). Pass `GH_TOKEN` on the command line or put it in `.env`. Advisory
cache and OSV zips persist in the `vulnsight-data` volume.

If you change the compose bind to expose the port on the LAN, set
`VULNSIGHT_API_TOKEN` in `.env` so `/api/search` and `/api/ai/*` require
the `X-VulnSight-Token` header. `python app.py` with `HOST` other than
loopback refuses to start while credentials are loaded unless both
`VULNSIGHT_EXPOSE=1` and `VULNSIGHT_API_TOKEN` are set.

**Requirements**

- [`gh` CLI](https://cli.github.com/) installed and authenticated
  (`gh auth login`) — used for all GHSA fetches.
- Python 3.9+.
- *(Optional)* AI credentials in `.env` to enable the **Refine with AI** button.

### AI provider (optional)

The AI pass talks to an Anthropic-Messages-compatible endpoint. Configure it in
`.env` (never commit real tokens — `.env` is git-ignored):

```shell
CVE_AI_PROVIDER=anthropic
AI_BASE_URL=https://your-ai-endpoint.example.com
AI_TOKEN=<your token — keep it in .env only>
AI_model=model-xyz
```

## Layout

```
app.py        thin Flask entry point (routes only)
modules/      core logic: search orchestration, GHSA/OSV clients, CWE map,
              CVSS scoring, SQLite cache, AI classifier
static/       style.css + app.js
templates/    index.html (page shell)
tests/        per-module offline unit tests
```

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v   # full suite, offline
```

## More

- **[USAGE.md](USAGE.md)** — full UI walkthrough, data-source details, the list
  of shipped bug classes, and coverage notes.
- **[SECURITY.md](SECURITY.md)** — how to report vulnerabilities, threat model,
  and how to run this with credentials without exposing the port.
- Extend or tune bug classes in
  [`modules/cwe_categories.py`](modules/cwe_categories.py).
