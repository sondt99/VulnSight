# VulnSight

**Search vulnerability advisories by *bug class*, not by keyword.**

Advisory titles are inconsistent. A real Broken Access Control bug is often
written up without the words "BOLA", "BFLA" or "IDOR" appearing anywhere, so
keyword search misses it silently — the worst failure mode for a triage tool,
because the result looks like an answer.

Every reviewed advisory *is* tagged with one or more **CWE** IDs. VulnSight
filters on the CWE set that characterises a bug class, merges GHSA + NVD +
OSV.dev through their alias graph, and can then run an **LLM pass** that reads
each advisory and states whether the root cause really is the class you asked
for.

```
you ask:  "Broken Access Control, Maven, last year"
          → 15 CWEs → GHSA + NVD + OSV → merged & de-duplicated
          → optional AI pass: is_match / confidence / vuln_type / reason
          → CSV / JSON
```

---

## Quick start

```bash
cp .env.example .env      # optional: AI credentials for the "Refine with AI" pass
./run.sh                  # creates a venv, installs Flask, launches
# open http://127.0.0.1:5000
```

Needs Python 3.9+ and the [`gh` CLI](https://cli.github.com/) authenticated
(`gh auth login`) — every GHSA fetch goes through it.
[Docker and configuration →](docs/getting-started.md)

## What you get

- **The whole CWE catalog is searchable.** Type a code (`639`), MITRE's official
  name ("prototype pollution"), or a community alias (`IDOR`, `BOLA`, `SSRF`,
  `XXE`) and pick from all **944 weaknesses of CWE 4.20**. The catalog is
  searched in the browser — ~0.5 ms per keystroke, no round trip.
- **29 curated bug classes** in 7 groups, each with a high-precision *core* CWE
  set, a wider *extended* set, and the terms people actually type (`toctou`,
  `__proto__`, `md5`, `webshell`). Any single CWE also works as an ad-hoc class
  via `cwe:<id>` — filtered on *and* AI-scored.
- **Four sources, one queue.** GHSA (server-side CWE filter), NVD (CVSS/CPE/KEV),
  the OSV bulk export, and **OSV source-native records that carry no CWE at all**
  and are only reachable through the AI path.
- **An AI pass you can audit.** Each verdict carries the categories it was scored
  against; change the query and the UI marks the old verdicts stale instead of
  letting them filter your results.
- **Costs are stated before they are spent.** The AI pass is metered
  (`categories × advisories`), capped server-side, and every control that would
  spend budget says so first.
- **Exports that stand on their own** — CSV/JSON including which class matched
  and whether scoring partially failed.

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Install, Docker, requirements, first search |
| [Configuration](docs/configuration.md) | Every environment variable, with defaults |
| [Using the UI](docs/usage.md) | The full walkthrough, control by control |
| [Bug classes](docs/bug-classes.md) | All 29 classes, and how to add one correctly |
| [CWE catalog](docs/cwe-catalog.md) | Where the 944 CWEs come from, `cwe:<id>`, regeneration |
| [Data sources](docs/data-sources.md) | GHSA / NVD / OSV / OSV-native, and honest coverage limits |
| [AI classification](docs/ai-classification.md) | Prompt, verdict cache, key rotation, cost controls |
| [HTTP API](docs/api.md) | Every endpoint, request and response shape |
| [Architecture](docs/architecture.md) | Module map and the search pipeline end to end |
| [Testing](docs/testing.md) | 270 offline tests + 21 browser tests, and how to verify a change |
| [Operations](docs/operations.md) | Exposure, caches, quotas, troubleshooting |
| [SECURITY.md](SECURITY.md) | Threat model and how to report a vulnerability |

## Tests

```bash
.venv/bin/python -m unittest discover -s tests    # 270 tests, offline, no credentials
```

The 21 browser tests in `tests/test_ui_e2e.py` skip themselves unless Playwright
and a browser are installed — see [Testing](docs/testing.md).

## Status and limits

This is a research tool for a single operator on `localhost`. It binds loopback
by default and refuses to serve credentials on a public interface without an
explicit token — read [SECURITY.md](SECURITY.md) before exposing it.

Known limits are documented rather than hidden: CWE tagging is imperfect
(umbrella CWEs like `CWE-284` sweep in unrelated bugs, which is what the AI pass
is for), OSV's CWE-tagged records largely mirror GHSA, and sort order interacts
with per-source truncation. See
[Data sources](docs/data-sources.md#honest-coverage-notes) and
[Architecture](docs/architecture.md#known-limits).
