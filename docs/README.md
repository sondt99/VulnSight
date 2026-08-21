# VulnSight documentation

Start at the top if you are new; each page is self-contained otherwise.

## Running it

- **[Getting started](getting-started.md)** — install, `run.sh`, Docker Compose,
  requirements, and your first search.
- **[Configuration](configuration.md)** — every environment variable the tool
  reads, with its default and what happens when you leave it unset.
- **[Operations](operations.md)** — exposing the port safely, cache sizes and
  where they live, AI quota behaviour, and a troubleshooting table.

## Using it

- **[Using the UI](usage.md)** — the left rail control by control, the result
  card, the AI pass, exports, and the keyboard shortcuts.
- **[Bug classes](bug-classes.md)** — the 29 shipped classes, what each one
  means, and the invariants a new class has to satisfy.
- **[CWE catalog](cwe-catalog.md)** — the full MITRE catalog, how search ranking
  works, `cwe:<id>` ad-hoc classes, and how to regenerate the table.
- **[Data sources](data-sources.md)** — what GHSA, NVD, OSV and OSV-native each
  contribute, their cost, and where coverage genuinely overlaps.
- **[AI classification](ai-classification.md)** — the prompt, the verdict cache
  and why it invalidates, multi-key rotation, and the cost caps.

## Working on it

- **[Architecture](architecture.md)** — module map, the search pipeline end to
  end, and the known limits of the current design.
- **[HTTP API](api.md)** — every endpoint with request/response shapes, useful
  for scripting the tool without the UI.
- **[Testing](testing.md)** — the offline suite, the optional browser suite, and
  how to verify a change properly.

## Conventions used in these docs

- Numbers are measured, not estimated. Where a figure came from a specific run
  (page weight, search latency, wasted API calls) the measurement is stated so
  you can re-run it.
- Limits and failure modes are written down next to the feature they affect,
  not collected in a footnote. If something is approximate or unverified, it
  says so.
