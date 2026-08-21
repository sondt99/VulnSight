# Using the UI

The left rail builds a query; the right column is the result queue. Nothing is
fetched until you press one of the two buttons at the bottom of the rail.

## 1 · Find a bug

The search box at the top of the rail matches **both** the 29 curated bug
classes and all **944 weaknesses of CWE 4.20**, by:

| You type | It matches |
|---|---|
| `639`, `CWE-639`, `13` | CWE **code**, exact then prefix |
| `authorization bypass`, `prototype pollution` | MITRE's **official name** |
| `IDOR`, `BOLA`, `BFLA`, `SSRF`, `XXE`, `SSTI`, `SQLi` | **community aliases** |

`↑`/`↓` moves, `Enter` adds, `Esc` closes. Picking a **class** ticks its
checkbox; picking a **CWE** adds a chip. Both show up under **Query targets**.

Ranking puts an exact CWE id first, then id prefixes, then exact/prefix name or
alias matches, then "contains every word". A curated class outranks a lone CWE on
an equal textual match, because the class carries a real definition for the AI
and a wider CWE set — so typing "prototype pollution" offers the **PROTO** class
above `CWE-1321`, with the CWE right below it.

The whole catalog is fetched once from `/api/cwes` and searched in the browser.
Measured at **~0.5 ms per keystroke** over 944 rows, so there is no debounce and
no round trip. Details: [CWE catalog](cwe-catalog.md).

## 2 · Query targets

Everything you have selected, as removable chips. The line above them states the
cost of the AI pass you are setting up:

> `3 selected · 3 AI passes per advisory`

That number is literal: each selected target is scored separately per advisory,
so three targets over 100 advisories is 300 model calls. See
[AI classification → cost](ai-classification.md#what-a-pass-costs).

## 3 · Bug classes

29 classes in 7 groups, `Broken Access Control` preselected. The **filter box**
narrows the list by label, description, group name **or** community term — so
`toctou`, `__proto__`, `md5`, `dll hijack` and `webshell` all find their class.

A class you have already selected is **never hidden by the filter**: it is part
of your query, so it stays visible (with a thin accent bar marking that it was
kept rather than matched).

**Include extended CWEs** — on gives higher recall with more noise, off keeps
only the high-precision *core* set. It only affects curated classes; a CWE you
picked yourself is always used exactly as-is.

Full table: [Bug classes](bug-classes.md).

## 4 · Sources

Tick any combination of GHSA, NVD, OSV and OSV-native. The NVD hint below the
checkbox computes the real cost of your current selection
(`N CWEs × ~7 s` without an API key), because NVD is the one source whose cost
scales with how many CWEs you picked.

**Force-refresh OSV cache** re-downloads the bulk export: ~10 MB for maven/go,
**~220 MB for npm**. Selecting both `OSV` and `OSV native` downloads it once, not
twice.

What each source actually adds: [Data sources](data-sources.md).

## 5 · Scope and options

Ecosystem (`maven` = Java, `go` = Golang), an optional **exact** package name,
severity, publish window, max results (1–500), sort field and direction, and
advisory type (reviewed / unreviewed / malware).

Two honest caveats about sort, both consequences of merging truncated sources:

- Sorting by **EPSS** or **CVE ID** ranks the page you fetched, not the whole
  corpus: each source truncates to `max_results` *before* the merge, and GHSA
  only supports `published`/`updated` server-side.
- **Oldest first** is honoured by GHSA but ignored by OSV and NVD, which always
  return newest-first, so a mixed-source query in ascending order is a mixture.

## 6 · Search

- **Search raw advisories** — free. Fetch, merge, de-duplicate, show. `⌘/Ctrl +
  Enter` does exactly this (the shortcut is printed on this button and runs
  this button).
- **Run intelligent scan** — picks optimal sources *for that run only*, searches,
  runs the AI pass, then keeps confirmed matches. It **costs AI budget**. Your
  source checkboxes are not modified; a toast tells you what it used.

The summary line above the results tracks what is actually on screen —
`50 of 100 shown` once a filter hides something — and says `capped at 100` when
the page is full, because "0 hits for CWE-639" and "truncated before CWE-639"
mean very different things during triage.

## 7 · Refine with AI

Sends each advisory to the model, which returns
`is_match / confidence / vuln_type / reason` per selected target. Verdicts are
cached in SQLite, so re-running the same query is free.

**Do not skip this for BAC.** Umbrella CWEs like `CWE-284` also tag SSRF, ReDoS,
crypto bugs and header issues. A live pass over the 272 newest BAC-tagged
advisories dropped 25 that were not access control at all.

Three things protect you here:

- **Stale verdicts are flagged, not used.** Change the selection after scoring
  and a banner appears; `Confirmed only` is disabled until you re-score. A
  verdict for "BAC" says nothing about "SQL injection", and it must not filter
  your results as if it did.
- **Confirmed only asks first.** It looks like a local filter but has to score
  the queue, so it states the call count and waits for confirmation — and
  un-ticks itself if the pass fails, rather than leaving you with an empty queue.
- **Failures are not reported as zero.** A failed pass says so instead of
  claiming "0 confirmed matches", which reads as "nothing is vulnerable".

Per-card **Retry** appears on any advisory whose scoring errored, next to a
plain-language reason (quota/rate-limit errors are named as such).

Details: [AI classification](ai-classification.md).

## 8 · Recent searches

Every successful search lands at the top of the rail: targets, ecosystem, hit
count, and — once you run the AI pass — the confirmed count. Click a row to
restore every filter and re-run it; `×` forgets it; **Clear** empties the list.

- Kept in `localStorage` (last 12, de-duplicated). It never leaves the browser.
- Rows are keyed by a signature of the query, so two tabs cannot delete or
  restore each other's wrong row.
- A restored query is re-validated before it is sent, and `Force-refresh OSV
  cache` is deliberately **not** replayed — a click should not trigger a 220 MB
  download. A toast says so.

## 9 · The result card

| Element | Meaning |
|---|---|
| Left bar + `CRITICAL/HIGH/…` | Severity (highest across sources) |
| `GHSA`, `GHSA+NVD` | Which sources contributed |
| `KEV / EXPLOITED` | In CISA's Known Exploited Vulnerabilities catalog |
| `CWE-639 Authorization Bypass…` | Code **and** name, inline — not tooltip-only |
| `NO CWE · AI` | OSV-native record with no CWE; only the AI pass can classify it |
| `WITHDRAWN 2024-09-20` | Retired advisory; the card is de-emphasised |
| `EPSS 94.12% · p100` | Exploit-prediction score and percentile. Absent when there is no data — it is never rendered as a measured `0.00%` |
| Verdict block | `Confirmed match` / `Not a match` / `Incomplete score` / `AI error`, with a confidence bar coloured by state |

The confidence bar is coloured per verdict, not brand-coloured: a 97 %-confident
**non**-match draws a long grey bar, not a long green one.

## 10 · Export

CSV, JSON, or "CSV / matches" (AI-confirmed only). Exports exactly what is
visible, in the order shown. CSV is Excel-friendly (UTF-8 BOM, RFC-4180 quoting,
formula-injection neutralised) and includes:

`ai_match`, `ai_confidence`, `ai_vuln_type`, `ai_reason`,
`ai_scored_categories`, `ai_matched_category`, `ai_has_errors`

The last three exist so a CSV can be told apart from one scored against a
different bug class, and so a partial failure is visible after the fact.

## Keyboard

| Key | Action |
|---|---|
| `⌘/Ctrl + Enter` | Run the free raw search |
| `↑` `↓` | Move within the CWE finder |
| `Enter` | Add the highlighted target (never starts a search) |
| `Esc` | Close the finder popup, then the filter panel |
| `Tab` | Leaves the finder and dismisses its popup |
