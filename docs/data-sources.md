# Data sources

Four sources, merged into one queue and de-duplicated across the full
CVE ↔ GHSA ↔ OSV alias graph. A record found in more than one source is tagged
`GHSA+NVD` and keeps each source's own metadata under `source_records`.

| Source | CWE filter | Cost | What it uniquely adds |
|---|---|---|---|
| **GHSA** | server-side | 1 request per 100 results, CWE-count independent | the primary browse engine; any ecosystem |
| **NVD** | server-side | **1 request per CWE**, ~6.5 s apart without an API key | CVSS v3/v4 vectors, CPE, KEV flags |
| **OSV** | local | one bulk zip per ecosystem, then in-memory | breadth; needs a specific ecosystem |
| **OSV native** | none — there is no CWE | same zip, keyword prefilter | **records with no CWE at all**, only reachable via the AI pass |

## GHSA

Goes through the `gh` CLI, so it inherits your `gh auth login`. The CWE set is
sent as one comma-separated `cwes` parameter, so selecting 1 CWE or 41 costs the
same. Pagination follows the `Link` cursor at `per_page=100` and stops as soon as
`max_results` is reached (hard page cap of 50).

Only `published` and `updated` are supported as server-side sort fields; asking
for EPSS or CVE-ID order sorts the page you fetched, not the corpus.

## NVD

The only source whose cost scales with your CWE selection, because the NVD API
accepts one `cweId` per request. Without `NVD_API_KEY` the client sleeps ~6.5 s
between requests; with a key, ~0.7 s.

| CWEs selected | No API key | With API key |
|---|---|---|
| 1 | ~7 s | ~1 s |
| 18 (all curated classes, core only) | **~4 min** | ~25 s |
| 41 (all classes, extended) | **~9 min** | ~1 min |

The UI computes this for your actual selection and shows it under the NVD
checkbox, so the cost is visible before you commit to it. [Get a free key.](https://nvd.nist.gov/developers/request-an-api-key)

Long publish windows are split into API-compatible 120-day slices and merged
back. Each CWE is fetched with the full result budget and truncation happens
after the merge, so NVD can fetch considerably more than `max_results` before
trimming.

## OSV

Downloads `{ecosystem}/all.zip` from OSV's storage bucket, caches it in
`osv_cache/` for 24 h, and filters locally. Sizes are **not** uniform:

| Ecosystem | Export size |
|---|---|
| maven | ~10 MB |
| go | ~11 MB |
| **npm** | **~220 MB** |

Parsing the zip dominates the cost and is independent of how many CWEs you
selected. The parsed result is memoised in-process (1 h TTL, 5 ecosystems).

Selecting both `OSV` and `OSV native` downloads and parses the export **once**,
even with force-refresh on.

## OSV native

Source-native records — `GO-…`, `RUSTSEC-…`, `PYSEC-…` — that carry **no CWE
tag** and are therefore invisible to every CWE filter, including this tool's
primary mechanism.

They are narrowed by the keyword prefilter of your selected bug classes (see
[Bug classes](bug-classes.md)) and then handed to the AI pass, which is the only
thing that can classify them. Cards show a `NO CWE · AI` badge.

Without the AI pass this source is close to useless, and the search says so with
a warning.

## Honest coverage notes

**OSV largely mirrors GHSA for package ecosystems.** For maven / Go / npm / pip /
crates, OSV's CWE-tagged records are mostly the same `GHSA-…` records. A scan
found **0 extra CWE-tagged records** beyond GHSA for those ecosystems, and Maven
is ~100 % GHSA. So `GHSA` alone and `GHSA+OSV` usually return nearly the same
set, at very different cost.

**The genuine win is OSV native.** Roughly 230 Go, 11.7k PyPI and 347 Rust
records carry no CWE and surface only through the AI path — a live test found 5
real XSS issues in Go native records that CWE filtering shows zero of.

**OSV's other populations are out of scope.** Debian, Ubuntu, Alpine, kernel and
Android records are outside these package ecosystems and are mostly not
application-level access-control or injection bugs.

## Filters applied to every source

`published`, `affects` (package) and `severity` are re-checked on the normalized
records after the merge, so a source with a fuzzier server-side filter cannot
sneak rows past them. Two consequences worth knowing:

- **`affects` is an exact match**, e.g. `org.apache.tomcat:tomcat`. NVD's
  server-side equivalent is a fuzzy keyword search, so the exact post-filter can
  prune a lot of what NVD returned — a `max_results=100` query may legitimately
  end with a handful of rows.
- Truncation happens per source **before** the merge, so the boundary of what you
  see is decided per source, not globally.

## Enrichment

**EPSS** (exploit-prediction scores) are fetched from FIRST for every CVE in the
result set, batched 100 at a time. When sorting by a non-EPSS field the result
set is truncated first, which cuts the number of EPSS requests by up to 4× on a
four-source query. Sorting *by* EPSS necessarily enriches everything first.

An advisory with no EPSS data renders nothing — never a `0.00%`, which would be a
fabricated measurement.

**CVSS** vectors are parsed locally (`modules/cvss.py`, spec-exact v3.0/v3.1
rounding) rather than trusted from whichever source supplied them.
