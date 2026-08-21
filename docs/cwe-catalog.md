# CWE catalog

## What ships

`modules/cwe_catalog.py` is a **generated** table of MITRE's complete CWE
weakness list:

| | |
|---|---|
| Source | `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` |
| Version | CWE **4.20** (released 2026-04-30) |
| Weaknesses | **969** total; 25 deprecated |
| Offered in the picker | **944** (deprecated ones are hidden) |
| With community aliases | 97 |
| File size | ~70 KiB of Python |

Three tables:

- `NAMES` — every CWE id → official name, **including deprecated ones**, so a
  historical advisory tag still renders a label instead of a bare number.
- `ALIASES` — community terms, taken from MITRE's own `Alternate_Terms` plus a
  small curated table for terms MITRE never spells out. This is why `IDOR` and
  `BOLA` find `CWE-639`: MITRE lists both as alternate terms for it.
- `ABSTRACTION` — Pillar / Class / Base / Variant / Compound, shown in the picker
  so an umbrella CWE is obvious at a glance.

Deprecated ids stay in `NAMES` but are excluded from the picker and from
`picker_catalog()`. They remain valid query targets, because advisories still
carry them.

## How it reaches the browser

`GET /api/cwes` serves the table once as compact column-oriented rows:

```json
{
  "version": "4.20",
  "columns": ["id", "label", "aliases", "level"],
  "rows": [["639", "Authorization Bypass Through User-Controlled Key",
            "Insecure Direct Object Reference|IDOR|Broken Object Level Authorization|BOLA|Horizontal Authorization",
            "Base"]]
}
```

~66 KB, served with a version `ETag` and `Cache-Control: private, max-age=86400`,
so a reload revalidates to `304`. The page itself stays ~51 KB because the
searchable text is **not** duplicated into the HTML.

The consequence that matters: search runs entirely in the browser. Measured at
**0.5–0.9 ms per keystroke** across 944 rows plus 29 classes, so there is no
debounce and no request per keystroke.

## Ranking

Higher wins. Ties break toward the lower CWE id.

| Match | Score |
|---|---|
| Exact CWE id | 2000 |
| Id prefix | 1200 − id length |
| Exact name or alias | 900 |
| Name or alias starts with the query | 800 |
| Query at a word boundary | 700 |
| Every word present (multi-word query) | 600 |
| Substring anywhere | 500 |
| **+60** | the row is a curated bug class |
| **+30** | the CWE is already covered by a curated class |

The two bonuses encode a judgement: a curated class carries an AI-grade
definition and a wider CWE set, so it is usually the better query target. That is
why "prototype pollution" surfaces the **PROTO** class above `CWE-1321`, with the
CWE itself immediately below.

`cwe-639`, `CWE 639` and `639` are all treated as the id form.

## Ad-hoc single-CWE classes

Any CWE can act as its own bug class using the key `cwe:<id>`:

```jsonc
POST /api/search
{"categories": ["bac", "cwe:1321"], "ecosystem": "npm"}
```

This is not just a filter shortcut. A `cwe:<id>` target is a first-class class
everywhere downstream:

- **Search** — resolves to exactly that CWE.
- **AI pass** — gets a real prompt built from the CWE's official MITRE name and
  aliases, so the verdict means something. (An earlier design added extra CWEs to
  the query but gave the AI nothing to score them against.)
- **Verdict cache** — stored under the `cwe:<id>` key like any other class.
- **OSV-native prefilter** — keywords derived from the CWE's aliases and the
  parenthesised short form MITRE puts in many names.

Rules enforced server-side:

- Canonical form only: `cwe:639`. No leading zeros, at most 7 digits, positive.
- Case-insensitive on input but **folded to one key** — `CWE:639` and `cwe:639`
  become the same category, so a verdict is never computed or cached twice.
- The id must exist in the MITRE catalog. `cwe:9999999` is rejected with a clear
  400 rather than reaching the model as a class with no definition. Deprecated
  ids are accepted.

## Regenerating the table

When MITRE publishes a new release:

```bash
python tools/generate_cwe_catalog.py                 # downloads the latest
python tools/generate_cwe_catalog.py path/to.xml     # or use a local copy
python -m pytest tests/test_cwe_categories.py        # verifies the invariants
```

The generator is deterministic — the same input produces a byte-identical module.
It excludes Views and Categories (advisories are tagged with Weaknesses), splits
`Alternate_Terms` like `"Insecure Direct Object Reference / IDOR"` into separate
searchable terms, and drops an alias already contained in the name because it
adds nothing to search.

`EXTRA_ALIASES` at the top of the generator is the curated part: terms the
community uses that MITRE does not list, such as `BFLA` for `CWE-862`. It fails
loudly if it references a CWE that does not exist.

After regenerating, the test suite will tell you if a curated bug class now
points at an id MITRE removed or deprecated.
