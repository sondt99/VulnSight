# Bug classes

A bug class is a named root cause plus the CWE set that identifies it. It is the
unit you search by, and the unit the AI pass judges against.

Each class carries:

| Field | Used for |
|---|---|
| `code` | the short badge in the picker's fixed-width column (`BAC`, `DESER`) |
| `group` | the heading it is listed under |
| `label` | the display name — **and the class name given to the AI** |
| `description` | **the class definition given to the AI**, so it must be precise enough to judge a borderline advisory |
| `core` | CWEs that almost always mean this class — high precision |
| `extended` | CWEs that often but not always belong — higher recall, more noise |
| `KEYWORDS` | text prefilter for OSV-native records, which carry no CWE at all; also what the picker's filter matches on |

`core` alone is what you get with **Include extended CWEs** off.

## The 29 shipped classes

`~` marks the extended set.

#### Injection

| Key | Code | Class | Core | Extended |
|---|---|---|---|---|
| `sqli` | `SQLI` | SQL Injection | 89 | 564, 943 |
| `xss` | `XSS` | Cross-Site Scripting (XSS) | 79 | 80, 83, 87, 116 |
| `ssti` | `SSTI` | Server-Side Template Injection / Code Injection | 1336, 94 | 95, 96, 917 |
| `cmdi` | `CMDI` | OS / Command Injection | 77, 78 | 88 |
| `deserialization` | `DESER` | Insecure Deserialization | 502 | — |
| `xxe` | `XXE` | XML External Entity (XXE) | 611 | 827, 776 |
| `queryinj` | `QINJ` | LDAP / XPath / XQuery Injection | 643, 90 | 91, 652 |
| `crlf` | `CRLF` | CRLF / Header Injection & Request Smuggling | 93, 113 | 117, 444 |
| `protopollution` | `PROTO` | Prototype Pollution | 1321 | 915 |

#### Access control & auth

| Key | Code | Class | Core | Extended |
|---|---|---|---|---|
| `bac` | `BAC` | Broken Access Control (BAC / BOLA / BFLA / IDOR) | 284, 285, 639, 862, 863, 732, 306, 287 | 269, 266, 668, 1220, 552, 425, 913 |
| `csrf` | `CSRF` | Cross-Site Request Forgery (CSRF) | 352 | 1275 |
| `cors` | `CORS` | CORS / Origin Validation Failure | 942 | 346, 1385 |
| `session` | `SESS` | Session Management Flaws | 384 | 613, 539, 488 |
| `hardcodedcreds` | `CREDS` | Hard-coded / Default Credentials | 798 | 259, 321, 1392 |
| `clickjacking` | `CLICK` | Clickjacking / UI Redressing | 1021 | — |

#### Files & server-side requests

| Key | Code | Class | Core | Extended |
|---|---|---|---|---|
| `ssrf` | `SSRF` | Server-Side Request Forgery (SSRF) | 918 | — |
| `pathtraversal` | `PATH` | Path Traversal / File Disclosure | 22 | 23, 36, 73, 434 |
| `openredirect` | `OPRED` | Open Redirect | 601 | 610 |
| `upload` | `UPLD` | Unrestricted File Upload | 434 | 646, 351, 436 |
| `searchpath` | `SPATH` | Untrusted Search Path / Library Hijack | 426, 427 | 428, 114 |

#### Crypto & secrets

| Key | Code | Class | Core | Extended |
|---|---|---|---|---|
| `crypto` | `CRYPT` | Broken Cryptography & Verification | 327, 347, 295 | 326, 328, 916, 261, 759, 760, 780, 323, 324 |
| `randomness` | `RAND` | Insufficient Randomness | 330, 338 | 335, 340, 341, 1241 |
| `infoleak` | `INFO` | Sensitive Information Disclosure | 200 | 209, 532, 359, 497, 215, 540, 1230 |

#### Memory & concurrency

| Key | Code | Class | Core | Extended |
|---|---|---|---|---|
| `memory` | `MEM` | Memory Safety (OOB / UAF / Double Free) | 787, 125, 416, 415, 476 | 121, 122, 119, 120, 824, 908, 843, 401, 590 |
| `intoverflow` | `INT` | Integer Overflow / Wraparound | 190 | 191, 192, 197, 680, 681 |
| `race` | `RACE` | Race Condition / TOCTOU | 362, 367 | 366, 421, 1223 |

#### Availability

| Key | Code | Class | Core | Extended |
|---|---|---|---|---|
| `redos` | `REDOS` | Regular Expression DoS (ReDoS) | 1333 | 407 |
| `dos` | `DOS` | Denial of Service / Resource Exhaustion | 400, 770 | 409, 674, 789, 405, 834, 617 |

#### Broad / umbrella

| Key | Code | Class | Core | Extended |
|---|---|---|---|---|
| `inputval` | `INPUT` | Improper Input Validation (umbrella) | 20 | 1284, 129, 704 |

139 distinct CWEs are reachable through these classes; the other ~800 are
reachable individually — see [CWE catalog](cwe-catalog.md).

## Reading the tables honestly

**Some `core` entries are umbrella Class-level CWEs** — `CWE-284`, `CWE-200`,
`CWE-400`, `CWE-327`, `CWE-330`, `CWE-362`, `CWE-20`. They are in `core` because
advisories really are tagged with them, not because they are precise. They are
also the main reason the AI pass exists.

**`inputval` is deliberately noisy.** It exists so advisories tagged only with
`CWE-20` are reachable at all, since no specific class covers them. Its own
description tells the model to name the real root cause.

**Classes overlap, and that is fine.** `CWE-434` is `upload`'s core and
`pathtraversal`'s extended; `CWE-352` appears in `csrf` and near `cors`. CWE
resolution de-duplicates, so selecting both costs nothing extra in the query —
but it does cost one extra AI pass per advisory.

## Adding a class

1. Add an entry to `CATEGORIES` in `modules/cwe_categories.py` with all seven
   fields, and a `KEYWORDS` entry.
2. **Verify every CWE id against the real catalog before committing.** A quick
   check that prints MITRE's official name for each id:

   ```python
   from modules.cwe_catalog import NAMES, DEPRECATED, ABSTRACTION
   level = {i: l for l, ids in ABSTRACTION.items() for i in ids}
   for cwe_id in ("352", "1275"):
       print(cwe_id, level.get(cwe_id, "—"), NAMES.get(cwe_id, "*** NOT A WEAKNESS ***"),
             "(deprecated)" if cwe_id in DEPRECATED else "")
   ```

   This is not ceremony. A class drafted for "Security Misconfiguration" was cut
   during development precisely because its anchor, `CWE-16`, turned out to be a
   MITRE *Category* rather than a Weakness — it does not exist in the weakness
   catalog and would have silently matched nothing.
3. Run `python -m pytest tests/test_cwe_categories.py`. The suite enforces:
   - a code that is unique, uppercase and ≤ 5 characters;
   - a non-empty group, label and `core` set;
   - a description of at least 40 characters, because it *is* the AI's definition;
   - keyword prefilters present, lowercase and de-duplicated;
   - canonical bare-numeric CWE ids that all exist in the MITRE catalog;
   - no id in both `core` and `extended`, and no duplicates within either.

### Guidelines that the tests cannot check

- Put a CWE in `core` only if an advisory carrying it is almost certainly this
  class. When in doubt it belongs in `extended`.
- Write the description as a *root cause*, not a name: "unescaped carriage
  returns let the attacker inject headers" gives the model something to judge.
  "CRLF injection" does not.
- If two classes would answer the same question, they should be one class. If a
  class needs the word "other" to describe itself, it probably needs splitting.
- Keywords are substrings matched against advisory text. `"dos"` matches
  "kudos"; prefer `"denial of service"`.

## Ad-hoc single-CWE classes

Anything outside these 29 is still directly queryable as `cwe:<id>`, which is
filtered on *and* AI-scored using that CWE's real MITRE name and aliases:

```jsonc
// POST /api/search
{"categories": ["bac", "cwe:1321"], "ecosystem": "npm"}
```

See [CWE catalog → ad-hoc classes](cwe-catalog.md#ad-hoc-single-cwe-classes).
