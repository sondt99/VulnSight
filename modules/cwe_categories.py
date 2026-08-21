"""CWE category definitions for GHSA/CVE filtering.

Each category maps a human-friendly bug class to the set of CWE IDs that the
GitHub Advisory Database uses to tag advisories. Filtering by CWE is far more
reliable than filtering by advisory title, because many GHSA entries do not
follow any naming convention.

The GHSA REST API (`GET /advisories`) accepts a comma-separated `cwes` filter
using the bare numeric form ("639") or the prefixed form ("CWE-639"). We store
the bare numeric IDs and prefix them when talking to the AI layer / UI.

Extend this file when you want new bug classes (already seeded with the common
injection families requested in the README).

Beyond these curated classes, any single CWE from the full MITRE catalog can be
used as an ad-hoc class via the ``cwe:<id>`` key (see :func:`cwe_key`). That is
what the UI's CWE search box produces, so "CWE-1321" is a first-class query
target even though no curated bug class covers it.
"""

from __future__ import annotations

import re

from .cwe_catalog import ALIASES, ABSTRACTION, CWE_VERSION, DEPRECATED, NAMES

# ---------------------------------------------------------------------------
# Category -> metadata
# ---------------------------------------------------------------------------
# "code"        : short badge shown in the UI's fixed-width code column, so a
#                 long key like "deserialization" cannot crowd out the CWE name
# "group"       : heading the class is listed under in the picker
# "label"       : also the class name given to the AI
# "description" : also the class *definition* given to the AI, so it has to be
#                 precise enough to judge a borderline advisory against
# "core"        : CWEs that almost always mean this bug class (high precision)
# "extended"    : broader CWEs that often but not always belong (higher recall,
#                 more noise -> good candidates for the AI refinement pass)
#
# Every field is enforced by tests/test_cwe_categories.py. Adding a class also
# needs a KEYWORDS entry below, or OSV-native records will never match it.
# ---------------------------------------------------------------------------
MAX_CATEGORY_CODE_LENGTH = 5

CATEGORIES: dict[str, dict] = {
    "bac": {
        "code": "BAC",
        "group": "Access control & auth",
        "label": "Broken Access Control (BAC / BOLA / BFLA / IDOR)",
        "description": (
            "Authorization and access-control flaws: object-level (BOLA/IDOR), "
            "function-level (BFLA), missing/incorrect authorization, privilege "
            "management and authentication bypass."
        ),
        "core": [
            "284",  # Improper Access Control (umbrella)
            "285",  # Improper Authorization
            "639",  # Authorization Bypass Through User-Controlled Key (IDOR/BOLA)
            "862",  # Missing Authorization (BFLA)
            "863",  # Incorrect Authorization
            "732",  # Incorrect Permission Assignment for Critical Resource
            "306",  # Missing Authentication for Critical Function
            "287",  # Improper Authentication
        ],
        "extended": [
            "269",  # Improper Privilege Management
            "266",  # Incorrect Privilege Assignment
            "668",  # Exposure of Resource to Wrong Sphere
            "1220",  # Insufficient Granularity of Access Control
            "552",  # Files/Directories Accessible to External Parties
            "425",  # Direct Request ('Forced Browsing')
            "913",  # Improper Control of Dynamically-Managed Code Resources
        ],
    },
    "sqli": {
        "code": "SQLI",
        "group": "Injection",
        "label": "SQL Injection",
        "description": "Improper neutralization of SQL / NoSQL query elements.",
        "core": ["89"],
        "extended": ["564", "943"],  # Hibernate SQLi, improper query neutralization
    },
    "xss": {
        "code": "XSS",
        "group": "Injection",
        "label": "Cross-Site Scripting (XSS)",
        "description": "Improper neutralization of input during web page generation.",
        "core": ["79"],
        "extended": ["80", "83", "87", "116"],
    },
    "ssti": {
        "code": "SSTI",
        "group": "Injection",
        "label": "Server-Side Template Injection / Code Injection",
        "description": "Template injection and dynamic code evaluation flaws.",
        "core": ["1336", "94"],  # SSTI, Improper Control of Code Generation
        "extended": ["95", "96", "917"],  # eval injection, EL injection
    },
    "cmdi": {
        "code": "CMDI",
        "group": "Injection",
        "label": "OS / Command Injection",
        "description": "Improper neutralization of OS command / argument elements.",
        "core": ["77", "78"],
        "extended": ["88"],  # Argument injection
    },
    "ssrf": {
        "code": "SSRF",
        "group": "Files & server-side requests",
        "label": "Server-Side Request Forgery (SSRF)",
        "description": "Server can be coerced into making unintended requests.",
        "core": ["918"],
        "extended": [],
    },
    "pathtraversal": {
        "code": "PATH",
        "group": "Files & server-side requests",
        "label": "Path Traversal / File Disclosure",
        "description": "Improper limitation of a pathname to a restricted directory.",
        "core": ["22"],
        "extended": ["23", "36", "73", "434"],  # incl. unrestricted upload
    },
    "deserialization": {
        "code": "DESER",
        "group": "Injection",
        "label": "Insecure Deserialization",
        "description": "Deserialization of untrusted data leading to RCE / DoS.",
        "core": ["502"],
        "extended": [],
    },
    "xxe": {
        "code": "XXE",
        "group": "Injection",
        "label": "XML External Entity (XXE)",
        "description": "Improper restriction of XML external entity references.",
        "core": ["611"],
        "extended": ["827", "776"],
    },
    # ---- Injection -------------------------------------------------------
    "queryinj": {
        "code": "QINJ",
        "group": "Injection",
        "label": "LDAP / XPath / XQuery Injection",
        "description": (
            "Untrusted input concatenated into a non-SQL query language, so the "
            "attacker changes the query's structure: LDAP filters, XPath or "
            "XQuery expressions."
        ),
        "core": ["643", "90"],
        "extended": ["91", "652"],
    },
    "crlf": {
        "code": "CRLF",
        "group": "Injection",
        "label": "CRLF / Header Injection & Request Smuggling",
        "description": (
            "Unescaped carriage returns or newlines let the attacker inject HTTP "
            "headers, split a response, forge log entries, or desynchronise a "
            "proxy from the origin (request smuggling)."
        ),
        "core": ["93", "113"],
        "extended": ["117", "444"],
    },
    "protopollution": {
        "code": "PROTO",
        "group": "Injection",
        "label": "Prototype Pollution",
        "description": (
            "Attacker-controlled keys reach a recursive merge, clone or property "
            "assignment and modify Object.prototype (or another shared object's "
            "attributes), changing behaviour across the whole program."
        ),
        "core": ["1321"],
        "extended": ["915"],
    },

    # ---- Access control & auth -------------------------------------------
    "csrf": {
        "code": "CSRF",
        "group": "Access control & auth",
        "label": "Cross-Site Request Forgery (CSRF)",
        "description": (
            "A state-changing request is accepted using only ambient credentials, "
            "so another site can cause it to be sent on the victim's behalf. "
            "Missing or bypassable anti-CSRF tokens and SameSite gaps."
        ),
        "core": ["352"],
        "extended": ["1275"],
    },
    "cors": {
        "code": "CORS",
        "group": "Access control & auth",
        "label": "CORS / Origin Validation Failure",
        "description": (
            "Cross-origin access control is too permissive or the Origin is "
            "validated incorrectly (reflected origins, null origin, sloppy "
            "prefix or suffix matching), letting an untrusted site read responses."
        ),
        "core": ["942"],
        "extended": ["346", "1385"],
    },
    "session": {
        "code": "SESS",
        "group": "Access control & auth",
        "label": "Session Management Flaws",
        "description": (
            "Session identifiers survive when they should not, or are accepted "
            "when they should not be: session fixation, sessions that never "
            "expire, tokens left valid after logout, sensitive persistent cookies."
        ),
        "core": ["384"],
        "extended": ["613", "539", "488"],
    },
    "hardcodedcreds": {
        "code": "CREDS",
        "group": "Access control & auth",
        "label": "Hard-coded / Default Credentials",
        "description": (
            "A password, API key or cryptographic key is embedded in the shipped "
            "artifact, or a default credential is active out of the box, so every "
            "deployment shares the same secret."
        ),
        "core": ["798"],
        "extended": ["259", "321", "1392"],
    },
    "clickjacking": {
        "code": "CLICK",
        "group": "Access control & auth",
        "label": "Clickjacking / UI Redressing",
        "description": (
            "The UI can be framed or overlaid by another origin, so a victim's "
            "click lands on an action they cannot see."
        ),
        "core": ["1021"],
        "extended": [],
    },

    # ---- Files & server-side requests ------------------------------------
    "openredirect": {
        "code": "OPRED",
        "group": "Files & server-side requests",
        "label": "Open Redirect",
        "description": (
            "A redirect target is taken from user input without validation, so "
            "the application forwards victims to an attacker-chosen site — often "
            "the pivot for phishing or for stealing tokens in the URL."
        ),
        "core": ["601"],
        "extended": ["610"],
    },
    "upload": {
        "code": "UPLD",
        "group": "Files & server-side requests",
        "label": "Unrestricted File Upload",
        "description": (
            "The type, extension or content of an uploaded file is not restricted, "
            "letting the attacker place executable or interpreter-visible content "
            "where the server will run it."
        ),
        "core": ["434"],
        "extended": ["646", "351", "436"],
    },
    "searchpath": {
        "code": "SPATH",
        "group": "Files & server-side requests",
        "label": "Untrusted Search Path / Library Hijack",
        "description": (
            "A library, helper binary or plugin is resolved through a path the "
            "attacker can influence (current directory, writable PATH entry, "
            "unquoted path), so their code is loaded instead."
        ),
        "core": ["426", "427"],
        "extended": ["428", "114"],
    },

    # ---- Crypto & secrets ------------------------------------------------
    "crypto": {
        "code": "CRYPT",
        "group": "Crypto & secrets",
        "label": "Broken Cryptography & Verification",
        "description": (
            "A broken or misapplied cryptographic primitive, or a verification "
            "step that does not actually verify: risky algorithms, weak hashes "
            "for passwords, unchecked signatures, unvalidated certificates."
        ),
        "core": ["327", "347", "295"],
        "extended": ["326", "328", "916", "261", "759", "760", "780", "323", "324"],
    },
    "randomness": {
        "code": "RAND",
        "group": "Crypto & secrets",
        "label": "Insufficient Randomness",
        "description": (
            "A value that must be unguessable is generated from a non-crypto PRNG, "
            "a predictable seed or observable state — tokens, session ids, "
            "password-reset links, nonces."
        ),
        "core": ["330", "338"],
        "extended": ["335", "340", "341", "1241"],
    },
    "infoleak": {
        "code": "INFO",
        "group": "Crypto & secrets",
        "label": "Sensitive Information Disclosure",
        "description": (
            "Data crosses a boundary it should not: secrets in logs or error "
            "messages, internal system detail in responses, credentials in source "
            "or metadata. Umbrella CWE-200 is broad, so confirm the leaked value "
            "is genuinely sensitive."
        ),
        "core": ["200"],
        "extended": ["209", "532", "359", "497", "215", "540", "1230"],
    },

    # ---- Memory & concurrency -------------------------------------------
    "memory": {
        "code": "MEM",
        "group": "Memory & concurrency",
        "label": "Memory Safety (OOB / UAF / Double Free)",
        "description": (
            "Spatial or temporal memory errors in native or unsafe code: reads "
            "and writes outside an allocation, use after free, double free, null "
            "dereference, type confusion."
        ),
        "core": ["787", "125", "416", "415", "476"],
        "extended": ["121", "122", "119", "120", "824", "908", "843", "401", "590"],
    },
    "intoverflow": {
        "code": "INT",
        "group": "Memory & concurrency",
        "label": "Integer Overflow / Wraparound",
        "description": (
            "Arithmetic exceeds the range of its type and wraps, or a conversion "
            "loses sign or precision, so a length or index check is computed on "
            "the wrong value."
        ),
        "core": ["190"],
        "extended": ["191", "192", "197", "680", "681"],
    },
    "race": {
        "code": "RACE",
        "group": "Memory & concurrency",
        "label": "Race Condition / TOCTOU",
        "description": (
            "Concurrent access to a shared resource without adequate "
            "synchronisation, including check-then-use windows where the state "
            "changes between the check and the use."
        ),
        "core": ["362", "367"],
        "extended": ["366", "421", "1223"],
    },

    # ---- Availability ----------------------------------------------------
    "redos": {
        "code": "REDOS",
        "group": "Availability",
        "label": "Regular Expression DoS (ReDoS)",
        "description": (
            "A regular expression with super-linear behaviour is applied to "
            "attacker-controlled input, so a short string costs disproportionate "
            "CPU (catastrophic backtracking)."
        ),
        "core": ["1333"],
        "extended": ["407"],
    },
    "dos": {
        "code": "DOS",
        "group": "Availability",
        "label": "Denial of Service / Resource Exhaustion",
        "description": (
            "Attacker-controlled input drives unbounded memory, CPU, disk or "
            "recursion, or reaches a crash path, making the service unavailable. "
            "Excludes regex-specific cases, which are ReDoS."
        ),
        "core": ["400", "770"],
        "extended": ["409", "674", "789", "405", "834", "617"],
    },

    # ---- Broad ------------------------------------------------------------
    "inputval": {
        "code": "INPUT",
        "group": "Broad / umbrella",
        "label": "Improper Input Validation (umbrella)",
        "description": (
            "Deliberately broad: advisories tagged only with CWE-20 and its "
            "children, where the report does not identify a more specific class. "
            "Expect noise and rely on the AI pass to name the real root cause."
        ),
        "core": ["20"],
        "extended": ["1284", "129", "704"],
    },
}

# Ecosystems the README cares about first (Java=maven, Go=go). The GHSA API
# supports many more; these are surfaced in the UI dropdown.
ECOSYSTEMS: list[str] = [
    "maven",
    "go",
    "npm",
    "pip",
    "composer",
    "rubygems",
    "nuget",
    "rust",
    "erlang",
    "actions",
    "pub",
    "swift",
    "other",
]

SEVERITIES: list[str] = ["low", "medium", "high", "critical"]


# Keyword prefilters per bug class, used for OSV *native* records (GO-/RUSTSEC-/
# PYSEC-…) that carry NO CWE tag and are therefore invisible to CWE filtering.
# We narrow the candidate pool by text match, then let the AI make the call.
KEYWORDS: dict[str, list[str]] = {
    "bac": [
        "authoriz", "authorisation", "access control", "access-control",
        "permission", "idor", "bola", "bfla", "privilege", "escalat", "bypass",
        "unauthenticated", "unauthorized", "unauthorised", "forbidden", "acl",
        "tenant", "cross-namespace", "cross namespace", "improper access",
        "auth check", "authentication bypass", "insecure direct",
    ],
    "sqli": ["sql injection", "sqli", "sql statement", "query injection", "nosql injection"],
    "xss": ["cross-site scripting", "cross site scripting", "xss", "script injection", "html injection"],
    "ssti": ["template injection", "ssti", "expression language", "el injection",
             "code injection", "arbitrary code", "remote code execution via", "eval"],
    "cmdi": ["command injection", "os command", "shell command", "arbitrary command", "argument injection"],
    "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
    "pathtraversal": ["path traversal", "directory traversal", "arbitrary file read",
                      "arbitrary file write", "file disclosure", "zip slip", "arbitrary file"],
    "deserialization": ["deserializ", "unsafe deserialization", "object injection", "unmarshal"],
    "xxe": ["xxe", "xml external entity", "external entity"],
    "queryinj": ["ldap injection", "xpath injection", "xquery injection", "xml injection",
                 "ldap query", "xpath expression"],
    "crlf": ["crlf", "carriage return", "http response splitting", "header injection",
             "log injection", "request smuggling", "log forging"],
    "protopollution": ["prototype pollution", "__proto__", "prototype chain",
                       "object prototype", "constructor.prototype"],
    "csrf": ["csrf", "xsrf", "cross-site request forgery", "cross site request forgery",
             "samesite", "anti-csrf", "state-changing request"],
    "cors": ["cors", "cross-origin", "cross origin", "access-control-allow-origin",
             "origin validation", "permissive cross-domain", "null origin"],
    "session": ["session fixation", "session expiration", "session token", "session id",
                "session identifier", "persistent cookie", "does not invalidate",
                "after logout"],
    "hardcodedcreds": ["hard-coded", "hardcoded", "hard coded", "default credential",
                       "default password", "embedded credential", "static key"],
    "clickjacking": ["clickjack", "ui redress", "x-frame-options", "frame-ancestors",
                     "frame ancestors", "iframe"],
    "openredirect": ["open redirect", "url redirection", "unvalidated redirect",
                     "redirect to untrusted", "arbitrary redirect"],
    "upload": ["unrestricted upload", "arbitrary file upload", "file upload", "webshell",
               "dangerous file type", "upload of a file"],
    "searchpath": ["search path", "dll hijack", "dll injection", "untrusted search",
                   "library hijack", "loads a library", "preload"],
    "crypto": ["cryptograph", "weak hash", "md5", "sha-1", "sha1", "broken cipher",
               "signature verification", "certificate validation", "certificate check",
               "improper verification", "ecb mode", "padding oracle"],
    "randomness": ["insecure random", "weak random", "insufficiently random",
                   "predictable", "math.random", "prng", "weak prng", "predictable token"],
    "infoleak": ["information disclosure", "information leak", "info leak",
                 "sensitive information", "exposure of sensitive", "leaks the",
                 "discloses", "leaked in logs"],
    "memory": ["out-of-bounds", "out of bounds", "use after free", "use-after-free",
               "double free", "null pointer", "null dereference", "buffer overflow",
               "buffer over-read", "heap overflow", "stack overflow", "memory corruption",
               "segmentation fault", "type confusion", "uninitialized memory"],
    "intoverflow": ["integer overflow", "integer underflow", "integer wraparound",
                    "wraparound", "signedness", "truncation of", "overflows"],
    "race": ["race condition", "toctou", "time-of-check", "time of check", "data race",
             "concurrent access", "not thread-safe", "deadlock"],
    "redos": ["redos", "regular expression denial", "catastrophic backtracking",
              "inefficient regular expression", "regex denial", "exponential backtracking"],
    "dos": ["denial of service", "dos attack", "resource exhaustion", "out of memory",
            "memory exhaustion", "cpu exhaustion", "infinite loop", "unbounded",
            "uncontrolled recursion", "stack exhaustion", "decompression bomb", "panic"],
    "inputval": ["improper input validation", "input validation", "insufficient validation",
                 "unvalidated input", "does not validate"],
}


# ---------------------------------------------------------------------------
# Single-CWE pseudo categories ("cwe:639")
# ---------------------------------------------------------------------------
# The UI lets the user search the full MITRE catalog and pick individual CWEs.
# Each pick becomes a category key of the form "cwe:<id>", so one code path
# covers curated classes and ad-hoc CWEs everywhere downstream: CWE resolution,
# the OSV-native keyword prefilter, the AI prompt and the verdict cache.
# ---------------------------------------------------------------------------

CWE_KEY_PREFIX = "cwe:"
MAX_CWE_ID_DIGITS = 7
_CWE_KEY_RE = re.compile(rf"^{CWE_KEY_PREFIX}([1-9][0-9]{{0,{MAX_CWE_ID_DIGITS - 1}}})$")
_PARENTHESISED = re.compile(r"\(([^)]{3,})\)")


def cwe_key(cwe_id: str) -> str:
    """'CWE-639' / '639' -> the pseudo-category key 'cwe:639'."""
    return f"{CWE_KEY_PREFIX}{normalize_cwe_id(str(cwe_id))}"


def parse_cwe_key(category: str) -> str | None:
    """'cwe:639' -> '639'. Returns None for anything that is not a CWE key.

    Callers pass values already validated as strings by ``parse_str_list``.
    """
    match = _CWE_KEY_RE.match(category.strip().lower())
    return match.group(1) if match else None


def is_known_category(category: str) -> bool:
    """True for a curated class key, or a 'cwe:<id>' key MITRE actually defines.

    Requiring the CWE to exist keeps a typo from reaching the AI as the
    contentless class "CWE-9999999" and burning tokens on it. Deprecated IDs are
    accepted: advisories still carry them.
    """
    if category in CATEGORIES:
        return True
    cwe_id = parse_cwe_key(category)
    return cwe_id is not None and cwe_id in NAMES


def canonical_category(category: str) -> str:
    """Fold equivalent spellings of a CWE key into one.

    'CWE:639' and 'cwe:639' must not become two categories: they would be
    filtered on twice, classified twice and cached under two keys.
    """
    cwe_id = parse_cwe_key(category)
    return cwe_key(cwe_id) if cwe_id else category


def category_label(category: str) -> str:
    """Human label for a curated class or a single-CWE pseudo category."""
    cwe_id = parse_cwe_key(category)
    if cwe_id:
        return f"CWE-{cwe_id}: {cwe_label(cwe_id)}"
    return CATEGORIES.get(category, {}).get("label", category)


def category_description(category: str) -> str:
    cwe_id = parse_cwe_key(category)
    if cwe_id:
        aliases = ", ".join(ALIASES.get(cwe_id, ()))
        base = f"MITRE CWE-{cwe_id}: {cwe_label(cwe_id)}."
        return f"{base} Also known as: {aliases}." if aliases else base
    return CATEGORIES.get(category, {}).get("description", "")


def category_keywords(categories: list[str]) -> list[str]:
    """Lowercased text prefilters for the OSV-native (CWE-less) record pool."""
    kws: list[str] = []
    for c in categories:
        cwe_id = parse_cwe_key(c)
        if cwe_id:
            kws += _cwe_keywords(cwe_id)
        else:
            kws += KEYWORDS.get(c, [])
    return list(dict.fromkeys(k.lower() for k in kws if k))


def _cwe_keywords(cwe_id: str) -> list[str]:
    """Text a CWE-less advisory would plausibly use for this weakness.

    The official CWE name rarely appears verbatim in an advisory, so the
    community aliases ("IDOR", "SSRF") and the parenthesised short form MITRE
    puts in many names ("'Cross-site Scripting'") carry most of the signal.
    """
    name = NAMES.get(cwe_id, "")
    terms = [term.strip(" '\"") for term in _PARENTHESISED.findall(name)]
    terms += list(ALIASES.get(cwe_id, ()))
    if name:
        terms.append(name)
    return terms


def category_cwes(category: str, include_extended: bool = True) -> list[str]:
    """Return the CWE numeric IDs for a curated class or a 'cwe:<id>' key."""
    cwe_id = parse_cwe_key(category)
    if cwe_id:
        return [cwe_id]
    cat = CATEGORIES.get(category)
    if not cat:
        return []
    cwes = list(cat["core"])
    if include_extended:
        cwes += cat["extended"]
    # de-dup preserving order
    return list(dict.fromkeys(cwes))


def resolve_cwes(categories: list[str], include_extended: bool = True) -> list[str]:
    """Union of CWE IDs across several categories."""
    seen = set()
    out: list[str] = []
    for cat in categories:
        for c in category_cwes(cat, include_extended):
            if c not in seen:
                seen.add(c)
                out.append(c)
    return out


def normalize_cwe_id(value: str) -> str:
    """Normalize 'CWE-639', 'cwe-639', ' 639 ' -> bare numeric '639'."""
    return value.upper().replace("CWE-", "").strip()


def cwe_label(cwe_id: str) -> str:
    """Official MITRE name for a bare or prefixed CWE id (best effort)."""
    num = normalize_cwe_id(cwe_id)
    return NAMES.get(num, f"CWE-{num}")


def cwe_aliases(cwe_id: str) -> tuple[str, ...]:
    """Community terms for a CWE ('IDOR', 'BOLA') — what people actually type."""
    return ALIASES.get(normalize_cwe_id(cwe_id), ())


def picker_catalog() -> dict:
    """The full CWE catalog in the compact shape the UI's search box consumes.

    Deprecated CWEs keep their label (so historical advisory tags still render
    via :func:`cwe_label`) but are excluded here — they are never a useful
    search target. Rows are column-oriented to keep the payload small; the
    whole table ships to the browser so the search itself needs no round trip.
    """
    level_by_id = {
        cwe_id: level for level, ids in ABSTRACTION.items() for cwe_id in ids
    }
    return {
        "version": CWE_VERSION,
        "columns": ["id", "label", "aliases", "level"],
        "rows": [
            [cwe_id, NAMES[cwe_id], "|".join(ALIASES.get(cwe_id, ())), level]
            for cwe_id, level in sorted(level_by_id.items(), key=lambda kv: int(kv[0]))
            if cwe_id not in DEPRECATED
        ],
    }


# Curated, well-known packages per ecosystem — surfaced as pick-from
# suggestions in the UI so the package field needs no typing.
POPULAR_PACKAGES: dict[str, list[str]] = {
    "maven": [
        "org.apache.tomcat:tomcat",
        "org.apache.tomcat.embed:tomcat-embed-core",
        "org.springframework:spring-web",
        "org.springframework:spring-core",
        "org.springframework.security:spring-security-core",
        "org.springframework.boot:spring-boot",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.apache.struts:struts2-core",
        "org.keycloak:keycloak-core",
        "org.apache.logging.log4j:log4j-core",
        "org.hibernate:hibernate-core",
        "org.eclipse.jetty:jetty-server",
        "com.google.guava:guava",
        "org.apache.shiro:shiro-core",
        "org.apache.cxf:cxf-core",
        "org.jenkins-ci.main:jenkins-core",
    ],
    "go": [
        "github.com/gin-gonic/gin",
        "github.com/gofiber/fiber",
        "github.com/labstack/echo",
        "github.com/hashicorp/vault",
        "github.com/rancher/rancher",
        "k8s.io/kubernetes",
        "github.com/docker/docker",
        "github.com/grafana/grafana",
        "github.com/gogs/gogs",
        "github.com/argoproj/argo-cd",
        "github.com/traefik/traefik",
        "github.com/minio/minio",
        "github.com/goharbor/harbor",
        "github.com/hashicorp/consul",
    ],
    "npm": [
        "next", "express", "lodash", "axios", "react-dom",
        "webpack", "vue", "jsonwebtoken", "passport", "mongoose",
    ],
    "pip": [
        "django", "flask", "requests", "pyyaml", "jinja2",
        "sqlalchemy", "pillow", "cryptography", "urllib3", "werkzeug",
    ],
}
