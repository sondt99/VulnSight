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
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Category -> metadata
# ---------------------------------------------------------------------------
# "core"     : CWEs that almost always mean this bug class (high precision)
# "extended" : broader CWEs that often but not always belong (higher recall,
#              more noise -> good candidates for the AI refinement pass)
# ---------------------------------------------------------------------------

CATEGORIES: dict[str, dict] = {
    "bac": {
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
        "label": "SQL Injection",
        "description": "Improper neutralization of SQL / NoSQL query elements.",
        "core": ["89"],
        "extended": ["564", "943"],  # Hibernate SQLi, improper query neutralization
    },
    "xss": {
        "label": "Cross-Site Scripting (XSS)",
        "description": "Improper neutralization of input during web page generation.",
        "core": ["79"],
        "extended": ["80", "83", "87", "116"],
    },
    "ssti": {
        "label": "Server-Side Template Injection / Code Injection",
        "description": "Template injection and dynamic code evaluation flaws.",
        "core": ["1336", "94"],  # SSTI, Improper Control of Code Generation
        "extended": ["95", "96", "917"],  # eval injection, EL injection
    },
    "cmdi": {
        "label": "OS / Command Injection",
        "description": "Improper neutralization of OS command / argument elements.",
        "core": ["77", "78"],
        "extended": ["88"],  # Argument injection
    },
    "ssrf": {
        "label": "Server-Side Request Forgery (SSRF)",
        "description": "Server can be coerced into making unintended requests.",
        "core": ["918"],
        "extended": [],
    },
    "pathtraversal": {
        "label": "Path Traversal / File Disclosure",
        "description": "Improper limitation of a pathname to a restricted directory.",
        "core": ["22"],
        "extended": ["23", "36", "73", "434"],  # incl. unrestricted upload
    },
    "deserialization": {
        "label": "Insecure Deserialization",
        "description": "Deserialization of untrusted data leading to RCE / DoS.",
        "core": ["502"],
        "extended": [],
    },
    "xxe": {
        "label": "XML External Entity (XXE)",
        "description": "Improper restriction of XML external entity references.",
        "core": ["611"],
        "extended": ["827", "776"],
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
}


def category_keywords(categories: list[str]) -> list[str]:
    kws: list[str] = []
    for c in categories:
        kws += KEYWORDS.get(c, [])
    return [k.lower() for k in kws]


def category_cwes(category: str, include_extended: bool = True) -> list[str]:
    """Return the CWE numeric IDs for a category."""
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
    """Human label for a bare or prefixed CWE id (best effort)."""
    num = normalize_cwe_id(cwe_id)
    return _CWE_NAMES.get(num, f"CWE-{num}")


def all_cwes() -> list[dict]:
    """Full CWE catalog we know labels for, sorted numerically.

    Powers the 'extra CWEs' tick-list in the UI so the user never types a CWE.
    """
    return [
        {"id": k, "label": v}
        for k, v in sorted(_CWE_NAMES.items(), key=lambda kv: int(kv[0]))
    ]


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


# Ready-made scenarios: one click fills categories + ecosystem + date window.
SCENARIOS: list[dict] = [
    {"key": "java_bac_1y", "label": "Java · BAC · last year",
     "categories": ["bac"], "ecosystem": "maven", "published": "1y",
     "include_extended": True},
    {"key": "go_bac_1y", "label": "Go · BAC · last year",
     "categories": ["bac"], "ecosystem": "go", "published": "1y",
     "include_extended": True},
    {"key": "java_inj_1y", "label": "Java · Injection (SQLi/XSS/SSTI/CMDi)",
     "categories": ["sqli", "xss", "ssti", "cmdi"], "ecosystem": "maven",
     "published": "1y", "include_extended": False},
    {"key": "go_inj_1y", "label": "Go · Injection (SQLi/SSTI/CMDi)",
     "categories": ["sqli", "ssti", "cmdi"], "ecosystem": "go",
     "published": "1y", "include_extended": False},
    {"key": "java_bac_all", "label": "Java · BAC · all time (core only)",
     "categories": ["bac"], "ecosystem": "maven", "published": "any",
     "include_extended": False},
    {"key": "crit_bac_all", "label": "Any · BAC · critical only",
     "categories": ["bac"], "ecosystem": "any", "published": "any",
     "include_extended": True, "severity": "critical"},
]


# Minimal name table for badges in the UI (covers the CWEs we filter on).
_CWE_NAMES: dict[str, str] = {
    "22": "Path Traversal",
    "23": "Relative Path Traversal",
    "36": "Absolute Path Traversal",
    "73": "External Control of File Name",
    "77": "Command Injection",
    "78": "OS Command Injection",
    "79": "Cross-site Scripting",
    "80": "Basic XSS",
    "83": "Improper Neutralization of Script in Attributes",
    "87": "Improper Neutralization of Alternate XSS Syntax",
    "88": "Argument Injection",
    "89": "SQL Injection",
    "94": "Code Injection",
    "95": "Eval Injection",
    "96": "Static Code Injection",
    "116": "Improper Encoding of Output",
    "200": "Information Exposure",
    "266": "Incorrect Privilege Assignment",
    "269": "Improper Privilege Management",
    "284": "Improper Access Control",
    "285": "Improper Authorization",
    "287": "Improper Authentication",
    "306": "Missing Authentication for Critical Function",
    "425": "Forced Browsing",
    "434": "Unrestricted File Upload",
    "502": "Deserialization of Untrusted Data",
    "552": "Files/Directories Accessible to External Parties",
    "564": "Hibernate SQL Injection",
    "611": "XML External Entity (XXE)",
    "639": "Authorization Bypass Through User-Controlled Key (IDOR/BOLA)",
    "668": "Exposure of Resource to Wrong Sphere",
    "732": "Incorrect Permission Assignment for Critical Resource",
    "776": "XML Entity Expansion",
    "827": "Improper Control of Document Type Definition",
    "862": "Missing Authorization (BFLA)",
    "863": "Incorrect Authorization",
    "913": "Improper Control of Dynamically-Managed Code Resources",
    "917": "Expression Language Injection",
    "918": "Server-Side Request Forgery (SSRF)",
    "943": "Improper Neutralization of Data in Query Logic",
    "1220": "Insufficient Granularity of Access Control",
    "1336": "Server-Side Template Injection (SSTI)",
}
