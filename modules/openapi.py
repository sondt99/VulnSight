"""The OpenAPI description of the HTTP API.

Written by hand, checked by machine. Flask carries no type information about
request or response bodies, so anything claiming to *derive* this document would
be deriving paths and inventing schemas — and an invented schema in an API
description is worse than none, because a client generator will believe it.

What is enforced instead (tests/test_openapi.py):

- every route in ``url_map`` under /api/v1 appears here, and vice versa, so a
  new endpoint cannot ship undescribed;
- the methods match;
- the example search request validates against the documented request schema;
- a real response from the app validates against the documented response schema.

That last one is the point: the document is checked against what the server
actually sends, not against what it was believed to send when it was written.
"""

from __future__ import annotations

from .cwe_categories import CATEGORIES, ECOSYSTEMS, SEVERITIES

API_VERSION = "1.0.0"

_TOKEN_SCHEME = "vulnsightToken"

_ERROR = {
    "type": "object",
    "required": ["error"],
    "properties": {
        "error": {
            "type": "string",
            "description": "Operator-facing message. Never an exception string.",
        }
    },
}

_SEARCH_REQUEST = {
    "type": "object",
    "required": ["categories"],
    "properties": {
        "categories": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 64},
            "description": (
                "Curated bug-class keys and/or `cwe:<id>` for any single MITRE "
                "weakness. Both forms are filtered on and AI-scored."
            ),
        },
        "include_extended": {
            "type": "boolean",
            "default": True,
            "description": "Add each class's wider CWE set to its high-precision core.",
        },
        "ecosystem": {"type": "string", "enum": ["any", *ECOSYSTEMS], "default": "any"},
        "affects": {
            "type": "string",
            "maxLength": 300,
            "nullable": True,
            "description": "Exact, case-insensitive package name match.",
        },
        "severity": {"type": "string", "enum": ["any", *SEVERITIES], "default": "any"},
        "published": {
            "type": "string",
            "description": (
                "`YYYY-MM-DD`, a comparator (`>=`, `>`, `<=`, `<`) plus a date, "
                "or a `from..to` range. Bounds are UTC."
            ),
        },
        "type": {
            "type": "string",
            "enum": ["reviewed", "unreviewed", "malware"],
            "default": "reviewed",
        },
        "sort": {
            "type": "string",
            "enum": ["published", "updated", "cve_id",
                     "epss_percentage", "epss_percentile"],
            "default": "published",
            "description": "An unrecognised value falls back to `published` silently.",
        },
        "direction": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
        "max_results": {
            "type": "integer", "minimum": 1, "maximum": 500, "default": 100,
            "description": "Clamped, not rejected, when out of range.",
        },
        "sources": {
            "type": "array",
            "items": {"type": "string",
                      "enum": ["ghsa", "nvd", "osv", "osv-native"]},
            "default": ["ghsa"],
        },
        "refresh_osv": {
            "type": "boolean",
            "default": False,
            "description": "Re-download the OSV bulk export before searching.",
        },
    },
}

_STATS = {
    "type": "object",
    "required": ["fetched_per_source", "fetched_total", "after_merge",
                 "after_filter", "returned", "truncated"],
    "properties": {
        "fetched_per_source": {
            "type": "object", "additionalProperties": {"type": "integer"},
            "description": "Rows from each source, counted before the merge.",
        },
        "fetched_total": {"type": "integer"},
        "after_merge": {"type": "integer",
                        "description": "After alias de-duplication."},
        "after_filter": {"type": "integer",
                         "description": "After local published/affects/severity."},
        "returned": {"type": "integer", "description": "Equals `count`."},
        "truncated": {
            "type": "boolean",
            "description": (
                "The *local* pipeline dropped rows for `max_results`. It does "
                "NOT mean the source is exhausted: each source truncates on its "
                "own first, so a single-source search usually reports false."
            ),
        },
    },
}

_ADVISORY = {
    "type": "object",
    "properties": {
        "advisory_id": {"type": "string"},
        "ghsa_id": {"type": "string", "nullable": True},
        "cve_id": {"type": "string", "nullable": True},
        "aliases": {"type": "array", "items": {"type": "string"}},
        "sources": {"type": "array", "items": {"type": "string"}},
        "source_records": {
            "type": "object",
            "description": "Each contributing source's untouched snapshot.",
        },
        "severity": {"type": "string",
                     "enum": ["unknown", "low", "medium", "high", "critical"]},
        "severity_by_source": {"type": "object",
                               "additionalProperties": {"type": "string"}},
        "cvss_score": {
            "type": "number", "nullable": True,
            "description": (
                "Null for an advisory whose only vector is CVSS v4.0: v4 is "
                "not scored here, and a wrong number is worse than none. Use "
                "cvss_vector to score it yourself."
            ),
        },
        "cvss_vector": {
            "type": "string", "nullable": True,
            "description": "The vector cvss_score came from, or the v4 vector when unscored.",
        },
        "cvss_by_source": {"type": "object",
                           "additionalProperties": {"type": "number"}},
        "cwes": {"type": "array", "items": {"type": "string"}},
        "cwe_labels": {"type": "array", "items": {"type": "object"}},
        "packages": {"type": "array", "items": {"type": "object"}},
        "ecosystems": {"type": "array", "items": {"type": "string"}},
        "published_at": {"type": "string", "nullable": True},
        "updated_at": {"type": "string", "nullable": True},
        "withdrawn_at": {"type": "string", "nullable": True},
        "kev": {"type": "boolean"},
        "epss_percentage": {"type": "number", "nullable": True},
        "epss_percentile": {"type": "number", "nullable": True},
        "html_url": {"type": "string", "nullable": True},
        "summary": {"type": "string", "nullable": True},
        "description": {"type": "string", "nullable": True},
        "ai": {
            "type": "object",
            "nullable": True,
            "description": (
                "Present only when a fresh cached verdict exists for EVERY "
                "requested category. A partial hit is never shown as a decision."
            ),
        },
    },
}

_SEARCH_RESPONSE = {
    "type": "object",
    "required": ["count", "query", "stats", "warnings", "results"],
    "properties": {
        "count": {"type": "integer"},
        "query": {
            "type": "object",
            "description": "The query as the server resolved it, echoed back.",
        },
        "stats": _STATS,
        "warnings": {
            "type": "array", "items": {"type": "string"},
            "description": (
                "A source that failed while others succeeded. An all-sources "
                "failure still returns 200 with count 0, so check this."
            ),
        },
        "results": {"type": "array", "items": _ADVISORY},
    },
}

_JOB = {
    "type": "object",
    "required": ["job_id", "kind", "status", "created_at"],
    "properties": {
        "job_id": {"type": "string", "pattern": "^[0-9a-f]{24}$"},
        "kind": {"type": "string", "enum": ["search"]},
        "status": {"type": "string",
                   "enum": ["queued", "running", "done", "failed"]},
        "created_at": {"type": "number"},
        "started_at": {"type": "number", "nullable": True},
        "finished_at": {"type": "number", "nullable": True},
        "result": {"allOf": [_SEARCH_RESPONSE],
                   "description": "Present only when status is `done`."},
        "error": {"type": "string",
                  "description": "Present only when status is `failed`."},
    },
}


def _json_body(schema: dict, *, required: bool = True) -> dict:
    return {
        "required": required,
        "content": {"application/json": {"schema": schema}},
    }


def _json_response(description: str, schema: dict) -> dict:
    return {
        "description": description,
        "content": {"application/json": {"schema": schema}},
    }


_ERROR_RESPONSE = _json_response("Error", _ERROR)


def build_spec(server_url: str = "/") -> dict:
    """The full OpenAPI 3.1 document."""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "VulnSight",
            "version": API_VERSION,
            "summary": "Search vulnerability advisories by bug class, not keyword.",
            "description": (
                "Filters GHSA, NVD and OSV on the CWE set that characterises a "
                "bug class, merges them through their alias graph, and can run "
                "an LLM pass that judges whether each advisory's root cause "
                "really is that class.\n\n"
                f"Ships {len(CATEGORIES)} curated bug classes; any single CWE "
                "also works as an ad-hoc class via `cwe:<id>`.\n\n"
                "Every path is also served without the `/v1` prefix. Those "
                "aliases are permanent, but new clients should use `/v1`."
            ),
        },
        "servers": [{"url": server_url}],
        "components": {
            "securitySchemes": {
                _TOKEN_SCHEME: {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-VulnSight-Token",
                    "description": (
                        "Required on every mutating call, and on job polling, "
                        "when VULNSIGHT_API_TOKEN is set. "
                        "`Authorization: Bearer <token>` is accepted too."
                    ),
                }
            },
            "schemas": {
                "Error": _ERROR,
                "SearchRequest": _SEARCH_REQUEST,
                "SearchResponse": _SEARCH_RESPONSE,
                "SearchStats": _STATS,
                "Advisory": _ADVISORY,
                "Job": _JOB,
            },
        },
        "paths": {
            "/api/v1/meta": {
                "get": {
                    "operationId": "getMeta",
                    "summary": "Curated taxonomy, ecosystems, and service status",
                    "responses": {"200": _json_response(
                        "Reference data", {"type": "object"})},
                }
            },
            "/api/v1/cwes": {
                "get": {
                    "operationId": "getCweCatalog",
                    "summary": "The full MITRE CWE catalog, column-oriented",
                    "description": (
                        "Served with a version ETag and a one-day cache. Send "
                        "`If-None-Match` to get a 304 instead of ~66 KB."
                    ),
                    "responses": {
                        "200": _json_response("Catalog", {"type": "object"}),
                        "304": {"description": "Catalog unchanged"},
                    },
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "operationId": "getOpenApiSpec",
                    "summary": "This document",
                    "responses": {
                        "200": _json_response("OpenAPI 3.1 document",
                                              {"type": "object"}),
                        "304": {"description": "Specification unchanged"},
                    },
                }
            },
            "/api/v1/osv/status": {
                "get": {
                    "operationId": "getOsvStatus",
                    "summary": "Which OSV bulk exports are cached, and how stale",
                    "responses": {"200": _json_response(
                        "Cache status", {"type": "object"})},
                }
            },
            "/api/v1/search": {
                "post": {
                    "operationId": "search",
                    "summary": "Search advisories by bug class (synchronous)",
                    "description": (
                        "Runs on the request thread. Use POST /api/v1/jobs "
                        "instead when `sources` includes `nvd`: without an NVD "
                        "API key that path sleeps ~6.5 s per CWE, which is "
                        "minutes for a class with extended CWEs enabled."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body(_SEARCH_REQUEST),
                    "responses": {
                        "200": _json_response("Search results", _SEARCH_RESPONSE),
                        "400": _ERROR_RESPONSE,
                        "401": _ERROR_RESPONSE,
                        "415": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                        "502": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/jobs": {
                "post": {
                    "operationId": "submitSearchJob",
                    "summary": "Queue a search and poll for it",
                    "description": (
                        "Takes exactly the body /api/v1/search takes. The query "
                        "is validated before the job is created, so a malformed "
                        "request fails now rather than a minute later. Spends "
                        "the same rate-limit bucket as a synchronous search."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body(_SEARCH_REQUEST),
                    "responses": {
                        "202": _json_response("Job accepted", {
                            "type": "object",
                            "required": ["job_id", "kind", "status", "poll"],
                            "properties": {
                                "job_id": {"type": "string"},
                                "kind": {"type": "string"},
                                "status": {"type": "string", "enum": ["queued"]},
                                "poll": {"type": "string"},
                            },
                        }),
                        "400": _ERROR_RESPONSE,
                        "401": _ERROR_RESPONSE,
                        "415": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/jobs/{job_id}": {
                "get": {
                    "operationId": "getJob",
                    "summary": "Poll a queued search",
                    "description": (
                        "The only GET that requires the token when one is set: "
                        "a job result is the output of your query, not public "
                        "reference data. `result` appears only on `done` and "
                        "`error` only on `failed` — there are no partial results."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "parameters": [{
                        "name": "job_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "pattern": "^[0-9a-f]{24}$"},
                    }],
                    "responses": {
                        "200": _json_response("Job state", _JOB),
                        "401": _ERROR_RESPONSE,
                        "404": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/ai/classify": {
                "post": {
                    "operationId": "classify",
                    "summary": "Run the LLM pass over cached advisories",
                    "description": (
                        "Costs `len(categories) × len(advisory_ids)` model "
                        "calls, capped at 500 per request. Advisories must "
                        "already be in the cache — run a search first; unknown "
                        "ids come back under `missing` rather than failing."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body({
                        "type": "object",
                        "required": ["categories", "advisory_ids"],
                        "properties": {
                            "categories": {"type": "array",
                                           "items": {"type": "string"}},
                            "advisory_ids": {"type": "array", "maxItems": 100,
                                             "items": {"type": "string"}},
                            "force": {
                                "type": "boolean", "default": False,
                                "description":
                                    "Ignore cached verdicts and re-spend.",
                            },
                        },
                    }),
                    "responses": {
                        "200": _json_response("Verdicts", {"type": "object"}),
                        "400": _ERROR_RESPONSE,
                        "401": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/ai/test": {
                "post": {
                    "operationId": "pingAiProvider",
                    "summary": "One trivial prompt, to check the provider answers",
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body({"type": "object"}, required=False),
                    "responses": {
                        "200": _json_response("Provider reply", {"type": "object"}),
                        "401": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
        },
    }
