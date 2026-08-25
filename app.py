"""VulnSight — Flask web UI for browsing security advisories by bug class.

Run:
    ./run.sh          # or: python app.py
Then open http://127.0.0.1:5000

Environment: reads .env in this folder (see .env.example) for the AI provider.
"""

from __future__ import annotations

import functools
import logging
import os
import secrets
import sys

from flask import Flask, g, jsonify, render_template, request

from modules import (
    ai_classifier,
    cache,
    config,
    jobs,
    openapi,
    osv_client,
    search_service,
    security,
)
from modules import ghsa_client as ghsa
from modules.cwe_categories import (
    CATEGORIES,
    CWE_VERSION,
    KEYWORDS,
    ECOSYSTEMS,
    POPULAR_PACKAGES,
    SEVERITIES,
    canonical_category,
    is_known_category,
    picker_catalog,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")

logger = logging.getLogger(__name__)

MAX_AI_BATCH = 100

# One classify request fans out to len(categories) × len(advisory_ids) model
# calls. Capping the product keeps a single request from turning into thousands
# of paid calls; the UI sizes its batches from the same number.
MAX_AI_CALLS_PER_REQUEST = 500


@functools.lru_cache(maxsize=1)
def _cwe_payload() -> dict:
    """The CWE picker catalog, serialized shape built once per process."""
    return picker_catalog()


def _json_object() -> tuple[dict | None, tuple | None]:
    """Require a JSON object so cross-origin text/plain requests are rejected."""
    if not request.is_json:
        return None, (jsonify({"error": "Content-Type must be application/json."}), 415)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None, (jsonify({"error": "Request body must be a JSON object."}), 400)
    return body, None


def _search_payload(q: search_service.SearchQuery, outcome) -> dict:
    """The body of a search response.

    Shared with the job runner so a polled result is identical to a synchronous
    one — a client that switches to /jobs for a slow query should not have to
    parse a second shape to read the same search.
    """
    return {
        "count": len(outcome.results),
        "query": {
            "categories": q.categories,
            "cwes": q.cwes,
            "ecosystem": q.ecosystem,
            "severity": q.severity,
            "affects": q.affects,
            "published": q.published,
            "type": q.adv_type,
            "sort": q.sort,
            "direction": q.direction,
            "include_extended": q.include_extended,
            "max_results": q.max_results,
            "sources": q.sources,
            "per_source": outcome.per_source,
        },
        # Row counts per pipeline stage. `count` alone could not tell a
        # de-duplicated row from one dropped by max_results, so a paging
        # client had no way to know whether more existed.
        "stats": outcome.stats,
        "warnings": outcome.warnings,
        "results": outcome.results,
    }


def _run_search_job(request_body: dict) -> dict:
    """Job runner for a queued search. Executes off the request thread."""
    try:
        q = search_service.parse_search_query(request_body)
        outcome = search_service.run_search(q)
    except search_service.SearchError as e:
        raise jobs.JobFailure(e.public_message, e.status) from e
    return _search_payload(q, outcome)


def create_app():
    """Application factory: build and return a fully configured Flask app."""
    config.load_dotenv()
    cache.init_db()
    # Jobs from a previous process are not running any more — the pool died with
    # it — so fail them now rather than leaving a poller waiting forever.
    jobs.startup()

    app = Flask(__name__)

    try:
        _max_request_bytes = int(os.environ.get("MAX_REQUEST_BYTES", "1048576"))
    except ValueError:
        _max_request_bytes = 1048576
    app.config["MAX_CONTENT_LENGTH"] = max(1024, _max_request_bytes)
    _bind_host = os.environ.get("HOST", "127.0.0.1").strip() or "127.0.0.1"
    security.ensure_api_token_for_bind(_bind_host)
    app.config["VULNSIGHT_TOKEN"] = os.environ.get("VULNSIGHT_API_TOKEN", "").strip()
    app.config["PUBLIC_HOSTS"] = security.public_hosts_from_env()
    _rate_off = os.environ.get("VULNSIGHT_RATE_LIMIT", "on").strip().lower() in (
        "0", "off", "false", "no",
    )
    app.config["RATE_LIMIT_ENABLED"] = not _rate_off
    _rate_window = security.env_int("VULNSIGHT_RATE_WINDOW", 60)
    app.config["SEARCH_LIMITER"] = security.RateLimiter(
        security.env_int("VULNSIGHT_SEARCH_RATE", 30), _rate_window
    )
    app.config["AI_LIMITER"] = security.RateLimiter(
        security.env_int("VULNSIGHT_AI_RATE", 20), _rate_window
    )

    # -----------------------------------------------------------------------
    # Request lifecycle hooks
    # -----------------------------------------------------------------------

    @app.before_request
    def _csrf_check():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if security.mutating_request_allowed(
            origin=request.headers.get("Origin"),
            referer=request.headers.get("Referer"),
            host=request.host,
            sec_fetch_site=request.headers.get("Sec-Fetch-Site"),
            extra_hosts=app.config.get("PUBLIC_HOSTS") or [],
        ):
            return None
        return jsonify({"error": "Cross-origin request blocked."}), 403

    # Auth is registered before rate limiting, and the order is load-bearing:
    # Flask runs before_request hooks in registration order, so with it the
    # other way round an unauthenticated caller spent the operator's own bucket
    # and locked them out with a 429 while every one of its requests was 401.
    @app.before_request
    def _auth_check():
        # Job polling is the one GET that is guarded. Every other GET serves
        # public reference data (the CWE catalog, the taxonomy); a job result is
        # the output of the operator's own query, and the id alone should not be
        # the only thing standing between a reader and it.
        guarded_read = request.endpoint == "api_jobs_get"
        if request.method not in ("POST", "PUT", "PATCH", "DELETE") and not guarded_read:
            return None
        if not request.path.startswith("/api/"):
            return None
        expected = app.config.get("VULNSIGHT_TOKEN") or ""
        if not expected:
            return None  # auth not configured; token_matches itself fails closed
        provided = security.extract_request_token(
            request.headers.get("X-VulnSight-Token"),
            request.headers.get("Authorization"),
        )
        if security.token_matches(expected, provided):
            return None
        return jsonify({"error": "Authentication required."}), 401

    @app.before_request
    def _rate_limit():
        if request.method != "POST" or not app.config.get("RATE_LIMIT_ENABLED", True):
            return None
        # Matched on the endpoint, not the path: every route answers on both
        # /api/... and /api/v1/..., and a path match would have left the
        # versioned alias unlimited.
        limiter = None
        # Queueing a search costs the same upstream budget as running one, so
        # /jobs shares the search bucket. Leaving it out would have made the job
        # endpoint a free way around the very limit it exists to work with.
        if request.endpoint in ("api_search", "api_jobs_create"):
            limiter = app.config.get("SEARCH_LIMITER")
        elif request.endpoint in ("api_ai_classify", "api_ai_test"):
            limiter = app.config.get("AI_LIMITER")
        if limiter is None:
            return None
        key = security.client_key(
            request.remote_addr, request.headers.get("X-Forwarded-For")
        )
        if limiter.allow(key):
            return None
        retry_after = str(getattr(limiter, "window_seconds", 60))
        response = jsonify({"error": "Too many requests. Try again shortly."})
        response.status_code = 429
        response.headers["Retry-After"] = retry_after
        return response

    @app.before_request
    def create_csp_nonce():
        """Give every response a fresh nonce for the one inline bootstrap script."""
        g.csp_nonce = secrets.token_urlsafe(18)

    @app.after_request
    def add_security_headers(response):
        nonce = g.get("csp_nonce", "")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "; ".join((
                "default-src 'self'",
                f"script-src 'self' 'nonce-{nonce}'",
                "style-src 'self'",
                "img-src 'self' data:",
                "connect-src 'self'",
                "object-src 'none'",
                "base-uri 'none'",
                "frame-ancestors 'none'",
                "form-action 'self'",
            )),
        )
        return response

    # Error handlers. A script driving /api/ is promised {"error": ...} on every
    # failure, but only 413 was handled, so a wrong path or an unhandled
    # exception answered with a Werkzeug HTML page — and a client doing
    # r.json() got a parse error instead of the reason. HTML is still correct
    # for the UI, so the shape is chosen by path.
    def _api_error(message: str, status: int, original):
        if request.path.startswith("/api/"):
            return jsonify({"error": message}), status
        return original

    @app.errorhandler(413)
    def request_too_large(error):
        return _api_error("Request body is too large.", 413, error)

    @app.errorhandler(404)
    def not_found(error):
        return _api_error("No such endpoint.", 404, error)

    @app.errorhandler(405)
    def method_not_allowed(error):
        return _api_error("Method not allowed for this endpoint.", 405, error)

    @app.errorhandler(500)
    def internal_error(error):
        logger.exception("Unhandled error on %s", request.path)
        return _api_error("Internal error. See server logs.", 500, error)

    # -----------------------------------------------------------------------
    # Pages
    # -----------------------------------------------------------------------

    @app.route("/")
    def index():
        categories = [
            {
                "key": k,
                "code": v["code"],
                "group": v["group"],
                "label": v["label"],
                "description": v["description"],
                # The community terms people actually type ("__proto__",
                # "toctou", "samesite", "md5"); searchable, and the first few
                # are shown as aliases in the picker.
                "terms": KEYWORDS.get(k, []),
                # The CWE finder needs these to flag which CWEs a class already
                # covers, so picking one is an informed choice rather than a
                # redundant extra AI pass, and to size the NVD cost estimate.
                "core": list(dict.fromkeys(v["core"])),
                "extended": [c for c in dict.fromkeys(v["extended"]) if c not in v["core"]],
            }
            for k, v in CATEGORIES.items()
        ]
        # 29 classes is too many for a flat list, so the picker renders them
        # under their group headings in declaration order.
        groups: list[dict] = []
        for category in categories:
            name = category["group"]
            if not groups or groups[-1]["name"] != name:
                existing = next((g for g in groups if g["name"] == name), None)
                if existing is None:
                    groups.append({"name": name, "items": [category]})
                    continue
                existing["items"].append(category)
            else:
                groups[-1]["items"].append(category)

        ai_cfg = ai_classifier.load_config()
        return render_template(
            "index.html",
            categories=categories,
            category_groups=groups,
            ecosystems=ECOSYSTEMS,
            severities=SEVERITIES,
            cwe_version=CWE_VERSION,
            cwe_count=len(_cwe_payload()["rows"]),
            ai_call_budget=MAX_AI_CALLS_PER_REQUEST,
            popular_packages=POPULAR_PACKAGES,
            osv_supported=list(osv_client.ECOSYSTEM_MAP.keys()),
            ai_configured=ai_cfg.configured,
            gh_ok=ghsa.gh_auth_ok(),
            cached_count=cache.count_advisories(),
            csp_nonce=g.csp_nonce,
            auth_required=bool(app.config.get("VULNSIGHT_TOKEN")),
        )

    # -----------------------------------------------------------------------
    # API
    # -----------------------------------------------------------------------

    @app.route("/api/meta")
    @app.route("/api/v1/meta")
    def api_meta():
        return jsonify(
            {
                "categories": {
                    k: {
                        "code": v["code"],
                        "label": v["label"],
                        "description": v["description"],
                        "core": v["core"],
                        "extended": v["extended"],
                    }
                    for k, v in CATEGORIES.items()
                },
                "ecosystems": ECOSYSTEMS,
                "severities": SEVERITIES,
                "gh_ok": ghsa.gh_auth_ok(),
                "ai_configured": ai_classifier.load_config().configured,
            }
        )

    @app.route("/api/cwes")
    @app.route("/api/v1/cwes")
    def api_cwes():
        """Full MITRE CWE catalog powering the UI's CWE/bug-name search box.

        The whole table is sent once so the search itself never needs a round
        trip. It only changes when MITRE ships a release and the generated
        module is refreshed, so it is served with a version ETag the browser can
        revalidate cheaply.
        """
        payload = _cwe_payload()
        etag = f'W/"cwe-{payload["version"]}"'
        if request.headers.get("If-None-Match") == etag:
            return "", 304
        response = jsonify(payload)
        response.headers["ETag"] = etag
        response.headers["Cache-Control"] = "private, max-age=86400"
        return response

    @app.route("/api/ai/test", methods=["POST"])
    @app.route("/api/v1/ai/test", methods=["POST"])
    def api_ai_test():
        _body, error = _json_object()
        if error:
            return error
        return jsonify(ai_classifier.ping())

    @app.route("/api/docs")
    def api_docs():
        """Human-readable reference, rendered in the browser from the spec.

        Not Swagger UI: that means ~1.4 MB of vendored minified JavaScript in a
        tool whose stated constraint is that an operator can read it end to end,
        and relaxing style-src to 'unsafe-inline' for the styles it injects at
        runtime. The spec itself remains the interoperable artefact — load
        /api/v1/openapi.json into Swagger Editor, Postman or a generator.
        """
        return render_template("apidocs.html", csp_nonce=g.get("csp_nonce", ""))

    @app.route("/api/openapi.json")
    @app.route("/api/v1/openapi.json")
    def api_openapi():
        """The machine-readable contract, for client generators and Postman."""
        payload = openapi.build_spec()
        etag = f'W/"openapi-{openapi.API_VERSION}"'
        if request.headers.get("If-None-Match") == etag:
            return "", 304
        response = jsonify(payload)
        response.headers["ETag"] = etag
        response.headers["Cache-Control"] = "private, max-age=3600"
        return response

    @app.route("/api/osv/status")
    @app.route("/api/v1/osv/status")
    def api_osv_status():
        return jsonify({
            "supported": list(osv_client.ECOSYSTEM_MAP.keys()),
            "cached": osv_client.cache_status(),
        })

    @app.route("/api/search", methods=["POST"])
    @app.route("/api/v1/search", methods=["POST"])
    def api_search():
        body, error = _json_object()
        if error:
            return error
        assert body is not None
        try:
            q = search_service.parse_search_query(body)
            outcome = search_service.run_search(q)
        except search_service.SearchError as e:
            return jsonify({"error": e.public_message}), e.status
        return jsonify(_search_payload(q, outcome))

    @app.route("/api/jobs", methods=["POST"])
    @app.route("/api/v1/jobs", methods=["POST"])
    def api_jobs_create():
        """Queue a search and return immediately with an id to poll.

        Takes exactly the body /api/v1/search takes, so moving a slow query off
        the request thread is a URL change and nothing else. The query is
        validated here rather than inside the worker: a malformed request should
        be a 400 the caller sees now, not a job that fails a minute later.
        """
        body, error = _json_object()
        if error:
            return error
        assert body is not None
        try:
            search_service.parse_search_query(body)
        except search_service.SearchError as e:
            return jsonify({"error": e.public_message}), e.status
        job_id = jobs.submit("search", body, _run_search_job)
        response = jsonify({
            "job_id": job_id,
            "kind": "search",
            "status": "queued",
            "poll": f"/api/v1/jobs/{job_id}",
        })
        response.status_code = 202
        response.headers["Location"] = f"/api/v1/jobs/{job_id}"
        return response

    @app.route("/api/jobs/<job_id>")
    @app.route("/api/v1/jobs/<job_id>")
    def api_jobs_get(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            return jsonify({"error": "No such job."}), 404
        return jsonify(jobs.public_view(job))

    @app.route("/api/ai/classify", methods=["POST"])
    @app.route("/api/v1/ai/classify", methods=["POST"])
    def api_ai_classify():
        body, error = _json_object()
        if error:
            return error
        assert body is not None

        try:
            categories = search_service.parse_str_list(
                body.get("categories"),
                field_name="categories",
                max_items=search_service.MAX_CATEGORY_INPUTS,
                max_item_length=64,
            )
            if not categories:
                categories = [search_service.parse_text(
                    body.get("category"), "bac", "category"
                )]
            # Fold 'CWE:639' / 'cwe:639' into one key so the verdict cache and
            # the search path agree on the category name.
            categories = list(dict.fromkeys(canonical_category(c) for c in categories))
            advisory_ids = list(dict.fromkeys(search_service.parse_str_list(
                body.get("advisory_ids") or body.get("ghsa_ids"),
                field_name="advisory IDs",
                max_items=MAX_AI_BATCH,
                max_item_length=200,
            )))
            force = search_service.parse_bool(body.get("force"), False)
        except search_service.SearchError as exc:
            return jsonify({"error": exc.public_message}), exc.status

        invalid_categories = [
            category for category in categories if not is_known_category(category)
        ]
        if invalid_categories:
            return jsonify({"error": f"Unsupported categories: {', '.join(invalid_categories)}"}), 400

        cfg = ai_classifier.load_config()
        if not cfg.configured:
            return jsonify({"error": "AI not configured. Set AI_* in .env."}), 400
        if not advisory_ids:
            return jsonify({"error": "No advisories to classify."}), 400
        if len(advisory_ids) > MAX_AI_BATCH:
            return jsonify({
                "error": f"Too many advisories; maximum batch size is {MAX_AI_BATCH}."
            }), 400
        if any(len(gid) > 128 for gid in advisory_ids):
            return jsonify({"error": "Advisory identifiers may not exceed 128 characters."}), 400
        planned_calls = len(categories) * len(advisory_ids)
        if planned_calls > MAX_AI_CALLS_PER_REQUEST:
            return jsonify({
                "error": (
                    f"Request would issue {planned_calls} AI calls "
                    f"({len(categories)} categories × {len(advisory_ids)} advisories); "
                    f"the per-request limit is {MAX_AI_CALLS_PER_REQUEST}. "
                    "Send fewer advisories per request or select fewer categories."
                )
            }), 400

        records: dict[str, dict] = {}
        missing: list[str] = []
        for gid in advisory_ids:
            rec = cache.get_advisory(gid)
            if rec:
                # The id we looked it up by is authoritative. Older cache rows
                # predate the advisory_id field, and without this the verdict
                # comes back keyed by nothing and is dropped on the floor.
                rec["advisory_id"] = rec.get("advisory_id") or gid
                records[gid] = rec
            else:
                missing.append(gid)

        by_category: dict[str, dict[str, dict]] = {}
        for category in categories:
            fingerprints = {
                gid: ai_classifier.classification_fingerprint(cfg, rec, category)
                for gid, rec in records.items()
            }
            category_results: dict[str, dict] = {}
            if not force:
                category_results.update(cache.get_classifications(
                    list(records), category, expected_fingerprints=fingerprints
                ))
            todo = [rec for gid, rec in records.items() if gid not in category_results]

            def _persist(gid, verdict, *, _category=category, _fps=fingerprints):
                cache.save_classification(
                    gid,
                    _category,
                    verdict,
                    cfg.model,
                    fingerprint=_fps[gid],
                )

            fresh = ai_classifier.classify_many(
                cfg, todo, category, on_result=_persist
            )
            category_results.update(fresh)
            by_category[category] = category_results

        verdicts = {
            gid: ai_classifier.aggregate_category_verdicts({
                category: by_category[category][gid]
                for category in categories
                if gid in by_category[category]
            })
            for gid in records
        }

        return jsonify({
            "category": categories[0],
            "categories": categories,
            "verdicts": verdicts,
            "by_category": by_category,
            "missing": missing,
        })

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1").strip() or "127.0.0.1"
    security.assert_safe_bind(host)
    debug = "--debug" in sys.argv
    security.assert_safe_debug(host, debug)
    print(f"  VulnSight -> http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
