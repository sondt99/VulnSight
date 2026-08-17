"""VulnSight — Flask web UI for browsing security advisories by bug class.

Run:
    ./run.sh          # or: python app.py
Then open http://127.0.0.1:5000

Environment: reads .env in this folder (see .env.example) for the AI provider.
"""

from __future__ import annotations

import logging
import os
import secrets
import sys

from flask import Flask, g, jsonify, render_template, request

from modules import ai_classifier, cache, config, osv_client, search_service
from modules import ghsa_client as ghsa
from modules.cwe_categories import (
    CATEGORIES,
    ECOSYSTEMS,
    POPULAR_PACKAGES,
    SCENARIOS,
    SEVERITIES,
    all_cwes,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")

config.load_dotenv()
cache.init_db()

app = Flask(__name__)

try:
    _max_request_bytes = int(os.environ.get("MAX_REQUEST_BYTES", "1048576"))
except ValueError:
    _max_request_bytes = 1048576
app.config["MAX_CONTENT_LENGTH"] = max(1024, _max_request_bytes)

MAX_AI_BATCH = 100


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


def _json_object() -> tuple[dict | None, tuple | None]:
    """Require a JSON object so cross-origin text/plain requests are rejected."""
    if not request.is_json:
        return None, (jsonify({"error": "Content-Type must be application/json."}), 415)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None, (jsonify({"error": "Request body must be a JSON object."}), 400)
    return body, None


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request body is too large."}), 413


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    categories = [
        {
            "key": k,
            "label": v["label"],
            "description": v["description"],
            "cwe_count": len(v["core"]) + len(v["extended"]),
        }
        for k, v in CATEGORIES.items()
    ]
    ai_cfg = ai_classifier.load_config()
    return render_template(
        "index.html",
        categories=categories,
        ecosystems=ECOSYSTEMS,
        severities=SEVERITIES,
        cwe_catalog=all_cwes(),
        popular_packages=POPULAR_PACKAGES,
        scenarios=SCENARIOS,
        osv_supported=list(osv_client.ECOSYSTEM_MAP.keys()),
        ai_configured=ai_cfg.configured,
        gh_ok=ghsa.gh_auth_ok(),
        cached_count=cache.count_advisories(),
        csp_nonce=g.csp_nonce,
    )


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.route("/api/meta")
def api_meta():
    return jsonify(
        {
            "categories": {
                k: {
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


@app.route("/api/ai/test", methods=["POST"])
def api_ai_test():
    _body, error = _json_object()
    if error:
        return error
    return jsonify(ai_classifier.ping())


@app.route("/api/osv/status")
def api_osv_status():
    return jsonify({
        "supported": list(osv_client.ECOSYSTEM_MAP.keys()),
        "cached": osv_client.cache_status(),
    })


@app.route("/api/search", methods=["POST"])
def api_search():
    body, error = _json_object()
    if error:
        return error
    assert body is not None
    try:
        q = search_service.parse_search_query(body)
        outcome = search_service.run_search(q)
    except search_service.SearchError as e:
        return jsonify({"error": str(e)}), e.status
    return jsonify(
        {
            "count": len(outcome.results),
            "query": {
                "categories": q.categories,
                "cwes": q.cwes,
                "ecosystem": q.ecosystem,
                "severity": q.severity,
                "affects": q.affects,
                "max_results": q.max_results,
                "sources": q.sources,
                "per_source": outcome.per_source,
            },
            "warnings": outcome.warnings,
            "results": outcome.results,
        }
    )


@app.route("/api/ai/classify", methods=["POST"])
def api_ai_classify():
    body, error = _json_object()
    if error:
        return error
    assert body is not None

    try:
        categories = search_service.parse_str_list(
            body.get("categories"),
            field_name="categories",
            max_items=len(CATEGORIES),
            max_item_length=64,
        )
        if not categories:
            categories = [search_service.parse_text(
                body.get("category"), "bac", "category"
            )]
        categories = list(dict.fromkeys(categories))
        ghsa_ids = list(dict.fromkeys(search_service.parse_str_list(
            body.get("ghsa_ids"),
            field_name="advisory IDs",
            max_items=MAX_AI_BATCH,
            max_item_length=200,
        )))
        force = search_service.parse_bool(body.get("force"), False)
    except search_service.SearchError as exc:
        return jsonify({"error": str(exc)}), exc.status

    invalid_categories = [category for category in categories if category not in CATEGORIES]
    if invalid_categories:
        return jsonify({"error": f"Unsupported categories: {', '.join(invalid_categories)}"}), 400

    cfg = ai_classifier.load_config()
    if not cfg.configured:
        return jsonify({"error": "AI not configured. Set AI_* in .env."}), 400
    if not ghsa_ids:
        return jsonify({"error": "No advisories to classify."}), 400
    if len(ghsa_ids) > MAX_AI_BATCH:
        return jsonify({
            "error": f"Too many advisories; maximum batch size is {MAX_AI_BATCH}."
        }), 400
    if any(len(gid) > 128 for gid in ghsa_ids):
        return jsonify({"error": "Advisory identifiers may not exceed 128 characters."}), 400

    records: dict[str, dict] = {}
    missing: list[str] = []
    for gid in ghsa_ids:
        rec = cache.get_advisory(gid)
        if rec:
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = "--debug" in sys.argv
    print(f"  VulnSight -> http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)
