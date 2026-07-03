"""VulnSight — Flask web UI for browsing security advisories by bug class.

Run:
    ./run.sh          # or: python app.py
Then open http://127.0.0.1:5000

Environment: reads .env in this folder (see .env.example) for the AI provider.
"""

from __future__ import annotations

import logging
import os
import sys

from flask import Flask, jsonify, render_template, request

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


@app.route("/api/ai/test")
def api_ai_test():
    return jsonify(ai_classifier.ping())


@app.route("/api/osv/status")
def api_osv_status():
    return jsonify({
        "supported": list(osv_client.ECOSYSTEM_MAP.keys()),
        "cached": osv_client.cache_status(),
    })


@app.route("/api/search", methods=["POST"])
def api_search():
    body = request.get_json(force=True, silent=True) or {}
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
    body = request.get_json(force=True, silent=True) or {}
    category = (body.get("category") or "bac").strip()
    ghsa_ids = search_service.parse_str_list(body.get("ghsa_ids"))
    force = bool(body.get("force", False))

    cfg = ai_classifier.load_config()
    if not cfg.configured:
        return jsonify({"error": "AI not configured. Set AI_* in .env."}), 400
    if not ghsa_ids:
        return jsonify({"error": "No advisories to classify."}), 400

    # Load records from cache; skip ones already classified unless forced.
    # Ids absent from the cache (and without a verdict) are reported back
    # as "missing" instead of being dropped silently.
    todo = []
    missing: list[str] = []
    results = {}
    if not force:
        results.update(cache.get_classifications(ghsa_ids, category))
    for gid in ghsa_ids:
        if gid in results and not force:
            continue
        rec = cache.get_advisory(gid)
        if rec:
            todo.append(rec)
        else:
            missing.append(gid)

    def _persist(gid, verdict):
        cache.save_classification(gid, category, verdict, cfg.model)

    fresh = ai_classifier.classify_many(cfg, todo, category, on_result=_persist)
    results.update(fresh)

    return jsonify({"category": category, "verdicts": results, "missing": missing})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = "--debug" in sys.argv
    print(f"  VulnSight -> http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)
