"""End-to-end Flask endpoint tests (offline: gh CLI, OSV and AI all mocked;
cache pointed at a temp SQLite DB before the app module is imported)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import io
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

from modules import ai_classifier
from modules import cache
from modules import ghsa_client as ghsa
from modules import nvd_client
from modules import osv_client
from samples import NVD_VULN, OSV_GHSA, SAMPLE, SORT_A, SORT_B, SORT_C, make_sortable_raw

import app as app_module

# EPSS enrichment runs inside run_search, and nothing was mocking it, so the
# "offline" suite made 26 live DNS lookups to api.first.org per run. It passed
# only because epss_client swallows every failure — which also meant these
# tests would pass identically if EPSS enrichment were entirely broken.
# Individual tests that patch fetch_epss themselves still win: an inner
# mock.patch takes precedence over this one.
_epss_patch = None


def setUpModule():
    global _epss_patch
    _epss_patch = mock.patch("modules.epss_client.fetch_epss", return_value={})
    _epss_patch.start()


def tearDownModule():
    if _epss_patch is not None:
        _epss_patch.stop()


class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        # Point the cache at a temp db BEFORE calling the app factory
        # (create_app() runs cache.init_db()).
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        # Isolate these tests from a developer .env that enables auth/limits.
        self._sec_env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "",
            "VULNSIGHT_RATE_LIMIT": "off",
            "VULNSIGHT_PUBLIC_HOST": "",
            "HOST": "127.0.0.1",
        }, clear=False)
        self._sec_env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self._sec_env.stop()
        cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    # ------------------------------------------------------------------ meta

    def test_meta(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/api/meta")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("bac", data["categories"])
        self.assertIn("maven", data["ecosystems"])

    # ---------------------------------------------------------------- search

    def test_search_mocked(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/search", json={"categories": ["bac"], "ecosystem": "maven"})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["ghsa_id"], "GHSA-h3m5-97jq-qjrf")
        self.assertTrue(data["results"][0]["cwe_labels"])
        # persisted to cache
        self.assertEqual(cache.count_advisories(cache.DB_PATH), 1)

    def test_search_merge_dedupe_ghsa_osv(self):
        # Same CVE from both sources should collapse into ONE row tagged both.
        ghsa_rec = dict(SAMPLE, ghsa_id="GHSA-dupe", cve_id="CVE-2026-777")
        osv_rec = dict(OSV_GHSA, id="GHSA-dupe", aliases=["CVE-2026-777"])
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[ghsa_rec]), \
             mock.patch("modules.osv_client.fetch_osv",
                        return_value=[osv_client.normalize_osv(osv_rec)]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "ecosystem": "go",
                                       "sources": ["ghsa", "osv"]})
        data = r.get_json()
        self.assertEqual(data["count"], 1)                       # deduped
        self.assertEqual(sorted(data["results"][0]["sources"]), ["ghsa", "osv"])
        self.assertEqual(data["results"][0]["source"], "ghsa")   # GHSA base kept
        self.assertEqual(data["query"]["per_source"], {"ghsa": 1, "osv": 1})

    def test_search_osv_only_native_record(self):
        with mock.patch("modules.osv_client.fetch_osv",
                        return_value=[osv_client.normalize_osv(OSV_GHSA)]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "ecosystem": "go",
                                       "sources": ["osv"]})
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["sources"], ["osv"])

    def test_search_osv_any_ecosystem_warns(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "ecosystem": "any",
                                       "sources": ["ghsa", "osv"]})
        data = r.get_json()
        self.assertTrue(any("OSV" in w for w in data["warnings"]))

    def test_search_no_category_returns_400(self):
        r = self.client.post("/api/search", json={})
        self.assertEqual(r.status_code, 400)
        self.assertIn("bug class", r.get_json()["error"].lower())

    def test_search_ghsa_error_502(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", side_effect=ghsa.GhCliError("nope")):
            r = self.client.post("/api/search", json={"categories": ["bac"]})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.get_json()["error"], "GHSA fetch failed.")
        self.assertNotIn("nope", r.get_data(as_text=True))

    def test_mutating_apis_require_json_content_type(self):
        r = self.client.post(
            "/api/search", data='{"categories":["bac"]}', content_type="text/plain"
        )
        self.assertEqual(r.status_code, 415)
        r = self.client.post(
            "/api/ai/classify", data='{"advisory_ids":["X"]}', content_type="text/plain"
        )
        self.assertEqual(r.status_code, 415)
        with mock.patch("modules.ai_classifier.ping") as ping:
            r = self.client.post(
                "/api/ai/test", data="{}", content_type="text/plain"
            )
        self.assertEqual(r.status_code, 415)
        ping.assert_not_called()

    def test_ai_health_check_accepts_json_and_sets_security_headers(self):
        with mock.patch(
            "modules.ai_classifier.ping", return_value={"ok": True}
        ) as ping:
            r = self.client.post("/api/ai/test", json={})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        ping.assert_called_once_with()
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])

    def test_search_sort_updated_end_to_end(self):
        # Regression: body.sort="updated" used to be ignored (always published_at).
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=make_sortable_raw()):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "sort": "updated"})
        self.assertEqual(r.status_code, 200)
        ids = [x["ghsa_id"] for x in r.get_json()["results"]]
        self.assertEqual(ids, [SORT_B, SORT_C, SORT_A])  # by updated_at desc

    # ------------------------------------------------------------ ai/classify

    def test_ai_classify_not_configured(self):
        with mock.patch("modules.ai_classifier.load_config",
                        return_value=ai_classifier.AIConfig("anthropic", "", [], "")):
            r = self.client.post("/api/ai/classify", json={"category": "bac", "advisory_ids": ["X"]})
        self.assertEqual(r.status_code, 400)

    def test_ai_classify_flow(self):
        # Seed cache with an advisory, then classify with mocked AI.
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("modules.ai_classifier._call_messages",
                        return_value='{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'):
            r = self.client.post("/api/ai/classify",
                                 json={"category": "bac", "advisory_ids": [SAMPLE["ghsa_id"]]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["verdicts"][SAMPLE["ghsa_id"]]["is_match"])
        self.assertEqual(data["missing"], [])  # everything was in the cache

    def test_ai_classifies_every_selected_category(self):
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch(
                 "modules.ai_classifier._call_messages",
                 return_value=(
                     '{"is_match": true, "confidence": 0.9, '
                     '"vuln_type": "match", "reason": "r"}'
                 ),
             ) as call:
            r = self.client.post(
                "/api/ai/classify",
                json={
                    "categories": ["xss", "sqli"],
                    "advisory_ids": [SAMPLE["ghsa_id"]],
                },
            )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["categories"], ["xss", "sqli"])
        self.assertEqual(set(data["by_category"]), {"xss", "sqli"})
        self.assertEqual(call.call_count, 2)
        self.assertEqual(
            data["verdicts"][SAMPLE["ghsa_id"]]["scored_categories"],
            ["sqli", "xss"],
        )

    def test_ai_batch_is_bounded(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg):
            r = self.client.post(
                "/api/ai/classify",
                json={
                    "category": "bac",
                    "advisory_ids": [f"GHSA-{index}" for index in range(101)],
                },
            )
        self.assertEqual(r.status_code, 400)
        self.assertIn("maximum is", r.get_json()["error"])

    def test_ai_classify_rejects_nested_and_oversized_list_values(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg):
            for body in (
                {"categories": [{"name": "bac"}], "advisory_ids": ["X"]},
                {"categories": ["bac"], "advisory_ids": [{"id": "X"}]},
                {"categories": ["bac"], "advisory_ids": ["X" * 201]},
            ):
                with self.subTest(body=body):
                    r = self.client.post("/api/ai/classify", json=body)
                    self.assertEqual(r.status_code, 400)

    def test_ai_health_check_is_post_only(self):
        self.assertEqual(self.client.get("/api/ai/test").status_code, 405)

    def test_ai_classify_reports_missing_ids(self):
        # Regression: ids absent from the cache used to be dropped silently;
        # now they must come back in "missing" (and the call still succeeds).
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("modules.ai_classifier._call_messages",
                        return_value='{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'):
            r = self.client.post(
                "/api/ai/classify",
                json={"category": "bac",
                      "advisory_ids": [SAMPLE["ghsa_id"], "GHSA-not-in-cache"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(
            set(data.keys()),
            {"category", "categories", "verdicts", "by_category", "missing"},
        )
        self.assertEqual(data["missing"], ["GHSA-not-in-cache"])
        self.assertIn(SAMPLE["ghsa_id"], data["verdicts"])
        self.assertNotIn("GHSA-not-in-cache", data["verdicts"])

    # -------------------------------------------------------------- NVD source

    def test_search_nvd_source(self):
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        with mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "sources": ["nvd"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(data["results"][0]["source"], "nvd")
        self.assertEqual(data["query"]["per_source"], {"nvd": 1})

    def test_search_nvd_and_ghsa_dedupe(self):
        ghsa_raw = dict(SAMPLE, cve_id="CVE-2021-44228")
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=[ghsa_raw]), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"],
                                       "sources": ["ghsa", "nvd"]})
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertIn("ghsa", data["results"][0]["sources"])
        self.assertIn("nvd", data["results"][0]["sources"])
        self.assertEqual(data["results"][0]["source"], "ghsa")

    def test_search_nvd_error_502_when_only_source(self):
        with mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "sources": ["nvd"]})
        self.assertEqual(r.status_code, 502)

    def test_search_nvd_error_warning_with_other_sources(self):
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=[SAMPLE]), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"],
                                       "sources": ["ghsa", "nvd"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(any("NVD fetch failed" in w for w in data["warnings"]))
        self.assertEqual(data["query"]["per_source"].get("ghsa"), 1)

    def test_index_has_nvd_checkbox(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        self.assertIn(b'value="nvd"', r.data)

    # ----------------------------------------------------------------- pages

    def test_index_renders(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"VulnSight", r.data)
        self.assertIn(b"window.BOOT", r.data)  # server data is injected via BOOT

    def test_index_boot_and_static_assets(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        self.assertIn(b"window.BOOT", r.data)
        self.assertIn(b"app.js", r.data)
        self.assertIn(b"style.css", r.data)

    def test_index_keeps_frontend_dom_contract(self):
        """The visual shell may change, but app.js hooks must remain stable."""
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            html = self.client.get("/").get_data(as_text=True)

        required_ids = [
            "refresh_osv", "include_extended", "ecosystem",
            "severity", "affects_pick", "published", "max_results", "sort",
            "direction", "type", "auto-btn", "search-btn",
            "cwe-search", "cwe-clear", "cwe-options", "selected-chips",
            "selection-count", "selection-live",
            "history-section", "history-list", "history-clear", "stale-banner",
            "class-search", "class-count", "taxonomy-list", "taxonomy-empty",
            "summary", "ai-btn", "retry-btn", "only_match", "export-btn",
            "results", "ai-test-pill", "filters-toggle", "filters-close",
            "filter-scrim",
            "auth-gate", "auth-token", "auth-save",
        ]
        for element_id in required_ids:
            self.assertEqual(html.count(f'id="{element_id}"'), 1, element_id)

        for name in ("category", "source"):
            self.assertIn(f'name="{name}"', html)
        # The CWE catalog is fetched from /api/cwes, never inlined in the page.
        self.assertNotIn("cwe_catalog", html)
        # Screen-reader landmarks: one h1, and no aria-label stranded on a bare
        # <div> (role=generic drops the label).
        self.assertEqual(html.count("<h1"), 1)
        for labelled_div in ('class="system-status"', 'class="rail-stats"', 'class="threat-key"'):
            index = html.index(labelled_div)
            self.assertIn('role="group"', html[index - 40:index + 80], labelled_div)
        self.assertLess(len(html), 60000, "index page should stay lean")
        for export_format in ("csv", "json", "csv-matches"):
            self.assertIn(f'data-fmt="{export_format}"', html)
        self.assertLess(html.index("window.BOOT"), html.index("app.js"))
        self.assertIn('id="ai-test-pill" type="button"', html)
        self.assertIn('value="epss_percentage"', html)
        self.assertIn('value="epss_percentile"', html)
        self.assertIn('id="theme-toggle"', html)
        self.assertIn("AUTH_REQUIRED: false", html)

    def test_static_assets_served(self):
        css = self.client.get("/static/style.css")
        js = self.client.get("/static/app.js")
        self.assertEqual(css.status_code, 200)
        self.assertIn("text/css", css.headers.get("Content-Type", ""))
        self.assertEqual(js.status_code, 200)
        self.assertIn("function csvCell", js.get_data(as_text=True))
        self.assertIn("epss_percentage", js.get_data(as_text=True))

    def test_osv_status_endpoint(self):
        r = self.client.get("/api/osv/status")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("supported", data)
        self.assertIn("cached", data)

    def test_cwe_catalog_endpoint(self):
        r = self.client.get("/api/cwes")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["columns"], ["id", "label", "aliases", "level"])
        self.assertGreater(len(data["rows"]), 900)
        by_id = {row[0]: row for row in data["rows"]}
        # Full name and code for every entry — that is the point of the picker.
        self.assertEqual(by_id["639"][1], "Authorization Bypass Through User-Controlled Key")
        self.assertIn("IDOR", by_id["639"][2].split("|"))
        self.assertEqual(by_id["639"][3], "Base")

    def test_cwe_catalog_is_cacheable(self):
        """The browser must reuse the catalog instead of refetching 60+ KB."""
        first = self.client.get("/api/cwes")
        etag = first.headers["ETag"]
        self.assertIn("max-age=", first.headers["Cache-Control"])
        again = self.client.get("/api/cwes", headers={"If-None-Match": etag})
        self.assertEqual(again.status_code, 304)
        self.assertEqual(again.get_data(), b"")

    def test_classify_accepts_single_cwe_pseudo_category(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
                mock.patch("modules.cache.get_advisory", return_value=None):
            r = self.client.post(
                "/api/ai/classify",
                json={"categories": ["cwe:1321", "bac"], "advisory_ids": ["GHSA-x"]},
            )
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["categories"], ["cwe:1321", "bac"])
        self.assertEqual(body["missing"], ["GHSA-x"])

    def test_classify_rejects_over_budget_fan_out(self):
        """categories × advisories is the real cost; cap the product, not each."""
        from modules.cwe_categories import picker_catalog

        real_cwes = [f"cwe:{row[0]}" for row in picker_catalog()["rows"][:30]]
        advisory_ids = [f"GHSA-x-{i}" for i in range(30)]
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg):
            r = self.client.post(
                "/api/ai/classify",
                json={"categories": real_cwes, "advisory_ids": advisory_ids},
            )
        self.assertEqual(r.status_code, 400)
        error = r.get_json()["error"]
        self.assertIn("900", error)
        self.assertIn(str(app_module.MAX_AI_CALLS_PER_REQUEST), error)

    def test_classify_allows_fan_out_within_budget(self):
        from modules.cwe_categories import picker_catalog

        real_cwes = [f"cwe:{row[0]}" for row in picker_catalog()["rows"][:10]]
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
                mock.patch("modules.cache.get_advisory", return_value=None):
            r = self.client.post(
                "/api/ai/classify",
                json={"categories": real_cwes,
                      "advisory_ids": [f"GHSA-x-{i}" for i in range(20)]},
            )
        self.assertEqual(r.status_code, 200)

    def test_index_exposes_the_ai_call_budget_to_the_client(self):
        """The UI sizes its batches from this, so it must be in BOOT."""
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn(
            f"AI_CALL_BUDGET: {app_module.MAX_AI_CALLS_PER_REQUEST}", html
        )

    def test_classify_rejects_malformed_cwe_pseudo_category(self):
        r = self.client.post(
            "/api/ai/classify",
            json={"categories": ["cwe:0"], "advisory_ids": ["GHSA-x"]},
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("Unsupported categories", r.get_json()["error"])

    def test_csrf_blocks_foreign_origin(self):
        r = self.client.post(
            "/api/search",
            json={"categories": ["bac"]},
            headers={"Origin": "http://evil.example"},
        )
        self.assertEqual(r.status_code, 403)
        self.assertIn("Cross-origin", r.get_json()["error"])

    def test_csrf_allows_localhost_origin(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"Origin": "http://127.0.0.1:5000"},
            )
        self.assertEqual(r.status_code, 200)

    def test_csrf_blocks_prefix_lookalike_origins(self):
        for origin in (
            "http://localhost.evil.com",
            "http://localhostevil.com",
            "http://127.0.0.1.attacker.com",
            "http://127.0.0.1.example",
            "http://127.0.0.1:5000.evil.com",
        ):
            with self.subTest(origin=origin):
                r = self.client.post(
                    "/api/search",
                    json={"categories": ["bac"]},
                    headers={"Origin": origin},
                )
                self.assertEqual(r.status_code, 403, origin)

    def test_csrf_blocks_cross_site_fetch_metadata(self):
        r = self.client.post(
            "/api/search",
            json={"categories": ["bac"]},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(r.status_code, 403)

    def test_csrf_blocks_evil_referer_without_origin(self):
        r = self.client.post(
            "/api/search",
            json={"categories": ["bac"]},
            headers={"Referer": "http://evil.example/page"},
        )
        self.assertEqual(r.status_code, 403)

    def test_search_ghsa_error_does_not_leak_cli_stderr(self):
        with mock.patch(
            "modules.ghsa_client.fetch_advisories",
            side_effect=ghsa.GhCliError("token ghp_LEAKED"),
        ):
            r = self.client.post("/api/search", json={"categories": ["bac"]})
        self.assertEqual(r.status_code, 502)
        body = r.get_data(as_text=True)
        self.assertNotIn("ghp_LEAKED", body)
        self.assertEqual(r.get_json()["error"], "GHSA fetch failed.")

    def test_ai_test_hides_provider_error_body(self):
        cfg = ai_classifier.AIConfig("glm", "https://x", ["tok"], "m")
        err = urllib.error.HTTPError(
            url="https://x/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"invalid api_key sk-secret-abc"}'),
        )
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("urllib.request.urlopen", side_effect=err):
            r = self.client.post("/api/ai/test", json={})
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertFalse(r.get_json()["ok"])
        self.assertEqual(r.get_json()["error"], "AI provider returned HTTP 401")
        self.assertNotIn("sk-secret-abc", body)
        self.assertNotIn("invalid api_key", body)

    def test_ai_classify_hides_provider_error_body(self):
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("glm", "https://x", ["tok"], "m")
        err = urllib.error.HTTPError(
            url="https://x/chat/completions",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"token ghp_LEAKED rejected"}'),
        )
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("urllib.request.urlopen", side_effect=err):
            r = self.client.post(
                "/api/ai/classify",
                json={"category": "bac", "advisory_ids": [SAMPLE["ghsa_id"]]},
            )
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        data = r.get_json()
        self.assertEqual(
            data["by_category"]["bac"][SAMPLE["ghsa_id"]]["error"],
            "AI provider returned HTTP 403",
        )
        self.assertIn("AI provider returned HTTP 403", data["verdicts"][SAMPLE["ghsa_id"]]["error"])
        self.assertNotIn("ghp_LEAKED", body)

    def test_index_csp_nonce_matches_header(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        html = r.get_data(as_text=True)
        csp = r.headers["Content-Security-Policy"]
        marker = 'script nonce="'
        nonce = html.split(marker, 1)[1].split('"', 1)[0]
        self.assertGreaterEqual(len(nonce), 20)
        self.assertIn(f"'nonce-{nonce}'", csp)


class TestApiVersioning(unittest.TestCase):
    """Every API route answers on both /api/... and /api/v1/...."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        self._env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "off",
            "HOST": "127.0.0.1",
        }, clear=False)
        self._env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self._env.stop()
        cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def test_every_api_route_has_a_v1_twin(self):
        """Fails when a new /api/ route ships without its versioned alias."""
        # /api/docs is an HTML reference page, not versioned API surface: it
        # renders whatever the current spec says, so there is nothing to pin.
        not_api_surface = {"/api/docs"}
        rules = [
            str(rule) for rule in self.app.url_map.iter_rules()
            if str(rule).startswith("/api/") and str(rule) not in not_api_surface
        ]
        legacy = {r for r in rules if not r.startswith("/api/v1/")}
        versioned = {
            "/api" + r[len("/api/v1"):] for r in rules if r.startswith("/api/v1/")
        }
        self.assertTrue(legacy, "no /api routes found — the check would be vacuous")
        self.assertEqual(
            legacy - versioned, set(),
            "these /api routes have no /api/v1 alias",
        )

    def test_v1_and_legacy_return_the_same_payload(self):
        for legacy, versioned in (
            ("/api/meta", "/api/v1/meta"),
            ("/api/cwes", "/api/v1/cwes"),
            ("/api/osv/status", "/api/v1/osv/status"),
        ):
            with self.subTest(path=versioned):
                with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=True):
                    a = self.client.get(legacy)
                    b = self.client.get(versioned)
                self.assertEqual(a.status_code, 200)
                self.assertEqual(b.status_code, 200)
                self.assertEqual(a.get_json(), b.get_json())

    def test_v1_search_is_rate_limited_like_the_legacy_path(self):
        """The limiter matches on endpoint; a path match left /api/v1 unlimited."""
        self._env.stop()
        self._env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "on",
            "VULNSIGHT_SEARCH_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60",
            "HOST": "127.0.0.1",
        }, clear=False)
        self._env.start()
        from app import create_app
        client = create_app().test_client()
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = client.post("/api/v1/search",
                                json={"categories": ["bac"], "ecosystem": "maven"})
            second = client.post("/api/v1/search",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    def test_search_reports_row_counts_per_pipeline_stage(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/v1/search",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
        stats = r.get_json()["stats"]
        self.assertEqual(stats["fetched_per_source"], {"ghsa": 1})
        self.assertEqual(
            [stats["fetched_total"], stats["after_merge"],
             stats["after_filter"], stats["returned"]],
            [1, 1, 1, 1],
        )
        self.assertFalse(stats["truncated"])

    def test_truncated_flag_distinguishes_paging_from_dedupe(self):
        """`count` alone could not tell a dropped row from a de-duplicated one."""
        raw = [dict(SAMPLE, ghsa_id=f"GHSA-{n}", cve_id=f"CVE-2026-{n}")
               for n in range(5)]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=raw):
            r = self.client.post("/api/v1/search", json={
                "categories": ["bac"], "ecosystem": "maven", "max_results": 2,
            })
        stats = r.get_json()["stats"]
        self.assertEqual(stats["after_filter"], 5)
        self.assertEqual(stats["returned"], 2)
        self.assertTrue(stats["truncated"])


class TestJobEndpoints(unittest.TestCase):
    """The async path: submit, poll, and the guards around both."""

    def _make(self, env=None):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        merged = {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "off",
            "HOST": "127.0.0.1",
        }
        merged.update(env or {})
        self._env = mock.patch.dict(os.environ, merged, clear=False)
        self._env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        from modules import jobs
        jobs.shutdown(wait=True)
        if hasattr(self, "_env"):
            self._env.stop()
        if hasattr(self, "_orig_db"):
            cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def _poll(self, job_id, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self.client.get(f"/api/v1/jobs/{job_id}")
            body = r.get_json()
            if body["status"] in ("done", "failed"):
                return body
            time.sleep(0.01)
        raise AssertionError("job never finished")

    def test_submit_returns_202_with_a_pollable_location(self):
        self._make()
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/v1/jobs",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
            self.assertEqual(r.status_code, 202)
            body = r.get_json()
            self.assertEqual(body["status"], "queued")
            self.assertEqual(body["kind"], "search")
            self.assertEqual(r.headers["Location"], f"/api/v1/jobs/{body['job_id']}")
            done = self._poll(body["job_id"])
        self.assertEqual(done["status"], "done")
        self.assertEqual(done["result"]["count"], 1)

    def test_job_result_matches_the_synchronous_response(self):
        """Moving a slow query to /jobs must not mean parsing a second shape."""
        self._make()
        query = {"categories": ["bac"], "ecosystem": "maven"}
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            sync = self.client.post("/api/v1/search", json=query).get_json()
            job_id = self.client.post("/api/v1/jobs", json=query).get_json()["job_id"]
            async_result = self._poll(job_id)["result"]
        self.assertEqual(sync.keys(), async_result.keys())
        self.assertEqual(sync["query"], async_result["query"])
        self.assertEqual(sync["stats"], async_result["stats"])
        self.assertEqual(sync["results"], async_result["results"])

    def test_a_bad_query_is_rejected_now_not_a_minute_later(self):
        self._make()
        r = self.client.post("/api/v1/jobs", json={"categories": []})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("job_id", r.get_json())

    def test_a_failing_search_becomes_a_failed_job_with_its_status(self):
        self._make()
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")):
            job_id = self.client.post(
                "/api/v1/jobs",
                json={"categories": ["bac"], "sources": ["ghsa"]},
            ).get_json()["job_id"]
            done = self._poll(job_id)
        self.assertEqual(done["status"], "failed")
        self.assertEqual(done["error"], "GHSA fetch failed.")
        self.assertNotIn("nope", done["error"])
        self.assertNotIn("result", done)

    def test_unknown_and_malformed_job_ids_are_404(self):
        self._make()
        for job_id in ("0" * 24, "not-a-job", "a" * 23, "A" * 24, "1;DROP TABLE jobs"):
            with self.subTest(job_id=job_id):
                r = self.client.get(f"/api/v1/jobs/{job_id}")
                self.assertEqual(r.status_code, 404)
                self.assertEqual(r.get_json(), {"error": "No such job."})

    def test_traversal_in_a_job_id_never_reaches_the_handler(self):
        """Werkzeug normalises the path, so it matches no route at all."""
        self._make()
        r = self.client.get("/api/v1/jobs/%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json(), {"error": "No such endpoint."})

    def test_api_errors_are_json_even_when_no_route_matches(self):
        """A script doing r.json() on a wrong path used to get a parse error."""
        self._make()
        missing = self.client.get("/api/v1/nope")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.get_json(), {"error": "No such endpoint."})

        wrong_method = self.client.get("/api/v1/search")
        self.assertEqual(wrong_method.status_code, 405)
        self.assertIn("error", wrong_method.get_json())

        # The UI still gets HTML, because a browser is not a script.
        html = self.client.get("/definitely-not-a-page")
        self.assertEqual(html.status_code, 404)
        self.assertIsNone(html.get_json(silent=True))

    def test_polling_requires_the_token_unlike_other_gets(self):
        """A job result is the operator's query output, not public reference data."""
        self._make({"VULNSIGHT_API_TOKEN": "secret"})
        headers = {"X-VulnSight-Token": "secret"}
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            job_id = self.client.post(
                "/api/v1/jobs", json={"categories": ["bac"], "ecosystem": "maven"},
                headers=headers,
            ).get_json()["job_id"]
        self.assertEqual(self.client.get(f"/api/v1/jobs/{job_id}").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/cwes").status_code, 200)
        authed = self.client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        self.assertEqual(authed.status_code, 200)

    def test_submitting_a_job_spends_the_search_rate_limit(self):
        """Otherwise /jobs is a free way around the limit it exists to work with."""
        self._make({"VULNSIGHT_RATE_LIMIT": "on", "VULNSIGHT_SEARCH_RATE": "1",
                    "VULNSIGHT_RATE_WINDOW": "60"})
        query = {"categories": ["bac"], "ecosystem": "maven"}
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post("/api/v1/jobs", json=query)
            second = self.client.post("/api/v1/jobs", json=query)
            third = self.client.post("/api/v1/search", json=query)
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(third.status_code, 429)  # shared bucket, not two budgets

    def test_legacy_job_paths_work_too(self):
        self._make()
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/jobs",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
            self.assertEqual(r.status_code, 202)
            job_id = r.get_json()["job_id"]
            self._poll(job_id)
        self.assertEqual(self.client.get(f"/api/jobs/{job_id}").status_code, 200)


class TestAppAuthAndLimits(unittest.TestCase):
    def _make(self, env):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        merged = {
            "VULNSIGHT_API_TOKEN": "",
            "VULNSIGHT_RATE_LIMIT": "on",
            "VULNSIGHT_PUBLIC_HOST": "",
            "VULNSIGHT_SEARCH_RATE": "30",
            "VULNSIGHT_AI_RATE": "20",
            "VULNSIGHT_RATE_WINDOW": "60",
            "HOST": "127.0.0.1",
        }
        merged.update(env)
        self._env = mock.patch.dict(os.environ, merged, clear=False)
        self._env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        if hasattr(self, "_env"):
            self._env.stop()
        if hasattr(self, "_orig_db"):
            cache.DB_PATH = self._orig_db
        if hasattr(self, "tmp"):
            for ext in ["", "-wal", "-shm"]:
                try:
                    os.unlink(self.tmp.name + ext)
                except OSError:
                    pass

    def test_token_required_on_post_not_get(self):
        self._make({"VULNSIGHT_API_TOKEN": "test-secret-token"})
        self.assertEqual(
            self.client.post("/api/search", json={"categories": ["bac"]}).status_code,
            401,
        )
        self.assertEqual(self.client.get("/api/meta").status_code, 200)
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn("AUTH_REQUIRED: true", html)
        self.assertNotIn("test-secret-token", html)
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            ok = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-VulnSight-Token": "test-secret-token"},
            )
            bearer = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"Authorization": "Bearer test-secret-token"},
            )
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(bearer.status_code, 200)
        self.assertEqual(
            self.client.post(
                "/api/search",
                json={"categories": ["bac"]},
                headers={"X-VulnSight-Token": "wrong"},
            ).status_code,
            401,
        )

    def test_csrf_allows_configured_public_host(self):
        self._make({"VULNSIGHT_PUBLIC_HOST": "vulnsight.example"})
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"Origin": "https://vulnsight.example"},
            )
        self.assertEqual(r.status_code, 200)

    def test_search_rate_limit(self):
        self._make({"VULNSIGHT_SEARCH_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60"})
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"}
            )
            second = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"}
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.headers.get("Retry-After"), "60")

    def test_unauthenticated_posts_do_not_consume_the_rate_limit(self):
        """Auth runs before rate limiting, so a rejected caller spends nothing.

        With the hooks the other way round an unauthenticated flood drained the
        shared bucket and the operator's own next request — with the right
        token — came back 429. Every request here is 401; none reaches the
        limiter, and the authenticated request that follows still succeeds.
        """
        self._make({
            "VULNSIGHT_API_TOKEN": "secret",
            "VULNSIGHT_SEARCH_RATE": "2",
            "VULNSIGHT_RATE_WINDOW": "60",
        })
        rejected = [
            self.client.post("/api/search", json={"categories": ["bac"]}).status_code
            for _ in range(6)
        ]
        self.assertEqual(rejected, [401] * 6)
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            operator = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-VulnSight-Token": "secret"},
            )
        self.assertEqual(operator.status_code, 200)

    def test_rate_limit_key_ignores_forwarded_for_by_default(self):
        """X-Forwarded-For is client-controlled; trusting it mints free buckets."""
        self._make({"VULNSIGHT_SEARCH_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60"})
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "1.1.1.1"},
            )
            second = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "2.2.2.2"},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    def test_rate_limit_key_honours_forwarded_for_when_proxy_trusted(self):
        self._make({
            "VULNSIGHT_SEARCH_RATE": "1",
            "VULNSIGHT_RATE_WINDOW": "60",
            "VULNSIGHT_TRUST_PROXY": "1",
        })
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "1.1.1.1"},
            )
            other_client = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "2.2.2.2"},
            )
            same_client = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "1.1.1.1"},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(other_client.status_code, 200)  # separate bucket
        self.assertEqual(same_client.status_code, 429)   # same bucket, exhausted

    def test_non_loopback_autogens_token(self):
        data_dir = tempfile.mkdtemp()
        self._make({
            "HOST": "0.0.0.0",
            "GLM_TOKEN": "live-key",
            "VULNSIGHT_API_TOKEN": "",
            "VULNSIGHT_DATA_DIR": data_dir,
            "VULNSIGHT_RATE_LIMIT": "off",
        })
        token = self.app.config["VULNSIGHT_TOKEN"]
        self.assertTrue(token)
        path = os.path.join(data_dir, ".vulnsight_api_token")
        with open(path, encoding="utf-8") as fh:
            saved = fh.read().strip()
        self.assertEqual(saved, token)
        self.assertEqual(self.client.post("/api/search", json={"categories": ["bac"]}).status_code, 401)
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            ok = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-VulnSight-Token": token},
            )
        self.assertEqual(ok.status_code, 200)

    def test_ai_rate_limit(self):
        self._make({"VULNSIGHT_AI_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60"})
        with mock.patch("modules.ai_classifier.ping", return_value={"ok": True}):
            first = self.client.post("/api/ai/test", json={})
            second = self.client.post("/api/ai/test", json={})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)


if __name__ == "__main__":
    unittest.main(verbosity=2)
