"""End-to-end Flask endpoint tests (offline: gh CLI, OSV and AI all mocked;
cache pointed at a temp SQLite DB before the app module is imported)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tempfile
import unittest
from unittest import mock

from modules import ai_classifier
from modules import cache
from modules import ghsa_client as ghsa
from modules import nvd_client
from modules import osv_client
from samples import NVD_VULN, OSV_GHSA, SAMPLE, SORT_A, SORT_B, SORT_C, make_sortable_raw


class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        # Point the app's cache at a temp db BEFORE importing the app module
        # (import runs cache.init_db()).
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        cache.init_db(cache.DB_PATH)
        import app as app_module
        self.app_module = app_module
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
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

    def test_search_no_category_defaults_bac(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[]):
            r = self.client.post("/api/search", json={})
        self.assertEqual(r.status_code, 200)
        self.assertIn("bac", r.get_json()["query"]["categories"])

    def test_search_ghsa_error_502(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", side_effect=ghsa.GhCliError("nope")):
            r = self.client.post("/api/search", json={"categories": ["bac"]})
        self.assertEqual(r.status_code, 502)

    def test_mutating_apis_require_json_content_type(self):
        r = self.client.post(
            "/api/search", data='{"categories":["bac"]}', content_type="text/plain"
        )
        self.assertEqual(r.status_code, 415)
        r = self.client.post(
            "/api/ai/classify", data='{"ghsa_ids":["X"]}', content_type="text/plain"
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
            r = self.client.post("/api/ai/classify", json={"category": "bac", "ghsa_ids": ["X"]})
        self.assertEqual(r.status_code, 400)

    def test_ai_classify_flow(self):
        # Seed cache with an advisory, then classify with mocked AI.
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("modules.ai_classifier._call_messages",
                        return_value='{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'):
            r = self.client.post("/api/ai/classify",
                                 json={"category": "bac", "ghsa_ids": [SAMPLE["ghsa_id"]]})
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
                    "ghsa_ids": [SAMPLE["ghsa_id"]],
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
                    "ghsa_ids": [f"GHSA-{index}" for index in range(101)],
                },
            )
        self.assertEqual(r.status_code, 400)
        self.assertIn("maximum is", r.get_json()["error"])

    def test_ai_classify_rejects_nested_and_oversized_list_values(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg):
            for body in (
                {"categories": [{"name": "bac"}], "ghsa_ids": ["X"]},
                {"categories": ["bac"], "ghsa_ids": [{"id": "X"}]},
                {"categories": ["bac"], "ghsa_ids": ["X" * 201]},
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
                      "ghsa_ids": [SAMPLE["ghsa_id"], "GHSA-not-in-cache"]})
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
            "scenario", "refresh_osv", "include_extended", "ecosystem",
            "severity", "affects_pick", "published", "max_results", "sort",
            "direction", "type", "extra_cwes_count", "auto-btn", "search-btn",
            "summary", "ai-btn", "retry-btn", "only_match", "export-btn",
            "results", "ai-test-pill", "filters-toggle", "filters-close",
            "filter-scrim",
        ]
        for element_id in required_ids:
            self.assertEqual(html.count(f'id="{element_id}"'), 1, element_id)

        for name in ("category", "source", "extra_cwe"):
            self.assertIn(f'name="{name}"', html)
        for export_format in ("csv", "json", "csv-matches"):
            self.assertIn(f'data-fmt="{export_format}"', html)
        self.assertLess(html.index("window.BOOT"), html.index("app.js"))
        self.assertIn('id="ai-test-pill" type="button"', html)
        self.assertNotIn("style=", html)

    def test_index_csp_nonce_matches_header(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        html = r.get_data(as_text=True)
        csp = r.headers["Content-Security-Policy"]
        marker = 'script nonce="'
        nonce = html.split(marker, 1)[1].split('"', 1)[0]
        self.assertGreaterEqual(len(nonce), 20)
        self.assertIn(f"'nonce-{nonce}'", csp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
