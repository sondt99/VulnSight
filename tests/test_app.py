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
from modules import osv_client
from samples import OSV_GHSA, SAMPLE, SORT_A, SORT_B, SORT_C, make_sortable_raw


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
                        return_value=ai_classifier.AIConfig("anthropic", "", "", "")):
            r = self.client.post("/api/ai/classify", json={"category": "bac", "ghsa_ids": ["X"]})
        self.assertEqual(r.status_code, 400)

    def test_ai_classify_flow(self):
        # Seed cache with an advisory, then classify with mocked AI.
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", "tok", "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("modules.ai_classifier._call_messages",
                        return_value='{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'):
            r = self.client.post("/api/ai/classify",
                                 json={"category": "bac", "ghsa_ids": [SAMPLE["ghsa_id"]]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["verdicts"][SAMPLE["ghsa_id"]]["is_match"])
        self.assertEqual(data["missing"], [])  # everything was in the cache

    def test_ai_classify_reports_missing_ids(self):
        # Regression: ids absent from the cache used to be dropped silently;
        # now they must come back in "missing" (and the call still succeeds).
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", "tok", "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("modules.ai_classifier._call_messages",
                        return_value='{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'):
            r = self.client.post(
                "/api/ai/classify",
                json={"category": "bac",
                      "ghsa_ids": [SAMPLE["ghsa_id"], "GHSA-not-in-cache"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(set(data.keys()), {"category", "verdicts", "missing"})
        self.assertEqual(data["missing"], ["GHSA-not-in-cache"])
        self.assertIn(SAMPLE["ghsa_id"], data["verdicts"])
        self.assertNotIn("GHSA-not-in-cache", data["verdicts"])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
