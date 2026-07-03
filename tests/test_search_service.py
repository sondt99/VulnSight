"""Tests for search_service: query parsing, merge/dedupe, and run_search
orchestration (sort-field fix, source error policy). All fetchers are mocked
and the cache is pointed at a temp SQLite DB."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tempfile
import unittest
from unittest import mock

from modules import cache
from modules import ghsa_client as ghsa
from modules import search_service
from samples import SORT_A, SORT_B, SORT_C, make_sortable_raw


class TestParseStrList(unittest.TestCase):
    def test_comma_string(self):
        self.assertEqual(search_service.parse_str_list("a, b,,c"), ["a", "b", "c"])

    def test_list_coerced_to_str(self):
        self.assertEqual(search_service.parse_str_list(["x", 1]), ["x", "1"])

    def test_none_and_empty(self):
        self.assertEqual(search_service.parse_str_list(None), [])
        self.assertEqual(search_service.parse_str_list(""), [])


class TestParseSearchQuery(unittest.TestCase):
    def test_defaults(self):
        q = search_service.parse_search_query({})
        self.assertEqual(q.categories, ["bac"])
        self.assertEqual(q.sort, "published")
        self.assertEqual(q.direction, "desc")
        self.assertEqual(q.max_results, 100)
        self.assertEqual(q.sources, ["ghsa"])
        self.assertEqual(q.ecosystem, "any")
        self.assertEqual(q.severity, "any")
        self.assertEqual(q.adv_type, "reviewed")
        self.assertTrue(q.include_extended)
        self.assertIn("639", q.cwes)  # resolved from bac

    def test_bogus_sort_and_direction_fall_back(self):
        q = search_service.parse_search_query({"sort": "bogus", "direction": "sideways"})
        self.assertEqual(q.sort, "published")
        self.assertEqual(q.direction, "desc")

    def test_max_results_clamped(self):
        cases = [(0, 1), (9999, 500), ("abc", 100), ("250", 250), (-5, 1)]
        for raw, want in cases:
            with self.subTest(max_results=raw):
                q = search_service.parse_search_query({"max_results": raw})
                self.assertEqual(q.max_results, want)

    def test_extra_cwes_merged_without_duplicates(self):
        q = search_service.parse_search_query(
            {"categories": ["xss"], "extra_cwes": "CWE-79, 639"})
        self.assertEqual(q.cwes.count("79"), 1)   # already in xss core, not duped
        self.assertIn("639", q.cwes)              # genuinely new -> appended
        self.assertNotIn("89", q.cwes)            # sqli not requested

    def test_unknown_category_without_extras_is_400(self):
        with self.assertRaises(search_service.SearchError) as cm:
            search_service.parse_search_query({"categories": ["nope"]})
        self.assertEqual(cm.exception.status, 400)
        # ... but extra CWEs alone can still make the query resolvable.
        q = search_service.parse_search_query(
            {"categories": ["nope"], "extra_cwes": "CWE-79"})
        self.assertEqual(q.cwes, ["79"])


class TestMergeAdvisories(unittest.TestCase):
    def test_same_cve_prefers_ghsa_base_even_if_later(self):
        osv_rec = {"cve_id": "CVE-2026-1", "ghsa_id": "GHSA-osvv", "source": "osv",
                   "summary": "from osv"}
        ghsa_rec = {"cve_id": "CVE-2026-1", "ghsa_id": "GHSA-real", "source": "ghsa",
                    "summary": "from ghsa"}
        out = search_service.merge_advisories([osv_rec, ghsa_rec])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["summary"], "from ghsa")  # GHSA base won
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])  # union, sorted

    def test_ghsa_first_keeps_ghsa_base(self):
        ghsa_rec = {"cve_id": "CVE-2026-2", "source": "ghsa", "summary": "from ghsa"}
        osv_rec = {"cve_id": "CVE-2026-2", "source": "osv", "summary": "from osv"}
        out = search_service.merge_advisories([ghsa_rec, osv_rec])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["summary"], "from ghsa")
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])

    def test_keyless_record_kept_and_order_preserved(self):
        rec_x = {"cve_id": "CVE-2026-3", "source": "ghsa", "summary": "x"}
        keyless = {"summary": "no ids at all"}
        rec_y = {"cve_id": "CVE-2026-4", "source": "osv", "summary": "y"}
        dup_x = {"cve_id": "CVE-2026-3", "source": "osv", "summary": "x-osv"}
        out = search_service.merge_advisories([rec_x, keyless, rec_y, dup_x])
        self.assertEqual([r["summary"] for r in out], ["x", "no ids at all", "y"])
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])
        self.assertEqual(out[1]["sources"], ["?"])  # fallback source tag


class TestRunSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        cache.init_db(cache.DB_PATH)

    def tearDown(self):
        cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def _run(self, body):
        q = search_service.parse_search_query(body)
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=make_sortable_raw()):
            return search_service.run_search(q)

    def test_sort_published_default(self):
        out = self._run({})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_A, SORT_C, SORT_B])
        self.assertEqual(out.per_source, {"ghsa": 3})

    def test_sort_updated_fixed(self):
        # Regression: the old code always sorted by published_at.
        out = self._run({"sort": "updated"})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_B, SORT_C, SORT_A])

    def test_sort_updated_ascending(self):
        out = self._run({"sort": "updated", "direction": "asc"})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_A, SORT_C, SORT_B])

    def test_sort_cve_id(self):
        out = self._run({"sort": "cve_id"})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_B, SORT_A, SORT_C])
        out = self._run({"sort": "cve_id", "direction": "asc"})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_C, SORT_A, SORT_B])

    def test_ghsa_only_failure_is_502(self):
        q = search_service.parse_search_query({})  # sources == ["ghsa"]
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")):
            with self.assertRaises(search_service.SearchError) as cm:
                search_service.run_search(q)
        self.assertEqual(cm.exception.status, 502)

    def test_ghsa_failure_with_other_sources_is_warning(self):
        q = search_service.parse_search_query(
            {"sources": ["ghsa", "osv"], "ecosystem": "go"})
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")), \
             mock.patch("modules.osv_client.fetch_osv", return_value=[]):
            out = search_service.run_search(q)
        self.assertTrue(any("GHSA fetch failed" in w for w in out.warnings))
        self.assertNotIn("ghsa", out.per_source)
        self.assertEqual(out.per_source.get("osv"), 0)
        self.assertEqual(out.results, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
