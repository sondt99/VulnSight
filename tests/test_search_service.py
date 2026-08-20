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
from modules import nvd_client
from modules import search_service
from samples import NVD_VULN, SAMPLE, SORT_A, SORT_B, SORT_C, make_sortable_raw


class TestParseStrList(unittest.TestCase):
    def test_comma_string(self):
        self.assertEqual(search_service.parse_str_list("a, b,,c"), ["a", "b", "c"])

    def test_list_entries_must_be_strings(self):
        with self.assertRaises(search_service.SearchError):
            search_service.parse_str_list(["x", 1])

    def test_none_and_empty(self):
        self.assertEqual(search_service.parse_str_list(None), [])
        self.assertEqual(search_service.parse_str_list(""), [])


class TestParseSearchQuery(unittest.TestCase):
    def test_empty_categories_raises(self):
        with self.assertRaises(search_service.SearchError) as cm:
            search_service.parse_search_query({})
        self.assertEqual(cm.exception.status, 400)
        self.assertIn("category", str(cm.exception).lower())
        self.assertEqual(cm.exception.public_message, str(cm.exception))
        self.assertNotIn("Traceback", cm.exception.public_message)

    def test_defaults(self):
        q = search_service.parse_search_query({"categories": ["bac"]})
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
        q = search_service.parse_search_query({"categories": ["bac"], "sort": "bogus", "direction": "sideways"})
        self.assertEqual(q.sort, "published")
        self.assertEqual(q.direction, "desc")

    def test_max_results_clamped(self):
        cases = [(0, 1), (9999, 500), ("abc", 100), ("250", 250), (-5, 1)]
        for raw, want in cases:
            with self.subTest(max_results=raw):
                q = search_service.parse_search_query({"categories": ["bac"], "max_results": raw})
                self.assertEqual(q.max_results, want)

    def test_extra_cwes_merged_without_duplicates(self):
        q = search_service.parse_search_query(
            {"categories": ["xss"], "extra_cwes": "CWE-79, 639"})
        self.assertEqual(q.cwes.count("79"), 1)   # already in xss core, not duped
        self.assertIn("639", q.cwes)              # genuinely new -> appended
        self.assertNotIn("89", q.cwes)            # sqli not requested

    def test_unknown_category_is_400_even_with_extra_cwes(self):
        for body in (
            {"categories": ["nope"]},
            {"categories": ["nope"], "extra_cwes": "CWE-79"},
        ):
            with self.subTest(body=body), self.assertRaises(search_service.SearchError) as cm:
                search_service.parse_search_query(body)
            self.assertEqual(cm.exception.status, 400)

    def test_extra_cwes_are_bounded_and_strictly_typed(self):
        invalid_values = (
            ["9" * (search_service.MAX_CWE_ID_DIGITS + 1)],
            ["CWE-0"],
            [{"id": "79"}],
            list(range(1, search_service.MAX_EXTRA_CWES + 2)),
        )
        for extra_cwes in invalid_values:
            with self.subTest(extra_cwes=type(extra_cwes[0]).__name__), \
                    self.assertRaises(search_service.SearchError):
                search_service.parse_search_query({"categories": ["bac"], "extra_cwes": extra_cwes})

    def test_extra_cwes_are_canonicalized_and_deduplicated(self):
        q = search_service.parse_search_query(
            {
                "categories": ["sqli"],
                "include_extended": False,
                "extra_cwes": ["CWE-00079", 79, "639"],
            }
        )
        self.assertEqual(q.cwes, ["89", "79", "639"])

    def test_string_list_fields_are_bounded_and_strictly_typed(self):
        invalid_bodies = (
            {"categories": [{"name": "bac"}]},
            {"categories": ["b" * 65]},
            {"categories": ["bac"], "sources": ["ghsa", "nvd", "osv", "osv-native", "ghsa"]},
            {"categories": ["bac"], "sources": [{"name": "ghsa"}]},
        )
        for body in invalid_bodies:
            with self.subTest(body=body), self.assertRaises(search_service.SearchError):
                search_service.parse_search_query(body)

    def test_sources_are_deduplicated(self):
        q = search_service.parse_search_query({"categories": ["bac"], "sources": ["ghsa", "ghsa"]})
        self.assertEqual(q.sources, ["ghsa"])

    def test_string_false_is_not_truthy(self):
        q = search_service.parse_search_query({"categories": ["bac"], "include_extended": "false"})
        self.assertFalse(q.include_extended)

    def test_invalid_source_and_date_rejected(self):
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "sources": ["made-up"]})
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "published": "last Tuesday"})
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "published": "2026-02-30"})
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "ecosystem": {"unexpected": True}})
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "extra_cwes": ["CWE-not-a-number"]})


class TestMergeAdvisories(unittest.TestCase):
    def test_same_cve_prefers_ghsa_base_even_if_later(self):
        osv_rec = {"advisory_id": "GHSA-osvv", "cve_id": "CVE-2026-1",
                   "ghsa_id": "GHSA-osvv", "source": "osv", "summary": "from osv"}
        ghsa_rec = {"advisory_id": "GHSA-real", "cve_id": "CVE-2026-1",
                    "ghsa_id": "GHSA-real", "source": "ghsa", "summary": "from ghsa"}
        out = search_service.merge_advisories([osv_rec, ghsa_rec])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["summary"], "from ghsa")  # GHSA base won
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])  # union, sorted

    def test_ghsa_first_keeps_ghsa_base(self):
        ghsa_rec = {"advisory_id": "CVE-2026-2", "cve_id": "CVE-2026-2",
                    "source": "ghsa", "summary": "from ghsa"}
        osv_rec = {"advisory_id": "CVE-2026-2", "cve_id": "CVE-2026-2",
                   "source": "osv", "summary": "from osv"}
        out = search_service.merge_advisories([ghsa_rec, osv_rec])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["summary"], "from ghsa")
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])

    def test_keyless_record_kept_and_order_preserved(self):
        rec_x = {"advisory_id": "CVE-2026-3", "cve_id": "CVE-2026-3",
                 "source": "ghsa", "summary": "x"}
        keyless = {"summary": "no ids at all"}
        rec_y = {"advisory_id": "CVE-2026-4", "cve_id": "CVE-2026-4",
                 "source": "osv", "summary": "y"}
        dup_x = {"advisory_id": "CVE-2026-3", "cve_id": "CVE-2026-3",
                 "source": "osv", "summary": "x-osv"}
        out = search_service.merge_advisories([rec_x, keyless, rec_y, dup_x])
        self.assertEqual([r["summary"] for r in out], ["x", "no ids at all", "y"])
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])
        self.assertEqual(out[1]["sources"], ["?"])  # fallback source tag

    def test_merge_preserves_complementary_metadata(self):
        nvd = {
            "advisory_id": "CVE-2026-55", "ghsa_id": None,
            "cve_id": "CVE-2026-55", "source": "nvd",
            "severity": "critical", "cvss_score": 9.8, "cwes": ["89"],
            "references": ["https://nvd.example"], "packages": [], "ecosystems": [],
            "kev": True, "nvd_status": "Analyzed",
        }
        ghsa = {
            "advisory_id": "GHSA-bridge", "ghsa_id": "GHSA-bridge",
            "cve_id": "CVE-2026-55", "source": "ghsa",
            "severity": "high", "cvss_score": 8.1, "cwes": ["CWE-89"],
            "references": ["https://ghsa.example"], "packages": [], "ecosystems": [],
        }
        merged = search_service.merge_advisories([nvd, ghsa])[0]
        self.assertEqual(merged["source"], "ghsa")
        self.assertTrue(merged["kev"])
        self.assertEqual(merged["nvd_status"], "Analyzed")
        self.assertEqual(merged["severity"], "critical")
        self.assertEqual(merged["cvss_by_source"], {"nvd": 9.8, "ghsa": 8.1})
        self.assertEqual(set(merged["references"]), {"https://nvd.example", "https://ghsa.example"})
        self.assertEqual(set(merged["source_records"]), {"ghsa", "nvd"})

    def test_alias_graph_bridge_merges_all_records(self):
        records = [
            {"advisory_id": "GHSA-one", "ghsa_id": "GHSA-one",
             "aliases": ["CVE-2026-77"], "source": "ghsa"},
            {"advisory_id": "GO-2026-1", "osv_id": "GO-2026-1",
             "ghsa_id": "GO-2026-1",
             "aliases": ["CVE-2026-77", "RUSTSEC-2026-1"], "source": "osv"},
            {"advisory_id": "RUSTSEC-2026-1", "osv_id": "RUSTSEC-2026-1",
             "ghsa_id": "RUSTSEC-2026-1", "source": "osv"},
        ]
        merged = search_service.merge_advisories(records)
        self.assertEqual(len(merged), 1)
        self.assertIn("RUSTSEC-2026-1", merged[0]["aliases"])


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
        body.setdefault("categories", ["bac"])
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

    def test_sort_epss_handles_missing_scores(self):
        """Records without EPSS used to crash sort (float vs '')."""
        body = {"categories": ["bac"], "sort": "epss_percentage"}
        q = search_service.parse_search_query(body)
        scores = {
            "CVE-2026-0002": {"epss": 0.9, "percentile": 0.99},
            "CVE-2026-0001": {"epss": 0.1, "percentile": 0.4},
        }
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=make_sortable_raw()), \
             mock.patch("modules.epss_client.fetch_epss", return_value=scores):
            out = search_service.run_search(q)
        ids = [r["ghsa_id"] for r in out.results]
        self.assertEqual(ids, [SORT_A, SORT_C, SORT_B])

    def test_common_filters_are_enforced_after_normalization(self):
        q = search_service.parse_search_query({"categories": ["bac"], "published": ">=2099-01-01"})
        with mock.patch(
            "modules.ghsa_client.fetch_advisories", return_value=make_sortable_raw()
        ):
            out = search_service.run_search(q)
        self.assertEqual(out.results, [])

    def test_ghsa_only_failure_is_502(self):
        q = search_service.parse_search_query({"categories": ["bac"]})  # sources == ["ghsa"]
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")):
            with self.assertRaises(search_service.SearchError) as cm:
                search_service.run_search(q)
        self.assertEqual(cm.exception.status, 502)
        self.assertEqual(str(cm.exception), "GHSA fetch failed.")
        self.assertNotIn("nope", str(cm.exception))

    def test_ghsa_failure_with_other_sources_is_warning(self):
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["ghsa", "osv"], "ecosystem": "go"})
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")), \
             mock.patch("modules.osv_client.fetch_osv", return_value=[]):
            out = search_service.run_search(q)
        self.assertTrue(any("GHSA fetch failed" in w for w in out.warnings))
        self.assertFalse(any("nope" in w for w in out.warnings))
        self.assertNotIn("ghsa", out.per_source)
        self.assertEqual(out.per_source.get("osv"), 0)
        self.assertEqual(out.results, [])


class TestRunSearchNvd(unittest.TestCase):
    """NVD source integration in run_search."""

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

    def test_nvd_source_included(self):
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["nvd"]})
        with mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            out = search_service.run_search(q)
        self.assertEqual(out.per_source, {"nvd": 1})
        self.assertEqual(out.results[0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(out.results[0]["source"], "nvd")

    def test_nvd_only_failure_is_502(self):
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["nvd"]})
        with mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            with self.assertRaises(search_service.SearchError) as cm:
                search_service.run_search(q)
        self.assertEqual(cm.exception.status, 502)

    def test_nvd_failure_with_ghsa_is_warning(self):
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["ghsa", "nvd"]})
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=make_sortable_raw()), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            out = search_service.run_search(q)
        self.assertTrue(any("NVD fetch failed" in w for w in out.warnings))
        self.assertEqual(out.per_source.get("ghsa"), 3)
        self.assertNotIn("nvd", out.per_source)

    def test_nvd_ghsa_dedupe_by_cve(self):
        """Same CVE from GHSA and NVD should merge into one record."""
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        ghsa_raw_rec = dict(SAMPLE, cve_id="CVE-2021-44228")
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["ghsa", "nvd"]})
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=[ghsa_raw_rec]), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            out = search_service.run_search(q)
        cves = [r["cve_id"] for r in out.results]
        self.assertEqual(cves.count("CVE-2021-44228"), 1)
        self.assertIn("ghsa", out.results[0]["sources"])
        self.assertIn("nvd", out.results[0]["sources"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
