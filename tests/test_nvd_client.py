"""Tests for nvd_client: normalisation, date params, fetch logic.

All HTTP calls are mocked; nothing touches the network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import unittest
from datetime import datetime, timezone
from unittest import mock

from modules import nvd_client
from samples import NVD_VULN


class TestNormalize(unittest.TestCase):
    def test_basic_fields(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertIsNone(n["ghsa_id"])
        self.assertEqual(n["advisory_id"], "CVE-2021-44228")
        self.assertEqual(n["cve_id"], "CVE-2021-44228")
        self.assertEqual(n["source"], "nvd")
        self.assertEqual(n["severity"], "critical")
        self.assertEqual(n["cvss_score"], 10.0)
        self.assertTrue(n["kev"])
        self.assertEqual(n["nvd_status"], "Analyzed")

    def test_cwes_extracted(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertIn("917", n["cwes"])
        self.assertIn("20", n["cwes"])
        self.assertNotIn("noinfo", n["cwes"])

    def test_packages_from_cpe(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertTrue(len(n["packages"]) >= 1)
        pkg = n["packages"][0]
        self.assertEqual(pkg["name"], "apache:log4j")
        self.assertEqual(pkg["first_patched_version"], "2.15.0")

    def test_non_vulnerable_cpe_skipped(self):
        n = nvd_client.normalize(NVD_VULN)
        names = [p["name"] for p in n["packages"]]
        self.assertEqual(len(names), 1)

    def test_description_english_preferred(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertIn("Log4j2", n["description"])
        self.assertNotIn("espanol", n["description"])

    def test_references(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertEqual(len(n["references"]), 2)
        self.assertIn("logging.apache.org", n["references"][0])

    def test_html_url(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertEqual(n["html_url"], "https://nvd.nist.gov/vuln/detail/CVE-2021-44228")

    def test_summary_truncated(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertTrue(len(n["summary"]) <= 125)


class TestDateParams(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(nvd_client._build_date_params(None), {})
        self.assertEqual(nvd_client._build_date_params(""), {})

    def test_recent_date(self):
        params = nvd_client._build_date_params(">=2026-06-01")
        self.assertIn("pubStartDate", params)
        self.assertIn("pubEndDate", params)

    def test_old_date_is_split_without_losing_requested_start(self):
        now = datetime(2026, 8, 17, tzinfo=timezone.utc)
        windows = nvd_client._build_date_windows(">=2020-01-01", now=now)
        self.assertGreater(len(windows), 1)
        self.assertTrue(windows[0]["pubEndDate"].startswith("2026-08-17"))
        self.assertTrue(windows[-1]["pubStartDate"].startswith("2020-01-01"))
        for window in windows:
            start = datetime.fromisoformat(window["pubStartDate"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(window["pubEndDate"].replace("Z", "+00:00"))
            self.assertLessEqual((end - start).total_seconds(), 120 * 86400)

    def test_year_one_is_clamped_without_datetime_underflow(self):
        now = datetime(2026, 8, 17, tzinfo=timezone.utc)
        windows = nvd_client._build_date_windows(">=0001-01-01", now=now)
        self.assertGreater(len(windows), 1)
        self.assertTrue(windows[-1]["pubStartDate"].startswith("1988-01-01"))


class TestFetchNvd(unittest.TestCase):
    def _mock_urlopen(self, responses):
        """Create a mock for urllib.request.urlopen that returns responses in order."""
        call_count = {"i": 0}

        def _urlopen(req, timeout=None):
            i = call_count["i"]
            call_count["i"] += 1
            data = json.dumps(responses[i % len(responses)]).encode()
            resp = mock.MagicMock()
            resp.read.return_value = data
            resp.__enter__ = mock.Mock(return_value=resp)
            resp.__exit__ = mock.Mock(return_value=False)
            return resp

        return _urlopen

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "test-key"})
    @mock.patch("modules.nvd_client.time.sleep")
    def test_fetch_deduplicates(self, mock_sleep):
        response = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [NVD_VULN],
        }
        with mock.patch("modules.nvd_client.urllib.request.urlopen",
                        side_effect=self._mock_urlopen([response])):
            results = nvd_client.fetch_nvd(nvd_client.NvdSearchParams(
                cwes=["917", "20"], max_results=10))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2021-44228")

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "test-key"})
    @mock.patch("modules.nvd_client.time.sleep")
    def test_empty_cwes_returns_empty(self, mock_sleep):
        results = nvd_client.fetch_nvd(nvd_client.NvdSearchParams(cwes=[]))
        self.assertEqual(results, [])

    @mock.patch("modules.nvd_client._fetch_cves_for_cwe")
    @mock.patch("modules.nvd_client.time.sleep")
    def test_all_cwe_failures_are_not_silently_empty(self, mock_sleep, mock_fetch):
        mock_fetch.side_effect = nvd_client.NvdError("rate limited")
        with self.assertRaises(nvd_client.NvdError):
            nvd_client.fetch_nvd(nvd_client.NvdSearchParams(cwes=["79", "89"]))

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_request_delay_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NVD_API_KEY", None)
            delay = nvd_client._request_delay()
        self.assertGreaterEqual(delay, 6.0)

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "test-key"})
    def test_request_delay_with_key(self):
        delay = nvd_client._request_delay()
        self.assertLessEqual(delay, 1.0)


class TestNormalizeCVSSFallback(unittest.TestCase):
    def test_v2_fallback(self):
        vuln = {
            "cve": {
                "id": "CVE-2015-0001",
                "descriptions": [{"lang": "en", "value": "old vuln"}],
                "metrics": {
                    "cvssMetricV2": [{
                        "cvssData": {"baseScore": 7.5},
                        "baseSeverity": "HIGH",
                    }],
                },
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertEqual(n["cvss_score"], 7.5)
        self.assertEqual(n["severity"], "high")

    def test_no_metrics(self):
        vuln = {
            "cve": {
                "id": "CVE-2000-0001",
                "descriptions": [{"lang": "en", "value": "ancient"}],
                "metrics": {},
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertIsNone(n["cvss_score"])
        self.assertEqual(n["severity"], "unknown")

    def test_v40_preferred_over_v31(self):
        """When both v4.0 and v3.1 metrics exist, v4.0 is preferred."""
        vuln = {
            "cve": {
                "id": "CVE-2026-99999",
                "descriptions": [{"lang": "en", "value": "v4 vuln"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                    }],
                    "cvssMetricV40": [{
                        "cvssData": {
                            "version": "4.0",
                            "baseScore": 8.7,
                            "baseSeverity": "HIGH",
                        },
                    }],
                },
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertEqual(n["cvss_score"], 8.7)
        self.assertEqual(n["severity"], "high")

    def test_v40_only(self):
        """A CVE with only v4.0 metrics still extracts correctly."""
        vuln = {
            "cve": {
                "id": "CVE-2026-88888",
                "descriptions": [{"lang": "en", "value": "v4 only"}],
                "metrics": {
                    "cvssMetricV40": [{
                        "cvssData": {
                            "version": "4.0",
                            "baseScore": 9.3,
                            "baseSeverity": "CRITICAL",
                        },
                    }],
                },
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertEqual(n["cvss_score"], 9.3)
        self.assertEqual(n["severity"], "critical")


if __name__ == "__main__":
    unittest.main(verbosity=2)
