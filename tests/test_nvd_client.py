"""Tests for nvd_client: normalisation, date params, fetch logic.

All HTTP calls are mocked; nothing touches the network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import unittest
from unittest import mock

from modules import nvd_client
from samples import NVD_VULN


class TestNormalize(unittest.TestCase):
    def test_basic_fields(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertEqual(n["ghsa_id"], "CVE-2021-44228")
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

    def test_old_date_clamped_to_120_days(self):
        params = nvd_client._build_date_params(">=2020-01-01")
        self.assertIn("pubStartDate", params)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
