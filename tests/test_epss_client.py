"""Tests for epss_client: parsing, batching, empty input, error handling.

All HTTP calls are mocked; nothing touches the network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import unittest
from unittest import mock

from modules import epss_client


def _mock_urlopen(response_body: dict):
    """Return a context-manager mock for ``urllib.request.urlopen``."""
    data = json.dumps(response_body).encode()
    resp = mock.MagicMock()
    resp.read.return_value = data
    resp.__enter__ = mock.Mock(return_value=resp)
    resp.__exit__ = mock.Mock(return_value=False)
    return resp


class TestParseResponse(unittest.TestCase):
    """Verify that a well-formed API response is correctly parsed."""

    RESPONSE = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "total": 2,
        "offset": 0,
        "limit": 100,
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.03456", "percentile": "0.87654", "date": "2026-08-18"},
            {"cve": "CVE-2024-5678", "epss": "0.92100", "percentile": "0.99800", "date": "2026-08-18"},
        ],
    }

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_basic_parsing(self, mock_open):
        mock_open.return_value = _mock_urlopen(self.RESPONSE)
        result = epss_client.fetch_epss(["CVE-2024-1234", "CVE-2024-5678"])

        self.assertEqual(len(result), 2)
        self.assertAlmostEqual(result["CVE-2024-1234"]["epss"], 0.03456)
        self.assertAlmostEqual(result["CVE-2024-1234"]["percentile"], 0.87654)
        self.assertAlmostEqual(result["CVE-2024-5678"]["epss"], 0.92100)
        self.assertAlmostEqual(result["CVE-2024-5678"]["percentile"], 0.99800)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_missing_fields_skipped(self, mock_open):
        """Entries without cve/epss/percentile are silently dropped."""
        response = {
            "data": [
                {"cve": "CVE-2024-1111", "epss": "0.5", "percentile": "0.9"},
                {"epss": "0.3", "percentile": "0.7"},  # no cve key
                {"cve": "CVE-2024-2222"},  # no epss/percentile
            ],
        }
        mock_open.return_value = _mock_urlopen(response)
        result = epss_client.fetch_epss(["CVE-2024-1111", "CVE-2024-2222"])

        self.assertEqual(len(result), 1)
        self.assertIn("CVE-2024-1111", result)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_empty_data_array(self, mock_open):
        mock_open.return_value = _mock_urlopen({"data": []})
        result = epss_client.fetch_epss(["CVE-2024-0000"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_duplicates_are_deduplicated(self, mock_open):
        """Duplicate CVE IDs in input only produce one API query per CVE."""
        response = {
            "data": [
                {"cve": "CVE-2024-1234", "epss": "0.5", "percentile": "0.8"},
            ],
        }
        mock_open.return_value = _mock_urlopen(response)
        result = epss_client.fetch_epss(["CVE-2024-1234", "CVE-2024-1234", "CVE-2024-1234"])

        self.assertEqual(len(result), 1)
        # Only one HTTP call despite three duplicate input CVEs.
        mock_open.assert_called_once()


class TestBatching(unittest.TestCase):
    """Verify that >100 CVEs are split into multiple requests."""

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_splits_into_batches(self, mock_open):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(250)]

        def side_effect(req, timeout=None):
            # Parse the requested CVEs from the URL to return matching data.
            url = req.full_url if hasattr(req, "full_url") else req.get_full_url()
            qs = url.split("?", 1)[1] if "?" in url else ""
            from urllib.parse import parse_qs
            params = parse_qs(qs)
            requested = params.get("cve", [""])[0].split(",")
            data = [
                {"cve": cve, "epss": "0.01", "percentile": "0.50"}
                for cve in requested if cve
            ]
            return _mock_urlopen({"data": data})

        mock_open.side_effect = side_effect
        result = epss_client.fetch_epss(cve_ids)

        # Should have made 3 calls: 100 + 100 + 50.
        self.assertEqual(mock_open.call_count, 3)
        self.assertEqual(len(result), 250)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_exactly_100_is_one_batch(self, mock_open):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(100)]

        def side_effect(req, timeout=None):
            data = [{"cve": c, "epss": "0.1", "percentile": "0.5"} for c in cve_ids]
            return _mock_urlopen({"data": data})

        mock_open.side_effect = side_effect
        result = epss_client.fetch_epss(cve_ids)

        self.assertEqual(mock_open.call_count, 1)
        self.assertEqual(len(result), 100)


class TestEmptyInput(unittest.TestCase):
    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_empty_list_returns_empty_dict(self, mock_open):
        result = epss_client.fetch_epss([])
        self.assertEqual(result, {})
        mock_open.assert_not_called()

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_none_like_empty(self, mock_open):
        """Passing an empty list does not make any HTTP request."""
        result = epss_client.fetch_epss([])
        self.assertEqual(result, {})
        mock_open.assert_not_called()


class TestErrorHandling(unittest.TestCase):
    """Network and parse failures must return an empty dict, never crash."""

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_network_error_returns_empty(self, mock_open):
        mock_open.side_effect = OSError("Connection refused")
        result = epss_client.fetch_epss(["CVE-2024-1234"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_http_error_returns_empty(self, mock_open):
        import urllib.error
        mock_open.side_effect = urllib.error.HTTPError(
            url="https://api.first.org/data/v1/epss",
            code=500,
            msg="Internal Server Error",
            hdrs=None,  # type: ignore[arg-type]
            fp=None,
        )
        result = epss_client.fetch_epss(["CVE-2024-9999"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_invalid_json_returns_empty(self, mock_open):
        resp = mock.MagicMock()
        resp.read.return_value = b"not json at all"
        resp.__enter__ = mock.Mock(return_value=resp)
        resp.__exit__ = mock.Mock(return_value=False)
        mock_open.return_value = resp
        result = epss_client.fetch_epss(["CVE-2024-1234"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_partial_batch_failure(self, mock_open):
        """If the second batch fails, results from the first are still returned."""
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(150)]
        call_count = {"i": 0}

        def side_effect(req, timeout=None):
            call_count["i"] += 1
            if call_count["i"] == 1:
                data = [
                    {"cve": f"CVE-2024-{i:04d}", "epss": "0.05", "percentile": "0.60"}
                    for i in range(100)
                ]
                return _mock_urlopen({"data": data})
            raise OSError("Connection reset")

        mock_open.side_effect = side_effect
        result = epss_client.fetch_epss(cve_ids)

        # First batch of 100 succeeded.
        self.assertEqual(len(result), 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
