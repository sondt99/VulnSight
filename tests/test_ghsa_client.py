"""Tests for ghsa_client: query building, normalisation, pagination, header parsing.

All subprocess calls to the `gh` CLI are mocked; nothing touches the network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import unittest
from unittest import mock

from modules import ghsa_client as ghsa
from samples import SAMPLE


class TestSearchParams(unittest.TestCase):
    def test_query_build(self):
        p = ghsa.SearchParams(ecosystem="maven", cwes=["CWE-639", "862"],
                              severity="high", affects="a:b")
        q = p.to_query()
        self.assertEqual(q["ecosystem"], "maven")
        self.assertEqual(q["cwes"], "639,862")   # CWE- prefix stripped
        self.assertEqual(q["severity"], "high")
        self.assertEqual(q["affects"], "a:b")

    def test_any_omitted(self):
        p = ghsa.SearchParams(ecosystem="any", severity="any")
        q = p.to_query()
        self.assertNotIn("ecosystem", q)
        self.assertNotIn("severity", q)

    def test_per_page_capped(self):
        self.assertEqual(ghsa.SearchParams(per_page=500).to_query()["per_page"], "100")


class TestNormalize(unittest.TestCase):
    def test_normalize(self):
        n = ghsa.normalize(SAMPLE)
        self.assertEqual(n["ghsa_id"], "GHSA-h3m5-97jq-qjrf")
        self.assertEqual(n["cwes"], ["CWE-639"])
        self.assertEqual(n["severity"], "high")
        self.assertEqual(n["cvss_score"], 7.5)
        self.assertEqual(len(n["packages"]), 1)  # malformed skipped
        self.assertEqual(n["packages"][0]["name"], "org.openremote:manager")
        self.assertEqual(n["ecosystems"], ["maven"])
        self.assertEqual(n["references"], ["https://example.com/a"])  # non-str dropped


class TestPagination(unittest.TestCase):
    def _fake_run(self, pages):
        """Return a fake subprocess.run that yields pages sequentially."""
        calls = {"i": 0}

        def _run(cmd, capture_output, text, timeout):
            i = calls["i"]
            calls["i"] += 1
            body, next_url = pages[i]
            headers = "HTTP/2 200\ncontent-type: application/json"
            if next_url:
                headers += f'\nLink: <{next_url}>; rel="next"'
            out = headers + "\n\n" + json.dumps(body)
            return mock.Mock(returncode=0, stdout=out, stderr="")

        return _run, calls

    def test_follows_cursor_and_caps(self):
        pages = [
            ([{"ghsa_id": "A"}], "https://api.github.com/advisories?after=x"),
            ([{"ghsa_id": "B"}], "https://api.github.com/advisories?after=y"),
            ([{"ghsa_id": "C"}], None),
        ]
        fake, calls = self._fake_run(pages)
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=fake):
            res = ghsa.fetch_advisories(ghsa.SearchParams(per_page=1, max_results=2))
        self.assertEqual([r["ghsa_id"] for r in res], ["A", "B"])  # capped at 2
        self.assertEqual(calls["i"], 2)  # stopped early, didn't fetch page C

    def test_stops_when_no_next(self):
        pages = [([{"ghsa_id": "A"}], None)]
        fake, _ = self._fake_run(pages)
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=fake):
            res = ghsa.fetch_advisories(ghsa.SearchParams(max_results=100))
        self.assertEqual(len(res), 1)

    def test_api_error_raises(self):
        def _run(cmd, capture_output, text, timeout):
            body = {"message": "Bad creds", "documentation_url": "x"}
            return mock.Mock(returncode=0, stdout="HTTP/2 401\n\n" + json.dumps(body), stderr="")
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=_run):
            with self.assertRaises(ghsa.GhCliError):
                ghsa.fetch_advisories(ghsa.SearchParams())

    def test_nonzero_exit_raises(self):
        def _run(cmd, capture_output, text, timeout):
            return mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=_run):
            with self.assertRaises(ghsa.GhCliError):
                ghsa.fetch_advisories(ghsa.SearchParams())


class TestRunGhApiHeaderSplit(unittest.TestCase):
    def test_crlf_header_body_separator(self):
        """Regression: gh may emit \r\n line endings; the header/body split and
        the Link-header cursor must still be parsed."""
        body = [{"ghsa_id": "A"}]
        stdout = (
            "HTTP/2 200\r\n"
            "Content-Type: application/json\r\n"
            'Link: <https://api.github.com/advisories?after=zz>; rel="next"\r\n'
            "\r\n"
            + json.dumps(body)
        )

        def _run(cmd, capture_output, text, timeout):
            return mock.Mock(returncode=0, stdout=stdout, stderr="")

        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=_run):
            data, next_url = ghsa._run_gh_api("/advisories?per_page=1")
        self.assertEqual(data, body)
        self.assertEqual(next_url, "https://api.github.com/advisories?after=zz")


if __name__ == "__main__":
    unittest.main(verbosity=2)
