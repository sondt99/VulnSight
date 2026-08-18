"""Tests for osv_client: normalisation and local filtering of OSV bulk records.

The bulk-zip loader (_load_records) is mocked everywhere; nothing downloads.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import io
import json
import tempfile
import unittest
import zipfile
from unittest import mock

from modules import cwe_categories as cwe
from modules import osv_client
from samples import OSV_GHSA, OSV_NATIVE, make_osv_zip


class TestNormalizeOsv(unittest.TestCase):
    def test_normalize_ghsa_sourced(self):
        n = osv_client.normalize_osv(OSV_GHSA)
        self.assertEqual(n["advisory_id"], "GHSA-xr65-5cpm-g36x")
        self.assertEqual(n["ghsa_id"], "GHSA-xr65-5cpm-g36x")
        self.assertEqual(n["cve_id"], "CVE-2026-11122")
        self.assertEqual(n["cwes"], ["CWE-863"])
        self.assertEqual(n["severity"], "critical")
        self.assertEqual(n["source"], "osv")
        self.assertEqual(n["packages"][0]["first_patched_version"], "0.9.5")
        self.assertTrue(n["html_url"].endswith("GHSA-xr65-5cpm-g36x"))

    def test_normalize_native(self):
        n = osv_client.normalize_osv(OSV_NATIVE)
        self.assertEqual(n["advisory_id"], "GO-2023-1737")  # no GHSA alias -> keeps OSV id
        self.assertEqual(n["ghsa_id"], "GO-2023-1737")  # no GHSA alias -> keeps OSV id
        self.assertEqual(n["cve_id"], "CVE-2023-29401")
        self.assertEqual(n["cwes"], [])
        self.assertEqual(n["severity"], "low")  # derived from CVSS vector

    def test_supported(self):
        self.assertTrue(osv_client.supported_ecosystem("maven"))
        self.assertTrue(osv_client.supported_ecosystem("go"))
        self.assertFalse(osv_client.supported_ecosystem("any"))


class TestFetchOsv(unittest.TestCase):
    def test_invalid_download_does_not_replace_cached_zip(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch("modules.osv_client.urllib.request.urlopen") as urlopen:
            path = osv_client._zip_path("Go")
            good = make_osv_zip([OSV_NATIVE])
            with open(path, "wb") as handle:
                handle.write(good)
            response = mock.MagicMock()
            response.read.return_value = b"not-a-zip"
            response.__enter__.return_value = response
            response.__exit__.return_value = False
            urlopen.return_value = response
            with self.assertRaises(osv_client.OsvError):
                osv_client.download_ecosystem("Go", force=True)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), good)

    def test_zip_records_and_cwe_filter(self):
        # Build an in-memory bulk zip (samples.make_osv_zip replaces the removed
        # osv_client.bytes_to_records), unzip+normalize it ourselves, and drive
        # fetch_osv via a patched loader.
        data = make_osv_zip([OSV_GHSA, OSV_NATIVE])
        recs = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    recs.append(osv_client.normalize_osv(json.loads(zf.read(name))))
        self.assertEqual(len(recs), 2)
        with mock.patch("modules.osv_client._load_records", return_value=recs):
            # BAC includes CWE-863 -> only the GHSA-sourced record matches.
            out = osv_client.fetch_osv("go", cwe.category_cwes("bac"), max_results=50)
        self.assertEqual([r["ghsa_id"] for r in out], ["GHSA-xr65-5cpm-g36x"])

    def test_fetch_osv_requires_ecosystem(self):
        with self.assertRaises(osv_client.OsvError):
            osv_client.fetch_osv("any", ["863"])

    def _two_severities(self):
        crit = osv_client.normalize_osv(OSV_GHSA)  # critical, CWE-863, rancher/fleet
        low = osv_client.normalize_osv(dict(
            OSV_GHSA,
            id="GHSA-low1-low1-low1",
            aliases=["CVE-2026-99999"],
            database_specific={"cwe_ids": ["CWE-863"], "severity": "LOW"},
            affected=[{"package": {"ecosystem": "Go", "name": "github.com/other/pkg"},
                       "ranges": []}],
        ))
        return [crit, low]

    def test_fetch_osv_severity_filter(self):
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out = osv_client.fetch_osv("go", ["863"], severity="critical")
        self.assertEqual([r["ghsa_id"] for r in out], ["GHSA-xr65-5cpm-g36x"])
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out_any = osv_client.fetch_osv("go", ["863"], severity="any")
        self.assertEqual({r["ghsa_id"] for r in out_any},
                         {"GHSA-xr65-5cpm-g36x", "GHSA-low1-low1-low1"})

    def test_fetch_osv_published_filter(self):
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            recent = osv_client.fetch_osv(
                "go", ["863"], published=">=2026-01-01"
            )
        self.assertTrue(recent)
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            future = osv_client.fetch_osv(
                "go", ["863"], published=">=2099-01-01"
            )
        self.assertEqual(future, [])

    def test_fetch_osv_affects_filter_case_insensitive_exact(self):
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out = osv_client.fetch_osv(
                "go", ["863"], affects="GITHUB.COM/RANCHER/FLEET"
            )
        self.assertEqual([r["ghsa_id"] for r in out], ["GHSA-xr65-5cpm-g36x"])
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            partial = osv_client.fetch_osv("go", ["863"], affects="RANCHER/Fleet")
        self.assertEqual(partial, [])
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out2 = osv_client.fetch_osv("go", ["863"], affects="no-such-package")
        self.assertEqual(out2, [])


class TestFetchOsvNative(unittest.TestCase):
    def test_fetch_osv_native(self):
        # A native record with no CWE but a BAC keyword should be surfaced;
        # the GHSA-sourced one should be excluded (it's covered by CWE path).
        native_bac = dict(OSV_NATIVE, id="GO-2024-001",
                          summary="auth bypass: missing authorization on admin route",
                          aliases=[], database_specific={})
        native_other = dict(OSV_NATIVE, id="GO-2024-002",
                            summary="denial of service via large input", aliases=[],
                            database_specific={})
        recs = [osv_client.normalize_osv(r)
                for r in (OSV_GHSA, native_bac, native_other)]
        with mock.patch("modules.osv_client._load_records", return_value=recs):
            out = osv_client.fetch_osv_native("go", ["bac"], max_results=50)
        ids = [r["ghsa_id"] for r in out]
        self.assertIn("GO-2024-001", ids)       # keyword-matched native
        self.assertNotIn("GO-2024-002", ids)    # no keyword match
        self.assertNotIn("GHSA-xr65-5cpm-g36x", ids)  # GHSA-sourced excluded
        self.assertTrue(out[0]["native"])

    def test_native_respects_common_filters(self):
        native = dict(
            OSV_NATIVE,
            id="GO-2026-100",
            summary="authorization bypass",
            aliases=[],
            database_specific={"severity": "HIGH"},
        )
        records = [osv_client.normalize_osv(native)]
        package = records[0]["packages"][0]["name"]
        with mock.patch("modules.osv_client._load_records", return_value=records):
            out = osv_client.fetch_osv_native(
                "go",
                ["bac"],
                affects=package.upper(),
                severity="high",
                published=">=2023-01-01",
            )
        self.assertEqual([record["ghsa_id"] for record in out], ["GO-2026-100"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
