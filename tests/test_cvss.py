"""Tests for cvss: v3 base scores, spec Roundup(), severity buckets, and the
deliberate absence of v4 scoring."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest

from modules import cvss, osv_client


class TestBaseScore(unittest.TestCase):
    def test_known_vectors(self):
        # Ported from the old osv_client.cvss3_base_score coverage.
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"), 8.1)
        self.assertIsNone(cvss.base_score("CVSS:4.0/AV:N"))  # v4 handled by base_score_v4
        self.assertIsNone(cvss.base_score(""))

    def test_invalid_vectors_return_none(self):
        self.assertIsNone(cvss.base_score(None))
        self.assertIsNone(cvss.base_score("complete garbage"))
        # Missing base metrics (no S/C/I/A) must not raise.
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N"))
        # Unknown metric value.
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))


class TestRoundup(unittest.TestCase):
    def test_roundup_spec_appendix_a(self):
        self.assertEqual(cvss._roundup(4.0), 4.0)
        self.assertEqual(cvss._roundup(4.02), 4.1)

    def test_roundup_float_artifact_regression(self):
        # The old math.ceil(x * 10) / 10 turned 1.0000000000000002 into 1.1.
        self.assertEqual(cvss._roundup(1.0000000000000002), 1.0)


class TestSeverityFromScore(unittest.TestCase):
    def test_bucket_edges(self):
        cases = [
            (None, "unknown"),
            (0, "unknown"),
            (0.1, "low"),
            (3.9, "low"),
            (4.0, "medium"),
            (6.9, "medium"),
            (7.0, "high"),
            (8.9, "high"),
            (9.0, "critical"),
            (10, "critical"),
        ]
        for score, want in cases:
            with self.subTest(score=score):
                self.assertEqual(cvss.severity_from_score(score), want)


class TestV4IsNotScored(unittest.TestCase):
    """v4 vectors are recognised but never scored. See cvss.is_v4_vector."""

    def test_v4_vectors_are_recognised(self):
        self.assertTrue(cvss.is_v4_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        self.assertFalse(cvss.is_v4_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertFalse(cvss.is_v4_vector(""))
        self.assertFalse(cvss.is_v4_vector(None))

    def test_no_v4_scorer_is_exported(self):
        """The old approximation returned 10.0 for a vector whose true score is 5.1.

        Guards against a future "quick" reintroduction: v4 needs the real
        MacroVector table or nothing.
        """
        self.assertFalse(hasattr(cvss, "base_score_v4"))

    def test_v3_is_still_scored_exactly(self):
        self.assertEqual(
            cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertIsNone(cvss.base_score("CVSS:4.0/AV:N/AC:L/VC:H/VI:H/VA:H"))


class TestOsvPrefersV3OverV4(unittest.TestCase):
    """A record carrying both used to be scored from the made-up v4 number."""

    def _record(self, severities, ds_severity=None):
        rec = {"id": "GHSA-test", "severity": severities, "affected": []}
        if ds_severity:
            rec["database_specific"] = {"severity": ds_severity}
        return osv_client.normalize_osv(rec)

    def test_both_versions_present_uses_the_v3_score(self):
        out = self._record([
            {"type": "CVSS_V4",
             "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
            {"type": "CVSS_V3",
             "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N"},
        ])
        self.assertEqual(out["cvss_score"], 5.8)          # the real v3 score
        self.assertEqual(out["severity"], "medium")       # not "critical"
        self.assertTrue(out["cvss_vector"].startswith("CVSS:3.1/"))

    def test_v4_only_is_unscored_and_keeps_its_vector(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N"
        out = self._record([{"type": "CVSS_V4", "score": vector}])
        self.assertIsNone(out["cvss_score"])   # rather than a confident 10.0
        self.assertEqual(out["severity"], "unknown")
        self.assertEqual(out["cvss_vector"], vector)

    def test_v4_only_takes_severity_from_the_publisher(self):
        """All 1,104 v4-only records in the cached exports carry this field."""
        out = self._record(
            [{"type": "CVSS_V4",
              "score": "CVSS:4.0/AV:N/AC:L/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N"}],
            ds_severity="MODERATE",
        )
        self.assertIsNone(out["cvss_score"])
        self.assertEqual(out["severity"], "medium")

    def test_a_zero_v3_score_no_longer_blocks_anything(self):
        """`if score is not None: break` treated 0.0 as a usable score."""
        out = self._record([
            {"type": "CVSS_V3",
             "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
        ])
        self.assertEqual(out["cvss_score"], 0.0)
        self.assertEqual(out["severity"], "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
