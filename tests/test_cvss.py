"""Tests for cvss: base-score computation, v4 estimation, spec Roundup() and severity buckets."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest

from modules import cvss


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


class TestBaseScoreV4(unittest.TestCase):
    """CVSS v4.0 rough estimation via base_score_v4()."""

    def test_full_v4_vector_network_high_impact(self):
        # AV:N/AC:L with all high impact -> critical bucket.
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        score = cvss.base_score_v4(vec)
        self.assertIsNotNone(score)
        self.assertGreaterEqual(score, 9.0)  # critical

    def test_v4_network_low_impact(self):
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score = cvss.base_score_v4(vec)
        self.assertIsNotNone(score)
        self.assertGreaterEqual(score, 4.0)  # medium
        self.assertLess(score, 9.0)

    def test_v4_physical_high_complexity(self):
        vec = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score = cvss.base_score_v4(vec)
        self.assertIsNotNone(score)
        self.assertLess(score, 4.0)  # low

    def test_v4_no_impact_returns_zero(self):
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        self.assertEqual(cvss.base_score_v4(vec), 0.0)

    def test_v4_subsequent_system_impact(self):
        # High subsequent-system impact should still register.
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H"
        score = cvss.base_score_v4(vec)
        self.assertIsNotNone(score)
        self.assertGreaterEqual(score, 9.0)

    def test_v4_non_v4_returns_none(self):
        self.assertIsNone(cvss.base_score_v4("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertIsNone(cvss.base_score_v4(""))
        self.assertIsNone(cvss.base_score_v4(None))

    def test_v4_missing_required_metrics(self):
        # Missing AC entirely.
        self.assertIsNone(cvss.base_score_v4("CVSS:4.0/AV:N"))
        # Unknown AV value.
        self.assertIsNone(cvss.base_score_v4("CVSS:4.0/AV:Z/AC:L"))

    def test_v4_severity_buckets_match(self):
        # severity_from_score works the same for v4 scores.
        vec_crit = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        self.assertEqual(cvss.severity_from_score(cvss.base_score_v4(vec_crit)), "critical")

        vec_zero = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        self.assertEqual(cvss.severity_from_score(cvss.base_score_v4(vec_zero)), "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
