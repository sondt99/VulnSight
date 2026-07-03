"""Tests for cvss: base-score computation, spec Roundup() and severity buckets."""

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
        self.assertIsNone(cvss.base_score("CVSS:4.0/AV:N"))  # v4 unsupported
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
