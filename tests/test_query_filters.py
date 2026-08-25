"""Tests for filters that must behave identically across all data sources."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import query_filters


class TestCommonFilters(unittest.TestCase):
    def setUp(self):
        self.record = {
            "published_at": "2026-05-20T12:00:00Z",
            "severity": "high",
            "packages": [{"name": "github.com/acme/widget"}],
        }

    def test_published_comparators_and_range(self):
        self.assertTrue(query_filters.matches_published(self.record, ">=2026-05-20"))
        self.assertFalse(query_filters.matches_published(self.record, ">2026-05-20"))
        self.assertTrue(
            query_filters.matches_published(self.record, "2026-05-01..2026-05-31")
        )
        self.assertFalse(query_filters.matches_published(self.record, "<2026-05-20"))

    def test_package_is_exact_and_case_insensitive(self):
        self.assertTrue(
            query_filters.matches_package(self.record, "GITHUB.COM/ACME/WIDGET")
        )
        self.assertFalse(query_filters.matches_package(self.record, "acme/widget"))

    def test_missing_date_does_not_pass_a_date_filter(self):
        self.assertFalse(query_filters.matches_published({}, ">=2026-01-01"))

    def test_naive_timestamp_is_read_as_utc_not_local_time(self):
        """NVD API v2 sends naive UTC timestamps; GHSA and OSV send an offset.

        Reading the naive form as host-local time shifted NVD records by the
        machine's UTC offset and silently dropped the ones near a day boundary
        from every date filter — the same instant matched from GHSA and missed
        from NVD on any host that is not itself UTC.
        """
        naive = {"published_at": "2026-01-01T05:30:00.000"}   # NVD shape
        explicit = {"published_at": "2026-01-01T05:30:00Z"}   # GHSA / OSV shape
        for record in (naive, explicit):
            with self.subTest(published_at=record["published_at"]):
                self.assertTrue(
                    query_filters.matches_published(record, ">=2026-01-01"))
                self.assertTrue(
                    query_filters.matches_published(record, "2026-01-01..2026-01-01"))
        # An explicit offset is still honoured: 05:30+09:00 is 2025-12-31 UTC.
        self.assertFalse(query_filters.matches_published(
            {"published_at": "2026-01-01T05:30:00+09:00"}, ">=2026-01-01"))

    def test_invalid_calendar_dates_and_ranges_are_rejected(self):
        invalid = (
            "2026-02-30",
            "0000-01-01",
            "9999-99-99",
            "2026-05-31..2026-05-01",
            ">=2026-05-01..2026-05-31",
            ">9999-12-31",
            "<0001-01-01",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertFalse(query_filters.valid_published_filter(value))
                with self.assertRaises(ValueError):
                    query_filters.published_bounds(value)

        self.assertFalse(query_filters.valid_published_filter([]))
        with self.assertRaises(ValueError):
            query_filters.published_bounds([])


if __name__ == "__main__":
    unittest.main(verbosity=2)
