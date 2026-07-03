"""Tests for cwe_categories: category tables, CWE resolution and id helpers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest

from modules import cwe_categories as cwe


class TestCweCategories(unittest.TestCase):
    def test_bac_core_present(self):
        core = cwe.category_cwes("bac", include_extended=False)
        for c in ["639", "862", "863", "285", "284"]:
            self.assertIn(c, core)

    def test_extended_superset(self):
        core = set(cwe.category_cwes("bac", False))
        ext = set(cwe.category_cwes("bac", True))
        self.assertTrue(core.issubset(ext))
        self.assertGreater(len(ext), len(core))

    def test_resolve_dedups_across_categories(self):
        merged = cwe.resolve_cwes(["bac", "sqli", "bac"])
        self.assertEqual(len(merged), len(set(merged)))
        self.assertIn("89", merged)

    def test_unknown_category_empty(self):
        self.assertEqual(cwe.category_cwes("nope"), [])

    def test_label(self):
        self.assertIn("BOLA", cwe.cwe_label("639"))
        self.assertIn("BOLA", cwe.cwe_label("CWE-639"))
        self.assertEqual(cwe.cwe_label("999999"), "CWE-999999")


class TestNormalizeCweId(unittest.TestCase):
    def test_normalize_variants(self):
        self.assertEqual(cwe.normalize_cwe_id("CWE-639"), "639")
        self.assertEqual(cwe.normalize_cwe_id("cwe-89 "), "89")
        self.assertEqual(cwe.normalize_cwe_id(" 22 "), "22")
        self.assertEqual(cwe.normalize_cwe_id("639"), "639")


class TestDataIntegrity(unittest.TestCase):
    """The static tables must stay mutually consistent as categories grow."""

    def test_keyword_keys_are_known_categories(self):
        for key in cwe.KEYWORDS:
            self.assertIn(key, cwe.CATEGORIES,
                          msg=f"KEYWORDS['{key}'] has no matching category")

    def test_scenario_categories_are_known(self):
        for sc in cwe.SCENARIOS:
            for cat in sc["categories"]:
                self.assertIn(cat, cwe.CATEGORIES,
                              msg=f"scenario '{sc['key']}' references unknown category '{cat}'")

    def test_all_category_cwes_have_labels(self):
        for key, cat in cwe.CATEGORIES.items():
            for c in cat["core"] + cat["extended"]:
                self.assertNotEqual(
                    cwe.cwe_label(c), f"CWE-{c}",
                    msg=f"category '{key}': CWE-{c} has no label in _CWE_NAMES")


if __name__ == "__main__":
    unittest.main(verbosity=2)
