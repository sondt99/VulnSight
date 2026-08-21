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

    def test_label_uses_official_mitre_name(self):
        self.assertEqual(
            cwe.cwe_label("639"), "Authorization Bypass Through User-Controlled Key"
        )
        self.assertEqual(cwe.cwe_label("CWE-639"), cwe.cwe_label("639"))
        self.assertEqual(cwe.cwe_label("999999"), "CWE-999999")

    def test_community_terms_are_findable(self):
        """The terms people actually type must match, not just MITRE's names.

        The UI searches name + aliases together, so a term already present in
        the official name (SSRF, XXE) is deliberately not duplicated as an
        alias — assert on the combined searchable text instead.
        """
        searches = {
            "639": ("IDOR", "BOLA"),
            "918": ("SSRF",),
            "611": ("XXE",),
            "79": ("XSS",),
            "89": ("SQLi",),
            "1321": ("prototype pollution",),
            "862": ("BFLA",),
            "22": ("path traversal",),
            "502": ("deserialization",),
            "1336": ("SSTI", "template injection"),
        }
        for cwe_id, terms in searches.items():
            haystack = " ".join((cwe.cwe_label(cwe_id),) + cwe.cwe_aliases(cwe_id)).lower()
            for term in terms:
                with self.subTest(cwe=cwe_id, term=term):
                    self.assertIn(term.lower(), haystack)

    def test_aliases_of_unknown_cwe_are_empty(self):
        self.assertEqual(cwe.cwe_aliases("999999"), ())


class TestCwePseudoCategories(unittest.TestCase):
    """Any single CWE can act as an ad-hoc bug class via the 'cwe:<id>' key."""

    def test_round_trip(self):
        self.assertEqual(cwe.cwe_key("CWE-639"), "cwe:639")
        self.assertEqual(cwe.cwe_key("639"), "cwe:639")
        self.assertEqual(cwe.parse_cwe_key("cwe:639"), "639")
        self.assertEqual(cwe.parse_cwe_key("CWE:639"), "639")

    def test_non_keys_return_none(self):
        for value in ("bac", "cwe:", "cwe:0", "cwe:012", "cwe:79a", "cwe-79", "639",
                      "cwe:" + "9" * (cwe.MAX_CWE_ID_DIGITS + 1)):
            with self.subTest(value=value):
                self.assertIsNone(cwe.parse_cwe_key(value))

    def test_is_known_category(self):
        self.assertTrue(cwe.is_known_category("bac"))
        self.assertTrue(cwe.is_known_category("cwe:1321"))
        self.assertFalse(cwe.is_known_category("nope"))
        self.assertFalse(cwe.is_known_category("cwe:0"))

    def test_unknown_cwe_ids_are_rejected(self):
        """A typo must not reach the AI as a contentless class."""
        self.assertFalse(cwe.is_known_category("cwe:9999999"))
        self.assertNotIn("9999999", cwe.NAMES)

    def test_deprecated_cwe_ids_are_still_accepted(self):
        """Advisories still carry them, so they must stay queryable."""
        from modules import cwe_catalog

        deprecated = sorted(cwe_catalog.DEPRECATED, key=int)[0]
        self.assertTrue(cwe.is_known_category(f"cwe:{deprecated}"))

    def test_canonical_category_folds_equivalent_spellings(self):
        self.assertEqual(cwe.canonical_category("CWE:639"), "cwe:639")
        self.assertEqual(cwe.canonical_category("cwe:639"), "cwe:639")
        self.assertEqual(cwe.canonical_category("bac"), "bac")
        self.assertEqual(cwe.canonical_category("nope"), "nope")

    def test_resolves_to_exactly_that_cwe(self):
        self.assertEqual(cwe.category_cwes("cwe:1321"), ["1321"])
        self.assertEqual(cwe.category_cwes("cwe:1321", include_extended=False), ["1321"])
        self.assertEqual(cwe.resolve_cwes(["sqli", "cwe:1321"], False), ["89", "1321"])

    def test_label_and_description_are_ai_ready(self):
        """The AI prompt is built from these, so neither may be empty."""
        label = cwe.category_label("cwe:639")
        self.assertIn("CWE-639", label)
        self.assertIn("Authorization Bypass", label)
        description = cwe.category_description("cwe:639")
        self.assertIn("IDOR", description)
        self.assertTrue(cwe.category_description("cwe:9999999"))
        self.assertEqual(cwe.category_label("bac"), cwe.CATEGORIES["bac"]["label"])

    def test_keywords_prefer_aliases_over_the_official_name(self):
        keywords = cwe.category_keywords(["cwe:918"])
        self.assertIn("ssrf", keywords)
        self.assertTrue(all(k == k.lower() for k in keywords))
        self.assertEqual(len(keywords), len(set(keywords)))
        # Mixing a curated class with a CWE key yields both keyword sets.
        mixed = cwe.category_keywords(["sqli", "cwe:918"])
        self.assertIn("sql injection", mixed)
        self.assertIn("ssrf", mixed)


class TestPickerCatalog(unittest.TestCase):
    def test_shape_and_coverage(self):
        catalog = cwe.picker_catalog()
        self.assertEqual(catalog["columns"], ["id", "label", "aliases", "level"])
        self.assertGreater(len(catalog["rows"]), 900)
        self.assertRegex(catalog["version"], r"^\d+\.\d+$")
        ids = [row[0] for row in catalog["rows"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids, key=int))
        for row in catalog["rows"]:
            self.assertEqual(len(row), 4)
            self.assertTrue(row[1], msg=f"CWE-{row[0]} has no label")

    def test_deprecated_cwes_are_hidden_but_still_labelled(self):
        from modules import cwe_catalog

        listed = {row[0] for row in cwe.picker_catalog()["rows"]}
        self.assertTrue(cwe_catalog.DEPRECATED, "expected some deprecated CWEs")
        for cwe_id in cwe_catalog.DEPRECATED:
            self.assertNotIn(cwe_id, listed)
            # A historical advisory tag must still render a name.
            self.assertNotEqual(cwe.cwe_label(cwe_id), f"CWE-{cwe_id}")

    def test_every_curated_class_cwe_is_in_the_catalog(self):
        listed = {row[0] for row in cwe.picker_catalog()["rows"]}
        for key, cat in cwe.CATEGORIES.items():
            for cwe_id in cat["core"] + cat["extended"]:
                self.assertIn(cwe_id, listed,
                              msg=f"class '{key}' uses CWE-{cwe_id}, missing from catalog")


class TestNormalizeCweId(unittest.TestCase):
    def test_normalize_variants(self):
        self.assertEqual(cwe.normalize_cwe_id("CWE-639"), "639")
        self.assertEqual(cwe.normalize_cwe_id("cwe-89 "), "89")
        self.assertEqual(cwe.normalize_cwe_id(" 22 "), "22")
        self.assertEqual(cwe.normalize_cwe_id("639"), "639")


class TestDataIntegrity(unittest.TestCase):
    """The static tables must stay mutually consistent as categories grow."""

    def test_every_category_has_a_short_unique_code(self):
        """The UI renders these in a fixed-width column; long codes eat the name."""
        codes = [cat["code"] for cat in cwe.CATEGORIES.values()]
        self.assertEqual(len(codes), len(set(codes)), msg=f"duplicate codes: {codes}")
        for key, cat in cwe.CATEGORIES.items():
            code = cat["code"]
            with self.subTest(category=key):
                self.assertTrue(code)
                self.assertLessEqual(len(code), cwe.MAX_CATEGORY_CODE_LENGTH)
                self.assertEqual(code, code.upper())

    def test_keyword_keys_are_known_categories(self):
        for key in cwe.KEYWORDS:
            self.assertIn(key, cwe.CATEGORIES,
                          msg=f"KEYWORDS['{key}'] has no matching category")

    def test_all_category_cwes_have_labels(self):
        for key, cat in cwe.CATEGORIES.items():
            for c in cat["core"] + cat["extended"]:
                self.assertNotEqual(
                    cwe.cwe_label(c), f"CWE-{c}",
                    msg=f"category '{key}': CWE-{c} is not in the MITRE catalog")


if __name__ == "__main__":
    unittest.main(verbosity=2)
