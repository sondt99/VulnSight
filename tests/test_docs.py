"""Keep the documentation honest.

Docs that quote numbers rot silently, and a doc that lies is worse than no doc —
especially the ones stating what an operation *costs*. These tests derive the
figures from the code and fail when a doc drifts, and they check that every
internal link resolves.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app as app_module
from modules import cwe_catalog
from modules.cwe_categories import CATEGORIES, picker_catalog, resolve_cwes
from modules.search_service import MAX_CATEGORY_INPUTS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")


def _markdown_files():
    paths = [os.path.join(ROOT, name) for name in sorted(os.listdir(ROOT))
             if name.endswith(".md")]
    paths += [os.path.join(DOCS, name) for name in sorted(os.listdir(DOCS))
              if name.endswith(".md")]
    return paths


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class TestDocsStructure(unittest.TestCase):
    def test_the_expected_pages_exist(self):
        expected = {
            "README.md", "getting-started.md", "configuration.md", "usage.md",
            "bug-classes.md", "cwe-catalog.md", "data-sources.md",
            "ai-classification.md", "api.md", "architecture.md", "testing.md",
            "operations.md",
        }
        present = set(os.listdir(DOCS))
        self.assertTrue(expected.issubset(present), expected - present)

    def test_readme_links_to_every_doc_page(self):
        readme = _read(os.path.join(ROOT, "README.md"))
        for name in sorted(os.listdir(DOCS)):
            if name.endswith(".md") and name != "README.md":
                self.assertIn(f"docs/{name}", readme, name)

    def test_index_links_to_every_doc_page(self):
        index = _read(os.path.join(DOCS, "README.md"))
        for name in sorted(os.listdir(DOCS)):
            if name.endswith(".md") and name != "README.md":
                self.assertIn(f"({name})", index, name)

    def test_every_internal_link_and_anchor_resolves(self):
        link = re.compile(r"\[[^\]]+\]\(([^)#]+)(#[^)]+)?\)")
        heading = re.compile(r"^#{1,6}\s+(.*)$", re.M)

        def slug(text):
            text = re.sub(r"[`*\[\]():,./—–’'\"]", "", text.strip().lower())
            return re.sub(r"\s+", "-", text)

        anchors = {path: {slug(h) for h in heading.findall(_read(path))}
                   for path in _markdown_files()}
        checked = 0
        for path in _markdown_files():
            for target, fragment in link.findall(_read(path)):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                checked += 1
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname(path), target))
                rel = os.path.relpath(path, ROOT)
                self.assertTrue(os.path.exists(resolved),
                                f"{rel} -> {target} does not exist")
                if fragment and resolved.endswith(".md"):
                    self.assertIn(fragment[1:].lower(), anchors.get(resolved, set()),
                                  f"{rel} -> {target}{fragment} has no such heading")
        self.assertGreater(checked, 20, "link check found suspiciously few links")


class TestDocsMatchTheCode(unittest.TestCase):
    """Every number below is derived, so a doc cannot drift away from reality."""

    def setUp(self):
        # Keyed by path relative to the repo root: docs/README.md and the root
        # README.md would otherwise collide on their basename.
        self.text = {os.path.relpath(p, ROOT): _read(p) for p in _markdown_files()}

    def _assert_claim(self, page, pattern):
        """Assert a number *in the sentence that claims it*.

        Searching a whole page for a bare "944" is worthless — the figure occurs
        several times, so a wrong one in the summary table still passes. Anchor
        each number to its claim instead.
        """
        self.assertRegex(self.text[page], pattern,
                         f"{page} no longer states: {pattern}")

    def test_cwe_catalog_figures(self):
        catalog = picker_catalog()
        offered = len(catalog["rows"])
        total = len(cwe_catalog.NAMES)
        deprecated = len(cwe_catalog.DEPRECATED)
        version = re.escape(catalog["version"])

        self._assert_claim("docs/cwe-catalog.md", rf"CWE \*\*{version}\*\*")
        self._assert_claim("docs/cwe-catalog.md",
                           rf"Weaknesses \| \*\*{total}\*\* total; {deprecated} deprecated")
        self._assert_claim("docs/cwe-catalog.md",
                           rf"Offered in the picker \| \*\*{offered}\*\*")
        self._assert_claim("docs/cwe-catalog.md",
                           rf"{offered} rows plus \d+ classes")
        self._assert_claim("README.md",
                           rf"\*\*{offered} weaknesses of CWE {version}\*\*")
        self._assert_claim("docs/usage.md",
                           rf"\*\*944 weaknesses of CWE {version}\*\*".replace("944", str(offered)))

    def test_class_and_group_counts(self):
        classes = len(CATEGORIES)
        groups = len({spec["group"] for spec in CATEGORIES.values()})
        reachable = len(resolve_cwes(list(CATEGORIES)))

        self._assert_claim("README.md", rf"\*\*{classes} curated bug classes\*\* in {groups} groups")
        self._assert_claim("docs/usage.md", rf"{classes} classes in {groups} groups")
        self._assert_claim("docs/bug-classes.md", rf"## The {classes} shipped classes")
        self._assert_claim("docs/bug-classes.md",
                           rf"{reachable} distinct CWEs are reachable through these classes")
        self._assert_claim("docs/README.md", rf"the {classes} shipped classes")

    def test_every_class_appears_in_the_reference_table(self):
        table = self.text["docs/bug-classes.md"]
        for key, spec in CATEGORIES.items():
            self.assertIn(f"`{key}`", table, key)
            self.assertIn(f"`{spec['code']}`", table, spec["code"])

    def test_cost_limits_are_stated_correctly(self):
        calls = app_module.MAX_AI_CALLS_PER_REQUEST
        batch = app_module.MAX_AI_BATCH
        self._assert_claim("docs/configuration.md",
                           rf"`MAX_AI_CALLS_PER_REQUEST` \| `{calls}`")
        self._assert_claim("docs/configuration.md", rf"`MAX_AI_BATCH` \| `{batch}`")
        self._assert_claim("docs/configuration.md",
                           rf"`MAX_CATEGORY_INPUTS` \| `{MAX_CATEGORY_INPUTS}`")
        self._assert_claim("docs/ai-classification.md",
                           rf"\*\*{calls} \(`MAX_AI_CALLS_PER_REQUEST`\)\*\*")
        self._assert_claim("docs/ai-classification.md",
                           rf"Advisories per request \| {batch}")
        self._assert_claim("docs/api.md", rf"capped at \*\*{calls}\*\*")
        self._assert_claim("docs/api.md", rf"max {batch}")

    def test_every_route_is_documented(self):
        routes = {
            str(rule) for rule in app_module.create_app().url_map.iter_rules()
            if not str(rule).startswith("/static")
        }
        api_doc = self.text["docs/api.md"]
        for route in routes:
            self.assertIn(route, api_doc, f"{route} is not in docs/api.md")

    def test_documented_env_vars_exist_in_the_code(self):
        source = ""
        for name in ("app.py",):
            source += _read(os.path.join(ROOT, name))
        modules_dir = os.path.join(ROOT, "modules")
        for name in sorted(os.listdir(modules_dir)):
            if name.endswith(".py"):
                source += _read(os.path.join(modules_dir, name))

        documented = set(re.findall(r"`(VULNSIGHT_[A-Z_]+|AI_[A-Z_]+|NVD_API_KEY"
                                   r"|GH_TOKEN|GITHUB_TOKEN|CVE_AI_PROVIDER"
                                   r"|MAX_REQUEST_BYTES)`",
                                   self.text["docs/configuration.md"]))
        self.assertGreater(len(documented), 10, "env var table looks empty")
        for name in sorted(documented):
            self.assertIn(name, source, f"docs mention {name}, code never reads it")

    def test_no_stale_reference_to_the_old_usage_file(self):
        self.assertFalse(os.path.exists(os.path.join(ROOT, "USAGE.md")))
        for page, body in self.text.items():
            self.assertNotIn("USAGE.md", body, page)


if __name__ == "__main__":
    unittest.main()
