"""End-to-end UI tests driven through a real browser.

The rest of the suite is offline and dependency-free; this module is the one
exception and **skips itself** unless Playwright and a browser are both present:

    pip install -r requirements-dev.txt
    playwright install chromium      # or rely on a system Chrome

It exists because `static/app.js` carries the parts of this tool that decide
what the user believes — which advisories are hidden, which verdict belongs to
which advisory, and when real AI budget gets spent — and none of that is
reachable from a Python unit test. Every assertion here corresponds to a defect
that actually shipped.

Assert on **rendered** state, not on DOM properties. A `.cat { display: grid }`
rule once beat the UA sheet's `[hidden] { display: none }`, so the class filter
set `hidden` on every row and changed nothing on screen while a property-based
test stayed green.
"""

import json
import os
import socket
import sys
import threading
import unittest
import wsgiref.simple_server
from wsgiref.simple_server import WSGIRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:  # pragma: no cover - import guard
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

import app as app_module
from modules import cache


class _QuietHandler(WSGIRequestHandler):
    """The default handler prints every request to stderr."""

    def log_message(self, format, *args):  # noqa: A002 - signature is fixed
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _launch(playwright):
    """Prefer the Playwright browser, fall back to a system Chrome."""
    try:
        return playwright.chromium.launch()
    except Exception:
        return playwright.chromium.launch(channel="chrome")


def _advisory(index, **overrides):
    record = {
        "advisory_id": f"GHSA-{index}", "ghsa_id": f"GHSA-{index}",
        "cve_id": f"CVE-2026-{index}", "summary": f"advisory {index}",
        "severity": "high", "cvss_score": 7.5, "sources": ["ghsa"],
        "ecosystems": ["maven"], "packages": [], "cwes": ["639"],
        "cwe_labels": [{"id": "639", "label": "Authorization Bypass"}],
        "published_at": "2026-01-01T00:00:00Z", "html_url": "https://example.test/a",
    }
    record.update(overrides)
    return record


def _search_body(records, max_results=100):
    return json.dumps({
        "count": len(records), "warnings": [],
        "query": {"categories": ["bac"], "cwes": ["639", "862"],
                  "ecosystem": "maven", "severity": "any", "affects": None,
                  "max_results": max_results, "sources": ["ghsa"],
                  "per_source": {"ghsa": len(records)}},
        "results": records,
    })


def _verdicts_body(request, is_match=True):
    payload = json.loads(request.post_data or "{}")
    categories = payload.get("categories", [])
    return json.dumps({
        "categories": categories, "by_category": {}, "missing": [],
        "verdicts": {
            advisory_id: {"is_match": is_match, "confidence": 0.9,
                          "vuln_type": "t", "reason": "r",
                          "scored_categories": categories,
                          "cached": False, "has_errors": False}
            for advisory_id in payload.get("advisory_ids", [])
        },
    })


@unittest.skipIf(sync_playwright is None, "playwright is not installed")
class UITestCase(unittest.TestCase):
    """Serves the real app once for the whole class; a fresh page per test."""

    @classmethod
    def setUpClass(cls):
        cls._db = os.path.join(os.path.dirname(__file__), "_e2e_cache.db")
        cls._orig_db = cache.DB_PATH
        cache.DB_PATH = cls._db
        for name in ("VULNSIGHT_API_TOKEN", "VULNSIGHT_RATE_LIMIT"):
            os.environ.pop(name, None)
        os.environ["VULNSIGHT_RATE_LIMIT"] = "off"

        cls.port = _free_port()
        cls.server = wsgiref.simple_server.make_server(
            "127.0.0.1", cls.port, app_module.create_app(),
            handler_class=_QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        assert sync_playwright is not None   # guarded by skipIf on the class
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = _launch(cls.playwright)
        except Exception as exc:  # pragma: no cover - no browser available
            cls.playwright.stop()
            cls.server.shutdown()
            cache.DB_PATH = cls._orig_db
            raise unittest.SkipTest(f"no usable browser: {exc}")
        cls.base = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cache.DB_PATH = cls._orig_db
        for suffix in ("", "-wal", "-shm"):
            path = cls._db + suffix
            if os.path.exists(path):
                os.unlink(path)

    def setUp(self):
        self.errors = []
        # Substrings a test declares it expects to see logged, e.g. when it
        # deliberately makes an endpoint return 500.
        self.tolerated_errors: list[str] = []
        self.page = self.browser.new_page(viewport={"width": 1400, "height": 1000})
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.on(
            "console",
            lambda m: self.errors.append(m.text) if m.type == "error" else None,
        )

    def tearDown(self):
        self.page.close()
        unexpected = [
            message for message in self.errors
            if not any(allowed in message for allowed in self.tolerated_errors)
        ]
        self.assertEqual(unexpected, [], "unexpected JS errors")

    # -- helpers ----------------------------------------------------------
    def open(self, records=None, max_results=100, classify=True, is_match=True):
        records = records if records is not None else [_advisory(i) for i in range(4)]
        self.searches = []
        self.classifies = []

        def on_search(route):
            self.searches.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(status=200, content_type="application/json",
                          body=_search_body(records, max_results))
        self.page.route("**/api/search", on_search)

        if classify:
            def on_classify(route):
                self.classifies.append(json.loads(route.request.post_data or "{}"))
                route.fulfill(status=200, content_type="application/json",
                              body=_verdicts_body(route.request, is_match))
            self.page.route("**/api/ai/classify", on_classify)

        self.page.goto(self.base, wait_until="networkidle")

    def visible_classes(self):
        return self.page.eval_on_selector_all(
            "#taxonomy-list .taxonomy-item",
            "els => els.filter(e => getComputedStyle(e).display !== 'none')"
            "         .map(e => e.dataset.key)")

    def search_and_wait(self):
        self.page.click("#search-btn")
        self.page.wait_for_selector(".card")


class TestCweFinder(UITestCase):
    def test_community_alias_finds_the_cwe_with_its_full_name(self):
        self.open()
        self.page.fill("#cwe-search", "idor")
        self.page.wait_for_selector("#cwe-options .combo-option")
        rows = self.page.eval_on_selector_all(
            "#cwe-options .combo-option",
            "els => els.map(e => ({code: e.querySelector('.combo-code').textContent.trim(),"
            " label: e.querySelector('.combo-label').textContent.trim()}))")
        match = next((r for r in rows if r["code"] == "CWE-639"), None)
        self.assertIsNotNone(match, f"CWE-639 not offered for 'idor': {rows[:5]}")
        assert match is not None
        self.assertEqual(match["label"],
                         "Authorization Bypass Through User-Controlled Key")

    def test_exact_id_outranks_everything_else(self):
        self.open()
        for query, expected in (("639", "CWE-639"), ("CWE-1321", "CWE-1321")):
            self.page.fill("#cwe-search", query)
            self.page.wait_for_selector("#cwe-options .combo-option")
            first = self.page.text_content("#cwe-options .combo-option .combo-code")
            self.assertEqual((first or "").strip(), expected, query)

    def test_enter_adds_a_chip_and_does_not_start_a_search(self):
        self.open()
        self.page.fill("#cwe-search", "CWE-1321")
        self.page.wait_for_selector("#cwe-options .combo-option")
        self.page.press("#cwe-search", "Enter")
        self.page.wait_for_selector(".chip-cwe")
        self.assertEqual(
            self.page.eval_on_selector_all(".chip-cwe .chip-code",
                                           "els => els.map(e => e.textContent.trim())"),
            ["CWE-1321"])
        self.assertEqual(self.searches, [], "picking a CWE must not run a search")

    def test_dropdown_closes_when_focus_leaves(self):
        self.open()
        self.page.fill("#cwe-search", "auth")
        self.page.wait_for_selector("#cwe-options .combo-option")
        self.page.press("#cwe-search", "Tab")
        self.page.wait_for_timeout(150)
        self.assertTrue(self.page.evaluate(
            "() => document.querySelector('#cwe-options').hidden"))


class TestClassFilter(UITestCase):
    def test_filter_hides_rows_on_screen_not_just_in_the_dom(self):
        self.open()
        before = self.visible_classes()
        self.assertGreaterEqual(len(before), 20, "expected the full taxonomy")
        self.page.fill("#class-search", "prototype")
        self.page.wait_for_timeout(150)
        after = self.visible_classes()
        self.assertIn("protopollution", after)
        self.assertLess(len(after), len(before))
        self.assertNotIn("sqli", after)

    def test_a_selected_class_is_never_hidden(self):
        self.open()
        self.page.fill("#class-search", "prototype")
        self.page.wait_for_timeout(150)
        # 'bac' is preselected and does not match the filter.
        self.assertIn("bac", self.visible_classes())

    def test_community_terms_are_searchable(self):
        self.open()
        for query, expected in (("__proto__", "protopollution"), ("toctou", "race"),
                                ("samesite", "csrf"), ("webshell", "upload")):
            self.page.fill("#class-search", query)
            self.page.wait_for_timeout(120)
            self.assertIn(expected, self.visible_classes(), query)

    def test_group_heading_is_shown_exactly_when_it_has_visible_rows(self):
        self.open()
        self.page.fill("#class-search", "prototype")
        self.page.wait_for_timeout(150)
        self.assertTrue(self.page.evaluate("""() => {
          const shown = el => getComputedStyle(el).display !== 'none';
          const items = [...document.querySelectorAll('#taxonomy-list .taxonomy-item')];
          return [...document.querySelectorAll('.taxonomy-group')].every(h =>
            shown(h) === items.some(i => shown(i) && i.dataset.group === h.dataset.group));
        }"""))


class TestAiSpendRequiresConsent(UITestCase):
    def test_keyboard_shortcut_runs_the_free_search(self):
        self.open()
        self.page.evaluate("() => document.activeElement.blur()")
        self.page.keyboard.press("Control+Enter")
        self.page.wait_for_selector(".card")
        self.assertEqual(len(self.searches), 1)
        self.assertEqual(self.classifies, [],
                         "the shortcut is advertised on the free button")

    def test_confirmed_only_asks_before_scoring_and_reverts_on_cancel(self):
        self.open()
        self.search_and_wait()
        prompts = []

        def on_dialog(dialog):
            prompts.append(dialog.message)
            dialog.dismiss()
        self.page.on("dialog", on_dialog)
        self.page.click("#only_match")
        self.page.wait_for_timeout(400)
        self.assertEqual(len(prompts), 1, "no confirmation was shown")
        self.assertIn("AI call", prompts[0])
        self.assertEqual(self.classifies, [], "cancelling must not spend budget")
        self.assertFalse(self.page.is_checked("#only_match"))

    def test_a_failed_ai_pass_restores_the_raw_queue(self):
        self.open(classify=False)
        self.tolerated_errors.append("500 (Internal Server Error)")
        self.page.route("**/api/ai/classify", lambda route: route.fulfill(
            status=500, content_type="application/json",
            body='{"error": "AI quota exhausted"}'))
        self.search_and_wait()
        self.page.on("dialog", lambda d: d.accept())
        self.page.click("#only_match")
        self.page.wait_for_timeout(700)
        self.assertFalse(self.page.is_checked("#only_match"))
        self.assertEqual(self.page.locator(".card").count(), 4)


class TestVerdictsFollowTheQuery(UITestCase):
    def test_changing_the_class_marks_verdicts_stale_and_blocks_the_filter(self):
        self.open()
        self.search_and_wait()
        self.page.click("#ai-btn")
        self.page.wait_for_timeout(600)
        self.assertTrue(self.page.evaluate(
            "() => document.querySelector('#stale-banner').hidden"))

        self.page.evaluate("""() => {
          const boxes = [...document.querySelectorAll('input[name=category]')];
          boxes[0].checked = false;
          boxes[0].dispatchEvent(new Event('change', {bubbles: true}));
          boxes[1].checked = true;
          boxes[1].dispatchEvent(new Event('change', {bubbles: true}));
        }""")
        self.page.wait_for_timeout(200)
        self.assertFalse(self.page.evaluate(
            "() => document.querySelector('#stale-banner').hidden"),
            "stale verdicts were not flagged")
        self.assertTrue(self.page.is_disabled("#only_match"),
                        "filtering on stale verdicts must be blocked")

    def test_summary_reports_the_visible_count(self):
        self.open(records=[_advisory(i) for i in range(4)], is_match=False)
        self.search_and_wait()
        self.assertIn("4 advisories", self.page.text_content("#summary") or "")
        self.page.click("#ai-btn")
        self.page.wait_for_timeout(600)
        self.page.on("dialog", lambda d: d.accept())
        self.page.click("#only_match")
        self.page.wait_for_timeout(400)
        self.assertIn("0 of 4 shown", self.page.text_content("#summary") or "")


class TestFailureStates(UITestCase):
    def test_search_without_a_source_keeps_the_previous_view(self):
        self.open()
        self.search_and_wait()
        self.page.evaluate(
            "() => document.querySelectorAll('input[name=source]')"
            ".forEach(b => { b.checked = false; })")
        self.page.click("#search-btn")
        self.page.wait_for_timeout(400)
        self.assertFalse(self.page.evaluate(
            "() => !!document.querySelector('#results .spinner')"),
            "a rejected search left a spinner behind")
        self.assertEqual(self.page.locator(".card").count(), 4)

    def test_missing_epss_is_not_rendered_as_a_measured_zero(self):
        self.open(records=[
            _advisory(0, epss_percentage=None, epss_percentile=None),
            _advisory(1),
            _advisory(2, epss_percentage=0.5, epss_percentile=0.9),
        ])
        self.search_and_wait()
        meters = self.page.eval_on_selector_all(
            ".card", "els => els.map(e => e.querySelectorAll('.epss-meter').length)")
        self.assertEqual(meters, [0, 0, 1],
                         "Number(null) is 0 and finite — it must not print 0.00%")


class TestRecentSearches(UITestCase):
    def test_repeating_a_search_does_not_duplicate_the_entry(self):
        self.open()
        self.search_and_wait()
        self.page.click("#search-btn")
        self.page.wait_for_timeout(400)
        self.assertEqual(
            self.page.locator("#history-list .history-run").count(), 1)

    def test_entries_are_keyed_by_signature_not_position(self):
        self.open()
        self.search_and_wait()
        self.assertTrue(self.page.evaluate(
            "() => [...document.querySelectorAll('#history-list .history-run')]"
            ".every(r => r.dataset.sig && !r.dataset.index)"))

    def test_restoring_reapplies_the_stored_filters(self):
        self.open()
        self.search_and_wait()
        self.page.select_option("#ecosystem", "npm")
        self.page.click("#history-list .history-run")
        self.page.wait_for_selector(".card")
        self.assertEqual(self.page.input_value("#ecosystem"), "maven")


class TestAccessibility(UITestCase):
    def test_the_page_has_exactly_one_h1(self):
        self.open()
        self.assertEqual(
            self.page.evaluate("() => document.querySelectorAll('h1').length"), 1)

    def test_labelled_containers_expose_their_label(self):
        self.open()
        # aria-label is ignored on a bare <div> (role=generic prohibits it).
        self.assertTrue(self.page.evaluate("""() =>
          [...document.querySelectorAll('div[aria-label]')].every(el => el.getAttribute('role'))
        """))

    def test_mobile_panel_takes_focus_and_traps_it(self):
        self.open()
        page = self.browser.new_page(viewport={"width": 390, "height": 844})
        try:
            page.goto(self.base, wait_until="networkidle")
            page.click("#filters-toggle")
            page.wait_for_function(
                "() => document.activeElement.id === 'filters-close'", timeout=3000)
            self.assertTrue(page.evaluate(
                "() => document.querySelector('#workspace').inert"))
            for _ in range(25):
                page.keyboard.press("Tab")
                self.assertTrue(page.evaluate(
                    "() => !!document.activeElement.closest('#control-panel')"),
                    "focus escaped the modal panel")
        finally:
            page.close()


if __name__ == "__main__":
    unittest.main()
