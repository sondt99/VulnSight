"""Unit tests for CSRF origin parsing, bind guards, tokens, and rate limits."""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest import mock

from modules import security


class TestOriginAllowed(unittest.TestCase):
    def test_loopback_origins(self):
        for origin in (
            "http://127.0.0.1",
            "http://127.0.0.1:5000",
            "http://localhost",
            "http://localhost:5000",
            "https://localhost",
            "http://[::1]:5000",
        ):
            with self.subTest(origin=origin):
                self.assertTrue(security.origin_allowed(origin, "example.com:80"))

    def test_prefix_lookalikes_rejected(self):
        for origin in (
            "http://localhost.evil.com",
            "http://localhostevil.com",
            "http://127.0.0.1.attacker.com",
            "http://127.0.0.1.example",
            "https://localhost.example.com",
            "http://127.0.0.1:5000.evil.com",
            "http://127.0.0.1:5000evil",
        ):
            with self.subTest(origin=origin):
                self.assertFalse(security.origin_allowed(origin, "127.0.0.1:5000"))

    def test_userinfo_rejected(self):
        self.assertFalse(
            security.origin_allowed("http://evil@127.0.0.1", "127.0.0.1:5000")
        )

    def test_non_http_scheme_rejected(self):
        self.assertFalse(security.origin_allowed("javascript:alert(1)", "127.0.0.1"))
        self.assertFalse(security.origin_allowed("null", "127.0.0.1"))

    def test_configured_dns_host(self):
        extras = ["vulnsight.example"]
        self.assertTrue(
            security.origin_allowed("https://vulnsight.example", "127.0.0.1:5000", extras)
        )
        self.assertFalse(
            security.origin_allowed("https://other.example", "127.0.0.1:5000", extras)
        )
        self.assertTrue(
            security.origin_allowed(
                "https://vulnsight.example", "127.0.0.1:5000",
                ["vulnsight.example:443"],
            )
        )

    def test_matching_literal_ip(self):
        self.assertTrue(
            security.origin_allowed("http://192.168.1.9:5000", "192.168.1.9:5000")
        )
        self.assertFalse(
            security.origin_allowed("http://192.168.1.9:5000", "10.0.0.1:5000")
        )

    def test_dns_name_does_not_match_request_host(self):
        # DNS rebinding: Origin host == Host header, but the name is not allowlisted.
        self.assertFalse(
            security.origin_allowed("http://localhost.evil.com", "localhost.evil.com")
        )

    def test_public_hosts_strip_ports(self):
        with mock.patch.dict(
            os.environ, {"VULNSIGHT_PUBLIC_HOST": "vulnsight.example:443, 10.0.0.8:5000"},
            clear=False,
        ):
            self.assertEqual(
                security.public_hosts_from_env(),
                ["vulnsight.example", "10.0.0.8"],
            )


class TestMutatingRequestAllowed(unittest.TestCase):
    def test_missing_origin_allows_non_browser(self):
        self.assertTrue(
            security.mutating_request_allowed(
                origin=None, referer=None, host="127.0.0.1:5000",
                sec_fetch_site=None,
            )
        )

    def test_cross_site_fetch_metadata_rejected(self):
        self.assertFalse(
            security.mutating_request_allowed(
                origin="", referer="", host="127.0.0.1:5000",
                sec_fetch_site="cross-site",
            )
        )

    def test_bad_referer_without_origin_rejected(self):
        self.assertFalse(
            security.mutating_request_allowed(
                origin="", referer="http://evil.example/page",
                host="127.0.0.1:5000", sec_fetch_site=None,
            )
        )


class TestToken(unittest.TestCase):
    def test_not_configured(self):
        self.assertTrue(security.token_matches("", ""))
        self.assertTrue(security.token_matches("", "anything"))

    def test_match_and_mismatch(self):
        self.assertTrue(security.token_matches("secret", "secret"))
        self.assertFalse(security.token_matches("secret", "Secret"))
        self.assertFalse(security.token_matches("secret", "nope"))
        self.assertFalse(security.token_matches("secret", ""))

    def test_extract_headers(self):
        self.assertEqual(
            security.extract_request_token("abc", "Bearer ignored"), "abc"
        )
        self.assertEqual(
            security.extract_request_token(None, "Bearer xyz"), "xyz"
        )
        self.assertEqual(
            security.extract_request_token("", "bearer xyz"), "xyz"
        )
        self.assertEqual(security.extract_request_token(None, "Basic xyz"), "")


class TestBindGuard(unittest.TestCase):
    def test_loopback_is_safe(self):
        with mock.patch.dict(os.environ, {"GLM_TOKEN": "x"}, clear=False):
            security.assert_safe_bind("127.0.0.1")
            security.assert_safe_bind("localhost")

    def test_public_bind_without_secrets_is_safe(self):
        env = {
            "GLM_TOKEN": "", "AI_TOKEN": "", "ANTHROPIC_TOKEN": "",
            "GH_TOKEN": "", "GITHUB_TOKEN": "", "NVD_API_KEY": "",
            "VULNSIGHT_EXPOSE": "",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            security.assert_safe_bind("0.0.0.0")

    def test_public_bind_with_secrets_refuses(self):
        with mock.patch.dict(
            os.environ, {"GLM_TOKEN": "live", "VULNSIGHT_EXPOSE": ""}, clear=False
        ):
            with self.assertRaises(SystemExit):
                security.assert_safe_bind("0.0.0.0")

    def test_expose_override_requires_token(self):
        with mock.patch.dict(
            os.environ,
            {"GLM_TOKEN": "live", "VULNSIGHT_EXPOSE": "1", "VULNSIGHT_API_TOKEN": ""},
            clear=False,
        ):
            with self.assertRaises(SystemExit):
                security.assert_safe_bind("0.0.0.0")

    def test_expose_override(self):
        with mock.patch.dict(
            os.environ,
            {
                "GLM_TOKEN": "live",
                "VULNSIGHT_EXPOSE": "1",
                "VULNSIGHT_API_TOKEN": "secret",
            },
            clear=False,
        ):
            security.assert_safe_bind("0.0.0.0")

    def test_debug_refused_off_loopback(self):
        with self.assertRaises(SystemExit):
            security.assert_safe_debug("0.0.0.0", True)
        security.assert_safe_debug("127.0.0.1", True)
        security.assert_safe_debug("0.0.0.0", False)

    def test_ensure_token_loopback_stays_optional(self):
        with mock.patch.dict(
            os.environ, {"GLM_TOKEN": "live", "VULNSIGHT_API_TOKEN": ""}, clear=False
        ):
            self.assertEqual(security.ensure_api_token_for_bind("127.0.0.1"), "")

    def test_ensure_token_autogens_on_public_bind(self):
        import tempfile
        data_dir = tempfile.mkdtemp()
        env = {
            "GLM_TOKEN": "live",
            "VULNSIGHT_API_TOKEN": "",
            "VULNSIGHT_DATA_DIR": data_dir,
            "HOST": "0.0.0.0",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            token = security.ensure_api_token_for_bind("0.0.0.0")
        self.assertTrue(token)
        path = os.path.join(data_dir, ".vulnsight_api_token")
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read().strip(), token)
        with mock.patch.dict(os.environ, {**env, "VULNSIGHT_API_TOKEN": ""}, clear=False):
            again = security.ensure_api_token_for_bind("0.0.0.0")
        self.assertEqual(again, token)


class TestRateLimiter(unittest.TestCase):
    def test_blocks_after_budget(self):
        limiter = security.RateLimiter(2, 60)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))

    def test_evicts_when_key_cap_reached(self):
        limiter = security.RateLimiter(1, 60, max_keys=2)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))
        self.assertTrue(limiter.allow("c"))
        self.assertLessEqual(len(limiter._hits), 2)


class TestDocsHygiene(unittest.TestCase):
    """Docs must not imply a token ships with the repo, and must not leak one."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _doc_files(self):
        names = [".env.example"]
        for entry in sorted(os.listdir(self.ROOT)):
            if entry.endswith(".md"):
                names.append(entry)
        docs = os.path.join(self.ROOT, "docs")
        for entry in sorted(os.listdir(docs)):
            if entry.endswith(".md"):
                names.append(os.path.join("docs", entry))
        return names

    def test_every_doc_is_checked(self):
        names = self._doc_files()
        self.assertIn("README.md", names)
        self.assertIn(os.path.join("docs", "configuration.md"), names)
        self.assertGreaterEqual(len(names), 10)

    def test_docs_do_not_claim_prefilled_tokens(self):
        for name in self._doc_files():
            with open(os.path.join(self.ROOT, name), encoding="utf-8") as fh:
                text = fh.read().lower()
            self.assertNotIn("already filled", text, name)

    def test_docs_contain_no_token_shaped_strings(self):
        # A doc is the easiest place to paste a real key by accident.
        pattern = re.compile(
            r"(sk-[a-z0-9]{16,}|ghp_[a-z0-9]{20,}|gho_[a-z0-9]{20,}"
            r"|[a-f0-9]{32}\.[a-z0-9]{16,})", re.IGNORECASE)
        for name in self._doc_files():
            with open(os.path.join(self.ROOT, name), encoding="utf-8") as fh:
                hit = pattern.search(fh.read())
            self.assertIsNone(hit, f"{name}: possible credential {hit.group(0) if hit else ''}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
