"""Tests for ai_classifier: verdict parsing, retry policy and batch isolation.

_call_messages is mocked everywhere; AIConfig is built by hand (no .env read).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest
from unittest import mock

from modules import ai_classifier
from modules import ghsa_client as ghsa
from samples import SAMPLE


class TestAIParsing(unittest.TestCase):
    def test_parse_plain_json(self):
        v = ai_classifier._parse_verdict('{"is_match": true, "confidence": 0.8, "vuln_type": "BFLA", "reason": "x"}')
        self.assertTrue(v["is_match"])
        self.assertEqual(v["confidence"], 0.8)
        self.assertEqual(v["vuln_type"], "BFLA")

    def test_parse_code_fence(self):
        v = ai_classifier._parse_verdict('```json\n{"is_match": false, "confidence": 0.2}\n```')
        self.assertFalse(v["is_match"])

    def test_parse_with_prose_around(self):
        v = ai_classifier._parse_verdict('Sure! {"is_match": true, "confidence": 1.5} done')
        self.assertEqual(v["confidence"], 1.0)  # clamped

    def test_parse_no_json_raises(self):
        with self.assertRaises(ai_classifier.AIError):
            ai_classifier._parse_verdict("no json here")

    def test_parse_string_false_is_false(self):
        # Regression: bool("false") is truthy; the parser must coerce strictly.
        v = ai_classifier._parse_verdict('{"is_match": "false", "confidence": 0.9}')
        self.assertFalse(v["is_match"])
        v = ai_classifier._parse_verdict('{"is_match": "no", "confidence": 0.9}')
        self.assertFalse(v["is_match"])
        v = ai_classifier._parse_verdict('{"is_match": "yes", "confidence": 0.9}')
        self.assertTrue(v["is_match"])

    def test_parse_non_numeric_confidence_is_zero(self):
        # Regression: float("high") used to raise out of the parser.
        v = ai_classifier._parse_verdict('{"is_match": true, "confidence": "high"}')
        self.assertTrue(v["is_match"])
        self.assertEqual(v["confidence"], 0.0)


class TestConfig(unittest.TestCase):
    def test_config_detection(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", "tok", "PRO")
        self.assertTrue(cfg.configured)
        self.assertEqual(cfg.messages_url, "https://x/v1/messages")
        self.assertFalse(ai_classifier.AIConfig("anthropic", "", "", "").configured)


class TestClassify(unittest.TestCase):
    def _cfg(self):
        return ai_classifier.AIConfig("anthropic", "https://x", "tok", "PRO")

    def test_classify_many_mocked(self):
        cfg = self._cfg()
        advs = [dict(SAMPLE, ghsa_id="A"), dict(SAMPLE, ghsa_id="B")]
        advs = [ghsa.normalize(a) for a in advs]

        def fake_call(cfg, system, user, max_tokens=512, timeout=45):
            return '{"is_match": true, "confidence": 0.77, "vuln_type": "IDOR", "reason": "r"}'

        saved = []
        with mock.patch("modules.ai_classifier._call_messages", side_effect=fake_call):
            res = ai_classifier.classify_many(cfg, advs, "bac",
                                              on_result=lambda g, v: saved.append(g))
        self.assertEqual(set(res.keys()), {"A", "B"})
        self.assertTrue(all(v["is_match"] for v in res.values()))
        self.assertEqual(set(saved), {"A", "B"})

    def test_retry_then_success(self):
        cfg = self._cfg()
        adv = ghsa.normalize(SAMPLE)
        calls = {"n": 0}

        def flaky(cfg, system, user, max_tokens=512, timeout=45):
            calls["n"] += 1
            if calls["n"] < 3:
                raise ai_classifier.AIError("429 rate limited", status=429, retryable=True)
            return '{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'

        with mock.patch("modules.ai_classifier._call_messages", side_effect=flaky), \
             mock.patch("modules.ai_classifier.time.sleep", lambda *_: None):
            v = ai_classifier.classify_one(cfg, adv, "bac")
        self.assertTrue(v["is_match"])
        self.assertEqual(calls["n"], 3)  # failed twice, succeeded on 3rd

    def test_no_retry_on_client_error(self):
        cfg = self._cfg()
        adv = ghsa.normalize(SAMPLE)
        calls = {"n": 0}

        def bad_key(cfg, system, user, max_tokens=512, timeout=45):
            calls["n"] += 1
            raise ai_classifier.AIError("401 invalid key", status=401, retryable=False)

        with mock.patch("modules.ai_classifier._call_messages", side_effect=bad_key), \
             mock.patch("modules.ai_classifier.time.sleep", lambda *_: None):
            with self.assertRaises(ai_classifier.AIError):
                ai_classifier.classify_one(cfg, adv, "bac")
        self.assertEqual(calls["n"], 1)  # not retried

    def test_retry_exhausted_raises(self):
        cfg = self._cfg()
        adv = ghsa.normalize(SAMPLE)
        calls = {"n": 0}

        def always_429(cfg, system, user, max_tokens=512, timeout=45):
            calls["n"] += 1
            raise ai_classifier.AIError("429", status=429, retryable=True)

        with mock.patch("modules.ai_classifier._call_messages", side_effect=always_429), \
             mock.patch("modules.ai_classifier.time.sleep", lambda *_: None):
            with self.assertRaises(ai_classifier.AIError):
                ai_classifier.classify_one(cfg, adv, "bac")
        self.assertEqual(calls["n"], ai_classifier.MAX_RETRIES + 1)  # 1 + retries

    def test_classify_many_error_isolated(self):
        cfg = self._cfg()
        advs = [ghsa.normalize(dict(SAMPLE, ghsa_id="A"))]

        def boom(*a, **k):
            raise ai_classifier.AIError("429 rate limited")

        with mock.patch("modules.ai_classifier._call_messages", side_effect=boom):
            res = ai_classifier.classify_many(cfg, advs, "bac")
        self.assertIn("error", res["A"])

    def test_classify_many_unexpected_exception_isolated(self):
        # Regression: a non-AIError bug used to escape fut.result() and kill
        # the whole batch; now it must degrade to a per-advisory error verdict.
        cfg = self._cfg()
        advs = [ghsa.normalize(dict(SAMPLE, ghsa_id="A"))]

        with mock.patch("modules.ai_classifier._call_messages", side_effect=ValueError("kaboom")):
            with self.assertLogs("modules.ai_classifier", level="ERROR"):
                res = ai_classifier.classify_many(cfg, advs, "bac")
        self.assertIn("error", res["A"])
        self.assertIn("kaboom", res["A"]["error"])
        self.assertIsNone(res["A"]["is_match"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
