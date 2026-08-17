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

    def test_fingerprint_changes_with_model_and_advisory(self):
        adv = ghsa.normalize(SAMPLE)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "model-a")
        original = ai_classifier.classification_fingerprint(cfg, adv, "bac")
        changed_adv = dict(adv, description=adv["description"] + " changed")
        self.assertNotEqual(
            original,
            ai_classifier.classification_fingerprint(cfg, changed_adv, "bac"),
        )
        changed_model = ai_classifier.AIConfig(
            "anthropic", "https://x", ["tok"], "model-b"
        )
        self.assertNotEqual(
            original,
            ai_classifier.classification_fingerprint(changed_model, adv, "bac"),
        )

    def test_aggregate_multi_category_prefers_match(self):
        aggregate = ai_classifier.aggregate_category_verdicts({
            "xss": {"is_match": False, "confidence": 0.8, "cached": True},
            "sqli": {
                "is_match": True,
                "confidence": 0.9,
                "vuln_type": "SQLi",
                "reason": "query concatenation",
                "cached": True,
            },
        })
        self.assertTrue(aggregate["is_match"])
        self.assertEqual(aggregate["matched_category"], "sqli")
        self.assertEqual(aggregate["scored_categories"], ["sqli", "xss"])
        self.assertTrue(aggregate["cached"])


class TestConfig(unittest.TestCase):
    def test_config_detection(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        self.assertTrue(cfg.configured)
        self.assertEqual(cfg.token, "tok")
        self.assertEqual(cfg.messages_url, "https://x/v1/messages")
        self.assertFalse(ai_classifier.AIConfig("anthropic", "", [], "").configured)

    def test_multi_key_rotation(self):
        cfg = ai_classifier.AIConfig("glm", "https://x", ["k1", "k2", "k3"], "m")
        self.assertEqual(cfg.token, "k1")
        self.assertTrue(cfg.rotate_token())
        self.assertEqual(cfg.token, "k2")
        self.assertTrue(cfg.rotate_token())
        self.assertEqual(cfg.token, "k3")
        self.assertTrue(cfg.rotate_token())
        self.assertEqual(cfg.token, "k1")  # wraps around

    def test_single_key_no_rotation(self):
        cfg = ai_classifier.AIConfig("glm", "https://x", ["only"], "m")
        self.assertFalse(cfg.rotate_token())
        self.assertEqual(cfg.token, "only")


class TestClassify(unittest.TestCase):
    def _cfg(self):
        return ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")

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

    def test_multi_key_rotates_on_failure(self):
        """When a key fails, the next key is tried; succeeds on key #3."""
        cfg = ai_classifier.AIConfig("glm", "https://x",
                                     ["bad1", "bad2", "good3"], "m")
        adv = ghsa.normalize(SAMPLE)
        calls = []

        def by_key(cfg, system, user, max_tokens=512, timeout=45):
            key = cfg.token
            calls.append(key)
            if key.startswith("bad"):
                raise ai_classifier.AIError("429", status=429, retryable=True)
            return '{"is_match": true, "confidence": 0.9, "vuln_type": "t", "reason": "r"}'

        with mock.patch("modules.ai_classifier._call_messages", side_effect=by_key), \
             mock.patch("modules.ai_classifier.time.sleep", lambda *_: None):
            v = ai_classifier.classify_one(cfg, adv, "bac")
        self.assertTrue(v["is_match"])
        self.assertEqual(calls[-1], "good3")

    def test_all_keys_exhausted_raises(self):
        """When every key fails, the error propagates after trying them all."""
        cfg = ai_classifier.AIConfig("glm", "https://x",
                                     ["k1", "k2", "k3"], "m")
        adv = ghsa.normalize(SAMPLE)
        calls = {"n": 0}

        def always_fail(cfg, system, user, max_tokens=512, timeout=45):
            calls["n"] += 1
            raise ai_classifier.AIError("503", status=503, retryable=True)

        with mock.patch("modules.ai_classifier._call_messages", side_effect=always_fail), \
             mock.patch("modules.ai_classifier.time.sleep", lambda *_: None):
            with self.assertRaises(ai_classifier.AIError):
                ai_classifier.classify_one(cfg, adv, "bac")
        self.assertGreaterEqual(calls["n"], 3)

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
