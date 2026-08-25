"""The OpenAPI document is hand-written, so these tests are what keep it true.

The document's whole value is that a client generator will believe it. A
description that has drifted from the server is worse than no description, so
the checks here are deliberately the two that catch drift: the path set must
match ``url_map`` in both directions, and a real response from the app must
validate against the schema the document claims for it.

The validator is a small local one rather than `jsonschema`, because the project
runs on Flask and the standard library and a documentation test is not a good
reason to break that. It covers the subset the spec actually uses.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import tempfile
import unittest
from unittest import mock

from modules import cache, openapi
from samples import SAMPLE


def validate(value, schema, path="$") -> list[str]:
    """Return a list of human-readable violations; empty means valid."""
    errors: list[str] = []

    if "allOf" in schema:
        for sub in schema["allOf"]:
            errors += validate(value, sub, path)
        return errors

    expected = schema.get("type")
    if value is None:
        if schema.get("nullable") or expected is None:
            return errors
        return [f"{path}: null but type is {expected}"]

    checkers = {
        "object": dict, "array": list, "string": str,
        "boolean": bool, "number": (int, float), "integer": int,
    }
    if expected in checkers:
        # bool is a subclass of int in Python; the spec means them separately.
        if expected in ("number", "integer") and isinstance(value, bool):
            return [f"{path}: bool where {expected} expected"]
        if not isinstance(value, checkers[expected]):
            return [f"{path}: {type(value).__name__} where {expected} expected"]

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")

    if expected == "object":
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key {key!r}")
        for key, sub in (schema.get("properties") or {}).items():
            if key in value:
                errors += validate(value[key], sub, f"{path}.{key}")
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict):
            declared = set(schema.get("properties") or {})
            for key, item in value.items():
                if key not in declared:
                    errors += validate(item, extra, f"{path}.{key}")

    if expected == "array" and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            errors += validate(item, schema["items"], f"{path}[{index}]")

    return errors


class _AppCase(unittest.TestCase):
    """Shared fixture. Holds no tests, so subclasses do not re-run each other's."""

    def setUp(self):
        self.spec = openapi.build_spec()
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        self._env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "off",
            "HOST": "127.0.0.1",
        }, clear=False)
        self._env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        from modules import jobs
        jobs.shutdown(wait=True)
        self._env.stop()
        cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def _live_v1_routes(self) -> dict[str, set[str]]:
        """Flask spells parameters `<job_id>`; OpenAPI spells them `{job_id}`."""
        out: dict[str, set[str]] = {}
        for rule in self.app.url_map.iter_rules():
            path = re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", r"{\1}", str(rule))
            if not path.startswith("/api/v1/"):
                continue
            methods = {m for m in (rule.methods or ())
                       if m in ("GET", "POST", "PUT", "PATCH", "DELETE")}
            out.setdefault(path, set()).update(methods)
        return out


class TestSpecMatchesTheRoutes(_AppCase):
    def test_every_route_is_described(self):
        live = set(self._live_v1_routes())
        described = set(self.spec["paths"])
        self.assertTrue(live, "no /api/v1 routes found — the check would be vacuous")
        self.assertEqual(live - described, set(), "routes with no OpenAPI entry")

    def test_nothing_is_described_that_does_not_exist(self):
        live = set(self._live_v1_routes())
        described = set(self.spec["paths"])
        self.assertEqual(described - live, set(), "OpenAPI describes missing routes")

    def test_documented_methods_match_the_routes(self):
        for path, methods in self._live_v1_routes().items():
            with self.subTest(path=path):
                described = {m.upper() for m in self.spec["paths"][path]}
                self.assertEqual(described, methods)

    def test_spec_is_served_with_an_etag(self):
        r = self.client.get("/api/v1/openapi.json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["openapi"], "3.1.0")
        etag = r.headers["ETag"]
        again = self.client.get("/api/v1/openapi.json",
                                headers={"If-None-Match": etag})
        self.assertEqual(again.status_code, 304)


class TestSpecMatchesRealResponses(_AppCase):
    """The check that matters: validate what the server sends, not what we assumed."""

    def test_a_real_search_response_validates(self):
        schema = self.spec["components"]["schemas"]["SearchResponse"]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            body = self.client.post(
                "/api/v1/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
            ).get_json()
        self.assertEqual(validate(body, schema), [])

    def test_an_empty_search_response_validates(self):
        schema = self.spec["components"]["schemas"]["SearchResponse"]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[]):
            body = self.client.post(
                "/api/v1/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
            ).get_json()
        self.assertEqual(body["count"], 0)
        self.assertEqual(validate(body, schema), [])

    def test_a_real_job_response_validates_in_every_state(self):
        import time
        schema = self.spec["components"]["schemas"]["Job"]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            job_id = self.client.post(
                "/api/v1/jobs",
                json={"categories": ["bac"], "ecosystem": "maven"},
            ).get_json()["job_id"]
            seen = set()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                body = self.client.get(f"/api/v1/jobs/{job_id}").get_json()
                self.assertEqual(validate(body, schema), [], body)
                seen.add(body["status"])
                if body["status"] in ("done", "failed"):
                    break
                time.sleep(0.01)
        self.assertIn("done", seen)

    def test_an_error_response_validates(self):
        schema = self.spec["components"]["schemas"]["Error"]
        body = self.client.post("/api/v1/search", json={"categories": []}).get_json()
        self.assertEqual(validate(body, schema), [])

    def test_the_validator_actually_rejects_bad_data(self):
        """Guards against the whole suite passing because validate() returns []."""
        schema = self.spec["components"]["schemas"]["SearchResponse"]
        self.assertNotEqual(validate({}, schema), [])
        self.assertNotEqual(validate({"count": "twelve"}, schema), [])
        stats = self.spec["components"]["schemas"]["SearchStats"]
        self.assertNotEqual(validate({"truncated": "yes"}, stats), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
