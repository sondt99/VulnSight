"""Tests for the background job store and runner.

The pool is real here — these submit work and wait for it — because the thing
worth testing is that a job actually leaves the request thread, lands in SQLite,
and comes back with the right terminal state.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile
import unittest

from modules import cache, jobs


def _wait_for(job_id, path, statuses=("done", "failed"), timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = cache.get_job(job_id, path=path)
        if job and job["status"] in statuses:
            return job
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {statuses}")


class TestJobLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        cache.init_db(cache.DB_PATH)

    def tearDown(self):
        jobs.shutdown(wait=True)
        cache.DB_PATH = self._orig
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def test_successful_job_stores_its_result(self):
        job_id = jobs.submit("search", {"n": 2}, lambda req: {"doubled": req["n"] * 2})
        job = _wait_for(job_id, self.tmp.name)
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["result"], {"doubled": 4})
        self.assertIsNone(job["error"])
        self.assertIsNotNone(job["started_at"])
        self.assertIsNotNone(job["finished_at"])

    def test_job_failure_carries_the_public_message_and_status(self):
        def runner(_req):
            raise jobs.JobFailure("GHSA fetch failed.", 502)

        job_id = jobs.submit("search", {}, runner)
        job = _wait_for(job_id, self.tmp.name)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["error"], "GHSA fetch failed.")
        self.assertEqual(job["error_status"], 502)
        self.assertIsNone(job["result"])

    def test_unexpected_exception_is_not_leaked_to_the_caller(self):
        """A job result is a response body; exception text does not belong in one."""
        def runner(_req):
            raise RuntimeError("connection to 10.0.0.5 failed: password=hunter2")

        job_id = jobs.submit("search", {}, runner)
        job = _wait_for(job_id, self.tmp.name)
        self.assertEqual(job["status"], "failed")
        self.assertNotIn("hunter2", job["error"])
        self.assertNotIn("10.0.0.5", job["error"])
        self.assertEqual(job["error_status"], 500)

    def test_public_view_hides_internals_and_unfinished_results(self):
        job_id = jobs.submit("search", {"secret": "in-request"}, lambda _r: {"ok": 1})
        job = _wait_for(job_id, self.tmp.name)
        view = jobs.public_view(job)
        self.assertEqual(view["result"], {"ok": 1})
        self.assertNotIn("request", view)   # the echo belongs in the result, not here
        self.assertNotIn("error", view)

        queued = {**job, "status": "running", "result": {"partial": True}}
        running_view = jobs.public_view(queued)
        self.assertNotIn("result", running_view)  # no partial results

    def test_orphaned_jobs_are_failed_on_startup(self):
        """A restart leaves rows mid-flight that nothing is executing any more."""
        cache.create_job("a" * 24, "search", {}, path=self.tmp.name)
        cache.mark_job_running("a" * 24, path=self.tmp.name)
        cache.create_job("b" * 24, "search", {}, path=self.tmp.name)  # still queued

        failed = jobs.startup(path=self.tmp.name)
        self.assertEqual(failed, 2)
        for job_id in ("a" * 24, "b" * 24):
            job = cache.get_job(job_id, path=self.tmp.name)
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["error_status"], 503)
            self.assertIn("restart", job["error"].lower())

    def test_startup_leaves_finished_jobs_alone(self):
        job_id = jobs.submit("search", {}, lambda _r: {"ok": 1})
        _wait_for(job_id, self.tmp.name)
        jobs.startup(path=self.tmp.name)
        self.assertEqual(cache.get_job(job_id, path=self.tmp.name)["status"], "done")

    def test_prune_drops_finished_jobs_only(self):
        done = jobs.submit("search", {}, lambda _r: {"ok": 1})
        _wait_for(done, self.tmp.name)
        cache.create_job("c" * 24, "search", {}, path=self.tmp.name)  # unfinished

        removed = cache.prune_jobs(-1, path=self.tmp.name)  # everything is "old"
        self.assertEqual(removed, 1)
        self.assertIsNone(cache.get_job(done, path=self.tmp.name))
        self.assertIsNotNone(cache.get_job("c" * 24, path=self.tmp.name))

    def test_malformed_job_id_is_not_found_without_a_query(self):
        for bad in ("", "nothex", "../../etc/passwd", "a" * 23, "A" * 24, 42):
            with self.subTest(job_id=bad):
                self.assertIsNone(jobs.get(bad, path=self.tmp.name))

    def test_job_ids_are_unguessable(self):
        ids = {jobs.new_job_id() for _ in range(200)}
        self.assertEqual(len(ids), 200)
        self.assertTrue(all(len(i) == jobs.JOB_ID_BYTES * 2 for i in ids))


if __name__ == "__main__":
    unittest.main(verbosity=2)
