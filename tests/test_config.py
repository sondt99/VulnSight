"""The .env loader, and the ordering guarantee the rest of the code relies on.

Run in a subprocess with a scratch copy of the package: the assertion is about
what happens *at import*, and the modules under test are already imported in
this process, so nothing observable would be left to check in-process.
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from modules import config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestDotenvIsLoadedBeforeConstants(unittest.TestCase):
    """Constants derived at import must see the .env, whatever imports first.

    app.py used to import the modules and only then call load_dotenv(), so
    every import-time constant was computed against an environment the .env had
    not reached. AI_CLASSIFY_WORKERS worked because it is read at call time and
    AI_CLASSIFY_TIMEOUT did not, which is worse than a knob that plainly does
    not exist.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        shutil.copytree(os.path.join(ROOT, "modules"),
                        os.path.join(self.tmp, "modules"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _probe(self, dotenv: str, expression: str) -> str:
        with open(os.path.join(self.tmp, ".env"), "w", encoding="utf-8") as fh:
            fh.write(dotenv)
        result = subprocess.run(
            [sys.executable, "-c",
             "from modules import ai_classifier, cache, config\n"
             f"print({expression})"],
            cwd=self.tmp, capture_output=True, text=True,
            # A clean environment, so only the .env can be responsible.
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": self.tmp},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_import_time_constants_see_the_dotenv(self):
        cases = [
            ("AI_THINKING=on\n", "ai_classifier.THINKING_ENABLED", "True"),
            ("AI_CLASSIFY_TIMEOUT=999\n", "ai_classifier.CLASSIFY_TIMEOUT", "999"),
            ("AI_CLASSIFY_MAX_TOKENS=1234\n",
             "ai_classifier.CLASSIFY_MAX_TOKENS", "1234"),
        ]
        for dotenv, expression, expected in cases:
            with self.subTest(setting=dotenv.strip()):
                self.assertEqual(self._probe(dotenv, expression), expected)

    def test_data_dir_and_db_path_follow_the_dotenv(self):
        target = os.path.join(self.tmp, "elsewhere")
        self.assertEqual(
            self._probe(f"VULNSIGHT_DATA_DIR={target}\n", "config.DATA_DIR"),
            target,
        )
        self.assertEqual(
            self._probe(f"VULNSIGHT_DATA_DIR={target}\n", "cache.DB_PATH"),
            os.path.join(target, "advisories.db"),
        )

    def test_a_real_environment_variable_still_wins(self):
        """load_dotenv uses setdefault; the .env is a default, not an override."""
        with open(os.path.join(self.tmp, ".env"), "w", encoding="utf-8") as fh:
            fh.write("AI_CLASSIFY_TIMEOUT=999\n")
        result = subprocess.run(
            [sys.executable, "-c",
             "from modules import ai_classifier\nprint(ai_classifier.CLASSIFY_TIMEOUT)"],
            cwd=self.tmp, capture_output=True, text=True,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": self.tmp,
                 "AI_CLASSIFY_TIMEOUT": "7"},
        )
        self.assertEqual(result.stdout.strip(), "7", result.stderr)


class TestLoadDotenvParsing(unittest.TestCase):
    def test_comments_blanks_and_quotes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write('# a comment\n\nA="quoted"\nB=plain\nC=\nno_equals_here\n')
            path = fh.name
        try:
            for key in ("A", "B", "C"):
                os.environ.pop(key, None)
            config.load_dotenv(path)
            self.assertEqual(os.environ.get("A"), "quoted")
            self.assertEqual(os.environ.get("B"), "plain")
            self.assertEqual(os.environ.get("C"), "")
        finally:
            for key in ("A", "B", "C"):
                os.environ.pop(key, None)
            os.unlink(path)

    def test_a_missing_file_is_not_an_error(self):
        config.load_dotenv("/nonexistent/.env")


if __name__ == "__main__":
    unittest.main(verbosity=2)
