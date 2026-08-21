"""Run the Node-based frontend tests as part of the normal pytest suite.

The `tests/*.js` files exercise pure helpers lifted straight out of
`static/app.js` (CSV escaping, history sanitisation, …). They used to be
runnable only by hand, so regressions in them went unnoticed.
"""

import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
NODE = shutil.which("node") or ""


@unittest.skipUnless(NODE, "node is not installed")
class TestFrontendJavaScript(unittest.TestCase):
    def test_every_js_test_file_passes(self):
        scripts = sorted(
            name for name in os.listdir(TESTS_DIR)
            if name.startswith("test_") and name.endswith(".js")
        )
        self.assertTrue(scripts, "expected at least one tests/test_*.js file")
        for script in scripts:
            with self.subTest(script=script):
                proc = subprocess.run(
                    [NODE, os.path.join(TESTS_DIR, script)],
                    capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(
                    proc.returncode, 0,
                    msg=f"{script} failed:\n{proc.stdout}\n{proc.stderr}",
                )


if __name__ == "__main__":
    unittest.main()
