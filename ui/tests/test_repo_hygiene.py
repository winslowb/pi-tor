"""Repo hygiene: every script we ship must be executable.

`bin/usb_route` and `bin/usb_route_undo` were committed mode 644, so every
fresh clone failed at `sudo <script>` with "command not found" even though
the tests passed -- they invoked `bash bin/usb_route`, which does not need
the exec bit. This asserts the bit itself.
"""
import os
import unittest
from pathlib import Path

from helpers import REPO


class ExecutableScriptsTest(unittest.TestCase):

    def test_every_bin_script_is_executable(self):
        scripts = sorted(p for p in (REPO / "bin").iterdir() if p.is_file())
        self.assertTrue(scripts, "bin/ is empty?")
        bad = [p.name for p in scripts if not os.access(p, os.X_OK)]
        self.assertEqual(bad, [], f"not executable (chmod +x in git): {bad}")

    def test_every_bin_script_declares_an_interpreter(self):
        missing = []
        for p in sorted((REPO / "bin").iterdir()):
            if not p.is_file():
                continue
            first = p.read_text(errors="replace").splitlines()[:1]
            if not first or not first[0].startswith("#!"):
                missing.append(p.name)
        self.assertEqual(missing, [], f"missing shebang: {missing}")


if __name__ == "__main__":
    unittest.main()
