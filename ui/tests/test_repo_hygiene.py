"""Repo hygiene: every script we ship must be executable.

`bin/usb_route` and `bin/usb_route_undo` were committed mode 644, so every
fresh clone failed at `sudo <script>` with "command not found" even though
the tests passed -- they invoked `bash bin/usb_route`, which does not need
the exec bit. This asserts the bit itself.
"""
import os
import re
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

    def test_no_early_exiting_pipe_consumers(self):
        """Our scripts run under `set -o pipefail`.

        `cmd | head -n1` and `cmd | grep -q ...` close the pipe as soon as they
        are satisfied, so `cmd` takes SIGPIPE and the pipeline returns 141 --
        and pipefail plus `set -e` turns that into a fatal, mid-script exit.
        It only bites once the output gains a second line (two default routes,
        two DNS servers), which is exactly the state the tether creates. Use
        `sed -n '1p'` (reads to EOF) or capture into a variable instead.
        """
        offenders = []
        for p in sorted((REPO / "bin").iterdir()):
            if not p.is_file():
                continue
            text = p.read_text(errors="replace")
            if "pipefail" not in text:
                continue
            for m in re.finditer(r"\|\s*(head\b|grep\s+-q)", text):
                line = text[: m.start()].count("\n") + 1
                offenders.append(f"{p.name}:{line}")
        self.assertEqual(offenders, [], f"SIGPIPE-fatal pipes (use sed -n '1p'): {offenders}")


if __name__ == "__main__":
    unittest.main()
