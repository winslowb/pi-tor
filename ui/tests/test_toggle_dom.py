"""Execute the shipped toggle script and assert what it posts.

The toggle shipped inverted once: `on = current === "on"` meant every click
re-ran the state the host was already in, so the page could never turn the
tether on and undo answered "no saved tether state". A source-string assertion
catches that exact typo; running the script catches the class, so this drives
the real TETHER_SCRIPT in node against a stub DOM.

Skips when node is unavailable (the Pi has no node, and that is fine — the app
is stdlib Python; this is a workstation-only guard).
"""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from helpers import REPO

PROBE = Path(__file__).resolve().parent / "js" / "toggle_probe.js"


def toggle_script():
    """The exact script the UI serves, taken from the app module."""
    import hostui.app as app
    return app.TETHER_SCRIPT


def posts_for(state, node):
    payload = json.dumps({"script": toggle_script(), "state": state})
    out = subprocess.run([node, str(PROBE)], input=payload, text=True,
                         capture_output=True, timeout=60)
    if out.returncode != 0:
        raise AssertionError(f"probe failed: {out.stderr[:400]}")
    return json.loads(out.stdout or "[]")


class TogglePostsTheOppositeTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node") or shutil.which("nodejs")
        if not cls.node:
            raise unittest.SkipTest("node not installed")

    def test_off_state_posts_on_true(self):
        posts = posts_for("off", self.node)
        self.assertEqual(len(posts), 1, posts)
        self.assertIs(posts[0].get("on"), True, "clicking while off must ENABLE")

    def test_on_state_posts_on_false(self):
        posts = posts_for("on", self.node)
        self.assertEqual(len(posts), 1, posts)
        self.assertIs(posts[0].get("on"), False, "clicking while on must DISABLE")

    def test_unknown_state_posts_on_true(self):
        # "reverted"/"unknown" are not "on", so the button offers to enable
        posts = posts_for("reverted", self.node)
        self.assertEqual(len(posts), 1, posts)
        self.assertIs(posts[0].get("on"), True)


if __name__ == "__main__":
    unittest.main()
