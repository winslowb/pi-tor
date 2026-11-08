"""The dead-man revert: exactly one undo per tether session, only after the
window of consecutive probe failures — driven with a fake clock and fake
probe, so no sleeps and no network."""
import unittest

from hostui_helpers import FakeClock, make_app


class DeadManTest(unittest.TestCase):

    def setUp(self):
        import tempfile
        import shutil
        from pathlib import Path
        self.tmp = Path(tempfile.mkdtemp(prefix="pi-tor-deadman-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        app, cfg = make_app(self.tmp, dry_run=False)  # dead-man works for real,
        # but its undo is the stub below — nothing external is executed
        self.app = app
        self.cfg = cfg
        self.clock = FakeClock()
        app.deadman.clock = self.clock
        self.undo_calls = []

        def _stub_undo():
            self.undo_calls.append(1)
            return {"ok": True, "argv": ["stub-undo"],
                    "stdout": "", "stderr": ""}

        app.deadman.undo = _stub_undo

    def arm(self):
        # the way run_tether leaves state after a successful POST {"on": true}
        self.app.state.update(tether="on", reverts_used=0, revert_reason=None,
                              since="test", last_error=None)
        self.app.save()
        self.app.deadman.reset()
        # probe every 6th of the revert window (like 15 s with the 90 s default)
        self.step = self.cfg.revert_after / 6

    def tick(self):
        self.clock.advance(self.step)
        self.app.deadman.tick()

    def test_deadman_reverts_once_after_timeout(self):
        self.app.deadman.probe = lambda: False
        self.arm()
        # 6 ticks: the failure window is running but the 90 s are not used up
        for _ in range(6):
            self.tick()
        self.assertEqual(self.undo_calls, [],
                         f"{self.cfg.revert_after}s not yet reached")
        self.assertEqual(self.app.state["tether"], "on")
        # 7th tick: 90 s of consecutive failures elapsed -> exactly one revert
        self.tick()
        self.assertEqual(len(self.undo_calls), 1)
        state = self.app.state
        self.assertEqual(state["tether"], "reverted")
        self.assertEqual(state["reverts_used"], 1)
        self.assertIn("90s", state["revert_reason"])
        self.assertIn("consecutive probes", state["revert_reason"])
        self.assertTrue(any(e["event"] == "revert" for e in self.app.history))
        # a flapping link afterwards must not cause a second undo
        for _ in range(5):
            self.tick()
        self.assertEqual(len(self.undo_calls), 1)
        # neither does the Pi coming back: probing stopped after revert
        self.app.deadman.probe = lambda: True
        self.tick()
        self.assertEqual(len(self.undo_calls), 1)
        self.assertIsNone(self.app.deadman.pi_up)
        # and a restarted process would not retry either (persisted)
        reloaded_state = self.app._load_state()
        self.assertEqual(reloaded_state["reverts_used"], 1)
        self.assertNotEqual(reloaded_state["tether"], "on")

    def test_deadman_does_not_revert_while_pi_answers(self):
        self.app.deadman.probe = lambda: True
        self.arm()
        for _ in range(10):
            self.tick()
        self.assertEqual(self.undo_calls, [])
        self.assertEqual(self.app.state["tether"], "on")
        self.assertEqual(self.app.state["revert_reason"], None)
        self.assertTrue(self.app.deadman.armed())
        self.assertTrue(self.app.deadman.pi_up)

        # flap: five failures (75 s < 90 s) then recovery resets the window
        self.app.deadman.probe = lambda: False
        for _ in range(5):
            self.tick()
        self.assertEqual(self.undo_calls, [])
        self.app.deadman.probe = lambda: True
        self.tick()
        self.assertIsNone(self.app.deadman.first_failure)
        # a second failure run starts the window from zero again
        self.app.deadman.probe = lambda: False
        for _ in range(5):
            self.tick()
        self.assertEqual(self.undo_calls, [],
                         "window must restart after recovery")
        self.assertEqual(self.app.state["tether"], "on")


if __name__ == "__main__":
    unittest.main()
