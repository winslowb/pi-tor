"""The two hostui tabs: the Tether tab (default /) with toggle, worded
status rows and the bounded event log, and the Config tab (/config) with
validated persistence, live-applied saves, and the dry-run guarantee across
both tabs. Live-script tests use local stubs exactly like test_hostui.py;
the real usb_route / usb_route_undo are never executed."""
import json
import os
import unittest
from unittest import mock

from hostui_helpers import (BootedTest, FakeClock, hostui_app, req, req_raw)

SIX_FIELDS = ("pi_addr", "host_addr", "pi_ui_port", "probe_interval",
              "revert_after", "listen_port")


def full_form(**over):
    values = {"pi_addr": "10.12.194.1", "host_addr": "10.12.194.2",
              "pi_ui_port": "8080", "probe_interval": "15",
              "revert_after": "90", "listen_port": "8090"}
    values.update(over)
    return values


class TetherTabTest(BootedTest):

    def test_tether_tab_is_default_and_shows_toggle(self):
        app, srv, port, cfg = self.boot(config_file=self.tmp / "cfg.json")
        code, page = req_raw(port, "GET", "/")
        self.assertEqual(code, 200)
        # the toggle is the one control, the tabs point at each other...
        self.assertIn('id="toggle"', page)
        self.assertIn('<a class="tab active" href="/">tether</a>', page)
        self.assertIn('class="tab" href="/config"', page)
        # ...and the expected-icmp footnote is on the page, not a red row
        self.assertIn("ICMP does not work while tethered", page)
        # the config fields do NOT leak onto the default tab
        self.assertNotIn('id="f_pi_addr"', page)
        # / serves the tether tab, /config the config tab (same server)
        code, cfg_page = req_raw(port, "GET", "/config")
        self.assertEqual(code, 200)
        self.assertIn('<a class="tab active" href="/config">config</a>', cfg_page)
        for field in SIX_FIELDS:
            self.assertIn(f'id="f_{field}"', cfg_page)
        self.assertNotIn('id="toggle"', cfg_page)

    def test_status_rows_carry_words_not_only_colour(self):
        app, srv, port, cfg = self.boot(
            config_file=self.tmp / "cfg.json")
        # deterministic sandbox: no tether iface, DNS fails with a reason
        with mock.patch.object(hostui_app, "iface_with_addr",
                               return_value=None), \
             mock.patch.object(hostui_app, "dns_probe",
                               return_value=(False, "timed out")):
            # arm a session and let the dead-man see the Pi going down
            app.state.update(tether="on", reverts_used=0, revert_reason=None,
                             since="t", last_error=None)
            app.save()
            app.session_started_here = True
            app.deadman.pi_up = False
            app.deadman.fail_count = 3
            app.deadman.first_failure = app.deadman.clock() - 30
            code, st = req(port, "GET", "/api/status")
        self.assertEqual(code, 200)
        rows = st["rows"]
        self.assertEqual([r["label"] for r in rows],
                         ["gadget link", "pi reachable", "tether active",
                          "dns through pi", "tor exit", "dead-man"])
        for r in rows:
            self.assertIsInstance(r["word"], str) and self.assertTrue(r["word"])
            self.assertIn(r["cls"], ("ok", "bad", "warn", "idle"))
            self.assertNotEqual(r["word"], r["cls"],
                                "a colour class must never BE the word")
        # every red row says why in words; the words differ per state
        for r in rows:
            if r["cls"] == "bad":
                self.assertTrue(r["why"], f"{r['label']} is red without a why")
        pi = rows[1]
        self.assertEqual(pi["cls"], "bad")
        self.assertEqual(pi["word"], "not answering")
        self.assertIn("3 probe", pi["why"])
        dm = rows[5]
        self.assertEqual(dm["cls"], "warn")
        self.assertIn("armed", dm["word"])
        self.assertIn("60s", dm["word"])   # 90s window, 30s burned
        self.assertIn("consecutive", dm["why"])

    def test_log_endpoint_is_bounded_and_newest_first(self):
        app, srv, port, cfg = self.boot(
            config_file=self.tmp / "cfg.json")
        for i in range(600):
            app.log_event(f"ev{i}", f"detail {i}")
        code, body = req(port, "GET", "/api/log")
        self.assertEqual(code, 200)
        events = body["events"]
        # the UI sees a bounded tail, newest first
        self.assertEqual(len(events), 200)
        self.assertEqual([e["detail"] for e in events[:3]],
                         ["detail 599", "detail 598", "detail 597"])
        self.assertEqual(events[0]["event"], "ev599")
        for e in events:
            self.assertIn("t", e)   # timestamped
        # ...and the append-only file behind it is bounded too (500 lines)
        lines = app.log_file.read_text().splitlines()
        self.assertLessEqual(len(lines), 500)
        self.assertEqual(json.loads(lines[-1])["detail"], "detail 599")

    def test_log_shows_toggle_and_revert_events(self):
        sudo = self.tmp / "sudo-pass"
        sudo.write_text('#!/bin/sh\nexec "$2"\n')
        os.chmod(sudo, 0o755)
        route_on = self.tmp / "usb_route"
        route_on.write_text("#!/bin/sh\necho tethered\n")
        os.chmod(route_on, 0o755)
        route_off = self.tmp / "usb_route_undo"
        route_off.write_text("#!/bin/sh\necho restored\n")
        os.chmod(route_off, 0o755)
        app, srv, port, cfg = self.boot(
            dry_run=False, sudo=str(sudo), route_on=route_on,
            route_off=route_off)
        token = self.token_of(port)
        # a refused toggle is logged with why
        code, _ = req(port, "POST", "/api/tether", body={"on": True})
        self.assertEqual(code, 403)
        # the real toggle on...
        code, body = req(port, "POST", "/api/tether", body={"on": True},
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"], body)
        # ...then a simulated dead-man revert driven by a fake clock
        clock = FakeClock()
        app.deadman.clock = clock
        app.deadman.probe = lambda: False
        for _ in range(7):     # 7 * 15s = window of revert_after=90 elapses
            clock.advance(cfg.revert_after / 6)
            app.deadman.tick()
        self.assertEqual(app.state["reverts_used"], 1)
        code, body = req(port, "GET", "/api/log")
        events = body["events"]
        names = [e["event"] for e in events]
        self.assertIn("refused", names)
        self.assertIn("tether-on", names)
        self.assertIn("tether-off", names)
        self.assertIn("revert", names)
        # newest first: auto-undo > revert > window start > toggle > refusal
        idx = lambda n: names.index(n)  # noqa: E731
        self.assertLess(idx("tether-off"), idx("revert"))
        self.assertLess(idx("revert"), idx("tether-on"))
        self.assertLess(idx("tether-on"), idx("refused"))
        revert = next(e for e in events if e["event"] == "revert")
        self.assertIn("consecutive probes", revert["detail"])
        self.assertIn("across 7", revert["detail"])   # the failure count
        window = next(e for e in events if e["event"] == "dead-man")
        self.assertIn("failure window started", window["detail"])


class ConfigTabTest(BootedTest):

    def setUp(self):
        super().setUp()
        self.cpath = self.tmp / "cfg" / "config.json"

    def test_config_tab_rejects_invalid_ipv4(self):
        app, srv, port, cfg = self.boot(config_file=self.cpath)
        code, page = req_raw(port, "GET", "/config")
        self.assertEqual(code, 200)
        token = self.token_of(port)
        # an invalid form saves nothing ...
        code, body = req(port, "POST", "/api/config",
                         body=full_form(pi_addr="10.0.0.256"),
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 400)
        self.assertIn("IPv4", body["errors"]["pi_addr"])
        self.assertFalse(self.cpath.exists(), "a rejected save wrote a file")
        # ... neither for a missing field nor a nonsense interval
        bad = full_form()
        del bad["revert_after"]
        code, body = req(port, "POST", "/api/config", body=bad,
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 400)
        self.assertIn("10-3600", body["errors"]["revert_after"])
        code, _ = req(port, "POST", "/api/config",
                      body=full_form(probe_interval="-5"),
                      headers={"X-PiTor-Token": token})
        self.assertEqual(code, 400)
        self.assertFalse(self.cpath.exists())
        # and the live config never picked the bad values up
        self.assertEqual(app.cfg.pi_addr, "10.12.194.1")

    def test_config_save_applies_probe_interval_without_restart(self):
        app, srv, port, cfg = self.boot(config_file=self.cpath)
        token = self.token_of(port)
        code, body = req(port, "POST", "/api/config",
                         body=full_form(probe_interval="1.5",
                                        listen_port="8091"),
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["ok"])
        # the running process picked the new interval up, no restart: the
        # loop sleeps cfg.probe_interval each cycle (deadman_loop) and the
        # attr + the event log both show the change
        self.assertEqual(app.cfg.probe_interval, 1.5)
        self.assertIn("probe_interval 0.05 → 1.5", body["changes"])
        code, st = req(port, "GET", "/api/status")
        self.assertEqual(st["probe_interval"], 1.5)
        # the persisted file is what a restart would load
        saved = json.loads(self.cpath.read_text())
        self.assertEqual(saved["probe_interval"], 1.5)
        self.assertEqual(saved["listen_port"], 8091)
        events = req(port, "GET", "/api/log")[1]["events"]
        cfg_ev = next(e for e in events if e["event"] == "config")
        self.assertIn("probe_interval 0.05 → 1.5", cfg_ev["detail"])
        self.assertIn("listen_port applies on restart", cfg_ev["detail"])
        # the server is still serving on the original (ephemeral) port
        self.assertEqual(req(port, "GET", "/api/log")[0], 200)

    def test_config_save_keeps_armed_deadman_armed(self):
        app, srv, port, cfg = self.boot(config_file=self.cpath)
        # the way a successful POST {"on": true} leaves the session
        app.state.update(tether="on", reverts_used=0, revert_reason=None,
                         since="t", last_error=None)
        app.save()
        app.deadman.reset()
        self.assertTrue(app.deadman.armed())
        token = self.token_of(port)
        code, body = req(port, "POST", "/api/config",
                         body=full_form(pi_addr="10.12.194.9"),
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 200, body)
        # saving config changed only config: the armed session survives
        self.assertTrue(app.deadman.armed())
        self.assertEqual(app.state["tether"], "on")
        self.assertEqual(app.cfg.pi_addr, "10.12.194.9")
        st = req(port, "GET", "/api/status")[1]
        self.assertTrue(st["deadman_armed"])

    def test_dry_run_still_executes_nothing_on_either_tab(self):
        app, srv, port, cfg = self.boot(
            dry_run=True, config_file=self.tmp / "cfg.json")

        def _bomb(*args, **kwargs):
            raise AssertionError(f"subprocess during dry run: {args!r}")

        with mock.patch.object(hostui_app.subprocess, "run", new=_bomb):
            code, page = req_raw(port, "GET", "/")
            self.assertEqual(code, 200)
            self.assertIn("DRY RUN", page)
            # the config tab renders and says diagnostics are skipped
            code, cfg_page = req_raw(port, "GET", "/config")
            self.assertEqual(code, 200)
            self.assertIn("diagnostics are skipped", cfg_page)
            self.assertEqual(req(port, "GET", "/api/status")[0], 200)
            self.assertEqual(req(port, "GET", "/api/log")[0], 200)
            token = self.token_of(port)
            code, body = req(port, "POST", "/api/tether", body={"on": True},
                             headers={"X-PiTor-Token": token})
            self.assertEqual(code, 200)
            self.assertTrue(body["dry_run"])
            self.assertIn("nothing executed", body["message"])
            # a config save on either tab is not a tether mutation: it may
            # persist, but never executes anything
            code, body = req(port, "POST", "/api/config",
                             body=full_form(revert_after="45"),
                             headers={"X-PiTor-Token": token})
            self.assertEqual(code, 200, body)
            self.assertEqual(req_raw(port, "GET", "/")[0], 200)

    def test_mutations_refuse_cross_origin_posts(self):
        app, srv, port, cfg = self.boot(
            dry_run=True, config_file=self.tmp / "cfg.json")
        token = self.token_of(port)
        code, body = req(port, "POST", "/api/tether", body={"on": True},
                         headers={"X-PiTor-Token": token,
                                  "Origin": "http://evil.example"})
        self.assertEqual(code, 403)
        self.assertIn("cross-origin", body["error"])
        names = [e["event"] for e in
                 req(port, "GET", "/api/log")[1]["events"]]
        self.assertIn("refused", names)
        # same-origin passes for both mutations (dry run: 200 with notes)
        origin = f"http://127.0.0.1:{port}"
        code, body = req(port, "POST", "/api/tether", body={"on": True},
                         headers={"X-PiTor-Token": token, "Origin": origin})
        self.assertEqual(code, 200)
        code, body = req(port, "POST", "/api/config", body=full_form(),
                         headers={"X-PiTor-Token": token, "Origin": origin})
        self.assertEqual(code, 200)


if __name__ == "__main__":
    unittest.main()
