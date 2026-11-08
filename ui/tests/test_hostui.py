"""hostui HTTP surface: the CSRF gate, the loopback bind guard, the dry-run
no-execution guarantee, and what the toggle says when sudo is not configured.
Live calls here always hit local stub scripts — the real usb_route /
usb_route_undo are never executed (the one-time live pass is Karl's)."""
import os
import re
import unittest
from unittest import mock

from hostui_helpers import BootedTest, hostui_app, make_cfg, req, req_raw


class HostUiHttpTest(BootedTest):

    def test_hostui_requires_csrf_token(self):
        app, srv, port, cfg = self.boot()
        self.token_of(port)  # the page issues the token on its own
        # no header at all
        code, body = req(port, "POST", "/api/tether", body={"on": True})
        self.assertEqual(code, 403)
        self.assertIn("X-PiTor-Token", body["error"])
        # wrong header (a cross-origin page may set one; it must not match)
        code, _ = req(port, "POST", "/api/tether", body={"on": True},
                      headers={"X-PiTor-Token": "f" * 32})
        self.assertEqual(code, 403)
        state = req(port, "GET", "/api/status")[1]
        self.assertEqual(state["tether"], "off",
                         "a rejected POST must change nothing")
        # correct header works (dry run: reports what it would run)
        code, body = req(port, "POST", "/api/tether", body={"on": True},
                         headers={"X-PiTor-Token": app.token})
        self.assertEqual(code, 200)
        self.assertTrue(body["dry_run"])
        self.assertEqual(body["argv"], [cfg.sudo, "-n", str(cfg.route_on)])
        # read-only routes need no token
        self.assertEqual(req(port, "GET", "/api/log")[0], 200)

    def test_hostui_dry_run_never_executes(self):
        app, srv, port, cfg = self.boot(dry_run=True)

        def _bomb(*args, **kwargs):
            raise AssertionError(f"subprocess during dry run: {args!r}")

        with mock.patch.object(hostui_app.subprocess, "run", new=_bomb):
            code, page = req_raw(port, "GET", "/")
            self.assertEqual(code, 200)
            self.assertIn("DRY RUN", page)
            code, st = req(port, "GET", "/api/status")
            self.assertEqual(code, 200)
            for field in ("tether", "default_route", "dns_servers",
                          "gadget_iface", "pi_answers", "deadman_armed",
                          "last_revert", "state_file"):
                self.assertIn(field, st)
            self.assertTrue(st["dry_run"])
            self.assertEqual(st["state_file"], str(cfg.state_file))
            token = self.token_of(port)
            for on in (True, False):
                code, body = req(port, "POST", "/api/tether", body={"on": on},
                                 headers={"X-PiTor-Token": token})
                self.assertEqual(code, 200)
                self.assertTrue(body["dry_run"])
                self.assertIn("nothing executed", body["message"])
                self.assertEqual(body["argv"][-1],
                                 str(cfg.route_on if on else cfg.route_off))

    def test_hostui_refuses_non_loopback_bind(self):
        # 0.0.0.0 refused with a reason naming the override
        refusal = hostui_app.bind_refusal(make_cfg(self.tmp, bind="0.0.0.0"))
        self.assertIn("not loopback", refusal)
        self.assertIn("PI_TOR_HOSTUI_ALLOW_ANY", refusal)
        # a name, not an address: also refused
        self.assertIn("not an IP literal",
                      hostui_app.bind_refusal(
                          make_cfg(self.tmp, bind="mini.lan")))
        # loopback binds are always fine, ::1 included
        self.assertIsNone(hostui_app.bind_refusal(
            make_cfg(self.tmp, bind="127.0.0.1")))
        self.assertIsNone(hostui_app.bind_refusal(
            make_cfg(self.tmp, bind="::1")))
        # and the escape hatch really is opt-in
        self.assertIsNone(hostui_app.bind_refusal(
            make_cfg(self.tmp, bind="0.0.0.0", allow_any=True)))

    def test_hostui_toggle_names_missing_sudo_rule(self):
        # a stub 'sudo' that fails the way passwordless-less sudo does
        sudo = self.tmp / "sudo-fail"
        sudo.write_text(
            "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
        os.chmod(sudo, 0o755)
        route_on = self.tmp / "usb_route"
        route_on.write_text("#!/bin/sh\necho 'MUST NOT EXECUTE' >&2\nexit 3\n")
        os.chmod(route_on, 0o755)
        app, srv, port, cfg = self.boot(
            dry_run=False, sudo=str(sudo), route_on=route_on)
        token = self.token_of(port)
        code, body = req(port, "POST", "/api/tether", body={"on": True},
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 200, body)  # the failure is a named result, not a 500
        self.assertFalse(body["ok"])
        self.assertTrue(body["missing_sudo_rule"])
        self.assertIn("/etc/sudoers.d/pi-tor-tether", body["error"])
        self.assertIn("was not changed", body["error"])
        # and the state stayed untethered
        st = req(port, "GET", "/api/status")[1]
        self.assertEqual(st["tether"], "off")

    def test_hostui_toggle_runs_fixed_argv_and_arms(self):
        sudo = self.tmp / "sudo-pass"
        sudo.write_text("#!/bin/sh\nexec \"$2\"\n")
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
        code, body = req(port, "POST", "/api/tether", body={"on": True},
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["ok"], body)
        # exactly the documented fixed argv, including the script path
        self.assertEqual(body["argv"], [str(sudo), "-n", str(route_on)])
        st = req(port, "GET", "/api/status")[1]
        self.assertEqual(st["tether"], "on")   # session armed
        self.assertTrue(st["deadman_armed"])
        # a second toggle turns it back off and ends the session
        code, body = req(port, "POST", "/api/tether", body={"on": False},
                         headers={"X-PiTor-Token": token})
        self.assertEqual(code, 200, body)
        self.assertEqual(body["argv"][-1], str(cfg.route_off))
        self.assertFalse(
            req(port, "GET", "/api/status")[1]["deadman_armed"])

    def test_default_route_decodes_gateway(self):
        fixture = self.tmp / "route"
        fixture.write_text(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\t"
            "Mask\tMTU\tWindow\tIRTT\n"
            "usb0\t00000000\t01C20C0A\t0003\t0\t0\t5\t00000000\t0\t0\t0\n"
            "eth0\t0A0C0A00\t00000000\t0003\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
        self.assertEqual(hostui_app.default_route(str(fixture)),
                         {"iface": "usb0", "gateway": "10.12.194.1"})
        self.assertEqual(
            hostui_app.default_route(str(self.tmp / "route-none")), None)


if __name__ == "__main__":
    unittest.main()
