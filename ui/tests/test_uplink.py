"""Uplink interface: render, submission checks, and the read-only panel.

Host-dependent behavior uses synthetic `ip -j` JSON (and, for the HTTP
paths, `lo` which every Linux host has), so the suite does not depend on
any particular machine's interfaces.
"""
import shutil
import unittest

from helpers import REPO, make_config_tree
from test_http import HttpTestBase

import config_schema as schema
import dockerops
import render
import uplink


class UplinkSchemaRenderTest(unittest.TestCase):

    def test_uplink_rendered_into_systemd_env(self):
        rendered = render.render(schema.defaults())
        text = rendered["systemd/pi-tor.env.example"].decode()
        self.assertIn("PI_TOR_UPLINK=wlan0", text)
        self.assertIn("PI_TOR_PROTECTED_HOSTS=10.12.194.1", text)
        # the committed render target must be regenerated to match
        self.assertEqual(rendered["systemd/pi-tor.env.example"],
                         (REPO / "systemd" / "pi-tor.env.example").read_bytes())

    def test_uplink_roundtrip(self):
        cfg = dict(schema.defaults())
        cfg["uplink_interface"] = "eth5"
        self.assertEqual(schema.validate(cfg), [])
        rendered = render.render(cfg)
        self.assertIn("PI_TOR_UPLINK=eth5",
                      rendered["systemd/pi-tor.env.example"].decode())
        tree = make_config_tree()
        try:
            import apply as apply_mod
            apply_mod._write_all(tree, rendered)
            parsed = render.read_current(tree)["values"]
            self.assertEqual(parsed["uplink_interface"], "eth5")
            self.assertEqual(parsed["protected_hosts"], "10.12.194.1")
        finally:
            shutil.rmtree(tree, ignore_errors=True)


class UplinkSubmissionTest(unittest.TestCase):

    def test_uplink_missing_interface_is_error(self):
        cfg = dict(schema.defaults())
        cfg["uplink_interface"] = "nosuchif0"
        errors, warnings = uplink.submission(cfg, dict(schema.defaults()))
        self.assertEqual(warnings, [])
        self.assertEqual([e["key"] for e in errors], ["uplink_interface"])
        self.assertIn("does not exist", errors[0]["message"])

    def test_uplink_unchanged_value_skips_host_check(self):
        # wlan0 may not exist on the test host, but an unchanged config
        # must never block the write
        cfg = dict(schema.defaults())
        errors, warnings = uplink.submission(cfg, dict(schema.defaults()))
        self.assertEqual((errors, warnings), ([], []))

    def test_uplink_without_lease_is_warning_not_error(self):
        cfg = dict(schema.defaults())
        cfg["uplink_interface"] = "wlan0"
        no_lease = {"name": "wlan0", "operstate": "up", "ipv4": [],
                    "default_route": False}
        errors, warnings = uplink.submission(cfg, dict(schema.defaults()),
                                             row=no_lease)
        self.assertEqual(errors, [])
        self.assertEqual([w["key"] for w in warnings], ["uplink_interface"])
        self.assertTrue(any("has no IPv4 lease" in w["message"]
                            for w in warnings))
        # the lease fault is a warning, not an error: schema-only
        # validation must stay clean so the write is not blocked
        self.assertEqual(schema.validate(cfg), [])

    def test_uplink_no_default_route_is_warning_not_error(self):
        cfg = dict(schema.defaults())
        cfg["uplink_interface"] = "wlan0"
        leased = {"name": "wlan0", "operstate": "up",
                  "ipv4": ["192.168.7.9/24"], "default_route": False}
        errors, warnings = uplink.submission(cfg, dict(schema.defaults()),
                                             row=leased)
        self.assertEqual(errors, [])
        self.assertTrue(any("carries no default route" in w["message"]
                            for w in warnings))
        healthy = dict(leased, default_route=True)
        errors, warnings = uplink.submission(cfg, dict(schema.defaults()),
                                             row=healthy)
        self.assertEqual((errors, warnings), ([], []))


class UplinkPanelTest(unittest.TestCase):

    ADDR = [
        {"ifname": "lo", "operstate": "UNKNOWN",
         "addr_info": [{"family": "inet", "local": "127.0.0.1",
                        "prefixlen": 8}]},
        {"ifname": "wlan0", "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "192.168.1.50",
                        "prefixlen": 24}]},
        {"ifname": "eth9", "operstate": "DOWN", "addr_info": []},
    ]

    def test_uplink_panel_reports_lease_state(self):
        sys_only_lo = ["lo"]
        # green: IPv4 lease + default route
        p = uplink.panel("wlan0", addr=self.ADDR,
                         route=[{"dst": "default", "dev": "wlan0"}],
                         link="TestWiFi", sys_names=sys_only_lo)
        self.assertEqual(p["lease"], "ok")
        self.assertIn("tor can bootstrap", p["message"])
        self.assertEqual(p["ssid"], "TestWiFi")
        self.assertEqual(p["ipv4"], ["192.168.1.50/24"])
        names = [r["name"] for r in p["interfaces"]]
        self.assertNotIn("lo", names, "loopback must not appear in the panel")
        self.assertIn("eth9", names)  # no address, but a real row
        # amber: interface present, no IPv4 lease
        p2 = uplink.panel("eth9", addr=self.ADDR,
                          route=[{"dst": "default", "dev": "wlan0"}],
                          link=None, sys_names=sys_only_lo)
        self.assertEqual(p2["lease"], "no_ipv4")
        self.assertIn("no IPv4 lease", p2["message"])
        self.assertIn("tor cannot bootstrap", p2["message"])
        # amber: lease but no default route
        p3 = uplink.panel("wlan0", addr=self.ADDR,
                          route=[{"dst": "10.0.0.0/24", "dev": "wlan0"}],
                          link=None, sys_names=sys_only_lo)
        self.assertEqual(p3["lease"], "no_route")
        self.assertIn("no default route", p3["message"])
        # red: interface absent
        p4 = uplink.panel("nosuchif0", addr=self.ADDR, route=[], link=None,
                          sys_names=sys_only_lo)
        self.assertEqual(p4["lease"], "absent")
        self.assertIn("does not exist", p4["message"])


class UplinkHttpTest(HttpTestBase):

    def test_preview_bogus_uplink_is_field_error(self):
        code, _, body = self.client.json("POST", "/api/preview", body={
            "values": {"uplink_interface": "nosuchif0"}})
        self.assertEqual(code, 400)
        self.assertIn("uplink_interface", [e["key"] for e in body["errors"]])
        self.assertTrue(any("does not exist" in e["message"]
                            for e in body["errors"]))
        self.assertEqual(body["diffs"], {})

    def test_preview_real_interface_without_lease_warns_200(self):
        # `lo` exists on every Linux host and never carries the default route
        code, _, body = self.client.json("POST", "/api/preview", body={
            "values": {"uplink_interface": "lo"}})
        self.assertEqual(code, 200, body)
        self.assertEqual(body["errors"], [])
        self.assertEqual([w["key"] for w in body["warnings"]],
                         ["uplink_interface"])
        self.assertTrue(body["warnings"])
        # still renders the diff: a lease warning does not block the write
        self.assertIn("systemd/pi-tor.env.example", body["diffs"])


class UplinkApplyHttpTest(HttpTestBase):
    # own class = own tree: apply writes files, which would make a later
    # preview in the same tree see uplink_interface already applied

    def test_apply_echoes_uplink_warnings(self):
        code, _, report = self.client.json("POST", "/api/apply", body={
            "confirm": True, "values": {"uplink_interface": "lo"}})
        self.assertEqual(code, 200, report)
        self.assertEqual([w["key"] for w in report.get("warnings", [])],
                         ["uplink_interface"])


if __name__ == "__main__":
    unittest.main()
