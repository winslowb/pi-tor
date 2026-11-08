"""bin/usb_route{,_undo}: plans computed from synthetic interface snapshots.

Every run gets a stub PATH -- `ip`, `resolvectl` and `sudo` script stubs backed
by per-case fixture files, plus PI_TOR_NET_DIR/PI_TOR_STATE_DIR pointed into a
tmp dir (same convention as test_uplink_check.py). Dry-run is the only mode:
the scripts print the exact argv they would run, and the stubs log every call
so tests can assert that nothing stateful happens.
"""
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import REPO

ROUTE = REPO / "bin" / "usb_route"
UNDO = REPO / "bin" / "usb_route_undo"

IP_STUB = r"""#!/bin/bash
printf '%s\n' "$*" >> "$TETHER_FIXTURE/calls.log"
case "$*" in
  *"-4 route show default") cat "$TETHER_FIXTURE/ip_default_route.txt" 2>/dev/null ;;
  *"-o -4 addr show"*)      cat "$TETHER_FIXTURE/addr_${@: -1}.txt" 2>/dev/null ;;
esac
exit 0
"""

RESOLVED_STUB = r"""#!/bin/bash
printf '%s\n' "$*" >> "$TETHER_FIXTURE/calls.log"
[ $# -ge 2 ] && cat "$TETHER_FIXTURE/rc_${1}_${2}.txt" 2>/dev/null
exit 0
"""

SUDO_STUB = r"""#!/bin/bash
printf 'sudo %s\n' "$*" >> "$TETHER_FIXTURE/calls.log"
exec "$@"
"""

# Any logged call containing one of these mutates the system.
MUTATIONS = (
    "route add", "route del", "route replace", "addr flush", "addr add",
    "link set", "flush-caches", "sudo ",
)


class Case:
    """One synthetic host: stub bin dir, fixture files, fake /sys/class/net."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="tether-test-"))
        self.bin_dir = self.root / "stubbin"
        self.net_dir = self.root / "net"
        self.state_dir = self.root / "state"
        self.fixtures = self.root / "fixtures"
        self.bin_dir.mkdir()
        self.net_dir.mkdir()
        self.state_dir.mkdir()
        self.fixtures.mkdir()
        for name, text in [
            ("ip", IP_STUB),
            ("resolvectl", RESOLVED_STUB),
            ("sudo", SUDO_STUB),
        ]:
            p = self.bin_dir / name
            p.write_text(text)
            p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    def add_link(self, name, wifi=False):
        link = self.net_dir / name
        link.mkdir()
        if wifi:
            (link / "wireless").mkdir()

    def set_default_route(self, line):
        (self.fixtures / "ip_default_route.txt").write_text(line + "\n")

    def set_dns(self, link, servers):
        fixture = f"Link 2 ({link}): {servers}\n"
        (self.fixtures / f"rc_dns_{link}.txt").write_text(fixture)

    def set_domain(self, link, domain):
        fixture = f"Link 2 ({link}): {domain}\n"
        (self.fixtures / f"rc_domain_{link}.txt").write_text(fixture)

    def write_state(self, **fields):
        body = "".join(f"{k}='{v}'\n" for k, v in fields.items())
        (self.state_dir / "tether.conf").write_text(body)

    def run(self, script, *args):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin_dir}:{env['PATH']}"
        env["PI_TOR_NET_DIR"] = str(self.net_dir)
        env["PI_TOR_STATE_DIR"] = str(self.state_dir)
        env["TETHER_FIXTURE"] = str(self.fixtures)
        return subprocess.run(
            ["bash", str(script), *args],
            capture_output=True, text=True, env=env, timeout=30,
        )

    def calls(self):
        log = self.fixtures / "calls.log"
        return log.read_text().splitlines() if log.exists() else []


class TetherPlanTest(unittest.TestCase):
    def assert_no_mutation(self, case):
        for line in case.calls():
            for mutation in MUTATIONS:
                self.assertNotIn(mutation, line, f"mutating call recorded: {line}")

    def test_plan_wired_primary(self):
        """Wired primary: gadget + gateway + DNS detected from the route and
        restore values come from detection, not constants; nothing executes."""
        case = Case()
        case.add_link("enp3s0")
        case.add_link("enxe4f15a9c2b01")
        case.set_default_route(
            "default via 192.168.5.1 dev enp3s0 proto dhcp src 192.168.5.42 metric 100")
        case.set_dns("enp3s0", "192.168.5.53 192.168.5.54")
        case.set_domain("enp3s0", "corp.example.")
        res = case.run(ROUTE, "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("gadget=enxe4f15a9c2b01", res.stdout)
        self.assertIn("primary=enp3s0", res.stdout)
        self.assertIn("primary_gw=192.168.5.1", res.stdout)
        self.assertIn("primary_dns=192.168.5.53 192.168.5.54", res.stdout)
        self.assertIn("primary_domain=corp.example.", res.stdout)
        # the plan is the gadget, metric 5, with the Pi as resolver
        self.assertIn("route replace default via 10.12.194.1 dev enxe4f15a9c2b01 metric 5",
                      res.stdout)
        self.assertIn("resolvectl dns enxe4f15a9c2b01 10.12.194.1", res.stdout)
        self.assertIn("resolvectl domain enxe4f15a9c2b01 ~.", res.stdout)
        self.assertIn(" ip addr add 10.12.194.2/24 dev enxe4f15a9c2b01", res.stdout)
        self.assertNotIn("down", res.stdout)  # the primary link is never disabled
        self.assertFalse((case.state_dir / "tether.conf").exists())
        self.assert_no_mutation(case)

    def test_plan_wifi_primary(self):
        """Wi-Fi primary: link stays up; tether wins by metric, never downing."""
        case = Case()
        case.add_link("wlan0", wifi=True)
        case.add_link("usb5a3b2")
        case.set_default_route(
            "default via 192.168.7.1 dev wlan0 proto dhcp src 192.168.7.42 metric 600")
        case.set_dns("wlan0", "192.168.7.1")
        case.set_domain("wlan0", "7.pool.lan")
        res = case.run(ROUTE, "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("primary=wlan0", res.stdout)
        self.assertIn("wlan0 is Wi-Fi: the link stays up", res.stdout)
        self.assertIn("route replace default via 10.12.194.1 dev usb5a3b2 metric 5",
                      res.stdout)
        self.assertNotIn("down", res.stdout)
        self.assertNotIn("wlp3s0", res.stdout)  # no hardcoded interface names
        self.assert_no_mutation(case)

    def test_plan_metric_lowered_when_primary_beats_five(self):
        case = Case()
        case.add_link("eth0")
        case.add_link("usb5a3b2")
        case.set_default_route("default via 192.168.9.1 dev eth0 metric 3")
        case.set_dns("eth0", "192.168.9.1")
        case.set_domain("eth0", "lan")
        res = case.run(ROUTE, "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("route replace default via 10.12.194.1 dev usb5a3b2 metric 2",
                      res.stdout)

    def test_refuses_when_already_tethered(self):
        """The default already rides the gadget: refuse so a second run cannot
        overwrite the saved state the undo needs."""
        case = Case()
        case.add_link("enp3s0")
        case.add_link("usb5a3b2")
        case.set_default_route(
            "default via 10.12.194.1 dev usb5a3b2 metric 5")
        res = case.run(ROUTE, "--dry-run")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("already tethered", res.stderr)
        self.assertIn("usb_route_undo", res.stderr)
        self.assertFalse((case.state_dir / "tether.conf").exists())
        self.assert_no_mutation(case)

    def test_undo_refuses_without_saved_state(self):
        case = Case()
        case.add_link("enp3s0")
        res = case.run(UNDO, "--dry-run")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("no saved tether state", res.stderr)
        self.assertIn(str(case.state_dir / "tether.conf"), res.stderr)
        self.assertEqual(case.calls(), [])  # refused before touching anything

    def test_undo_restores_saved_values(self):
        """The undo plan replays exactly what was saved, never a guessed
        router like 192.168.0.1, and clears only the gadget it recorded."""
        case = Case()
        case.add_link("eth9")
        case.add_link("usb3")
        case.set_default_route("default via 10.12.194.1 dev usb3 metric 5")
        case.write_state(
            PRIMARY="eth9", PRIMARY_GW="192.168.99.254", PRIMARY_PROTO="dhcp",
            PRIMARY_METRIC="200", PRIMARY_DNS="9.9.9.9 149.112.112.149",
            PRIMARY_DOMAIN="example.org", GADGET="usb3", GADGET_PRE_ADDR="",
            GADGET_WAS_UP="0")
        res = case.run(UNDO, "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("route del default dev usb3", res.stdout)
        self.assertIn(
            "route replace default via 192.168.99.254 dev eth9 proto dhcp metric 200",
            res.stdout)
        self.assertIn("resolvectl dns eth9 9.9.9.9 149.112.112.149", res.stdout)
        self.assertIn("resolvectl domain eth9 example.org", res.stdout)
        # gadget state recorded by usb_route is exactly what gets cleared
        self.assertIn("resolvectl dns usb3\n", res.stdout)
        self.assertIn("resolvectl domain usb3\n", res.stdout)
        self.assertIn("addr flush dev usb3", res.stdout)
        self.assertIn("link set usb3 down", res.stdout)  # GADGET_WAS_UP=0
        self.assertIn("resolvectl flush-caches", res.stdout)
        self.assertNotIn("192.168.0.1", res.stdout)
        self.assertTrue((case.state_dir / "tether.conf").exists())  # dry-run keeps it
        self.assert_no_mutation(case)

    def test_undo_omits_empty_saved_fields(self):
        """A primary without proto/metric restores those absences exactly."""
        case = Case()
        case.add_link("eth9")
        case.add_link("usb3")
        case.set_default_route("default via 10.12.194.1 dev usb3 metric 5")
        case.write_state(
            PRIMARY="eth9", PRIMARY_GW="192.168.99.254", PRIMARY_DNS="9.9.9.9",
            GADGET="usb3", GADGET_WAS_UP="1")
        res = case.run(UNDO, "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(
            "route replace default via 192.168.99.254 dev eth9\n",
            res.stdout)  # no proto, no metric
        self.assertNotIn("metric", res.stdout)
        self.assertNotIn("link set usb3 down", res.stdout)  # it was up before

    def test_undo_with_gone_gadget_still_restores(self):
        """The Pi was unplugged: gadget cleanup is skipped, restore survives."""
        case = Case()
        case.add_link("eth9")
        case.set_default_route("default via 192.168.99.254 dev eth9 metric 200")
        case.write_state(
            PRIMARY="eth9", PRIMARY_GW="192.168.99.254", PRIMARY_METRIC="200",
            PRIMARY_DNS="9.9.9.9", GADGET="usb3", GADGET_WAS_UP="0")
        res = case.run(UNDO, "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("gadget interface usb3 is gone", res.stdout)
        self.assertIn(
            "route replace default via 192.168.99.254 dev eth9 metric 200",
            res.stdout)
        self.assertIn("resolvectl dns eth9 9.9.9.9", res.stdout)
        self.assertNotIn("link set", res.stdout)
        self.assert_no_mutation(case)


if __name__ == "__main__":
    unittest.main()
