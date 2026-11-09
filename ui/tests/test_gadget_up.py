"""bin/usb-gadget-up: configfs composition driven by a fixture tree.

The script runs under `sh` (dash) with a fixture configfs root, a fixture
`/sys/class/udc` holding one UDC, a fixture `/sys/class/net` and stub
`networkctl`/`modprobe` commands, so no gadget is really composed and no
module is loaded. The fixture is a plain filesystem, which cannot model
configfs dropping its own attribute files, so `down` is asserted on the
actions that matter (unbind, unlink the function, drop the networkd file)
rather than on the directory tree disappearing.
"""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import REPO

SCRIPT = REPO / "bin" / "usb-gadget-up"
UNIT = REPO / "systemd" / "pi-tor-gadget.service"
STACK = REPO / "systemd" / "pi-tor-stack.service"
DROPIN = (REPO / "systemd" / "pi-tor-gadget-watchdog.service.d"
          / "rzero-rebind.conf")
UDC = "ff400000.usb"

STUB = """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$GADGET_UP_TEST_CALLS"
exit 0
"""


class Case:
    def __init__(self, netdev: str | None = "usb0", udc: str | None = UDC):
        self.root = Path(tempfile.mkdtemp(prefix="gadget-up-test-"))
        self.gadgetfs = self.root / "configfs/usb_gadget"
        self.gadgetfs.mkdir(parents=True)
        self.udcdir = self.root / "udc"
        self.udcdir.mkdir()
        if udc:
            (self.udcdir / udc).mkdir()
        self.netdir = self.root / "net"
        self.netdir.mkdir()
        if netdev:
            (self.netdir / netdev).mkdir()
        self.networkd = self.root / "run-networkd"
        self.networkd.mkdir()
        stubbin = self.root / "stubbin"
        stubbin.mkdir()
        for name in ("networkctl", "modprobe"):
            p = stubbin / name
            p.write_text(STUB)
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
        self.calls_log = self.root / "calls.log"
        self.g = self.gadgetfs / "pi_tor"
        self.networkd_file = self.networkd / "10-pi-tor-usb0.network"

    def run(self, *args, **over):
        env = dict(os.environ)
        env["PATH"] = f"{self.root / 'stubbin'}:{env['PATH']}"
        env.update(
            PI_TOR_GADGETFS=str(self.gadgetfs),
            PI_TOR_UDC_DIR=str(self.udcdir),
            PI_TOR_NET_DIR=str(self.netdir),
            PI_TOR_NETWORKD_DIR=str(self.networkd),
            PI_TOR_MODPROBE=str(self.root / "stubbin" / "modprobe"),
            PI_TOR_GADGET_WAIT="1",
            GADGET_UP_TEST_CALLS=str(self.calls_log))
        env.update(over)
        return subprocess.run(["sh", str(SCRIPT), *args],
                              capture_output=True, text=True, env=env,
                              timeout=60)

    def calls(self):
        return (self.calls_log.read_text().splitlines()
                if self.calls_log.exists() else [])

    def attr(self, rel):
        return (self.g / rel).read_text()

    def functions(self):
        return sorted(p.name for p in (self.g / "functions").iterdir())


class GadgetUpTest(unittest.TestCase):

    def test_up_composes_ecm_only_and_binds_the_udc(self):
        case = Case()
        res = case.run("up")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(case.attr("idVendor"), "0x1d6b")
        self.assertEqual(case.attr("idProduct"), "0x0104")
        self.assertEqual(case.attr("UDC"), UDC)
        self.assertEqual(case.attr("functions/ecm.usb0/ifname"), "usb0")
        # ECM only: a gateway, never a payload device
        self.assertEqual(case.functions(), ["ecm.usb0"])
        linked = case.g / "configs/c.1/ecm.usb0"
        self.assertTrue(linked.is_symlink())
        self.assertEqual(os.readlink(linked), str(case.g / "functions/ecm.usb0"))
        self.assertEqual(case.attr("configs/c.1/MaxPower"), "250")
        self.assertIn("[usb-gadget] usb0 is up (udc %s)" % UDC, res.stdout)

    def test_up_is_idempotent(self):
        case = Case()
        self.assertEqual(case.run("up").returncode, 0)
        res = case.run("up")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("already bound to %s" % UDC, res.stdout)
        self.assertEqual(case.attr("UDC"), UDC)
        self.assertEqual(case.functions(), ["ecm.usb0"])

    def test_up_writes_the_runtime_networkd_address(self):
        case = Case()
        self.assertEqual(case.run("up").returncode, 0)
        self.assertEqual(case.networkd_file.read_text(),
                         "[Match]\nName=usb0\n\n"
                         "[Network]\nAddress=10.12.194.1/24\n"
                         "LinkLocalAddressing=no\nIPv6AcceptRA=no\n")
        self.assertIn("networkctl reload", case.calls())

    def test_interface_gateway_and_prefix_come_from_the_env(self):
        case = Case(netdev="usb9")
        res = case.run("up", PI_TOR_INTERFACE="usb9",
                       PI_TOR_GATEWAY="10.9.9.1", PI_TOR_SUBNET="10.9.9.0/16")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(case.functions(), ["ecm.usb9"])
        self.assertEqual(case.attr("functions/ecm.usb9/ifname"), "usb9")
        self.assertIn("Name=usb9", case.networkd_file.read_text())
        self.assertIn("Address=10.9.9.1/16", case.networkd_file.read_text())

    def test_down_unbinds_before_removing_and_drops_the_address_file(self):
        case = Case()
        self.assertEqual(case.run("up").returncode, 0)
        res = case.run("down")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(case.attr("UDC").strip(), "")
        self.assertIn("[usb-gadget] unbound %s" % UDC, res.stdout)
        self.assertFalse((case.g / "configs/c.1/ecm.usb0").exists())
        self.assertFalse(case.networkd_file.exists())
        self.assertIn("[usb-gadget] gadget down", res.stdout)

    def test_rebind_unbinds_then_rebinds(self):
        case = Case()
        self.assertEqual(case.run("up").returncode, 0)
        res = case.run("rebind")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("unbinding %s to re-enumerate" % UDC, res.stdout)
        self.assertIn("rebound %s on usb0" % UDC, res.stdout)
        self.assertEqual(case.attr("UDC"), UDC)

    def test_rebind_refuses_when_nothing_is_composed(self):
        case = Case()
        res = case.run("rebind")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("run 'usb-gadget-up up' first", res.stderr)

    def test_up_without_a_udc_creates_nothing(self):
        case = Case(udc=None)
        res = case.run("up")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("no UDC under", res.stderr)
        self.assertFalse(case.g.exists())

    def test_up_fails_when_the_interface_never_appears(self):
        case = Case(netdev=None)
        res = case.run("up", PI_TOR_GADGET_WAIT="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("usb0 did not appear within 1s", res.stderr)


def wired(path):
    """Non-comment lines of a unit/drop-in: what it actually declares."""
    return "\n".join(ln for ln in path.read_text().splitlines()
                     if ln.strip() and not ln.lstrip().startswith("#"))


class GadgetUnitTest(unittest.TestCase):

    def test_gadget_unit_contract(self):
        text = wired(UNIT)
        self.assertIn("Type=oneshot", text)
        self.assertIn("RemainAfterExit=yes", text)
        # gadget stack ready before anything binds; stack after the gadget
        self.assertIn("After=usb-gadget.target", text)
        self.assertIn("Before=pi-tor-stack.service", text)
        self.assertIn("EnvironmentFile=-/etc/default/pi-tor", text)
        # a literal absolute path: systemd cannot expand a variable into it
        self.assertIn("ExecStart=/opt/pi-tor/bin/usb-gadget-up up", text)
        self.assertIn("ExecStop=/opt/pi-tor/bin/usb-gadget-up down", text)
        # the node_exporter port belongs to that service alone
        self.assertNotIn("9100", text)

    def test_stack_unit_is_ordered_after_the_gadget(self):
        text = wired(STACK)
        self.assertIn("After=docker.service pi-tor-gadget.service", text)
        # compose needs the project dir as cwd, and it must be a literal path
        self.assertIn("WorkingDirectory=/opt/pi-tor", text)

    def test_watchdog_drop_in_rebinds_instead_of_modprobing_g_ether(self):
        text = wired(DROPIN)
        self.assertEqual(
            text,
            "[Service]\n"
            'Environment="WATCH_RELOAD_CMD=/opt/pi-tor/bin/usb-gadget-up rebind"')
        # a drop-in must not replace the watchdog's own command
        self.assertNotIn("ExecStart", text)


if __name__ == "__main__":
    unittest.main()
