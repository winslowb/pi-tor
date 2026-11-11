"""Render/parse round-trip tests against the committed defaults."""
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import REPO, make_config_tree

import config_schema as schema
import dockerops
import render


class RenderDefaultsTest(unittest.TestCase):

    def test_render_defaults_are_byte_identical(self):
        rendered = render.render(schema.defaults())
        tmp = Path(tempfile.mkdtemp(prefix="pi-tor-render-"))
        results = []
        # The seven targets from the brief; the committed stand-in for the
        # live (gitignored) .env is the regenerated .env.example.
        pairs = [
            (".env", ".env.example"),
            (".env.example", ".env.example"),
            ("tor/torrc", "tor/torrc"),
            ("systemd/pi-tor.env.example",
             "systemd/pi-tor.env.example"),
        ]
        for rel, committed_rel in pairs:
            out = tmp / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(rendered[rel])
            p = subprocess.run(["diff", "-q", str(out), str(REPO / committed_rel)],
                               capture_output=True, text=True, check=False)
            results.append(f"diff -q {rel} {committed_rel} -> "
                           f"rc={p.returncode} {p.stdout.strip()}")
            self.assertEqual(
                p.returncode, 0,
                f"render({rel!r}) differs from committed "
                f"{committed_rel!r}: {p.stdout}")
        # consistency: .env and .env.example share one template
        self.assertEqual(rendered[".env"], rendered[".env.example"])
        print("\n".join(results), file=sys.stderr)

    def test_subnet_change_propagates_to_all_targets(self):
        cfg = dict(schema.defaults())
        cfg["subnet"] = "10.44.0.0/24"
        cfg["gateway_ip"] = "10.44.0.1"
        # a gateway move must carry its protected host with it (the
        # unprotected-gateway guard would refuse the config below)
        cfg["protected_hosts"] = "10.44.0.1"
        self.assertEqual(schema.validate(cfg), [])
        rendered = render.render(cfg)

        torrc = rendered["tor/torrc"].decode()
        self.assertIn("SocksPolicy accept 10.44.0.0/24", torrc)
        self.assertIn("TransPort 10.44.0.1:9040", torrc)
        self.assertIn("DNSPort 10.44.0.1:5353", torrc)

        systemd = rendered["systemd/pi-tor.env.example"].decode()
        self.assertIn("PI_TOR_SUBNET=10.44.0.0/24", systemd)
        self.assertIn("PI_TOR_GATEWAY=10.44.0.1", systemd)

        # the env the rules script would receive when apply runs
        self.assertEqual(dockerops.rules_env(cfg), {
            "PI_TOR_INTERFACE": "usb0",
            "PI_TOR_SUBNET": "10.44.0.0/24",
            "PI_TOR_GATEWAY": "10.44.0.1",
            "PI_TOR_TRANS_PORT": "9040",
            "PI_TOR_DNS_PORT": "5353",
            "PI_TOR_PROTECTED_HOSTS": "10.44.0.1",
        })

        # parser round trip from a written tree
        tree = make_config_tree()
        try:
            import apply as apply_mod
            apply_mod._write_all(tree, rendered)
            parsed = render.read_current(tree)["values"]
            self.assertEqual(parsed["subnet"], "10.44.0.0/24")
            self.assertEqual(parsed["gateway_ip"], "10.44.0.1")
        finally:
            shutil.rmtree(tree, ignore_errors=True)


_BIND_RE = re.compile(r"^(SocksPort|TransPort|DNSPort)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s*$")
_POLICY_RE = re.compile(r"^SocksPolicy\s+(.*)$")


def _binds(torrc):
    return [(m.group(1), m.group(2), m.group(3))
            for line in torrc.splitlines()
            for m in [_BIND_RE.match(line)] if m]


def _policies(torrc):
    return [m.group(1).strip()
            for line in torrc.splitlines()
            for m in [_POLICY_RE.match(line)] if m]


class TorrcBindTest(unittest.TestCase):
    """The listener topology tor starts under:

    SOCKS is a single wildcard SocksPort whose SocksPolicy source ACL (a
    per-connection check, first-match-wins with reject * last) serves
    loopback and the subnet; DNS has a loopback listener for the local
    dnsmasq upstream plus the gadget-address listener for queries redirected
    off the gadget interface. Trans/DNS keep the gadget-address binds because
    a nat PREROUTING REDIRECT rewrites the destination to the incoming
    interface's own address, and those listeners have no source ACL, so they
    must never go wildcard. Loopback service (healthcheck, dnsmasq) never
    depends on the gadget interface being addressed.
    """

    def setUp(self):
        self.torrc = render.render(schema.defaults())["tor/torrc"].decode()
        self.gw = schema.DEFAULTS["gateway_ip"]
        self.loopback = [b for b in _binds(self.torrc) if b[1] == "127.0.0.1"]
        self.gadget = [b for b in _binds(self.torrc) if b[1] not in ("127.0.0.1", "0.0.0.0")]
        self.wildcards = [b for b in _binds(self.torrc) if b[1] == "0.0.0.0"]

    def test_torrc_loopback_ports_do_not_depend_on_gadget_address(self):
        # loopback consumers today: tor's own healthcheck (SOCKS via
        # 127.0.0.1, served by the wildcard + ACL) and Pi-hole's dnsmasq
        # upstream (server=127.0.0.1#5353, served by the loopback DNSPort)
        self.assertTrue(self.loopback, "no loopback listeners rendered")
        for kind, addr, port in self.loopback:
            self.assertEqual(addr, "127.0.0.1")
            self.assertNotIn(self.gw, f"{addr}:{port}",
                             f"loopback bind {kind} {addr}:{port} leaks the "
                             f"gadget address")
        socks_binds = [b for b in _binds(self.torrc) if b[0] == "SocksPort"]
        self.assertEqual([(b[1], b[2]) for b in socks_binds],
                         [("0.0.0.0", schema.DEFAULTS["socks_port"])],
                         f"SOCKS must come from the wildcard listener only: "
                         f"{socks_binds}")
        dns_loop = [b for b in self.loopback if b[0] == "DNSPort"]
        self.assertEqual([(b[2]) for b in dns_loop],
                         [schema.DEFAULTS["dns_port"]],
                         f"dnsmasq upstream needs a loopback DNSPort: "
                         f"{self.loopback}")

    def test_socksport_wildcard_has_reject_policy(self):
        self.assertEqual([(b[0], b[1]) for b in self.wildcards],
                         [("SocksPort", "0.0.0.0")],
                         "SOCKS is the only wildcard-bindable port")
        block = _policies(self.torrc)
        print("rendered SocksPolicy block:", block, file=sys.stderr)
        self.assertEqual(block, ["accept 127.0.0.1",
                                 f"accept {schema.DEFAULTS['subnet']}",
                                 "accept 10.12.195.0/24",
                                 "reject *"])
        # first-match-wins ACL: the terminator must be last, after the
        # loopback and subnet accepts, or non-listed sources would be
        # accepted by tor's default
        self.assertEqual(block[-1], "reject *")

    # bin/pi-tor-ap's PI_TOR_AP_SUBNET default. The AP nat chain DNATs guest
    # TCP to the TransPort, and tor runs this same source ACL on every entry
    # listener, TransPort included (connection_handle_listener_read checks
    # new_type == CONN_TYPE_AP before it looks at the listener). Unlisted, a
    # guest connection is accepted and closed before it can send a byte.
    AP_SUBNET = "10.12.195.0/24"

    def test_guest_subnet_may_enter_tor(self):
        block = _policies(self.torrc)
        self.assertIn(f"accept {self.AP_SUBNET}", block[:-1],
                      f"SocksPolicy would deny the AP guest net: {block}")
        self.assertEqual(block[-1], "reject *")

    def test_rendered_torrc_has_no_wildcard_trans_or_dns_port(self):
        # REDIRECT's destination is the incoming interface's primary address
        # (iptables-extensions(8), nf_nat_redirect_ipv4), so Trans/DNS keep
        # the gadget-address bind; with no source ACL on those listeners the
        # safety rule is a hard wildcard ban instead.
        for kind, addr, port in _binds(self.torrc):
            if kind == "SocksPort":
                continue
            self.assertIn(addr, ("127.0.0.1", self.gw),
                          f"{kind} bound to {addr} - only loopback or the "
                          f"gadget address may serve it")
            self.assertNotEqual(addr, "0.0.0.0")
        self.assertEqual([(k, p) for k, a, p in self.gadget],
                         [("TransPort", "9040"), ("DNSPort", "5353")],
                         f"gadget binds off-spec: {self.gadget}")


class ExitNodesTest(unittest.TestCase):

    def test_exit_nodes_round_trip(self):
        parsed = render.read_current(REPO)["values"]
        # committed torrc: active ExcludeExitNodes, commented ExitNodes
        self.assertEqual(parsed["exit_nodes_exclude"], "{ru},{cn},{ir},{kp}")
        self.assertEqual(parsed["exit_nodes_include"], "")

        cfg = dict(schema.defaults())
        cfg["exit_nodes_include"] = "{us},{ca}"
        cfg["exit_nodes_exclude"] = ""
        rendered = render.render(cfg)
        torrc = rendered["tor/torrc"].decode()
        self.assertIn("ExitNodes {us},{ca}\n", torrc)
        self.assertIn("#ExcludeExitNodes {ru},{cn},{ir},{kp}\n", torrc)

        tree = make_config_tree()
        try:
            import apply as apply_mod
            apply_mod._write_all(tree, rendered)
            back = render.read_current(tree)["values"]
            self.assertEqual(back["exit_nodes_include"], "{us},{ca}")
            self.assertEqual(back["exit_nodes_exclude"], "")
            # and back to defaults renders the committed form again
            redefault = render.render(schema.defaults())
            self.assertEqual(redefault["tor/torrc"],
                             (REPO / "tor/torrc").read_bytes())
        finally:
            shutil.rmtree(tree, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
