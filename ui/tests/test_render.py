"""Render/parse round-trip tests against the committed defaults."""
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
            ("pihole/etc-dnsmasq.d/02-listen.conf",
             "pihole/etc-dnsmasq.d/02-listen.conf"),
            ("pihole/etc-dnsmasq.d/02-upstream-tor.conf",
             "pihole/etc-dnsmasq.d/02-upstream-tor.conf"),
            ("pihole/etc-dnsmasq.d/02-usb0.conf",
             "pihole/etc-dnsmasq.d/02-usb0.conf"),
            ("pihole/etc-dnsmasq.d/99-tor-upstream.conf",
             "pihole/etc-dnsmasq.d/99-tor-upstream.conf"),
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
        self.assertEqual(schema.validate(cfg), [])
        rendered = render.render(cfg)

        torrc = rendered["tor/torrc"].decode()
        self.assertIn("SocksPolicy accept 10.44.0.0/24", torrc)
        self.assertIn("TransPort 10.44.0.1:9040", torrc)
        self.assertIn("DNSPort 10.44.0.1:5353", torrc)

        listen = rendered["pihole/etc-dnsmasq.d/02-listen.conf"].decode()
        self.assertIn("listen-address=10.44.0.1,127.0.0.1", listen)

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
