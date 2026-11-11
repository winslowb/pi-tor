"""bin/pi-tor-rules.sh: the non-DNS UDP leak-plug in the filter table
(INPUT + FORWARD), shown by show-rules without root and flushed again."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import REPO
from test_startup import STUB as IPT_STUB

RULES = REPO / "bin" / "pi-tor-rules.sh"


def run_show(env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["bash", str(RULES), "show-rules"],
                          capture_output=True, text=True, env=e, timeout=30)


class UdpLeakPlugTest(unittest.TestCase):

    def test_rules_show_includes_udp_drop(self):
        p = run_show()
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.splitlines()
        # the nat redirect chain is still printed
        self.assertTrue(
            any("-t nat -A PI_TOR_REDIRECT -p tcp -j REDIRECT" in l
                for l in lines), p.stdout)
        for chain in ("INPUT", "FORWARD"):
            flt = [l for l in lines if f"-t filter -A {chain} " in l]
            drops = [l for l in flt if "-j DROP" in l]
            self.assertEqual(
                len(drops), 1, f"expected exactly one DROP in {chain}: {flt}")
            self.assertIn("-p udp ! --dport 53 -j DROP", drops[0],
                          f"non-DNS UDP drop missing in {chain}")
            # the drop must follow the tor DNSPort ACCEPT in apply order: nat
            # REDIRECT rewrites tethered udp/53 to udp/5353 before filter sees it
            accept = [l for l in flt if "--dport 5353 -j ACCEPT" in l]
            self.assertEqual(len(accept), 1, f"missing DNSPort ACCEPT in {chain}")
            self.assertLess(flt.index(accept[0]), flt.index(drops[0]),
                            f"DNSPort ACCEPT must precede the drop in {chain}: {flt}")
            # and both must precede the subnet ACCEPT, which would otherwise
            # white-list every tethered packet first
            subnet = [l for l in flt if "-j ACCEPT" in l and "-s 10.12.194.0/24" in l]
            self.assertTrue(subnet, f"subnet ACCEPT missing in {chain}")
            self.assertLess(flt.index(accept[0]), flt.index(subnet[0]),
                            f"filter drops must precede the subnet ACCEPT in {chain}")

    def test_rules_flush_removes_udp_drop(self):
        # functional: run flush against a stub iptables that only records argvs
        # (refusing -C via exit 1 keeps delete_rule_if_present from looping)
        with tempfile.TemporaryDirectory(prefix="pi-tor-flush-") as d:
            stub = Path(d) / "iptables"
            log = Path(d) / "calls.log"
            # every -C answers "no" (so nothing is ever deleted and no -D is
            # issued) and everything else succeeds, because flush re-installs
            # the guard on the way out
            stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "
                            + str(log) + "\n\n"
                            "for a in \"$@\"; do\n"
                            "  case \"$a\" in -C|-D) exit 1 ;; esac\n"
                            "done\nexit 0\n")
            os.chmod(stub, 0o755)
            # flush re-installs the guard, so ip6tables has to answer: the
            # simulator from test_startup, against its own state dir
            stub6 = Path(d) / "ip6tables"
            stub6.write_text(IPT_STUB)
            os.chmod(stub6, 0o755)
            state6 = str(Path(d) / "state6")
            env = dict(os.environ, IPTABLES_BIN=str(stub),
                       IP6TABLES_BIN=str(stub6), PI_TOR_FAKE_ROOT="1",
                       PI_TOR_FAKE_STATE=state6, PI_TOR_FAKE_STATE6=state6)
            p = subprocess.run(["bash", str(RULES), "flush"], env=env,
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            calls = log.read_text().splitlines()
            asked = [c for c in calls if " -p udp " in c]
            targets = " ".join(asked)
            for chain in ("INPUT", "FORWARD"):
                self.assertIn(f"-t filter -C {chain} ", targets, calls)
                self.assertIn(
                    f"-t filter -C {chain} -i usb0 -p udp ! --dport 53 -j DROP",
                    targets, calls)
                self.assertIn(
                    f"-t filter -C {chain} -i usb0 -p udp --dport 5353 -j ACCEPT",
                    targets, calls)
            # and the flush is source-level complete: the deletes hit the
            # same specs (stub never succeeds, so no -D was issued)
            self.assertEqual(
                [c for c in calls if " -D " in c], [], calls)

            src = RULES.read_text()
            flush = src[src.index("flush_rules()"):src.index("case \"$ACTION\"")]
            for chain in ("INPUT", "FORWARD"):
                self.assertIn(
                    "delete_rule_if_present filter \"$chain\" -i \"$INTERFACE\" "
                    "-p udp '!' --dport 53 -j DROP", flush)
                self.assertIn(
                    "delete_rule_if_present filter \"$chain\" -i \"$INTERFACE\" "
                    "-p udp --dport \"$TOR_DNS_PORT\" -j ACCEPT", flush)


if __name__ == "__main__":
    unittest.main()
