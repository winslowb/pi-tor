"""bin/uplink-check.sh gadget-address wait gate.

The wait functions are extracted (name -> closing brace) and sourced into
bash against synthetic torrc/fib_trie fixtures, so the suite does not depend
on any particular machine's interfaces (same convention as test_uplink.py).
"""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import REPO

SCRIPT = REPO / "bin" / "uplink-check.sh"
TORRC_FIXTURE = """RunAsDaemon 0
Log notice stdout

SocksPort 127.0.0.1:9050
SocksPort 0.0.0.0:9050
SocksPolicy accept 127.0.0.1
SocksPolicy accept 10.12.194.0/24
SocksPolicy reject *

TransPort 10.12.194.1:9040

DNSPort 127.0.0.1:5353
DNSPort 10.12.194.1:5353

#DNSPort 10.9.9.9:99
"""

# /proc/net/fib_trie shape: host rows "|-- <ip>" (or "|--<ip>") followed by
# "/32 host LOCAL"; the no-space form and a broadcast row are both present
FIB_PRESENT = """           +-- 127.0.0.0/8 2 0 2
              |--127.0.0.1
              /32 host LOCAL
           +-- 10.12.194.0/24 2 0 1
              |-- 10.12.194.0
              /24 link UNICAST
              |-- 10.12.194.255
              /32 link BROADCAST
              |-- 10.12.194.1
              /32 host LOCAL
"""

FIB_ABSENT = FIB_PRESENT.replace(
    "              |-- 10.12.194.1\n              /32 host LOCAL\n", "")


def extract_functions():
    src = SCRIPT.read_text()
    blocks = []
    for name in ("have_addr", "wait_gadget_addrs"):
        start = src.index(f"{name}()")
        end = src.index("\n}", start) + 2
        blocks.append(src[start:end])
    return "\n".join(blocks)


def run_wait(bash_body, tmp):
    (tmp / "torrc.txt").write_text(TORRC_FIXTURE)
    (tmp / "fib.txt").write_text(FIB_PRESENT)
    (tmp / "fib-absent.txt").write_text(FIB_ABSENT)
    (tmp / "loonly.txt").write_text("SocksPort 127.0.0.1:9050\n")
    (tmp / "empty.txt").write_text("")
    (tmp / "fns.sh").write_text(extract_functions())
    p = subprocess.run(
        ["bash", "-c",
         f"source '{tmp}/fns.sh'\n" + bash_body.format(tmp=tmp)],
        capture_output=True, text=True, timeout=60)
    return p


class UplinkCheckWaitTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pi-tor-wait-"))
        self.addCleanup(lambda: subprocess.run(
            ["rm", "-rf", str(self.tmp)]))

    def test_have_addr_reads_fib_trie_host_rows(self):
        p = run_wait('''
            have_addr  10.12.194.1   {tmp}/fib.txt; echo "present:$?"
            have_addr  10.12.194.255 {tmp}/fib.txt; echo "bcast:$?"
            have_addr  10.9.9.9      {tmp}/fib.txt; echo "absent:$?"
            have_addr "10.9.9.9"      {tmp}/nofile.txt 2>/dev/null; echo "nofile:$?"
            ''', self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = dict(l.rsplit(":", 1) for l in p.stdout.split())
        self.assertEqual(out["present"], "0")   # host LOCAL row wins
        self.assertEqual(out["bcast"], "1")     # /32 link BROADCAST is not a host row
        self.assertEqual(out["absent"], "1")    # awk EOF-exit must not read as success
        self.assertNotEqual(out["nofile"], "0") # missing fib_trie is never "assigned"

    def test_wait_gate_bounded_and_source_of_truth(self):
        p = run_wait('''
            ( wait_gadget_addrs 2 {tmp}/loonly.txt {tmp}/fib.txt ); echo "loonly:$?"
            ( wait_gadget_addrs 0 {tmp}/empty.txt  {tmp}/fib.txt ); echo "empty:$?"
            ( wait_gadget_addrs 0 {tmp}/torrc.txt  {tmp}/fib-absent.txt ); echo "missing:$?"
            ( wait_gadget_addrs 1 {tmp}/torrc.txt  {tmp}/fib-absent.txt ); echo "bounded:$?"
            ''', self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = {m.group(1): m.group(2)
               for tok in p.stdout.split()
               for m in [re.fullmatch(r"(loonly|empty|missing|bounded):(\d+)",
                                      tok)] if m}
        self.assertEqual(out["loonly"], "0")   # all-loopback torrc: no wait
        self.assertEqual(out["empty"], "0")    # empty torrc: no wait
        # the addresses come from the torrc itself: only the two
        # gadget-subnet binds are waited for and the bound is fatal
        self.assertEqual(out["missing"], "1")
        self.assertEqual(out["bounded"], "1")
        self.assertIn("10.12.194.1", p.stderr)
        self.assertNotIn("10.9.9.9", p.stderr)          # commented-out line
        self.assertNotIn("127.0.0.1", p.stderr)         # loopback never waited
        self.assertNotIn("0.0.0.0", p.stderr)           # wildcard never waited
        wait_logs = [l for l in p.stdout.splitlines() if "waiting 1s/1s" in l]
        self.assertTrue(wait_logs, f"no per-second wait log: {p.stdout!r}")


if __name__ == "__main__":
    unittest.main()
