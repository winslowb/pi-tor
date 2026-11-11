"""bin/pi-tor-rules.sh: the :53 guard that lets FTL run with
`listeningMode=ALL` (docker-compose.yml) without serving DNS on the LAN.

FTL only answers a query that arrives on an interface it accepts, and a guest
query is DNAT'ed to the tether address while still *arriving* on the AP
interface: `SINGLE` + `dns.interface=usb0` dropped those (the live failure:
DNAT and INPUT counters rose, no reply, no RST). `ALL` answers them, so the
netfilter guard - not FTL - is what keeps :53 off the LAN.
"""
import unittest

from test_ap import Fixture

EXPECTED = [
    "-i lo -j ACCEPT",
    "-i usb0 -s 10.12.194.0/24 -j ACCEPT",
    "-i uap0 -s 10.12.195.0/24 -j ACCEPT",
    "-j DROP",
]
HOOKS = ["-p udp --dport 53 -j PI_TOR_DNS",
         "-p tcp --dport 53 -j PI_TOR_DNS"]


class DnsGuardTest(unittest.TestCase):

    def setUp(self):
        self.fx = Fixture()

    def tearDown(self):
        self.fx.cleanup()

    def _hooks(self):
        return [r for r in self.fx.chain("filter", "INPUT") or []
                if r.endswith("-j PI_TOR_DNS")]

    def test_apply_pins_dns_to_the_loopback_tether_and_guest_nets(self):
        res = self.fx.rules("apply")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED,
                         "DNS must be answered on loopback, the tether and the "
                         "guest link only")
        # both protocols hooked, and ahead of any broad ACCEPT already in INPUT
        self.assertEqual(sorted(self._hooks()), sorted(HOOKS))
        self.assertEqual(sorted(self.fx.chain("filter", "INPUT")[:2]),
                         sorted(HOOKS),
                         "a preseeded ACCEPT must not see DNS before the guard")

    def test_every_dns_accept_is_pinned_to_an_interface(self):
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        chain = self.fx.chain("filter", "PI_TOR_DNS")
        for rule in [r for r in chain if r.endswith("-j ACCEPT")]:
            self.assertRegex(rule, r"^-i \S+ ",
                             f"an unscoped DNS ACCEPT serves the LAN: {rule}")
            if "-i lo" not in rule:
                self.assertRegex(rule, r"-s \d+\.\d+\.\d+\.\d+/\d+",
                                 f"a non-loopback DNS ACCEPT needs a source "
                                 f"net: {rule}")
        self.assertEqual(chain[-1], "-j DROP", chain)

    def test_apply_ap_leaves_the_same_guard(self):
        # `apply` runs from the ui container (no AP env), apply-ap from the AP
        # unit: both must leave one identical chain, so neither can widen or
        # wipe the other's DNS policy
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED)
        self.assertEqual(sorted(self._hooks()), sorted(HOOKS))

    def test_flush_removes_the_guard(self):
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        res = self.fx.rules("flush")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIsNone(self.fx.chain("filter", "PI_TOR_DNS"))
        self.assertEqual(self._hooks(), [])

    def test_flush_ap_keeps_the_guard(self):
        # an AP teardown must not turn the LAN into a resolver
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)
        self.assertEqual(self.fx.rules("flush-ap").returncode, 0)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED)
        self.assertEqual(sorted(self._hooks()), sorted(HOOKS))

    def test_reapply_never_exposes_a_dns_window(self):
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        seen = len(self.fx.calls())
        self.assertEqual(self.fx.rules("apply").returncode, 0)

        log = self.fx.calls()[seen:]
        guard_in = "iptables -t filter -I INPUT 1 -p udp --dport 53 -j DROP"
        guard_out = "iptables -t filter -D INPUT -p udp --dport 53 -j DROP"
        flush = "iptables -t filter -F PI_TOR_DNS"
        refill = [i for i, call in enumerate(log)
                  if call == "iptables -t filter -A PI_TOR_DNS -j DROP"]
        self.assertIn(guard_in, log, log)
        self.assertIn(flush, log, log)
        self.assertTrue(refill, log)
        self.assertLess(log.index(guard_in), log.index(flush),
                        "the guard chain was refilled while still reachable")
        self.assertLess(refill[-1], log.index(guard_out),
                        "the temporary :53 DROP came out before the refill")
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED)

    def test_show_rules_prints_the_guard_without_root(self):
        res = self.fx.rules("show-rules")
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn("-t filter -A PI_TOR_DNS -j DROP", out)
        for rule in EXPECTED[:-1]:
            self.assertIn(f"-t filter -A PI_TOR_DNS {rule}", out)
        self.assertIn("-t filter -I INPUT 1 -p udp --dport 53 -j PI_TOR_DNS", out)
        self.assertFalse(self.fx.state.exists(), "show-rules wrote a ruleset")


if __name__ == "__main__":
    unittest.main()
