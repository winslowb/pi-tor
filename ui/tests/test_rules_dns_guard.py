"""bin/pi-tor-rules.sh: the :53 guard that lets FTL run with
`listeningMode=ALL` (docker-compose.yml) without serving DNS on the LAN.

FTL only answers a query that arrives on an interface it accepts, and a guest
query is DNAT'ed to the tether address while still *arriving* on the AP
interface: `SINGLE` + `dns.interface=usb0` dropped those (the live failure:
DNAT and INPUT counters rose, no reply, no RST). `ALL` answers them, so the
netfilter guard - not FTL - is what keeps :53 off the LAN, in both families:
ALL binds `::` too, and the uplink is IPv6-reachable.

The guard also has to exist before FTL binds :53 and has to survive a flush,
so `guard` is its own action (systemd/pi-tor-guard.service runs it before
docker starts any container) and `flush` reinstalls it instead of removing it.
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import REPO
from test_ap import RULES, Fixture

EXPECTED = [
    "-i lo -j ACCEPT",
    "-i usb0 -s 10.12.194.0/24 -j ACCEPT",
    "-i uap0 -s 10.12.195.0/24 -j ACCEPT",
    "-j DROP",
]
HOOKS = ["-p udp --dport 53 -j PI_TOR_DNS",
         "-p tcp --dport 53 -j PI_TOR_DNS"]

# IPv6: no approved path has IPv6 at all (bin/usb-gadget-up turns the tether's
# link-local addressing off, bin/pi-tor-ap sets disable_ipv6 on the AP
# interface and drops uap0 in ip6tables), so loopback is the only source that
# may resolve.
EXPECTED6 = ["-i lo -j ACCEPT", "-j DROP"]

UNIT_GUARD = REPO / "systemd" / "pi-tor-guard.service"
UNIT_STACK = REPO / "systemd" / "pi-tor-stack.service"


def _directives(path):
    return [ln.strip() for ln in path.read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith(("#", ";"))]


class DnsGuardTest(unittest.TestCase):

    def setUp(self):
        self.fx = Fixture()

    def tearDown(self):
        self.fx.cleanup()

    def _hooks(self, state=None):
        return [r for r in self.fx.chain("filter", "INPUT", state) or []
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

    def test_apply_confines_ipv6_dns_to_loopback(self):
        # FTL in ALL mode binds :: as well; the uplink is IPv6-reachable, and
        # neither the tether nor the guest link has IPv6 at all
        res = self.fx.rules("apply")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS", self.fx.state6),
                         EXPECTED6,
                         "an IPv6 :53 without a guard answers on the LAN")
        self.assertEqual(sorted(self._hooks(self.fx.state6)), sorted(HOOKS))

    def test_ipv6_guard_admits_loopback_only(self):
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        chain = self.fx.chain("filter", "PI_TOR_DNS", self.fx.state6)
        self.assertEqual([r for r in chain if r.endswith("-j ACCEPT")],
                         ["-i lo -j ACCEPT"],
                         f"only the Pi itself may resolve over IPv6: {chain}")
        self.assertEqual(chain[-1], "-j DROP")

    def test_ipv6_hooks_land_ahead_of_preseeded_accepts(self):
        seed = Path(self.fx.state6) / "filter" / "INPUT"
        seed.parent.mkdir(parents=True, exist_ok=True)
        seed.write_text("-j ACCEPT\n-i uap0 -j ACCEPT\n")
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        hooks = self.fx.chain("filter", "INPUT", self.fx.state6)
        self.assertEqual(sorted(hooks[:2]), sorted(HOOKS),
                         f"a preseeded IPv6 ACCEPT sees DNS first: {hooks}")
        self.assertIn("-j ACCEPT", hooks[2:])

    def test_apply_ap_leaves_the_same_guard(self):
        # `apply` runs from the ui container (no AP env), apply-ap from the AP
        # unit: both must leave one identical chain, so neither can widen or
        # wipe the other's DNS policy
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS", self.fx.state6),
                         EXPECTED6)
        self.assertEqual(sorted(self._hooks()), sorted(HOOKS))

    def test_guard_interface_and_subnet_have_their_own_override(self):
        # the ui apply knows the guest net/interface but must not set
        # PI_TOR_AP_INTERFACE: in this script that also enables AP mode
        res = self.fx.rules("apply", PI_TOR_AP_INTERFACE=None,
                            PI_TOR_AP_GUARD_INTERFACE="wlan9",
                            PI_TOR_AP_SUBNET="10.99.0.0/24")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"),
                         ["-i lo -j ACCEPT",
                          "-i usb0 -s 10.12.194.0/24 -j ACCEPT",
                          "-i wlan9 -s 10.99.0.0/24 -j ACCEPT",
                          "-j DROP"],
                         "a customised guest net must be the guard's source")
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"),
                          "a guard override must not install the AP chains")
        self.assertEqual(self.fx.chain("filter", "INPUT"),
                         ["-p tcp --dport 53 -j PI_TOR_DNS",
                          "-p udp --dport 53 -j PI_TOR_DNS",
                          "-i usb0 -p udp --dport 5353 -j ACCEPT",
                          "-i usb0 -p udp ! --dport 53 -j DROP",
                          "-i usb0 -s 10.12.194.0/24 -j ACCEPT"],
                         "every other rule stays tether-scoped")

    def test_flush_keeps_both_dns_guards(self):
        # FTL keeps listening in ALL mode after a flush, so flush may remove
        # the redirect but never the resolver boundary
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        res = self.fx.rules("flush")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS", self.fx.state6),
                         EXPECTED6)
        self.assertEqual(sorted(self._hooks()), sorted(HOOKS))
        self.assertEqual(sorted(self._hooks(self.fx.state6)), sorted(HOOKS))

    def test_flush_closes_dns_that_was_never_guarded(self):
        # the stopped-listener case: nothing was applied, so flush is the only
        # thing that could have left :53 open - it closes it instead
        res = self.fx.rules("flush")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS", self.fx.state6),
                         EXPECTED6)

    def test_guard_action_installs_only_the_dns_guards(self):
        # what the boot unit runs, before docker starts any container: the
        # resolver boundary and nothing else
        res = self.fx.rules("guard")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS"), EXPECTED)
        self.assertEqual(self.fx.chain("filter", "PI_TOR_DNS", self.fx.state6),
                         EXPECTED6)
        self.assertEqual(sorted(self._hooks()), sorted(HOOKS))
        self.assertEqual(sorted(self._hooks(self.fx.state6)), sorted(HOOKS))
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_REDIRECT"))
        self.assertIsNone(self.fx.chain("nat", "PREROUTING"))

    def test_guard_refuses_without_ip6tables(self):
        bash = shutil.which("bash")
        res = subprocess.run([bash, str(RULES), "guard"], capture_output=True,
                             text=True, timeout=60,
                             env=self.fx.env(PATH="/nonexistent",
                                             IP6TABLES_BIN=""))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("ip6tables", res.stderr)
        self.assertIn("refusing to apply", res.stderr)
        self.assertFalse(self.fx.state.exists(), "refused but wrote rules")

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

        # the ip6tables stub logs its own call and then the inner iptables
        # stub logs the same argv, so keep the two families apart by the
        # first call that belongs to ip6tables
        log = self.fx.calls()[seen:]
        split = next(i for i, c in enumerate(log) if c.startswith("ip6tables "))
        log, log6 = log[:split], [c for c in log[split:]
                                  if c.startswith("ip6tables ")]
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

        # the same hold-the-window-shut sequence in ip6tables
        guard6_in = ("ip6tables -t filter -I INPUT 1 -p udp --dport 53 "
                     "-j DROP")
        guard6_out = "ip6tables -t filter -D INPUT -p udp --dport 53 -j DROP"
        flush6 = "ip6tables -t filter -F PI_TOR_DNS"
        refill6 = [i for i, call in enumerate(log6)
                   if call == "ip6tables -t filter -A PI_TOR_DNS -j DROP"]
        self.assertIn(guard6_in, log6, log6)
        self.assertIn(flush6, log6, log6)
        self.assertTrue(refill6, log6)
        self.assertLess(log6.index(guard6_in), log6.index(flush6),
                        "the IPv6 guard chain was refilled while reachable")
        self.assertLess(refill6[-1], log6.index(guard6_out),
                        "the temporary IPv6 :53 DROP came out before the refill")

    def test_show_rules_prints_the_guard_without_root(self):
        res = self.fx.rules("show-rules")
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn("-t filter -A PI_TOR_DNS -j DROP", out)
        for rule in EXPECTED[:-1]:
            self.assertIn(f"-t filter -A PI_TOR_DNS {rule}", out)
        self.assertIn("-t filter -I INPUT 1 -p udp --dport 53 -j PI_TOR_DNS", out)
        # the IPv6 picture too: same chain, same order
        self.assertIn("ip6tables -t filter -I INPUT 1 -p udp --dport 53 "
                      "-j PI_TOR_DNS", out)
        self.assertIn("ip6tables -t filter -A PI_TOR_DNS -i lo -j ACCEPT", out)
        self.assertIn("ip6tables -t filter -A PI_TOR_DNS -j DROP", out)
        self.assertFalse(self.fx.state.exists(), "show-rules wrote a ruleset")


class StartupGuardTest(unittest.TestCase):
    """The guard has to be in the kernel before FTL can bind :53: at boot that
    is before docker starts, not a ui-container apply after pihole is up."""

    def test_guard_unit_runs_before_docker_and_is_persistent(self):
        text = "\n".join(_directives(UNIT_GUARD))
        self.assertIn("Type=oneshot", text)
        self.assertIn("RemainAfterExit=yes", text)
        self.assertIn("ExecStart=/opt/pi-tor/bin/pi-tor-rules.sh guard", text)
        self.assertIn("Before=docker.service", text)
        self.assertIn("EnvironmentFile=-/etc/default/pi-tor", text)
        self.assertIn("WantedBy=multi-user.target", text)

    def test_stack_unit_pulls_the_guard_in_first(self):
        # Requires, not Wants: a guard that cannot be installed must fail the
        # stack instead of letting pihole bind :53 unguarded
        lines = _directives(UNIT_STACK)
        self.assertIn("Requires=pi-tor-guard.service", lines)
        after = [l for l in lines if l.startswith("After=")]
        self.assertEqual(len(after), 1, after)
        for unit in ("docker.service", "pi-tor-guard.service"):
            self.assertIn(unit, after[0])
        self.assertTrue([l for l in lines
                         if l.startswith("ExecStart=/usr/bin/docker compose up")],
                        lines)

    def test_guard_is_a_hard_dependency_of_docker_not_just_ordering(self):
        """`Before=` alone only orders jobs in one transaction.

        Containers carry `restart=unless-stopped`, so dockerd auto-starts FTL
        without `pi-tor-stack.service` ever running: docker.service itself has
        to require the guard, and require -- not want -- so a guard that cannot
        be installed stops docker instead of leaving :53 open.
        """
        lines = _directives(UNIT_GUARD)
        before = [l for l in lines if l.startswith("Before=")]
        self.assertEqual(len(before), 1, before)
        self.assertIn("docker.service", before[0].split("=", 1)[1].split())
        required_by = [l for l in lines if l.startswith("RequiredBy=")]
        self.assertEqual(required_by, ["RequiredBy=docker.service"], required_by)

    @unittest.skipUnless(shutil.which("systemctl"), "needs systemctl --root")
    def test_enabling_the_guard_wires_it_into_docker(self):
        """The installer's `systemctl enable` is what creates the dependency:
        prove it lands in docker.service.requires/ (blocking), not .wants/."""
        with tempfile.TemporaryDirectory() as tmp:
            unitdir = Path(tmp) / "etc" / "systemd" / "system"
            unitdir.mkdir(parents=True)
            (unitdir / "docker.service").write_text(
                "[Unit]\nDescription=fake docker\n"
                "[Service]\nType=notify\nExecStart=/bin/true\n")
            shutil.copy(UNIT_GUARD, unitdir / UNIT_GUARD.name)
            res = subprocess.run(
                ["systemctl", "--root=" + tmp, "enable", UNIT_GUARD.name],
                capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            requires = unitdir / "docker.service.requires" / UNIT_GUARD.name
            wants = unitdir / "docker.service.wants" / UNIT_GUARD.name
            self.assertTrue(requires.is_symlink(),
                            "no docker.service.requires link: "
                            + ", ".join(sorted(p.name for p in unitdir.iterdir())))
            self.assertFalse(wants.exists(),
                             "a wants= link would not fail docker")

    def test_readme_installs_the_guard_before_the_stack(self):
        text = (REPO / "README.md").read_text()
        start = text.index("## Systemd (optional)")
        sec = text[start:text.index("\n## ", start + 1)]
        cp = sec.index("systemd/pi-tor-guard.service")
        enable = sec.index("systemctl enable --now pi-tor-guard.service")
        stack = sec.index("systemctl enable --now pi-tor-stack.service")
        self.assertLess(cp, enable, "the unit has to be installed before enabled")
        self.assertLess(enable, stack,
                        "the guard must be enabled before the stack it guards")


if __name__ == "__main__":
    unittest.main()
