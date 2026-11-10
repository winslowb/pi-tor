"""Wi-Fi AP (guest) mode: bin/pi-tor-ap lifecycle + bin/pi-tor-rules.sh
apply-ap/flush-ap, against stub iw/ip/hostapd/dnsmasq/iptables.

Nothing here touches a real radio, ruleset or daemon: every privileged command
is a stub, exactly like test_startup.py and test_gadget_up.py. What the stubs
cannot model is real hardware behaviour (a radio that refuses AP+station on the
chosen channel, whether Pi-hole answers a DNAT'ed query that arrived on the AP
interface); those are called out as device-verification constraints, not
covered by these tests.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import REPO
from test_startup import STUB as IPT_STUB

SCRIPT = REPO / "bin" / "pi-tor-ap"
RULES = REPO / "bin" / "pi-tor-rules.sh"
UNIT = REPO / "systemd" / "pi-tor-ap.service"
ENV_EXAMPLE = REPO / "systemd" / "pi-tor-ap.env.example"
COMPOSE = REPO / "docker-compose.yml"
TORRC = REPO / "tor" / "torrc"
PSK = "correct horse battery"

IW_STUB = """#!/bin/sh
printf 'iw %s\\n' "$*" >> "$AP_CALLS"
case "$*" in
  "dev wlan0 info")
    if [ "${AP_TEST_NO_CHANNEL:-}" = 1 ]; then
      printf 'Interface wlan0\\n\\tifindex 3\\n\\ttype managed\\n'
    else
      printf 'Interface wlan0\\n\\tifindex 3\\n\\ttype managed\\n'
      printf '\\tchannel 149 (5745 MHz), width: 80 MHz, center1: 155 MHz\\n'
    fi ;;
  "dev uap0 info")
    printf 'Interface uap0\\n\\ttype AP\\n\\tchannel 149 (5745 MHz), width: 20 MHz\\n' ;;
  "dev wlan0 link")
    if [ "${AP_TEST_NO_LINK:-}" = 1 ]; then
      printf 'Not connected.\\n'
    else
      printf 'Connected to aa:bb:cc:dd:ee:ff (on wlan0)\\n\\tSSID: home\\n'
    fi ;;
  "dev wlan0 interface add uap0 type __ap")
    mkdir -p "$AP_NET_DIR/uap0" "$AP_SYSCTL_DIR/uap0"
    printf 0 > "$AP_SYSCTL_DIR/uap0/disable_ipv6" ;;
  *) exit 1 ;;
esac
"""

IP_STUB = """#!/bin/sh
printf 'ip %s\\n' "$*" >> "$AP_CALLS"
case "$*" in
  "-o -4 addr show dev uap0")
    [ -f "$AP_ROOT/addr" ] && cat "$AP_ROOT/addr"
    exit 0 ;;
  "link set uap0 up") exit 0 ;;
  "addr add 10.12.195.1/24 dev uap0")
    printf 'inet 10.12.195.1/24 scope global uap0\\n' > "$AP_ROOT/addr" ;;
  "link del uap0")
    rm -rf "$AP_NET_DIR/uap0" "$AP_SYSCTL_DIR/uap0"; rm -f "$AP_ROOT/addr" ;;
  *) exit 2 ;;
esac
"""

HOSTAPD_STUB = """#!/bin/sh
printf 'hostapd %s\\n' "$*" >> "$AP_CALLS"
[ "${AP_TEST_HOSTAPD_FAIL:-}" = 1 ] && exit 1
pidfile=
while [ $# -gt 0 ]; do
  case "$1" in -P) pidfile=$2; shift ;; esac
  shift
done
sleep 300 >/dev/null 2>&1 &
printf '%s\\n' "$!" > "$pidfile"
"""

DNSMASQ_STUB = """#!/bin/sh
printf 'dnsmasq %s\\n' "$*" >> "$AP_CALLS"
pidfile=
for a in "$@"; do
  case "$a" in --pid-file=*) pidfile=${a#--pid-file=} ;; esac
done
[ -n "$pidfile" ] || exit 2
sleep 300 >/dev/null 2>&1 &
printf '%s\\n' "$!" > "$pidfile"
"""

IP6_STUB = """#!/bin/sh
printf 'ip6tables %s\\n' "$*" >> "$AP_CALLS"
PI_TOR_FAKE_STATE="$AP_STATE6" exec "$AP_IPTABLES" "$@"
"""


def _write(path, text, mode=0o755):
    path.write_text(text)
    path.chmod(path.stat().st_mode | mode)


class Fixture:
    """A disposable host: stub binaries, a fake /sys/class/net, a fake ruleset."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="pi-tor-ap-test-"))
        self.net = self.root / "net"
        self.net.mkdir()
        (self.net / "wlan0").mkdir()
        self.sysctl = self.root / "sysctl"
        self.sysctl.mkdir()
        self.rundir = self.root / "run"
        self.state = self.root / "state"
        self.state6 = self.root / "state6"
        self.calls_log = self.root / "calls.log"
        self.stubbin = self.root / "stubbin"
        self.stubbin.mkdir()
        iptables = self.stubbin / "iptables"
        _write(iptables, IPT_STUB)
        _write(self.stubbin / "iw", IW_STUB)
        _write(self.stubbin / "ip", IP_STUB)
        _write(self.stubbin / "hostapd", HOSTAPD_STUB)
        _write(self.stubbin / "dnsmasq", DNSMASQ_STUB)
        _write(self.stubbin / "ip6tables", IP6_STUB)

    def env(self, **over):
        env = dict(os.environ)
        env.update(
            AP_ROOT=str(self.root),
            AP_CALLS=str(self.calls_log),
            AP_NET_DIR=str(self.net),
            AP_SYSCTL_DIR=str(self.sysctl),
            AP_STATE6=str(self.state6),
            AP_IPTABLES=str(self.stubbin / "iptables"),
            PI_TOR_AP_RUNDIR=str(self.rundir),
            PI_TOR_NET_DIR=str(self.net),
            PI_TOR_AP_SYSCTL_DIR=str(self.sysctl),
            PI_TOR_IW=str(self.stubbin / "iw"),
            PI_TOR_IP=str(self.stubbin / "ip"),
            PI_TOR_HOSTAPD=str(self.stubbin / "hostapd"),
            PI_TOR_DNSMASQ=str(self.stubbin / "dnsmasq"),
            PI_TOR_RULES=str(RULES),
            PI_TOR_AP_WAIT="1",
            PI_TOR_FAKE_ROOT="1",
            PI_TOR_AP_INTERFACE="uap0",
            PI_TOR_AP_SUBNET="10.12.195.0/24",
            PI_TOR_AP_GATEWAY="10.12.195.1",
            PI_TOR_AP_SSID="Guests",
            PI_TOR_AP_PSK=PSK,
            PI_TOR_UPLINK="wlan0",
            PI_TOR_INTERFACE="usb0",
            IPTABLES_BIN=str(self.stubbin / "iptables"),
            IP6TABLES_BIN=str(self.stubbin / "ip6tables"),
            PI_TOR_FAKE_STATE=str(self.state),
        )
        env.update(over)
        return env

    def run(self, *args, **over):
        return subprocess.run(["/bin/sh", str(SCRIPT), *args],
                              capture_output=True, text=True,
                              env=self.env(**over), timeout=90)

    def rules(self, action, **over):
        return subprocess.run(["bash", str(RULES), action],
                              capture_output=True, text=True,
                              env=self.env(**over), timeout=60)

    def calls(self):
        if not self.calls_log.exists():
            return []
        return self.calls_log.read_text().splitlines()

    def chain(self, table, name, state=None):
        f = Path(state or self.state) / table / name
        return f.read_text().splitlines() if f.exists() else None

    def cleanup(self):
        # never leave the stub daemons behind, even when an assertion failed
        for pid in ("hostapd.pid", "dnsmasq.pid"):
            f = self.rundir / pid
            if f.exists():
                try:
                    os.kill(int(f.read_text().strip()), 9)
                except (ValueError, OSError):
                    pass
        shutil.rmtree(self.root, ignore_errors=True)


class ApUpTest(unittest.TestCase):

    def setUp(self):
        self.fx = Fixture()

    def tearDown(self):
        self.fx.cleanup()

    def test_up_renders_an_authenticated_ap_on_the_uplink_channel(self):
        res = self.fx.run("up")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

        conf = (self.fx.rundir / "hostapd.conf").read_text()
        self.assertIn("interface=uap0", conf)
        self.assertIn("ssid=Guests", conf)
        # the uplink's channel, read live: one radio, #channels <= 1
        self.assertIn("channel=149", conf)
        self.assertIn("hw_mode=a", conf)
        # authenticated only: no open/WEP/enterprise mode is reachable
        self.assertIn("wpa=2", conf)
        self.assertIn("wpa_key_mgmt=WPA-PSK", conf)
        self.assertIn(f"wpa_passphrase={PSK}", conf)
        self.assertNotIn("wpa=0", conf)
        # guests cannot talk to each other
        self.assertIn("ap_isolate=1", conf)
        # the secret lives in a root-only runtime file, never in the repo
        self.assertEqual(stat.S_IMODE((self.fx.rundir / "hostapd.conf").stat().st_mode),
                         0o600)
        self.assertEqual(stat.S_IMODE(self.fx.rundir.stat().st_mode), 0o700)

        dhcp = (self.fx.rundir / "dnsmasq.conf").read_text()
        self.assertIn("port=0", dhcp)          # no second DNS server
        self.assertIn("interface=uap0", dhcp)  # DHCP on the guest link only
        self.assertIn("bind-dynamic", dhcp)
        self.assertIn("dhcp-range=10.12.195.100,10.12.195.199,255.255.255.0,1h", dhcp)
        self.assertIn("dhcp-option=3,10.12.195.1", dhcp)
        self.assertIn("dhcp-option=6,10.12.195.1", dhcp)
        self.assertNotIn("server=", dhcp)

        # IPv6 off on the guest interface, and the address is the AP gateway
        self.assertEqual((self.fx.sysctl / "uap0" / "disable_ipv6").read_text(), "1")
        self.assertIn("ip addr add 10.12.195.1/24 dev uap0", self.fx.calls())
        self.assertIn("ip link set uap0 up", self.fx.calls())

        # the rules went on before the interface could carry a guest packet
        src = SCRIPT.read_text()
        up = src[src.index("up() {"):src.index("down() {")]
        self.assertLess(up.index("  rules\n"), up.index("  iface_up\n"),
                        "firewall must be applied before the AP interface is usable")
        self.assertIsNotNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"),
                             "AP nat chain missing after up")

    def test_up_refuses_a_missing_short_or_open_secret(self):
        for psk, msg in (("", "no open-AP mode"), ("short12", "8-63 characters"),
                         ("has\na newline", "must not contain a newline")):
            res = self.fx.run("up", PI_TOR_AP_PSK=psk)
            self.assertNotEqual(res.returncode, 0, f"{psk!r} must be refused")
            self.assertIn(msg, res.stderr, res.stderr)
        self.assertEqual(self.fx.calls(), [], "nothing may be created without a secret")
        self.assertFalse(self.fx.rundir.exists())
        self.assertFalse((self.fx.net / "uap0").exists())

    def test_up_refuses_a_subnet_that_overlaps_the_tether(self):
        res = self.fx.run("up", PI_TOR_AP_SUBNET="10.12.194.0/24",
                          PI_TOR_AP_GATEWAY="10.12.194.9")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("must not overlap the tether subnet", res.stderr)
        self.assertEqual(self.fx.calls(), [])

    def test_up_refuses_when_the_uplink_channel_is_unknown(self):
        res = self.fx.run("up", AP_TEST_NO_CHANNEL="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("channel", res.stderr)
        self.assertIn("no safe default", res.stderr)
        # refused before any mutation
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))

    def test_up_rolls_everything_back_when_hostapd_fails(self):
        res = self.fx.run("up", AP_TEST_HOSTAPD_FAIL="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("refused to start", res.stderr)
        self.assertIn("rolling the AP back down", res.stdout + res.stderr)
        self.assertFalse((self.fx.net / "uap0").exists(), "AP interface survived a failed start")
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"),
                          "AP rules survived a failed start")
        self.assertFalse(self.fx.rundir.exists(),
                         "the runtime dir (and the PSK in it) survived a failed start")

    def test_up_rolls_back_when_the_uplink_loses_its_association(self):
        res = self.fx.run("up", AP_TEST_NO_LINK="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("lost its association", res.stderr)
        self.assertIn("rolling the AP back down", res.stdout + res.stderr)
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))

    def test_down_tears_down_and_is_idempotent(self):
        self.assertEqual(self.fx.run("up").returncode, 0)
        res = self.fx.run("down")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertFalse(self.fx.rundir.exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))
        self.assertIsNone(self.fx.chain("filter", "PI_TOR_AP_IN"))
        second = self.fx.run("down")
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)

    def test_plan_writes_and_starts_nothing(self):
        res = self.fx.run("plan")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("channel 149", res.stdout)
        self.assertIn("apply-ap", res.stdout)
        self.assertNotIn(PSK, res.stdout, "the plan must never print the secret")
        self.assertFalse(self.fx.rundir.exists())
        # read-only probes are fine (the channel is live); no mutation may run
        for call in self.fx.calls():
            for mutation in ("interface add", "addr add", "link set", "hostapd",
                             "dnsmasq", "ip6tables"):
                self.assertNotIn(mutation, call, f"plan mutated: {call}")
        self.assertFalse(self.fx.state.exists())


class ApRulesTest(unittest.TestCase):

    def setUp(self):
        self.fx = Fixture()

    def tearDown(self):
        self.fx.cleanup()

    def test_ap_rules_dnat_then_drop(self):
        res = self.fx.rules("apply-ap")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

        chain = self.fx.chain("nat", "PI_TOR_AP_REDIRECT")
        self.assertIsNotNone(chain)
        # DNS to Pi-hole's own listener, TCP to tor's TransPort: DNAT, because
        # REDIRECT would land on the AP address where neither listens
        self.assertEqual(chain[0], "-p udp --dport 53 -j DNAT --to-destination 10.12.194.1:53")
        self.assertEqual(chain[1], "-p tcp --dport 53 -j DNAT --to-destination 10.12.194.1:53")
        self.assertEqual(chain[2], "-p tcp -j DNAT --to-destination 10.12.194.1:9040")
        # no RETURN: a guest must not reach the Pi's own services by IP
        self.assertEqual([l for l in chain if l.endswith("-j RETURN")], [])
        self.assertEqual(self.fx.chain("nat", "PREROUTING"), ["-i uap0 -j PI_TOR_AP_REDIRECT"])

        acl = self.fx.chain("filter", "PI_TOR_AP_IN")
        self.assertIsNotNone(acl)
        self.assertEqual(acl[-1], "-i uap0 -j DROP", f"the chain must end in DROP: {acl}")
        accepts = [l for l in acl if l.endswith("-j ACCEPT")]
        self.assertEqual(len(accepts), 4, acl)
        self.assertIn("-i uap0 -p udp -d 10.12.194.1 --dport 53 -j ACCEPT", acl)
        self.assertIn("-i uap0 -p tcp -d 10.12.194.1 --dport 53 -j ACCEPT", acl)
        self.assertIn("-i uap0 -p udp --dport 67 -j ACCEPT", acl)
        self.assertIn("-i uap0 -p tcp -d 10.12.194.1 --dport 9040 -j ACCEPT", acl)
        # management ports are not open to guests
        for port in ("--dport 22", "--dport 80", "--dport 8080"):
            self.assertFalse(any(port in l for l in acl), f"{port} exposed to guests: {acl}")
        self.assertEqual(self.fx.chain("filter", "INPUT"), ["-i uap0 -j PI_TOR_AP_IN"])
        # nothing is forwarded from the guest link
        self.assertEqual(self.fx.chain("filter", "FORWARD"), ["-i uap0 -j DROP"])
        # IPv6: dropped in ip6tables as well
        self.assertEqual(self.fx.chain("filter", "INPUT", self.fx.state6),
                         ["-i uap0 -j DROP"])
        self.assertEqual(self.fx.chain("filter", "FORWARD", self.fx.state6),
                         ["-i uap0 -j DROP"])

    def test_flush_ap_leaves_the_tether_rules_alone(self):
        self.assertEqual(self.fx.rules("apply").returncode, 0)
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)
        tether_chain = self.fx.chain("nat", "PI_TOR_REDIRECT")
        self.assertIsNotNone(tether_chain)

        res = self.fx.rules("flush-ap")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))
        self.assertIsNone(self.fx.chain("filter", "PI_TOR_AP_IN"))
        self.assertEqual(self.fx.chain("nat", "PREROUTING"), ["-i usb0 -j PI_TOR_REDIRECT"])
        self.assertEqual(self.fx.chain("nat", "PI_TOR_REDIRECT"), tether_chain)
        # the tether's own INPUT rules survive too
        self.assertIn("-i usb0 -p udp ! --dport 53 -j DROP",
                      self.fx.chain("filter", "INPUT"))
        # the ip6 chains stay (empty) or vanish; no DROP rule may survive
        self.assertIn(self.fx.chain("filter", "INPUT", self.fx.state6), (None, []))

    def test_apply_ap_refuses_without_ip6tables(self):
        bash = shutil.which("bash")
        env = self.fx.env(PATH="/nonexistent", IP6TABLES_BIN="")
        res = subprocess.run([bash, str(RULES), "apply-ap"], capture_output=True,
                             text=True, env=env, timeout=60)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("ip6tables", res.stderr)
        self.assertIn("refusing to apply AP rules", res.stderr)
        # refused before writing anything
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))

    def test_apply_ap_refuses_the_tether_interface(self):
        res = self.fx.rules("apply-ap", PI_TOR_AP_INTERFACE="usb0")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("must differ from PI_TOR_INTERFACE", res.stderr)
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))


class ApPolicyTest(unittest.TestCase):
    """The invariants that must not drift: one Pi-hole listener, no secret in
    the repo, and the unit wired to a root-only env file."""

    def test_pihole_keeps_its_single_interface_and_ap_adds_no_listener(self):
        compose = COMPOSE.read_text()
        self.assertEqual(compose.count("FTLCONF_dns_interface"), 1)
        self.assertNotIn("uap0", compose)
        self.assertNotIn("uap0", TORRC.read_text())
        # the AP's DNS path targets the existing listener, not a new one
        out = subprocess.run(["bash", str(RULES), "show-rules"],
                             capture_output=True, text=True,
                             env=dict(os.environ, PI_TOR_AP_INTERFACE="uap0"),
                             timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("-p udp --dport 53 -j DNAT --to-destination 10.12.194.1:53", out.stdout)

    def test_the_ap_env_example_carries_no_secret_and_is_not_rendered(self):
        text = ENV_EXAMPLE.read_text()
        self.assertIn("PI_TOR_AP_PSK=\n", text.replace("\r", ""))
        for line in text.splitlines():
            if line.startswith("PI_TOR_AP_PSK="):
                self.assertEqual(line, "PI_TOR_AP_PSK=",
                                 "the example must not ship a passphrase")
        import render
        self.assertNotIn(str(ENV_EXAMPLE.relative_to(REPO)), render.RENDER_TARGETS)

    def test_unit_contract(self):
        text = "\n".join(ln for ln in UNIT.read_text().splitlines()
                         if ln.strip() and not ln.lstrip().startswith("#"))
        self.assertIn("Type=oneshot", text)
        self.assertIn("RemainAfterExit=yes", text)
        self.assertIn("EnvironmentFile=-/etc/default/pi-tor", text)
        self.assertIn("EnvironmentFile=-/etc/default/pi-tor-ap", text)
        self.assertIn("After=pi-tor-stack.service", text)
        self.assertIn("Wants=pi-tor-stack.service", text)
        self.assertIn("ExecStart=/opt/pi-tor/bin/pi-tor-ap up", text)
        self.assertIn("ExecStop=/opt/pi-tor/bin/pi-tor-ap down", text)
        # a failed AP start stays failed and visible instead of restart-looping
        self.assertIn("Restart=no", text)


if __name__ == "__main__":
    unittest.main()
