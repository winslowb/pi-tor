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
README = REPO / "README.md"
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
  "-o -4 addr show")
    [ "${AP_TEST_IP_ADDR_FAIL:-}" = 1 ] && exit 1
    printf '2: wlan0    inet 192.168.0.188/24 brd 192.168.0.255 scope global wlan0\\n'
    if [ "${AP_TEST_ADDR_CONFLICT:-}" = 1 ]; then
      printf '9: lan0     inet 10.12.195.7/24 brd 10.12.195.255 scope global lan0\\n'
    fi
    if [ "${AP_TEST_ADDR_WIDE:-}" = 1 ]; then
      printf '3: wlan0    inet 10.12.0.5/16 brd 10.12.255.255 scope global wlan0\\n'
    fi
    exit 0 ;;
  "-o -4 addr show dev uap0")
    [ -f "$AP_ROOT/addr" ] && cat "$AP_ROOT/addr"
    exit 0 ;;
  "link set uap0 up") exit 0 ;;
  "addr add 10.12.195.1/24 dev uap0")
    printf 'inet 10.12.195.1/24 scope global uap0\\n' > "$AP_ROOT/addr" ;;
  "link del uap0")
    [ "${AP_TEST_IP_DEL_FAIL:-}" = 1 ] && exit 1
    rm -rf "$AP_NET_DIR/uap0" "$AP_SYSCTL_DIR/uap0"; rm -f "$AP_ROOT/addr" ;;
  *) exit 2 ;;
esac
"""

SS_STUB = """#!/bin/sh
printf 'ss %s\\n' "$*" >> "$AP_CALLS"
case "$*" in
  "-Hltn")
    [ "${AP_TEST_NO_TRANS:-}" = 1 ] || printf 'LISTEN 0 4096 10.12.194.1:9040 0.0.0.0:*\\n'
    exit 0 ;;
  "-Hlun")
    [ "${AP_TEST_NO_DNS:-}" = 1 ] || printf 'UNCONN 0 0 10.12.194.1:53 0.0.0.0:*\\n'
    exit 0 ;;
  *) exit 1 ;;
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
        _write(self.stubbin / "ss", SS_STUB)

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
            PI_TOR_AP_ENVFILE=str(self.root / "no-such-env-file"),
            PI_TOR_SS=str(self.stubbin / "ss"),
            PI_TOR_FAKE_LOG=str(self.calls_log),
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
        # None drops a key entirely: "unset" and "set to empty" differ
        for key, val in over.items():
            if val is None:
                env.pop(key, None)
            else:
                env[key] = val
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

    def test_up_reads_the_env_file_instead_of_the_argv(self):
        cfg = self.fx.root / "default-pi-tor-ap"
        cfg.write_text(
            "# the file systemd loads for the unit\n"
            'PI_TOR_AP_SSID="Guest Net"\n'
            f"PI_TOR_AP_PSK={PSK}\n"
            "\n"
            "PI_TOR_AP_SUBNET=10.12.195.0/24\n"
            "PI_TOR_AP_GATEWAY=10.12.195.1\n"
        )
        res = self.fx.run("up", PI_TOR_AP_ENVFILE=str(cfg),
                          PI_TOR_AP_SSID=None, PI_TOR_AP_PSK=None)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        conf = (self.fx.rundir / "hostapd.conf").read_text()
        self.assertIn("ssid=Guest Net", conf)
        self.assertIn(f"wpa_passphrase={PSK}", conf)
        # every stub logs its argv: the secret never travels on one
        self.assertNotIn(PSK, "\n".join(self.fx.calls()))

    def test_env_file_is_parsed_not_executed(self):
        marker = self.fx.root / "pwned"
        cfg = self.fx.root / "default-pi-tor-ap"
        cfg.write_text(
            "PI_TOR_AP_SSID=Guests\n"
            f"PI_TOR_AP_PSK={PSK}\n"
            f"PI_TOR_AP_EVIL=$(touch {marker})\n"
            f"SHELL_COMMAND=`touch {marker}`\n"
            # a PATH the loader must not adopt: the run could not mkdir/chmod
            "PATH=/nonexistent\n"
        )
        res = self.fx.run("up", PI_TOR_AP_ENVFILE=str(cfg),
                          PI_TOR_AP_SSID=None, PI_TOR_AP_PSK=None)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse(marker.exists(), "the env file must never be executed")
        self.assertIn("ssid=Guests", (self.fx.rundir / "hostapd.conf").read_text())

    def test_up_refuses_a_gateway_that_is_not_a_usable_host(self):
        for gw in ("10.12.195.0", "10.12.195.255"):
            res = self.fx.run("up", PI_TOR_AP_GATEWAY=gw)
            self.assertNotEqual(res.returncode, 0, gw)
            self.assertIn("not a usable host address", res.stderr)
        self.assertEqual(self.fx.calls(), [])
        self.assertFalse(self.fx.rundir.exists())

    def test_up_refuses_an_invalid_or_gateway_containing_dhcp_pool(self):
        cases = (
            ({"PI_TOR_AP_DHCP_START": "10.12.196.10"}, "not inside PI_TOR_AP_SUBNET"),
            ({"PI_TOR_AP_DHCP_END": "10.12.195.255"}, "not a usable host address"),
            ({"PI_TOR_AP_DHCP_START": "10.12.195.9", "PI_TOR_AP_DHCP_END": "10.12.195.9a"},
             "is not an IPv4 address"),
            ({"PI_TOR_AP_DHCP_START": "10.12.195.200", "PI_TOR_AP_DHCP_END": "10.12.195.150"},
             "is above"),
            ({"PI_TOR_AP_DHCP_START": "10.12.195.1", "PI_TOR_AP_DHCP_END": "10.12.195.99"},
             "is inside the DHCP pool"),
        )
        for over, msg in cases:
            res = self.fx.run("up", **over)
            self.assertNotEqual(res.returncode, 0, over)
            self.assertIn(msg, res.stderr, over)
        self.assertEqual(self.fx.calls(), [])
        self.assertFalse(self.fx.rundir.exists())

    def test_up_refuses_a_subnet_the_board_already_has_an_address_in(self):
        res = self.fx.run("up", AP_TEST_ADDR_CONFLICT="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("already configured on this host", res.stderr)
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))

    def test_up_refuses_any_overlap_with_the_tether_subnet(self):
        # the guest /24 is compared to the tether's, not the two subnet strings:
        # this pair used to differ textually and still share 10.12.194.0/24
        res = self.fx.run("up", PI_TOR_AP_SUBNET="10.12.194.128/24",
                          PI_TOR_AP_GATEWAY="10.12.194.200",
                          PI_TOR_AP_DHCP_START="10.12.194.201",
                          PI_TOR_AP_DHCP_END="10.12.194.250")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("must not overlap the tether subnet", res.stderr)
        self.assertEqual(self.fx.calls(), [])

    def test_up_refuses_a_tether_net_that_contains_the_guest_subnet(self):
        # 10.12.195.0/24 sits inside a /21 tether and shares no address string
        # with it: only a network comparison sees that. A tether CIDR nothing
        # can parse has to refuse too, not read as "no overlap".
        cases = (
            ({"PI_TOR_SUBNET": "10.12.192.0/21"}, "must not overlap the tether subnet"),
            ({"PI_TOR_SUBNET": "10.12.195.0/24"}, "must not overlap the tether subnet"),
            ({"PI_TOR_SUBNET": "10.12.195.0"}, "is not an IPv4 CIDR"),
            ({"PI_TOR_SUBNET": "10.12.195.0/33"}, "is not an IPv4 CIDR"),
        )
        for over, msg in cases:
            res = self.fx.run("up", **over)
            self.assertNotEqual(res.returncode, 0, over)
            self.assertIn(msg, res.stderr, over)
        self.assertEqual(self.fx.calls(), [], "nothing may be created for an overlapping tether")
        self.assertFalse(self.fx.rundir.exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))

    def test_up_refuses_when_the_host_addresses_cannot_be_read(self):
        # a failed `ip addr` used to read as "no addresses on this host", which
        # passed the conflict check silently; it has to stop before any change
        res = self.fx.run("up", AP_TEST_IP_ADDR_FAIL="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("cannot read this host's IPv4 addresses", res.stderr)
        self.assertEqual(self.fx.calls(), ["ip -o -4 addr show"],
                         "nothing may change after an unreadable address list")
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))
        self.assertFalse(self.fx.rundir.exists())

    def test_up_refuses_when_pihole_or_tor_is_not_listening(self):
        for over, msg in (({"AP_TEST_NO_TRANS": "1"}, "no egress"),
                          ({"AP_TEST_NO_DNS": "1"}, "no resolver")):
            res = self.fx.run("up", **over)
            self.assertNotEqual(res.returncode, 0, over)
            self.assertIn(msg, res.stderr, over)
        # refused before serving anything: no interface, no rules, no leases
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))
        self.assertFalse(self.fx.rundir.exists())

    def test_rollback_reports_an_incomplete_teardown_instead_of_aborting(self):
        res = self.fx.run("up", AP_TEST_HOSTAPD_FAIL="1", AP_TEST_IP_DEL_FAIL="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("refused to start", res.stderr)
        self.assertTrue((self.fx.net / "uap0").exists(), "the stub did not fail the delete")
        # down() dies on the incomplete teardown; the trap must still report it
        self.assertIn("WARNING: rollback incomplete", res.stdout + res.stderr)


    def test_env_file_only_sets_allowlisted_keys(self):
        # Key names, not values: a PI_TOR_* name that is not configured must
        # never reach the shell's own evaluation, and the internal control
        # variables (fake root, rules path, the runtime dir) must not be
        # loadable from a file at all.
        marker = self.fx.root / "pwned"
        elsewhere = self.fx.root / "elsewhere"
        cfg = self.fx.root / "default-pi-tor-ap"
        cfg.write_text(
            "PI_TOR_AP_SSID=Guests\n"
            f"PI_TOR_AP_PSK={PSK}\n"
            f"PI_TOR_AP_INTERFACE;touch {marker}=x\n"
            f"PI_TOR_AP_SUBNET`touch {marker}`=x\n"
            "PI_TOR_FAKE_ROOT=0\n"
            "PI_TOR_RULES=/nonexistent/pi-tor-rules.sh\n"
            f"PI_TOR_AP_RUNDIR={elsewhere}\n"
            "PI_TOR_AP_EVIL=1\n"
        )
        res = self.fx.run("up", PI_TOR_AP_ENVFILE=str(cfg), PI_TOR_AP_SSID=None)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse(marker.exists(), "a key name from the file was evaluated")
        self.assertIn("ssid=Guests", (self.fx.rundir / "hostapd.conf").read_text())
        self.assertFalse(elsewhere.exists(), "PI_TOR_AP_RUNDIR was taken from the file")
        self.assertIsNotNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"),
                             "the rules path was taken from the file")

    def test_up_refuses_a_gateway_outside_the_ap_subnet(self):
        # the DHCP network has to be the firewall's source subnet, so the
        # subnet decides it; a gateway-derived network would validate itself
        res = self.fx.run("up", PI_TOR_AP_GATEWAY="10.12.196.1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("is not inside PI_TOR_AP_SUBNET", res.stderr)
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))
        self.assertFalse(self.fx.rundir.exists())

    def test_up_refuses_a_subnet_inside_a_wider_uplink_route(self):
        # no address string matches 10.12.195.0/24, but this host's /16 covers
        # it: only a CIDR overlap check sees that
        res = self.fx.run("up", AP_TEST_ADDR_WIDE="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("already configured on this host", res.stderr)
        self.assertIn("10.12.0.5/16", res.stderr)
        self.assertFalse((self.fx.net / "uap0").exists())
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))

    def test_a_rundir_that_is_not_its_own_is_refused_and_never_removed(self):
        # `down` runs rm -rf on this path, so production may only use the
        # directory the script owns (a fake-root fixture is the exception)
        broad = self.fx.root / "broad"
        broad.mkdir()
        (broad / "keep").write_text("x")
        for action in ("down", "up"):
            res = self.fx.run(action, PI_TOR_AP_RUNDIR=str(broad), PI_TOR_FAKE_ROOT=None)
            self.assertNotEqual(res.returncode, 0, action)
            self.assertIn("must be /run/pi-tor-ap", res.stderr, action)
        self.assertTrue((broad / "keep").exists(),
                        "a directory the script does not own was removed")


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
        self.assertEqual(len(accepts), 5, acl)
        self.assertIn("-i uap0 -s 10.12.195.0/24 -p udp -d 10.12.194.1 --dport 53 -j ACCEPT", acl)
        self.assertIn("-i uap0 -s 10.12.195.0/24 -p tcp -d 10.12.194.1 --dport 53 -j ACCEPT", acl)
        self.assertIn("-i uap0 -s 10.12.195.0/24 -p tcp -d 10.12.194.1 --dport 9040 -j ACCEPT", acl)
        # DHCP: the no-lease bootstrap and a renewal, both pinned to DHCP's pair
        self.assertIn("-i uap0 -s 0.0.0.0/32 -p udp -d 255.255.255.255 "
                      "--sport 68 --dport 67 -j ACCEPT", acl)
        self.assertIn("-i uap0 -s 10.12.195.0/24 -p udp -d 10.12.195.1 "
                      "--sport 68 --dport 67 -j ACCEPT", acl)
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

    def _seed(self, table, chain, rule, state=None):
        """Pre-seed a chain the way Docker, a distro firewall or a stale run would."""
        f = Path(state or self.fx.state) / table / chain
        f.parent.mkdir(parents=True, exist_ok=True)
        with f.open("a") as fh:
            fh.write(rule + "\n")

    def test_ap_input_accepts_are_scoped_to_the_guest_subnet(self):
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)
        acl = self.fx.chain("filter", "PI_TOR_AP_IN")
        for rule in [l for l in acl if l.endswith("-j ACCEPT")]:
            self.assertTrue(
                "-s 10.12.195.0/24" in rule or "-s 0.0.0.0/32" in rule,
                f"an ACCEPT without a pinned source takes spoofed LAN traffic: {rule}")
        # the one unscoped-source accept has nothing but DHCP to talk to
        boot = [l for l in acl if "-s 0.0.0.0/32" in l]
        self.assertEqual(len(boot), 1, acl)
        self.assertIn("-d 255.255.255.255", boot[0])
        self.assertIn("--sport 68 --dport 67", boot[0])

    def test_ap_hooks_land_ahead_of_preseeded_broad_accepts(self):
        # a hostile/legacy ruleset installed before the AP: broad ACCEPTs that
        # would swallow every guest packet if the AP hooks were appended
        for chain in ("INPUT", "FORWARD"):
            self._seed("filter", chain, "-p tcp -j ACCEPT")
            self._seed("filter", chain, "-i uap0 -j ACCEPT")
            self._seed("filter", chain, "-j ACCEPT", state=self.fx.state6)
        self._seed("nat", "PREROUTING",
                   "-p tcp --dport 53 -j DNAT --to-destination 172.17.0.2:53")

        res = self.fx.rules("apply-ap")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

        # position 1 everywhere: nothing earlier can accept the packet first
        self.assertEqual(self.fx.chain("filter", "INPUT")[0], "-i uap0 -j PI_TOR_AP_IN")
        self.assertEqual(self.fx.chain("filter", "FORWARD")[0], "-i uap0 -j DROP")
        self.assertEqual(self.fx.chain("filter", "INPUT", self.fx.state6)[0],
                         "-i uap0 -j DROP")
        self.assertEqual(self.fx.chain("filter", "FORWARD", self.fx.state6)[0],
                         "-i uap0 -j DROP")
        self.assertEqual(self.fx.chain("nat", "PREROUTING")[0],
                         "-i uap0 -j PI_TOR_AP_REDIRECT")
        # the seeded rules survive, behind the AP's
        self.assertIn("-p tcp -j ACCEPT", self.fx.chain("filter", "INPUT")[1:])

    def test_flush_ap_removes_the_hooks_from_a_preseeded_ruleset(self):
        self._seed("filter", "INPUT", "-p tcp -j ACCEPT")
        self._seed("filter", "FORWARD", "-j ACCEPT", state=self.fx.state6)
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)
        self.assertEqual(self.fx.rules("flush-ap").returncode, 0)

        self.assertEqual(self.fx.chain("filter", "INPUT"), ["-p tcp -j ACCEPT"])
        self.assertEqual(self.fx.chain("filter", "FORWARD", self.fx.state6), ["-j ACCEPT"])
        self.assertEqual(self.fx.chain("nat", "PREROUTING"), [])
        self.assertIsNone(self.fx.chain("filter", "PI_TOR_AP_IN"))
        self.assertIsNone(self.fx.chain("nat", "PI_TOR_AP_REDIRECT"))

    def test_reapply_never_exposes_an_unfiltered_window(self):
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)
        seen = len(self.fx.calls())
        self.assertEqual(self.fx.rules("apply-ap").returncode, 0)

        log = self.fx.calls()[seen:]
        guard_in = "iptables -t filter -I INPUT 1 -i uap0 -j DROP"
        guard_out = "iptables -t filter -D INPUT -i uap0 -j DROP"
        flush = "iptables -t filter -F PI_TOR_AP_IN"
        refill = [i for i, call in enumerate(log)
                  if call == "iptables -t filter -A PI_TOR_AP_IN -i uap0 -j DROP"]
        self.assertIn(guard_in, log, log)
        self.assertIn(flush, log, log)
        self.assertTrue(refill, log)
        # the guest DROP covers the flush/refill, and only then comes back out
        self.assertLess(log.index(guard_in), log.index(flush),
                        "the guest chain was flushed while it was still reachable")
        self.assertLess(refill[-1], log.index(guard_out),
                        "the temporary DROP was removed before the refill finished")
        self.assertEqual(self.fx.chain("filter", "PI_TOR_AP_IN")[-1], "-i uap0 -j DROP")

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


class ApReadmeTest(unittest.TestCase):
    """The AP procedure has to be runnable as written: a unit that is enabled
    but never installed, or a distro unit apt starts because it was masked too
    late, is a documented failure rather than a papercut."""

    def section(self):
        text = README.read_text()
        start = text.index("## Wi-Fi AP (guest) mode")
        return text[start:text.index("\n## ", start + 1)]

    def test_the_unit_is_installed_and_reloaded_before_it_is_enabled(self):
        sec = self.section()
        install = sec.index("systemd/pi-tor-ap.service /etc/systemd/system/")
        reload_ = sec.index("systemctl daemon-reload")
        enable = sec.index("systemctl enable --now pi-tor-ap.service")
        self.assertLess(install, reload_, "daemon-reload must follow the unit install")
        self.assertLess(reload_, enable, "enable --now needs the unit on disk first")

    def test_the_distro_units_are_masked_before_apt_can_start_them(self):
        sec = self.section()
        stop = sec.index("systemctl stop dnsmasq.service hostapd.service")
        mask = sec.index("systemctl mask dnsmasq.service hostapd.service")
        install = sec.index("apt install hostapd")
        self.assertLess(stop, mask, "an already-running unit is stopped before it is masked")
        self.assertLess(mask, install, "apt starts both units as it installs them: mask first")


if __name__ == "__main__":
    unittest.main()
