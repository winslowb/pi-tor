"""bin/gadget-watchdog.sh: decision logic driven by fixtures, never the real gadget.

The script runs under `sh` (dash) as a subprocess with a stub PATH -- `ip`
(neighbour table), `sleep` (records the duration, does not sleep), plus
WATCH_PROBE_CMD / WATCH_RELOAD_CMD pointed at stub commands that log every
invocation to calls.log. Interface counters come from a fixture sysfs tree
via WATCH_SYSFS; the probe stub simulates the Pi's continued transmitting
by advancing the tx fixture (and rx too when the host is still receiving),
so "rx stagnant while tx advances" is produced with static files.
WATCH_RELOAD_CMD can never be a real modprobe, and WATCH_STATE_FILE lives
in the tmp dir.
"""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import REPO

SCRIPT = REPO / "bin" / "gadget-watchdog.sh"
UNIT = REPO / "systemd" / "pi-tor-gadget-watchdog.service"

NEIGH_IDLE = """10.12.194.21 dev eth0 lladdr de:ad:be:ef:00:21 REACHABLE
192.168.0.1 dev wlan0 lladdr a1:b2:c3:d4:e5:06 REACHABLE
10.12.194.20 dev eth0  REACHABLE
"""
# idempotent build of the tethered table: + the host line (with lladdr)
NEIGH_TETHERED = NEIGH_IDLE + "10.12.194.2 dev usb0 lladdr 02:34:56:78:9a:bc STALE\n"

FIB_SELF_ADDR = """           +-- 10.12.194.0/24 2 0 1
              |-- 10.12.194.2
              /32 link UNICAST
              |-- 10.12.194.1
              /32 host LOCAL
"""

IP_STUB = """#!/bin/sh
printf '%s\\n' "ip $*" >> "$WD_FIXTURE/calls.log"
cat "$WD_FIXTURE/neigh.txt" 2>/dev/null
exit 0
"""

SLEEP_STUB = """#!/bin/sh
printf '%s\\n' "sleep $*" >> "$WD_FIXTURE/calls.log"
"""

# A probe call means time passes on the link: the Pi keeps transmitting, so
# the tx counter fixture advances by 7 per call; if the fixture dir has
# rx_grows, the HOST is still receiving, so rx advances too.
PROBE_STUB = """#!/bin/sh
printf '%s\\n' "probe $*" >> "$WD_FIXTURE/calls.log"
st="${WATCH_SYSFS:?}/class/net/usb0/statistics"
tx=$(cat "$st/tx_packets"); printf '%s\\n' $((tx + 7)) > "$st/tx_packets"
if [ -f "$WD_FIXTURE/rx_grows" ]; then
  rx=$(cat "$st/rx_packets"); printf '%s\\n' $((rx + 3)) > "$st/rx_packets"
fi
if [ -f "$WD_FIXTURE/probe_fail_all" ]; then exit 1; fi
n=$(cat "$WD_FIXTURE/probe_count" 2>/dev/null); n=$((n + 1))
printf '%s\\n' "$n" > "$WD_FIXTURE/probe_count"
[ -f "$WD_FIXTURE/probe_fail_first" ] && [ "$n" -le 1 ] && exit 1
exit 0
"""

RELOAD_STUB = """#!/bin/sh
printf '%s\\n' "reload $*" >> "$WD_FIXTURE/calls.log"
exit 0
"""


class Case:
    """Fixture run of the watchdog: stub commands + fixture sysfs + state."""

    def __init__(self, tethered=True, fail="none", rx_grows=False, fib=True):
        self.root = Path(tempfile.mkdtemp(prefix="watchdog-test-"))
        self.fixture = self.root
        self.stubbin = self.root / "stubbin"
        self.sysfs = self.root / "sysfs"
        self.stubbin.mkdir()
        for name, text in (("ip", IP_STUB), ("sleep", SLEEP_STUB),
                           ("probe", PROBE_STUB), ("reload", RELOAD_STUB)):
            p = self.stubbin / name
            p.write_text(text)
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
        st = self.sysfs / "class/net/usb0/statistics"
        st.mkdir(parents=True)
        (st / "rx_packets").write_text("1\n")
        (st / "tx_packets").write_text("101\n")
        (self.fixture / "neigh.txt").write_text(
            NEIGH_TETHERED if tethered else NEIGH_IDLE)
        (self.fixture / ("fib.txt" if fib else "fib-absent.txt")).write_text(
            FIB_SELF_ADDR if fib else FIB_SELF_ADDR.replace(
                "              |-- 10.12.194.1\n              /32 host LOCAL\n", ""))
        for flag in ((fail == "all" and ["probe_fail_all"]) or
                     (fail == "first" and ["probe_fail_first"]) or [None]):
            if flag:
                (self.fixture / flag).write_text("")
        if rx_grows:
            (self.fixture / "rx_grows").write_text("")

    def run(self, cycles):
        env = dict(os.environ)
        env["PATH"] = f"{self.stubbin}:{env['PATH']}"
        env["WD_FIXTURE"] = str(self.fixture)
        env["WATCH_SYSFS"] = str(self.sysfs)
        env["WATCH_PROBE_CMD"] = str(self.stubbin / "probe")
        env["WATCH_RELOAD_CMD"] = f"{self.stubbin}/reload"
        env["WATCH_STATE_FILE"] = str(self.fixture / "state.conf")
        env["WATCH_FIB_TRIE"] = str(
            self.fixture / (("fib.txt" if (self.fixture / "fib.txt").exists()
                             else "fib-absent.txt")))
        env["WATCH_MAX_CYCLES"] = str(cycles)
        return subprocess.run(
            ["sh", str(SCRIPT)], capture_output=True, text=True,
            env=env, timeout=120)

    def calls(self):
        log = self.fixture / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def state(self):
        return (self.fixture / "state.conf").read_text()


class WatchdogDecisionTest(unittest.TestCase):

    def lines_of(self, res):
        # decision/state lines only: the single startup config line is
        # journal metadata, not a tether event
        return [ln for ln in res.stdout.splitlines()
                if ln.startswith("[gadget-watchdog]") and "watchdog on " not in ln]

    def cmd_count(self, case, name):
        """invocations of the stub command `name` (e.g. 'reload', ignoring
        the arg-string)"""
        return len([c for c in case.calls() if c.split()[0] == name])

    def test_watchdog_ignores_idle_link_without_host(self):
        """No lladdr for the host in the neighbour table: no probes, no
        reloads, no output -- an idle/gone host is not a stalled tether."""
        case = Case(tethered=False, fail="all")
        res = case.run(cycles=3)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.lines_of(res), [])
        self.assertTrue(res.stdout.startswith(
            "[gadget-watchdog] watchdog on usb0"), res.stdout)
        self.assertEqual(self.cmd_count(case, "probe"), 0)
        self.assertEqual(self.cmd_count(case, "reload"), 0)
        self.assertEqual(self.cmd_count(case, "ip"), 3)

    def test_watchdog_requires_two_failed_probes(self):
        """probe 1/2 fails, probe 2/2 succeeds -> recovery, never a reload."""
        case = Case(tethered=True, fail="first")
        res = case.run(cycles=2)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.cmd_count(case, "reload"), 0)
        joined = "\n".join(self.lines_of(res))
        self.assertIn("probe 1/2 to 10.12.194.2 failed", joined)
        self.assertIn("recovered: 10.12.194.2 answers probe 2/2", joined)

    def test_watchdog_requires_rx_stagnant_while_tx_advances(self):
        """2/2 failed probes reload only when rx stays still while tx moves;
        rx advancing (traffic arriving, e.g. ping dropped by the host
        firewall) is exactly the false positive this gate refuses."""
        stalled = Case(tethered=True, fail="all")
        res = stalled.run(cycles=1)
        self.assertEqual(res.returncode, 0, res.stderr)
        # exactly one reload invocation, whatever its arg-string
        self.assertEqual(self.cmd_count(stalled, "reload"), 1)
        joined = "\n".join(self.lines_of(res))
        self.assertIn("stall confirmed: probes 2/2 failed to 10.12.194.2, "
                      "rx 1→1 stationary, tx 101→115 advanced", joined)
        self.assertIn("reload attempt 1", joined)
        self.assertIn("is back with 10.12.194.1 after 0s; resuming probes", joined)

        alive_rx = Case(tethered=True, fail="all", rx_grows=True)
        res = alive_rx.run(cycles=1)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.cmd_count(alive_rx, "reload"), 0)
        joined = "\n".join(self.lines_of(res))
        self.assertIn("no reload: 2/2 probes to 10.12.194.2 failed but the "
                      "counters disagree (rx 1→7, tx 101→115;", joined)

    def test_watchdog_respects_hourly_cap(self):
        """3 reloads, then the 4th failed window is refused with the cap line
        (logged once), the backoffs 60 s/180 s happen between attempts, and
        the persisted state keeps the cap across restarts."""
        case = Case(tethered=True, fail="all")
        res = case.run(cycles=5)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.cmd_count(case, "reload"), 3)
        sleeps = [c for c in case.calls() if c.startswith("sleep")]
        self.assertIn("sleep 60", sleeps)
        self.assertIn("sleep 180", sleeps)
        joined = "\n".join(self.lines_of(res))
        self.assertEqual(joined.count("reload cap reached (3/3"), 1)
        self.assertIn("suspending reloads until the window clears", joined)
        self.assertEqual(joined.count("reload attempt"), 3)
        self.assertIn("RELOADS='3'\nWINDOW_START=", case.state())
        self.assertIn("CAP_LOGGED='1'\n", case.state())

    def test_watchdog_never_runs_reload_in_dry_analysis(self):
        """A healthy fixture: the reload command is reachable but never
        invoked, and the healthy tether logs nothing (beyond the startup
        config line)."""
        case = Case(tethered=True, fail="none")
        res = case.run(cycles=2)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.lines_of(res), [])
        self.assertTrue(res.stdout.startswith(
            "[gadget-watchdog] watchdog on usb0"), res.stdout)
        self.assertEqual(self.cmd_count(case, "reload"), 0)
        self.assertEqual(self.cmd_count(case, "probe"), 2)

    def test_watchdog_recovery_wait_is_bounded(self):
        """After a reload, resuming waits at most RECOVER_SECONDS (20) for
        the interface and the Pi's gadget address (fib fixture has none)."""
        case = Case(tethered=True, fail="all", fib=False)
        res = case.run(cycles=1)
        self.assertEqual(res.returncode, 0, res.stderr)
        # bounded: exactly RECOVER_SECONDS one-second steps, then give up
        self.assertEqual(case.calls().count("sleep 1"), 20)
        joined = "\n".join(self.lines_of(res))
        self.assertIn("still absent after 20s; resuming probes anyway", joined)


class WatchdogUnitTest(unittest.TestCase):
    def test_watchdog_service_unit_contract(self):
        unit = UNIT.read_text()
        # non-comment lines only: the acceptance is about what the unit
        # WIRES, and its comment legitimately describes the avoidance
        text = "\n".join(ln for ln in unit.splitlines()
                         if not ln.lstrip().startswith("#"))
        self.assertIn("ExecStart=/opt/pi-tor/bin/gadget-watchdog.sh", text)
        self.assertIn("Restart=always", text)
        self.assertIn("Type=simple", text)
        # the watchdog owns its env names; the unit must not wire the
        # stack's PI_TOR_INTERFACE (which belongs to the torrc rendering)
        self.assertNotIn("PI_TOR_INTERFACE", text)
        self.assertNotIn("EnvironmentFile=", text)


if __name__ == "__main__":
    unittest.main()
