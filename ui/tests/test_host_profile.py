"""bin/usb_host_profile: the NM profile plan, dry-run only.

Like test_tether.py, the script never touches a real NetworkManager: a
stub `nmcli` on PATH logs every invocation and serves the existing-profile
list from a fixture file. --dry-run is exercised as the default mode; the
stubs also make it structurally impossible for an assertion to miss a
real connection mutation.
"""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import REPO

SCRIPT = REPO / "bin" / "usb_host_profile"

NMCLI_STUB = """#!/bin/bash
printf '%s\\n' "nmcli $*" >> "$HP_FIXTURE/calls.log"
case "$*" in
  "-t -f NAME connection show") cat "$HP_FIXTURE/profiles.txt" 2>/dev/null ;;
esac
exit 0
"""

# any logged call containing one of these mutates NetworkManager state
MUTATIONS = ("connection add", "connection delete", "connection up")

PLAN_FRAGMENTS = (
    "match.interface-name=enx*,usb*",
    "connection.autoconnect yes",
    "connection.autoconnect-priority 10",
    "ipv4.method manual",
    "ipv4.addresses=10.12.194.2/24",
    "ipv4.never-default yes",
    # DNS is left at NM's default (empty) by OMITTING the property: nmcli
    # rejects a bare "ipv4.dns=" as "invalid property 'dns='".
    "would run: nmcli connection add type ethernet con-name pi-tor-gadget",
    "would run: nmcli connection up pi-tor-gadget",
)


class Case:
    def __init__(self, profiles):
        self.root = Path(tempfile.mkdtemp(prefix="host-profile-test-"))
        self.fixture = self.root
        self.stubbin = self.root / "stubbin"
        self.stubbin.mkdir()
        p = self.stubbin / "nmcli"
        p.write_text(NMCLI_STUB)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        (self.root / "profiles.txt").write_text(profiles)

    def run(self, *args, env_extra=None):
        env = dict(os.environ)
        env["PATH"] = f"{self.stubbin}:{env['PATH']}"
        env["HP_FIXTURE"] = str(self.fixture)
        env.update(env_extra or {})
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True, text=True, env=env, timeout=60)

    def calls(self):
        log = self.fixture / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def assert_no_mutation(self, testcase):
        for line in self.calls():
            for mutation in MUTATIONS:
                testcase.assertNotIn(mutation, line,
                                     f"mutating call recorded: {line}")


class HostProfileTest(unittest.TestCase):

    def test_host_profile_dry_run_changes_nothing(self):
        """--dry-run prints the exact nmcli plan (static addr, no gateway,
        never-default, empty dns, name-glob match, autoconnect) and only
        reads: no connection add/delete/up is ever executed."""
        case = Case(profiles="")
        res = case.run("--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        for fragment in PLAN_FRAGMENTS:
            self.assertIn(fragment, res.stdout)
        # No planned argument may carry an empty value: nmcli parses a bare
        # "ipv4.dns=" as the property name "dns=" and aborts the whole
        # connection add. This is the assertion that would have caught it.
        for token in res.stdout.split():
            self.assertFalse(
                token.startswith(("ipv4.", "connection.", "match.")) and token.endswith("="),
                f"empty-valued nmcli argument in the plan: {token!r}",
            )
        self.assertNotIn("connection delete", res.stdout)
        case.assert_no_mutation(self)
        # the existence check is the only real (stubbed) call, and it is
        # the read-only listing
        self.assertIn("nmcli -t -f NAME connection show", case.calls())

    def test_host_profile_refuses_without_force_when_present(self):
        """A profile named pi-tor-gadget already there: refuse with the
        --force hint and record no mutation; --force --dry-run then plans
        the delete+re-add while still changing nothing."""
        case = Case(profiles="lo\npi-tor-gadget\nanother-profile\n")
        res = case.run()
        self.assertEqual(res.returncode, 1)
        self.assertIn("already exists", res.stderr)
        self.assertIn("--force", res.stderr)
        self.assertIn("--dry-run", res.stderr)
        self.assertIn("pi-tor-gadget", res.stderr)
        case.assert_no_mutation(self)

        res = case.run("--force", "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("replacing profile 'pi-tor-gadget'", res.stdout)
        self.assertIn("would run: nmcli connection delete pi-tor-gadget",
                      res.stdout)
        for fragment in PLAN_FRAGMENTS:
            self.assertIn(fragment, res.stdout)
        case.assert_no_mutation(self)

    def test_host_profile_remove_dry_run(self):
        """--remove --dry-run plans the deletion; removing an absent profile
        is a no-op note instead of a refusal."""
        case = Case(profiles="wired-pi-tor-old\npi-tor-gadget\n")
        res = case.run("--remove", "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("would run: nmcli connection delete pi-tor-gadget",
                      res.stdout)
        self.assertNotIn("connection add", res.stdout)
        case.assert_no_mutation(self)

        absent = Case(profiles="wired-pi-tor-old\n")
        res = absent.run("--remove", "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("nothing to remove", res.stdout)


if __name__ == "__main__":
    unittest.main()
