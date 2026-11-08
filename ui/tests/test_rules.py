"""bin/pi-tor-rules.sh protected hosts: rule order + IPv4 rejection, and
the env plumbing from the schema into the rules script."""
import os
import re
import shutil
import subprocess
import unittest

from helpers import REPO, make_config_tree

import apply as apply_mod
import config_schema as schema
import dockerops

RULES = REPO / "bin" / "pi-tor-rules.sh"


class ProtectedHostRuleOrderTest(unittest.TestCase):

    def _show(self, extra_env=None):
        env = dict(os.environ)
        env.update(extra_env or {})
        return subprocess.run(["bash", str(RULES), "show-rules"],
                              capture_output=True, text=True, env=env,
                              timeout=30)

    def test_protected_host_returns_before_redirects(self):
        """Generate the script's rule list: every RETURN precedes both the
        --dport 53 rules and the catch-all tcp REDIRECT."""
        p = self._show()
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = [l for l in p.stdout.splitlines()
                 if " -t nat -A PI_TOR_REDIRECT " in l]
        ret = [i for i, l in enumerate(lines) if l.endswith("-j RETURN")]
        dns = [i for i, l in enumerate(lines) if "--dport 53" in l]
        bare = [i for i, l in enumerate(lines)
                if re.search(r"-p tcp -j REDIRECT ", l)]
        self.assertTrue(ret, f"no RETURN rules generated: {p.stdout}")
        self.assertTrue(dns, f"no dport-53 rules generated: {p.stdout}")
        self.assertTrue(bare, f"no bare tcp REDIRECT generated: {p.stdout}")
        after_all = max(dns + bare)
        self.assertTrue(all(i < after_all for i in ret),
                        f"RETURN must precede the redirects: {lines}")
        self.assertGreater(max(bare), max(dns),
                           "catch-all tcp REDIRECT must come last")
        # default env protects exactly the gateway
        self.assertEqual(
            [l for l in lines if l.endswith("-j RETURN")],
            [f"iptables -t nat -A PI_TOR_REDIRECT -d 10.12.194.1 -j RETURN"])

    def test_multiple_protected_hosts_keep_order_and_flush_removes_them(self):
        p = self._show({"PI_TOR_PROTECTED_HOSTS":
                        "10.12.194.1, 10.12.194.2 10.0.0.5"})
        self.assertEqual(p.returncode, 0, p.stderr)
        ret = [l for l in p.stdout.splitlines() if l.endswith("-j RETURN")]
        self.assertEqual(len(ret), 3)
        dns_idx = p.stdout.splitlines().index(next(
            l for l in p.stdout.splitlines() if "--dport 53" in l))
        ret_idx = [p.stdout.splitlines().index(r) for r in ret]
        self.assertTrue(all(i < dns_idx for i in ret_idx))

        src = RULES.read_text()
        flush = src[src.index("flush_rules()"):src.index('case "$ACTION"')]
        # flush flushes and deletes the whole chain, which removes the
        # RETURN rules with it — that stays true
        self.assertIn('-F "$CHAIN"', flush)
        self.assertIn('-X "$CHAIN"', flush)
        self.assertIn("delete_rule_if_present nat PREROUTING -i", flush)

    def test_protected_host_rejects_non_ipv4(self):
        # schema level: per-field message
        cfg = dict(schema.defaults())
        cfg["protected_hosts"] = "10.12.194.1, banana, 10.0.0.5/24"
        errors = schema.validate(cfg)
        self.assertIn("protected_hosts", [e["key"] for e in errors])
        msg = " ".join(e["message"] for e in errors
                       if e["key"] == "protected_hosts")
        self.assertIn("'banana' must be an IPv4 address", msg)
        self.assertIn("'10.0.0.5/24' must be an IPv4 address", msg)
        good = dict(schema.defaults())
        good["protected_hosts"] = "10.12.194.1  10.44.0.1,10.55.0.9"
        self.assertEqual(schema.validate(good), [])

        # script level (no iptables run): rejects with a clear line
        p = self._show({"PI_TOR_PROTECTED_HOSTS": "banana,10.0.0.1"})
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not an IPv4 address", p.stderr)

    def test_protected_hosts_change_reapplies_rules(self):
        self.assertIn("protected_hosts", apply_mod.RULES_KEYS)


class ProtectedHostParseTest(unittest.TestCase):

    def test_empty_falls_back_to_gateway(self):
        src = RULES.read_text()
        # the script default: unset/empty -> gateway (validation only runs
        # for apply/show-rules; a flush with a stale bad value still works)
        self.assertIn('PROTECTED_HOSTS="${PI_TOR_PROTECTED_HOSTS:-${GATEWAY_IP}}"',
                      src)
        self.assertIn('if [[ ${#PROTECTED_ARR[@]} -eq 0 ]]; then', src)
        # rules_env passes the value through (default = gateway); a change
        # of protected_hosts re-runs the rules script; an empty submitted
        # value would pass "" and the script falls back
        cfg = dict(schema.defaults())
        self.assertEqual(dockerops.rules_env(cfg)["PI_TOR_PROTECTED_HOSTS"],
                         "10.12.194.1")
        cfg2 = dict(schema.defaults(), protected_hosts="10.12.194.9")
        self.assertEqual(dockerops.rules_env(cfg2)["PI_TOR_PROTECTED_HOSTS"],
                         "10.12.194.9")


class LockoutGuardTest(unittest.TestCase):
    """Gateway IP missing from protected hosts = operator lockout: the
    script refuses before any iptables call, the schema refuses the whole
    apply, and the empty-list fallback stays legal."""

    def _apply(self, protected):
        env = dict(os.environ)
        env.update({"PI_TOR_FAKE_ROOT": "1",
                    # guard must fire before any iptables binary is touched
                    "IPTABLES_BIN": "/nonexistent/iptables-stub-must-not-run",
                    "PI_TOR_PROTECTED_HOSTS": protected})
        return subprocess.run(["bash", str(RULES), "apply"],
                              capture_output=True, text=True, env=env,
                              timeout=30)

    def test_apply_refused_when_gateway_not_protected(self):
        p = self._apply("10.12.194.9")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("refusing to apply", p.stderr)
        self.assertIn("lock you out", p.stderr)

        # schema level: a hard error, not a warning
        cfg = dict(schema.defaults(), protected_hosts="10.12.194.9")
        errors = schema.validate(cfg)
        msg = " ".join(e["message"] for e in errors
                       if e["key"] == "protected_hosts")
        self.assertIn("lock you out", msg)
        self.assertIn("10.12.194.1", msg)

        # the guarded default still validates
        self.assertEqual(schema.validate(schema.defaults()), [])

        # and apply_changes refuses before writing or restarting anything
        tree = make_config_tree()
        try:
            report = apply_mod.apply_changes(
                tree, {"protected_hosts": "10.12.194.9"})
            self.assertFalse(report["ok"])
            self.assertIn("lock you out",
                          " ".join(e["message"] for e in report["errors"]))
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    def test_empty_protected_list_still_falls_back(self):
        # empty means "gateway" in the script, so the schema must not
        # reject an empty list (the guard only fires on an explicit list)
        cfg = dict(schema.defaults(), protected_hosts="")
        self.assertEqual(schema.validate(cfg), [])


if __name__ == "__main__":
    unittest.main()
