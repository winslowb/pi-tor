"""Startup firewall apply: two simulated starts drive the wrapper exactly
once per start and leave no duplicate chains (against a stub iptables, never
the real one), and a legacy iptables backend is refused with a visible error.
"""
import os
import shutil
import tempfile
import textwrap
import unittest
from unittest import mock

from helpers import make_config_tree

import apply as apply_mod
import dockerops
import render

# A minimal iptables simulator: table/chain state in $PI_TOR_FAKE_STATE,
# one file per chain, one rule per line. The script never touches a real
# ruleset because IPTABLES_BIN points here instead.
STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    set -u
    STATE="${PI_TOR_FAKE_STATE:?PI_TOR_FAKE_STATE required}"
    for a in "$@"; do
      if [[ "$a" == "-V" ]]; then
        echo "${PI_TOR_FAKE_VERSION:-iptables v1.8.99 (nf_tables)}"
        exit 0
      fi
    done
    table="filter"
    if [[ "$1" == "-t" ]]; then table="$2"; shift 2; fi
    op="$1"; chain="$2"; shift 2
    file="$STATE/$table/$chain"
    mkdir -p "$STATE/$table"
    rule="${*}"
    case "$op" in
      -A) printf '%s\\n' "$rule" >> "$file" ;;
      -C) [[ -e "$file" ]] && grep -qxF -- "$rule" "$file" || exit 1 ;;
      -D) [[ -e "$file" ]] || exit 1
          d=0; tmp="$file.tmp$$"; : > "$tmp"
          while IFS= read -r l; do
            if [[ $d -eq 0 && "$l" == "$rule" ]]; then d=1; continue; fi
            printf '%s\\n' "$l" >> "$tmp"
          done < "$file"
          mv "$tmp" "$file"
          [[ $d -eq 1 ]] || exit 1 ;;
      -N) [[ -e "$file" ]] && exit 1; : > "$file" ;;
      -F) [[ -e "$file" ]] || exit 1; : > "$file" ;;
      -X) [[ -e "$file" ]] || exit 1; rm -f "$file" ;;
      -L) [[ -e "$file" ]] || exit 1 ;;
      -S) [[ -e "$file" ]] || exit 1; cat "$file" ;;
      *) exit 2 ;;
    esac
""")


ENV_KEYS = ("IPTABLES_BIN", "PI_TOR_FAKE_STATE", "PI_TOR_FAKE_ROOT",
            "PI_TOR_FAKE_VERSION", "PI_TOR_UI_DRY_RUN")


class StartupApplyTest(unittest.TestCase):

    def setUp(self):
        self.tree = make_config_tree()
        self.tmp = tempfile.mkdtemp(prefix="pi-tor-fake-iptables-")
        self.state = os.path.join(self.tmp, "state")
        self.stub = os.path.join(self.tmp, "iptables-stub")
        with open(self.stub, "w") as f:
            f.write(STUB)
        os.chmod(self.stub, 0o755)
        self.old_env = {k: os.environ.pop(k, None) for k in ENV_KEYS}

    def tearDown(self):
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tree, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _use_stub(self, version="iptables v1.8.99 (nf_tables)"):
        os.environ.update({"IPTABLES_BIN": self.stub,
                           "PI_TOR_FAKE_STATE": self.state,
                           "PI_TOR_FAKE_ROOT": "1",
                           "PI_TOR_FAKE_VERSION": version})

    def test_startup_apply_is_idempotent(self):
        self._use_stub()
        values = render.read_current(self.tree)["values"]

        res = apply_mod.startup_rules_apply(self.tree)
        self.assertIn("applied", res, res)
        self.assertEqual(res["action"], "apply")

        # hook rule exactly once, one chain, RETURN first, four rules total
        hook = open(os.path.join(self.state, "nat", "PREROUTING"),
                    encoding="utf-8").read().splitlines()
        self.assertEqual(hook, ["-i usb0 -j PI_TOR_REDIRECT"])
        chain = open(os.path.join(self.state, "nat", "PI_TOR_REDIRECT"),
                     encoding="utf-8").read().splitlines()
        self.assertEqual(chain[0], "-d 10.12.194.1 -j RETURN")
        self.assertEqual(len(chain), 4)
        self.assertEqual(
            [l for l in chain if l.endswith("-j RETURN")],
            ["-d 10.12.194.1 -j RETURN"])

        # a second simulated start leaves the state unchanged
        res2 = apply_mod.startup_rules_apply(self.tree)
        self.assertIn("applied", res2, res2)
        self.assertEqual(
            open(os.path.join(self.state, "nat", "PREROUTING"),
                 encoding="utf-8").read().splitlines(),
            ["-i usb0 -j PI_TOR_REDIRECT"])

        # wrapper accounting: one apply call per start, driven through
        # startup_rules_apply (the wrapper), not through real iptables
        with mock.patch.object(dockerops, "run_rules") as rr:
            rr.return_value = {"applied": True}
            apply_mod.startup_rules_apply(self.tree)
            apply_mod.startup_rules_apply(self.tree)
        self.assertEqual(rr.call_count, 2)
        for call in rr.call_args_list:
            self.assertEqual(call.args[0], self.tree)

    def test_non_nft_backend_is_detected(self):
        self.assertEqual(
            dockerops.parse_backend("iptables v1.8.10 (nf_tables)"),
            "nf_tables")
        self.assertEqual(
            dockerops.parse_backend("iptables v1.8.7 (legacy)"), "legacy")
        self.assertEqual(dockerops.parse_backend("iptables v1.4.21"), "unknown")

        # startup refuses to write through a legacy binary
        self._use_stub(version="iptables v1.8.7 (legacy)")
        res = apply_mod.startup_rules_apply(self.tree)
        self.assertIn("error", res, res)
        self.assertIn("legacy", res["error"])
        self.assertIn("nf_tables", res["error"])
        # refusal happened before the script ran: no chain state exists
        self.assertFalse(os.path.exists(os.path.join(self.state, "nat")))

        # the nft flavour applies normally
        self._use_stub(version="iptables v1.8.10 (nf_tables)")
        res = apply_mod.startup_rules_apply(self.tree)
        self.assertIn("applied", res, res)

    def test_dry_run_skips_startup_apply(self):
        os.environ["PI_TOR_UI_DRY_RUN"] = "1"
        with mock.patch.object(dockerops.subprocess, "run",
                               side_effect=AssertionError("dry run ran a subprocess")):
            res = apply_mod.startup_rules_apply(self.tree)
        self.assertEqual(res, {"skipped": "dry-run"})


if __name__ == "__main__":
    unittest.main()
