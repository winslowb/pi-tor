"""Pi-hole v6 DNS policy: what compose hands FTL, and where those values
come from.

`pihole/pihole` >= 2024.08 (Pi-hole v6) ignores the v5 variables this repo
used to set (`WEBPASSWORD`, `DNSMASQ_LISTENING`, `DNS_QUERY_LOGGING`,
`PIHOLE_DNS_*`) and no longer reads `/etc/dnsmasq.d`. The live board showed
the consequence: `dns.listeningMode=LOCAL`, empty `dns.interface`, upstreams
`8.8.8.8,8.8.4.4` — LAN-wide answering off the public resolvers, while the
compose file still claimed `DNSMASQ_LISTENING=all`. These tests pin the v6
spellings and the fail-closed direction: SINGLE on the gadget interface, one
loopback upstream (tor's DNSPort), nothing that re-enables a dnsmasq.d dir.
"""
import re
import shutil
import unittest

from helpers import REPO, make_config_tree

import apply as apply_mod
import config_schema as schema
import render

COMPOSE = (REPO / "docker-compose.yml").read_text()
VAR_RE = re.compile(r"\$\{([A-Z0-9_]+):-([^}]*)\}")
PUBLIC_RESOLVERS = ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9")


def pihole_service(text=COMPOSE):
    match = re.search(r"^  pihole:\n(.*?)(?=^  \S)", text, re.S | re.M)
    if match is None:
        raise AssertionError("no pihole service in docker-compose.yml")
    return match.group(1)


def pihole_env(text=COMPOSE):
    """The pihole service's environment mapping, values exactly as written."""
    lines = pihole_service(text).splitlines()
    env = {}
    for i, line in enumerate(lines):
        if line.strip() != "environment:":
            continue
        for sub in lines[i + 1:]:
            if sub.strip() and not sub.startswith("      "):
                break
            if sub.startswith("      ") and sub.strip():
                key, _, value = sub.strip().partition(":")
                env[key.strip()] = value.strip()
        break
    return env


def resolve(value, envd):
    """Compose's ${VAR:-default} substitution against an .env mapping."""
    return VAR_RE.sub(lambda m: envd.get(m.group(1), m.group(2)), value)


class PiholeV6ComposeTest(unittest.TestCase):

    def test_listener_is_single_on_the_gadget_interface(self):
        env = pihole_env()
        self.assertEqual(env["FTLCONF_dns_listeningMode"], '"SINGLE"',
                         "SINGLE, not LOCAL/ALL: only usb0 (plus the implicit "
                         "loopback) may be answered")
        self.assertEqual(env["FTLCONF_dns_interface"],
                         '"${PI_TOR_INTERFACE:-usb0}"')

    def test_upstream_is_only_tors_dnsport(self):
        value = pihole_env()["FTLCONF_dns_upstreams"].strip('"')
        # one entry, loopback form, port substituted from the generated .env
        self.assertEqual(value, "127.0.0.1#${PI_TOR_DNS_PORT:-5353}")
        self.assertNotIn(";", value)
        self.assertNotIn(",", value)
        for port in ("5353", "5454"):
            resolved = resolve(value, {"PI_TOR_DNS_PORT": port})
            host, _, got_port = resolved.partition("#")
            self.assertEqual(host, "127.0.0.1",
                             f"upstream must stay on tor's DNSPort: {resolved}")
            self.assertEqual(got_port, port)

    def test_no_public_resolver_anywhere_in_the_service(self):
        block = pihole_service()
        for public in PUBLIC_RESOLVERS:
            self.assertNotIn(public, block,
                             f"{public} is a public resolver, not tor")

    def test_v5_variables_are_gone(self):
        env = pihole_env()
        for v5 in ("WEBPASSWORD", "DNSMASQ_LISTENING", "DNS_QUERY_LOGGING",
                   "PIHOLE_DNS_", "ServerIP", "DNS1", "DNS2"):
            self.assertNotIn(v5, env,
                             f"{v5} is a v5 variable Pi-hole v6 ignores")
        self.assertEqual(env["FTLCONF_webserver_api_password"],
                         '"${PIHOLE_WEBPASSWORD:-changeme}"')
        self.assertEqual(env["FTLCONF_dns_queryLogging"],
                         '"${PIHOLE_DNS_QUERY_LOGGING:-false}"')

    def test_dnsmasq_d_is_not_loaded_and_not_mounted(self):
        # a stale 02-listen.conf (local-service=0) survives on the deployed
        # board's tree; loading the directory again would re-widen listening
        self.assertNotRegex(COMPOSE,
                            r"(?m)^\s+FTLCONF_misc_etc_dnsmasq_d\s*:")
        self.assertNotRegex(COMPOSE, r"(?m)^\s*-\s*\./pihole/etc-dnsmasq\.d:")
        self.assertFalse((REPO / "pihole" / "etc-dnsmasq.d").exists(),
                         "the repo still ships dnsmasq snippets that v6 "
                         "ignores and a v6 tree would load unsafely")


class PiholeV6PlumbingTest(unittest.TestCase):
    """The schema renders the interface/port/edns values compose substitutes."""

    def _cfg(self, **over):
        cfg = dict(schema.defaults())
        cfg.update(over)
        self.assertEqual(schema.validate(cfg), [])
        return cfg

    def test_env_plumbing_tracks_interface_and_dns_port(self):
        rendered = render.render(self._cfg(interface="usb7", dns_port="5454"))
        envd = render._envdict(rendered[".env"].decode())
        self.assertEqual(envd["PI_TOR_INTERFACE"], "usb7")
        self.assertEqual(envd["PI_TOR_DNS_PORT"], "5454")
        self.assertEqual(rendered[".env"], rendered[".env.example"])

        env = pihole_env()
        self.assertEqual(resolve(env["FTLCONF_dns_interface"], envd).strip('"'),
                         "usb7")
        self.assertEqual(
            resolve(env["FTLCONF_dns_upstreams"], envd).strip('"'),
            "127.0.0.1#5454",
            "a DNSPort change must move the FTL upstream with it")
        self.assertEqual(
            resolve(env["FTLCONF_misc_dnsmasq_lines"], envd).strip('"'),
            "edns-packet-max=1232")

    def test_env_values_round_trip_through_the_parser(self):
        tree = make_config_tree()
        try:
            rendered = render.render(self._cfg(interface="usb7",
                                               dns_port="5454",
                                               edns_packet_max="1400"))
            apply_mod._write_all(tree, rendered)
            parsed = render.read_current(tree)
            self.assertEqual(parsed["warnings"], [], parsed["warnings"])
            self.assertEqual(parsed["values"]["interface"], "usb7")
            self.assertEqual(parsed["values"]["dns_port"], "5454")
            self.assertEqual(parsed["values"]["edns_packet_max"], "1400")
        finally:
            shutil.rmtree(tree, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
