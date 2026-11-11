"""Render all pi-tor config files from the schema, and parse them back.

The three committed files (plus the live `.env`, which shares the
`.env.example` template) must round-trip byte-identically at defaults.
Pi-hole's DNS policy is no longer rendered into dnsmasq snippets: v6 ignores
`/etc/dnsmasq.d` unless asked, so interface, listener mode and upstream live
in `docker-compose.yml` as `FTLCONF_*` substitutions from this `.env`.
"""
import difflib
import re
from pathlib import Path

import config_schema as schema


def render(cfg):
    """Render every config target from a full validated value dict."""
    cfg = schema.normalize_all(cfg)

    if cfg["exit_nodes_exclude"]:
        exclude_line = f"ExcludeExitNodes {cfg['exit_nodes_exclude']}"
    else:
        exclude_line = "#ExcludeExitNodes {ru},{cn},{ir},{kp}"
    if cfg["exit_nodes_include"]:
        include_line = f"ExitNodes {cfg['exit_nodes_include']}"
    else:
        include_line = "#ExitNodes {us},{ca},{gb},{nl},{se},{ch},{de}"

    torrc = f"""RunAsDaemon 0
Log notice stdout
AvoidDiskWrites 1

# SOCKS: the wildcard listener binds before the gadget interface is addressed
# and serves loopback (healthcheck) and the workstation; SocksPolicy below is
# a source ACL tor enforces per connection - this is the only wildcard bind.
# A second explicit-loopback SocksPort on the same port cannot co-exist with
# the wildcard bind (EADDRINUSE in either order, tor 0.4.9)
SocksPort 0.0.0.0:{cfg['socks_port']}
SocksPolicy accept 127.0.0.1
SocksPolicy accept {cfg['subnet']}
SocksPolicy reject *

# Transparent proxy: a nat PREROUTING REDIRECT rewrites the destination to
# the incoming interface's own address (not loopback), so this must keep the
# gadget-address bind and must never become a wildcard - TransPort has no ACL
TransPort {cfg['gateway_ip']}:{cfg['trans_port']}

# DNS: loopback serves the local dnsmasq upstream; the gadget address serves
# DNS redirected off the gadget interface. Same no-wildcard rule as TransPort
DNSPort 127.0.0.1:{cfg['dns_port']}
DNSPort {cfg['gateway_ip']}:{cfg['dns_port']}

VirtualAddrNetworkIPv4 {cfg['virtual_addr_network']}
AutomapHostsOnResolve 1

#StrictNodes 1
{exclude_line}
{include_line}

"""

    systemd_env = f"""# Copy this file to `/etc/default/pi-tor` (or another path referenced by
# EnvironmentFile=) to override defaults used by the provided systemd units
# and helper scripts.

# USB gadget interface + addressing used for the workstation tether
PI_TOR_INTERFACE={cfg['interface']}
PI_TOR_SUBNET={cfg['subnet']}
PI_TOR_GATEWAY={cfg['gateway_ip']}

# Ports exposed by tor inside the docker-compose stack
PI_TOR_TRANS_PORT={cfg['trans_port']}
PI_TOR_DNS_PORT={cfg['dns_port']}

# Uplink tor bootstraps through, and hosts the redirect must never touch
PI_TOR_UPLINK={cfg['uplink_interface']}
PI_TOR_PROTECTED_HOSTS={cfg['protected_hosts']}
"""

    envfile = f"""# Copy this file to `.env` and adjust values as needed.

# Timezone passed to the containers (IANA tz database format)
PI_TOR_TZ={cfg['tz']}

# Pi-hole admin UI password (compose: FTLCONF_webserver_api_password)
PIHOLE_WEBPASSWORD={cfg['pihole_webpassword']}

# Whether Pi-hole should log every DNS query (true/false)
PIHOLE_DNS_QUERY_LOGGING={cfg['dns_query_logging']}

# DNS/tether plumbing: PI_TOR_INTERFACE is the gadget interface (rules script,
# tor); compose substitutes the other two into FTLCONF_dns_upstreams /
# FTLCONF_misc_dnsmasq_lines
PI_TOR_INTERFACE={cfg['interface']}
PI_TOR_DNS_PORT={cfg['dns_port']}
PI_TOR_EDNS_PACKET_MAX={cfg['edns_packet_max']}

# Config UI (HTTP Basic auth; user: pi-tor)
PI_TOR_UI_PORT={cfg['ui_port']}
PI_TOR_UI_PASSWORD={cfg['ui_password']}
"""

    return {
        ".env": envfile.encode(),
        ".env.example": envfile.encode(),
        "tor/torrc": torrc.encode(),
        "systemd/pi-tor.env.example": systemd_env.encode(),
    }


RENDER_TARGETS = [".env", ".env.example", "tor/torrc",
                  "systemd/pi-tor.env.example"]

RAW_FILES = ["tor/torrc",
             "systemd/pi-tor.env.example",
             "docker-compose.yml"]


def _read(root, rel):
    p = Path(root) / rel
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return None


def _envdict(text):
    out = {}
    if not text:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


_TORRC_RES = [
    # (regex, key) — first two groups are host and port
    (re.compile(r"^SocksPort\s+(\S+?):(\d+)\s*$"), "socks_port"),
    (re.compile(r"^TransPort\s+(\S+?):(\d+)\s*$"), "trans_port"),
    (re.compile(r"^DNSPort\s+(\S+?):(\d+)\s*$"), "dns_port"),
]
_LO_RE = re.compile(r"(?:SocksPort|TransPort|DNSPort)\s+127\.0\.0\.1")
# Non-loopback bind addresses; 0.0.0.0 is the wildcard SocksPort, never the
# gateway, so it must not be parsed as one
_GW_BIND_RE = re.compile(r"^(?:SocksPort|TransPort|DNSPort)\s+(?!127\.0\.0\.1|0\.0\.0\.0)([0-9.]+):(\d+)")
_POLICY_ACCEPT_RE = re.compile(r"^SocksPolicy\s+accept\s+(\S+)\s*$")
_VIRTUAL_RE = re.compile(r"^VirtualAddrNetworkIPv4\s+(\S+)\s*$")
_EXCLUDE_RE = re.compile(r"^ExcludeExitNodes\s+(\S+)\s*$")
_INCLUDE_RE = re.compile(r"^ExitNodes\s+(\S+)\s*$")


def read_current(root):
    """Parse current values from the config tree on disk.

    Returns {"values", "warnings", "sources"}: values fall back to schema
    defaults with a warning when a key cannot be parsed from any file.
    Secrets are returned in clear text — the API layer masks them.
    """
    root = Path(root)
    values = schema.defaults()
    sources = {}
    warnings = []

    torrc = _read(root, "tor/torrc")
    # The live .env, falling back to the committed example template
    env = _read(root, ".env")
    env_source = ".env" if env is not None else ".env.example"
    if env is None:
        env = _read(root, ".env.example")
    systemd = _read(root, "systemd/pi-tor.env.example")

    envd = _envdict(env)
    sysd = _envdict(systemd)

    def set_from(key, rel, value):
        values[key] = value
        sources[key] = rel

    if torrc:
        for line in torrc.splitlines():
            m = _GW_BIND_RE.match(line)
            if m:
                set_from("gateway_ip", "tor/torrc", m.group(1))
            for rx, key in _TORRC_RES:
                m = rx.match(line)
                if m:
                    set_from(key, "tor/torrc", m.group(2))
            m = _POLICY_ACCEPT_RE.match(line)
            if m and m.group(1) != "127.0.0.1" and m.group(1) != "*":
                set_from("subnet", "tor/torrc", m.group(1))
            m = _VIRTUAL_RE.match(line)
            if m:
                set_from("virtual_addr_network", "tor/torrc", m.group(1))
            m = _EXCLUDE_RE.match(line)
            if m:
                set_from("exit_nodes_exclude", "tor/torrc", m.group(1))
            m = _INCLUDE_RE.match(line)
            if m:
                set_from("exit_nodes_include", "tor/torrc", m.group(1))

    if systemd:
        for env_key, key in (("PI_TOR_INTERFACE", "interface"),
                             ("PI_TOR_UPLINK", "uplink_interface"),
                             ("PI_TOR_SUBNET", "subnet"),
                             ("PI_TOR_GATEWAY", "gateway_ip"),
                             ("PI_TOR_TRANS_PORT", "trans_port"),
                             ("PI_TOR_DNS_PORT", "dns_port"),
                             ("PI_TOR_PROTECTED_HOSTS", "protected_hosts")):
            # env file is authoritative only for keys nothing else provided;
            # the parsed files above win already when present.
            if env_key in sysd and key not in sources:
                set_from(key, "systemd/pi-tor.env.example", sysd[env_key])

    # Compose plumbing in .env; a fallback only, the rendered files above stay
    # authoritative. edns_packet_max now lives nowhere but here (it reaches
    # Pi-hole through FTLCONF_misc_dnsmasq_lines).
    for env_key, key in (("PI_TOR_INTERFACE", "interface"),
                         ("PI_TOR_DNS_PORT", "dns_port"),
                         ("PI_TOR_EDNS_PACKET_MAX", "edns_packet_max")):
        if env_key in envd and key not in sources:
            set_from(key, env_source, envd[env_key])

    for env_key, key in (("PI_TOR_TZ", "tz"),
                         ("PIHOLE_WEBPASSWORD", "pihole_webpassword"),
                         ("PIHOLE_DNS_QUERY_LOGGING", "dns_query_logging"),
                         ("PI_TOR_UI_PORT", "ui_port"),
                         ("PI_TOR_UI_PASSWORD", "ui_password")):
        if env_key in envd:
            set_from(key, env_source, envd[env_key])

    # Exclude/ExitNodes: absent (or commented) means genuinely empty in tor
    for key in ("exit_nodes_exclude", "exit_nodes_include"):
        if key not in sources:
            values[key] = ""

    for key in schema.FIELDS:
        if key in sources:
            continue
        # Exclude/ExitNodes are legitimately absent from the default torrc
        # (the commented example line): no warning when shown as default.
        if key in ("exit_nodes_exclude", "exit_nodes_include"):
            continue
        warnings.append({
            "key": key,
            "message": f"'{key}' not found in any config file; "
                       f"showing schema default",
        })
    if env_source == ".env.example":
        warnings.append({
            "key": ".env",
            "message": "no live .env found; values read from .env.example",
        })

    return {"values": values, "warnings": warnings, "sources": sources}


def diff_all(root, cfg):
    """Unified diff per target between on-disk bytes and the new render."""
    rendered = render(cfg)
    diffs = {}
    for rel, new_bytes in rendered.items():
        old_text = _read(root, rel) or ""
        old = old_text.splitlines(keepends=True)
        new = new_bytes.decode("utf-8").splitlines(keepends=True)
        if old == new:
            diffs[rel] = None
        else:
            diffs[rel] = "".join(difflib.unified_diff(
                old, new, fromfile=f"a/{rel}", tofile=f"b/{rel}"))
    return diffs


def changed_files(root, cfg):
    rendered = render(cfg)
    changed = []
    for rel, new_bytes in rendered.items():
        p = Path(root) / rel
        try:
            old = p.read_bytes()
        except OSError:
            old = None
        if old != new_bytes:
            changed.append(rel)
    return changed
