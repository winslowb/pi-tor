"""Render all pi-tor config files from the schema, and parse them back.

The seven committed files (plus the live `.env`, which shares the
`.env.example` template) must round-trip byte-identically at defaults.
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

# SOCKS: allow localhost (for healthcheck) and your USB subnet (for the workstation)
SocksPort 127.0.0.1:{cfg['socks_port']}
SocksPort {cfg['gateway_ip']}:{cfg['socks_port']}
SocksPolicy accept 127.0.0.1
SocksPolicy accept {cfg['subnet']}
SocksPolicy reject *

# Transparent proxy: bind to loopback to avoid "public address" warning
# (iptables REDIRECT delivers locally, so 127.0.0.1 is perfect)
TransPort {cfg['gateway_ip']}:{cfg['trans_port']}

# DNS stays local-only (Pi-hole upstream or NAT redirect will use this)
DNSPort {cfg['gateway_ip']}:{cfg['dns_port']}

VirtualAddrNetworkIPv4 {cfg['virtual_addr_network']}
AutomapHostsOnResolve 1

#StrictNodes 1
{exclude_line}
{include_line}

"""

    listen_conf = f"""# Answer on usb0 and loopback explicitly
listen-address={cfg['gateway_ip']},127.0.0.1
# Do NOT restrict to "local only" (prevents REFUSED on legit clients)
local-service=0
"""

    upstream_tor_conf = f"""server=127.0.0.1#{cfg['dns_port']}
no-resolv
"""

    usb0_conf = f"""interface={cfg['interface']}
except-interface=lo
# don't rebind to OS resolver
no-resolv
# upstream stays Tor DNSPort
server=127.0.0.1#{cfg['dns_port']}
edns-packet-max={cfg['edns_packet_max']}
"""

    tor_upstream_conf = f"""no-resolv
server=127.0.0.1#{cfg['dns_port']}
edns-packet-max={cfg['edns_packet_max']}
"""

    systemd_env = f"""# Copy this file to `/etc/default/pi-tor` (or another path referenced by
# EnvironmentFile=) to override defaults used by the provided systemd units
# and helper scripts.

# Absolute path to the cloned repo
PROJECT_DIR=/opt/pi-tor

# USB gadget interface + addressing used for the workstation tether
PI_TOR_INTERFACE={cfg['interface']}
PI_TOR_SUBNET={cfg['subnet']}
PI_TOR_GATEWAY={cfg['gateway_ip']}

# Ports exposed by tor inside the docker-compose stack
PI_TOR_TRANS_PORT={cfg['trans_port']}
PI_TOR_DNS_PORT={cfg['dns_port']}
"""

    envfile = f"""# Copy this file to `.env` and adjust values as needed.

# Timezone passed to the containers (IANA tz database format)
PI_TOR_TZ={cfg['tz']}

# Password for the Pi-hole admin UI
PIHOLE_WEBPASSWORD={cfg['pihole_webpassword']}

# Whether Pi-hole should log every DNS query (true/false)
PIHOLE_DNS_QUERY_LOGGING={cfg['dns_query_logging']}

# Config UI (HTTP Basic auth; user: pi-tor)
PI_TOR_UI_PORT={cfg['ui_port']}
PI_TOR_UI_PASSWORD={cfg['ui_password']}
"""

    return {
        ".env": envfile.encode(),
        ".env.example": envfile.encode(),
        "tor/torrc": torrc.encode(),
        "pihole/etc-dnsmasq.d/02-listen.conf": listen_conf.encode(),
        "pihole/etc-dnsmasq.d/02-upstream-tor.conf": upstream_tor_conf.encode(),
        "pihole/etc-dnsmasq.d/02-usb0.conf": usb0_conf.encode(),
        "pihole/etc-dnsmasq.d/99-tor-upstream.conf": tor_upstream_conf.encode(),
        "systemd/pi-tor.env.example": systemd_env.encode(),
    }


RENDER_TARGETS = [".env", ".env.example", "tor/torrc",
                  "pihole/etc-dnsmasq.d/02-listen.conf",
                  "pihole/etc-dnsmasq.d/02-upstream-tor.conf",
                  "pihole/etc-dnsmasq.d/02-usb0.conf",
                  "pihole/etc-dnsmasq.d/99-tor-upstream.conf",
                  "systemd/pi-tor.env.example"]

RAW_FILES = ["tor/torrc",
             "pihole/etc-dnsmasq.d/02-listen.conf",
             "pihole/etc-dnsmasq.d/02-upstream-tor.conf",
             "pihole/etc-dnsmasq.d/02-usb0.conf",
             "pihole/etc-dnsmasq.d/99-tor-upstream.conf",
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
_GW_BIND_RE = re.compile(r"^(?:SocksPort|TransPort|DNSPort)\s+(?!127\.0\.0\.1)([0-9.]+):(\d+)")
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
    listen = _read(root, "pihole/etc-dnsmasq.d/02-listen.conf")
    usb0 = _read(root, "pihole/etc-dnsmasq.d/02-usb0.conf")
    upstream = _read(root, "pihole/etc-dnsmasq.d/02-upstream-tor.conf")
    tor_up = _read(root, "pihole/etc-dnsmasq.d/99-tor-upstream.conf")
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

    if listen:
        m = re.search(r"^listen-address=([0-9.]+),127\.0\.0\.1\s*$",
                      listen, re.M)
        if m:
            set_from("gateway_ip", "pihole/etc-dnsmasq.d/02-listen.conf",
                     m.group(1))

    for text, rel in ((usb0, "pihole/etc-dnsmasq.d/02-usb0.conf"),
                      (tor_up, "pihole/etc-dnsmasq.d/99-tor-upstream.conf")):
        if not text:
            continue
        m = re.search(r"^interface=(\S+)\s*$", text, re.M)
        if m:
            set_from("interface", rel, m.group(1))
        m = re.search(r"^edns-packet-max=(\d+)\s*$", text, re.M)
        if m:
            set_from("edns_packet_max", rel, m.group(1))

    for text, rel in (((usb0, "pihole/etc-dnsmasq.d/02-usb0.conf"),
                       (upstream, "pihole/etc-dnsmasq.d/02-upstream-tor.conf"),
                       (tor_up, "pihole/etc-dnsmasq.d/99-tor-upstream.conf"))):
        # dnsmasq upstream lines are a fallback; torrc wins when present
        if "dns_port" in sources:
            break
        if not text:
            continue
        m = re.search(r"^server=127\.0\.0\.1#(\d+)\s*$", text, re.M)
        if m:
            set_from("dns_port", rel, m.group(1))

    if systemd:
        for env_key, key in (("PI_TOR_INTERFACE", "interface"),
                             ("PI_TOR_SUBNET", "subnet"),
                             ("PI_TOR_GATEWAY", "gateway_ip"),
                             ("PI_TOR_TRANS_PORT", "trans_port"),
                             ("PI_TOR_DNS_PORT", "dns_port")):
            # env file is authoritative only for keys nothing else provided;
            # the parsed files above win already when present.
            if env_key in sysd and key not in sources:
                set_from(key, "systemd/pi-tor.env.example", sysd[env_key])

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
