"""Single source of truth for the pi-tor configuration schema.

Every rendered config file is produced from these keys; every parser and the
web form read the same table. Values are kept as strings (that is the shape
the .env / torrc / dnsmasq files already use).
"""
import ipaddress
import re
import zoneinfo

# UI placeholder returned instead of secret values; a POST containing it (or
# an empty string) means "keep the current value".
MASK = "********"

FIELDS = {
    "interface": {
        "label": "USB gadget interface",
        "default": "usb0",
        "targets": ".env → docker-compose.yml (FTLCONF_dns_upstreams), "
                   "firewall rules env, systemd env",
    },
    "uplink_interface": {
        "label": "Uplink interface (tor's internet route)",
        "default": "wlan0",
        "targets": "systemd env, tor container gate — read-only: this UI "
                   "declares and validates the uplink, it never configures "
                   "the link (no NetworkManager, no Wi-Fi credentials)",
    },
    "gateway_ip": {
        "label": "Gateway IP",
        "default": "10.12.194.1",
        "targets": "tor/torrc, rules env, systemd env",
    },
    "subnet": {
        "label": "Gadget subnet (CIDR)",
        "default": "10.12.194.0/24",
        "targets": "tor/torrc SocksPolicy, rules env, systemd env",
    },
    "socks_port": {
        "label": "Tor SOCKS port",
        "default": "9050",
        "targets": "tor/torrc",
    },
    "trans_port": {
        "label": "Tor transparent proxy port",
        "default": "9040",
        "targets": "tor/torrc, rules env, systemd env",
    },
    "protected_hosts": {
        "label": "Protected hosts (IPv4, comma/space separated; empty = gateway)",
        "default": "10.12.194.1",
        "targets": "firewall rules env, systemd env — traffic to these hosts "
                   "is never diverted into tor, so SSH :22, Pi-hole :80 and "
                   "this UI :8080 keep working once the rules are applied",
    },
    "dns_port": {
        "label": "Tor DNS port",
        "default": "5353",
        "targets": "tor/torrc, .env → docker-compose.yml "
                   "(FTLCONF_dns_upstreams), rules env, systemd env",
    },
    "virtual_addr_network": {
        "label": "Tor virtual address network (CIDR)",
        "default": "10.192.0.0/10",
        "targets": "tor/torrc",
    },
    "exit_nodes_exclude": {
        "label": "Exclude exit nodes (comma-separated)",
        "default": "{ru},{cn},{ir},{kp}",
        "targets": "tor/torrc ExcludeExitNodes",
    },
    "exit_nodes_include": {
        "label": "Restrict exit nodes (comma-separated, empty = any)",
        "default": "",
        "targets": "tor/torrc ExitNodes",
    },
    "edns_packet_max": {
        "label": "dnsmasq EDNS packet max",
        "default": "1232",
        "targets": ".env → docker-compose.yml "
                   "(FTLCONF_misc_dnsmasq_lines)",
    },
    "tz": {
        "label": "Timezone (IANA name)",
        "default": "UTC",
        "targets": ".env",
    },
    "pihole_webpassword": {
        "label": "Pi-hole admin password",
        "default": "changeme",
        "secret": True,
        "targets": ".env → docker-compose.yml "
                   "(FTLCONF_webserver_api_password)",
    },
    "dns_query_logging": {
        "label": "Pi-hole DNS query logging",
        "default": "false",
        "targets": ".env → docker-compose.yml (FTLCONF_dns_queryLogging)",
    },
    "ui_port": {
        "label": "Config UI port",
        "default": "8080",
        "targets": ".env, docker-compose.yml",
    },
    "ui_password": {
        "label": "Config UI password",
        "default": "changeme",
        "secret": True,
        "targets": ".env",
    },
}

DEFAULTS = {key: spec["default"] for key, spec in FIELDS.items()}

SECRET_KEYS = tuple(k for k, s in FIELDS.items() if s.get("secret"))

INTERFACE_RE = re.compile(r"[a-zA-Z0-9_.:-]{1,15}")
EXIT_NODE_RE = re.compile(r"[a-z0-9{}]{2,20}")
TOR_PORTS = ("socks_port", "trans_port", "dns_port")


def defaults():
    return dict(DEFAULTS)


def normalize(key, value):
    """Coerce one incoming value to the canonical string form."""
    spec = FIELDS[key]
    v = value if value is not None else spec["default"]
    v = str(v).strip()
    if key == "dns_query_logging":
        v = v.lower()
    return v


def normalize_all(values):
    """Merge optional posted values over the current/defaults for full set."""
    out = {}
    for key in FIELDS:
        out[key] = normalize(key, values.get(key))
    return out


def validate(values):
    """Validate a full value set; returns a list of {"key", "message"}."""
    errors = []

    def err(key, message):
        errors.append({"key": key, "message": message})

    v = normalize_all(values)

    if not INTERFACE_RE.fullmatch(v["interface"]):
        err("interface",
            "interface name must match [a-zA-Z0-9_.:-] and be 1-15 characters")

    if not INTERFACE_RE.fullmatch(v["uplink_interface"]):
        err("uplink_interface",
            "interface name must match [a-zA-Z0-9_.:-] and be 1-15 characters")

    protected = []
    bad_protected = False
    for host in [t for t in re.split(r"[,\s]+", v["protected_hosts"].strip())
                 if t]:
        try:
            addr = ipaddress.ip_address(host)
            if addr.version != 4:
                raise ValueError
            protected.append(str(addr))
        except ValueError:
            bad_protected = True
            err("protected_hosts", f"'{host}' must be an IPv4 address")

    nets = {}
    for key in ("subnet", "virtual_addr_network"):
        try:
            net = ipaddress.ip_network(v[key], strict=False)
            if net.version != 4:
                raise ValueError
            if not 8 <= net.prefixlen <= 30:
                err(key, f"prefix must be between 8 and 30 (got /{net.prefixlen})")
            nets[key] = net
        except ValueError:
            err(key, "must be a valid IPv4 CIDR like 10.12.194.0/24")

    try:
        gw = ipaddress.ip_address(v["gateway_ip"])
        if gw.version != 4:
            raise ValueError
        if "subnet" in nets and gw not in nets["subnet"]:
            err("gateway_ip",
                f"{gw} must lie inside subnet {v['subnet']}")
        gw_ok = True
    except ValueError:
        err("gateway_ip", "must be a valid IPv4 address like 10.12.194.1")
        gw_ok = False

    # Empty protected_hosts falls back to the gateway in the script; an
    # explicit list without the gateway would redirect the Pi's own traffic
    # and lock the operator out — refuse it outright.
    if protected and not bad_protected and gw_ok and v["gateway_ip"] not in protected:
        err("protected_hosts",
            f"the gateway {v['gateway_ip']} must be listed in protected_hosts — "
            "applying the firewall rules without it would lock you out of "
            "SSH, Pi-hole and this UI")

    ports = {}
    for key in TOR_PORTS + ("ui_port",):
        try:
            n = int(v[key])
            if not 1 <= n <= 65535:
                raise ValueError
            ports[key] = n
        except ValueError:
            err(key, "must be an integer between 1 and 65535")

    tor = [ports[p] for p in TOR_PORTS if p in ports]
    if len(set(tor)) < len(tor):
        seen = {}
        for key, n in ports.items():
            if key in TOR_PORTS:
                if n in seen:
                    err(key, f"ports must be distinct: {key} and {seen[n]} "
                             f"are both {n}")
                seen[n] = key
    if "ui_port" in ports and tor:
        if ports["ui_port"] in tor:
            err("ui_port",
                "must not collide with the tor SOCKS/Transparent/DNS ports")
        elif ports["ui_port"] == 80:
            err("ui_port", "must not use port 80 (Pi-hole admin)")

    try:
        zoneinfo.ZoneInfo(v["tz"])
    except Exception:
        err("tz",
            f"'{v['tz']}' is not a resolvable IANA timezone (e.g. UTC, Europe/Berlin)")

    for key in ("exit_nodes_exclude", "exit_nodes_include"):
        for entry in v[key].split(","):
            entry = entry.strip()
            if entry and not EXIT_NODE_RE.fullmatch(entry):
                err(key,
                    f"entry '{entry}' must be 2-20 chars of [a-z0-9] or a "
                    f"brace code like {{us}}")

    try:
        n = int(v["edns_packet_max"])
        if not 1 <= n <= 65535:
            raise ValueError
    except ValueError:
        err("edns_packet_max", "must be an integer between 1 and 65535")

    if v["dns_query_logging"] not in ("true", "false"):
        err("dns_query_logging", "must be true or false")

    for key in SECRET_KEYS:
        if not v[key]:
            err(key, "must not be empty")

    return errors


def merge_secrets(posted, current):
    """For secret keys, a masked/empty/missing post means 'keep current'."""
    merged = dict(posted)
    for key in SECRET_KEYS:
        if merged.get(key) in (None, "", MASK):
            merged[key] = current.get(key) or DEFAULTS[key]
    return merged
