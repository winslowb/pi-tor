"""Read-only uplink state: the interface tor must bootstrap through.

Every command here is read-only (`ip -j addr`, `ip -j route`,
`iw dev <if> link`) plus /sys and /proc reads — nothing changes state,
which is why the dashboard may render this panel in DRY_RUN too.

Verdicts drive two things: submission checks (missing interface = error,
no IPv4 lease / no default route = warning) and the dashboard's uplink
panel. NetworkManager is never touched; no credentials are read or stored.
"""
import json
import re
import subprocess
from pathlib import Path

LEASE_OK = "ok"
LEASE_NO_IPV4 = "no_ipv4"
LEASE_NO_ROUTE = "no_route"
LEASE_ABSENT = "absent"
LEASE_UNKNOWN = "unknown"


def _run_json(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return None
    return data if isinstance(data, list) else None


def exists(name):
    """Interface presence via /sys/class/net (no privileges, no subprocess)."""
    try:
        return Path("/sys/class/net", name).exists()
    except OSError:
        return False


def operstate(name):
    try:
        return Path("/sys/class/net", name, "operstate").read_text().strip() or "unknown"
    except OSError:
        return "unknown"


def _addr_json():
    return _run_json(["ip", "-j", "addr"])


def _route_json():
    return _run_json(["ip", "-j", "route"])


def _ssid(name):
    """Best-effort Wi-Fi SSID; None means unknown — never invent one."""
    try:
        p = subprocess.run(["iw", "dev", name, "link"], capture_output=True,
                           text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    m = re.search(r"^\s*SSID:\s(.+)$", p.stdout, re.M)
    return m.group(1).strip() if m else None


def _single_row(name, *, addr=None, route=None):
    """Row for exactly one interface (no lo filter — submission checks use it)."""
    if addr is None:
        addr = _addr_json()
    if route is None:
        route = _route_json()
    a = next((x for x in (addr or [])
              if isinstance(x, dict) and x.get("ifname") == name), {})
    inet = [b for b in a.get("addr_info", []) if b.get("family") == "inet"]
    state = operstate(name)
    if state == "unknown" and a.get("operstate"):
        state = str(a["operstate"]).lower()
    return {
        "name": name,
        "operstate": state,
        "ipv4": [f"{b.get('local')}/{b.get('prefixlen')}" for b in inet]
                if addr is not None else None,
        "default_route": any(isinstance(r, dict) and r.get("dst") == "default"
                             and r.get("dev") == name
                             for r in (route or []))
                       if route is not None else None,
    }


def interface_rows(*, addr=None, route=None, sys_names=None):
    """One read-only row per non-loopback interface (synthetic JSON ok).

    {name, operstate, ipv4[], default_route}; ipv4/default_route are None
    when the `ip` tool is unavailable or the JSON was not supplied.
    """
    if addr is None:
        addr = _addr_json()
    if route is None:
        route = _route_json()
    by_name = {}
    for a in addr or []:
        if isinstance(a, dict) and a.get("ifname"):
            by_name[a["ifname"]] = a
    default_devs = set()
    for r in route or []:
        if isinstance(r, dict) and r.get("dst") == "default" and r.get("dev"):
            default_devs.add(r["dev"])
    names = [n for n in by_name if n != "lo"]  # panel never shows loopback
    if sys_names is None:
        try:
            sys_names = [p.name for p in Path("/sys/class/net").iterdir()]
        except OSError:
            sys_names = []
    for name in sys_names or []:
        if name != "lo" and name not in names:
            names.append(name)
    out = []
    for name in names:
        a = by_name.get(name, {})
        inet = [b for b in a.get("addr_info", []) if b.get("family") == "inet"]
        if addr is None:
            ipv4 = None
        elif inet:
            ipv4 = [f"{b.get('local')}/{b.get('prefixlen')}" for b in inet]
        else:
            ipv4 = []
        state = operstate(name)
        if state == "unknown" and a.get("operstate"):
            state = str(a["operstate"]).lower()
        out.append({
            "name": name,
            "operstate": state,
            "ipv4": ipv4,
            "default_route": (name in default_devs) if route is not None else None,
        })
    return out


def panel(iface, *, addr=None, route=None, link=None, sys_names=None):
    """Dashboard payload: every interface plus the uplink lease verdict."""
    rows = interface_rows(addr=addr, route=route, sys_names=sys_names)
    me = next((r for r in rows if r["name"] == iface), None)
    if me is None:
        lease = LEASE_ABSENT
        message = f"{iface} does not exist — tor cannot bootstrap."
    elif me["ipv4"] is None or me["default_route"] is None:
        lease = LEASE_UNKNOWN
        message = f"{iface} state unknown — the 'ip' tool is not available on this host."
    elif not me["ipv4"]:
        lease = LEASE_NO_IPV4
        if me["operstate"] == "down":
            message = f"{iface} is down and has no IPv4 lease — tor cannot bootstrap."
        else:
            message = f"{iface} is up but has no IPv4 lease — tor cannot bootstrap."
    elif not me["default_route"]:
        lease = LEASE_NO_ROUTE
        message = (f"{iface} has an IPv4 lease but carries no default route"
                   " — tor cannot bootstrap.")
    else:
        lease = LEASE_OK
        message = f"{iface} has an IPv4 lease and the default route — tor can bootstrap."
    return {
        "interface": iface,
        "lease": lease,
        "message": message,
        "operstate": me["operstate"] if me else None,
        "ipv4": me["ipv4"] if me else None,
        "default_route": me["default_route"] if me else None,
        "ssid": _ssid(iface) if link is None else link,
        "interfaces": rows,
    }


def submission(values, current=None, *, row=None):
    """(errors, warnings) for the uplink against the live host.

    Runs the host checks only when the posted uplink_interface differs from
    the current one — re-applying an unchanged config must never block even
    when the interface is gone on this box; the dashboard panel still shows
    that. A deliberate change is checked against the live network state.
    """
    name = (values.get("uplink_interface") or "").strip()
    if row is None and current is not None:
        # re-applying an unchanged config must not block even when the
        # interface is gone on this box (the panel still shows that)
        cur = current.get("uplink_interface")
        if cur is not None and cur == name:
            return [], []
    if row is None:
        if not exists(name):
            row = {"missing": True}
        else:
            row = _single_row(name)
    if row.get("missing"):
        return ([{"key": "uplink_interface",
                  "message": f"'{name}' does not exist on this host"}], [])
    warnings = []
    if row.get("ipv4") is None or row.get("default_route") is None:
        warnings.append({"key": "uplink_interface",
                         "message": "'ip' is not available; uplink state unknown"})
    elif not row["ipv4"]:
        warnings.append({"key": "uplink_interface",
                         "message": f"{name} has no IPv4 lease; tor cannot bootstrap"})
    elif not row["default_route"]:
        warnings.append({"key": "uplink_interface",
                         "message": f"{name} carries no default route; tor cannot bootstrap"})
    return [], warnings
