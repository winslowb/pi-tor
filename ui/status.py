"""Dashboard status: service state, tor bootstrap, exit IP, Pi-hole
counters (best effort), and firewall-rule state. Never raises — a section
that cannot be measured degrades to a note."""
import json
import os
import re
import socket
import struct

import config_schema as schema
import dockerops
import render
import uplink

TOR_BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%")
SOCKS_HOST = "127.0.0.1"


def _dry():
    return os.environ.get("PI_TOR_UI_DRY_RUN") == "1"


def _uplink_section(root):
    values = render.read_current(root)["values"]
    return uplink.panel(
        values.get("uplink_interface") or schema.DEFAULTS["uplink_interface"])


def dashboard(root):
    root = str(root)
    if _dry():
        return {
            "dry_run": True,
            "services": {
                "tor": {"state": "n/a (dry run)"},
                "pihole": {"state": "n/a (dry run)"},
            },
            "tor": {"bootstrap": "n/a (dry run)", "exit_ip": "n/a (dry run)"},
            "pihole": {"counters": None,
                       "note": "dry run: Pi-hole API not queried"},
            "rules": {"state": "n/a (dry run)"},
            # the uplink panel is read-only, so it renders real data in dry run
            "uplink": _uplink_section(root),
        }

    current = render.read_current(root)
    values, sources = current["values"], current["sources"]
    out = {"dry_run": False, "services": {}, "tor": {}, "pihole": {},
           "rules": {}}

    for name in ("tor", "pihole"):
        try:
            info = dockerops.inspect(name)
        except OSError as exc:
            info = {"error": f"docker socket unavailable: {exc}"}
        if info is None:
            out["services"][name] = {"state": "not present"}
        elif "error" in info or "skipped" in info:
            out["services"][name] = info
        else:
            out["services"][name] = {
                "running": info.get("running"),
                "health": info.get("health"),
            }

    try:
        out["tor"]["bootstrap"] = _bootstrap_pct()
    except Exception as exc:  # noqa: BLE001
        out["tor"]["bootstrap"] = None
        out["tor"]["bootstrap_note"] = str(exc)

    try:
        out["tor"]["exit_ip"] = _exit_ip(values)
    except Exception as exc:  # noqa: BLE001
        out["tor"]["exit_ip"] = None
        out["tor"]["exit_ip_note"] = f"exit IP check failed: {exc}"

    try:
        out["pihole"]["counters"] = _pihole_counters(values)
    except Exception as exc:  # noqa: BLE001
        out["pihole"]["counters"] = None
        out["pihole"]["note"] = f"Pi-hole API failed: {exc}"

    out["rules"] = dockerops.iptables_status()
    out["uplink"] = _uplink_section(root)
    if "dns_port" not in sources or "socks_port" not in sources:
        out["config_note"] = "some config values fell back to defaults"
    return out


def _bootstrap_pct():
    res = dockerops.logs("tor", 200)
    if "error" in res:
        return None
    if "skipped" in res:
        return "n/a (dry run)"
    pcts = [int(m) for m in TOR_BOOTSTRAP_RE.findall(res["logs"])]
    return f"{max(pcts)}%" if pcts else None


def _exit_ip(values):
    """Exit IP through the local tor SOCKS port over a minimal SOCKS5 client."""
    port = int(values.get("socks_port") or 9050)
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(10)
    s.sendall(b"\x05\x01\x00")
    greeting = s.recv(2)
    if greeting != b"\x05\x00":
        s.close()
        raise OSError("tor SOCKS refused the handshake")
    host = b"checkip.amazonaws.com"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host +
              struct.pack(">H", 80))
    reply = s.recv(512)
    if len(reply) < 4 or reply[1] != 0:
        s.close()
        raise OSError(f"SOCKS CONNECT failed: {reply[:4].hex() if reply else '?'}")
    # reply is 4 bytes + variable addr (atyp 1 => 4 bytes) + 2 bytes port
    atyp = reply[3]
    extra = {1: 4, 3: 1 + reply[4] if len(reply) > 4 else 1, 4: 16}.get(atyp, 4)
    _ = reply[4 + extra:4 + extra + 2]
    s.sendall(b"GET / HTTP/1.0\r\nHost: checkip.amazonaws.com\r\n\r\n")
    body = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        body += c
    s.close()
    text = body.partition(b"\r\n\r\n")[2].strip()
    ip = text.split(b"\n")[0].strip().decode("utf-8", "replace")
    return ip or None


def _pihole_counters(values):
    """Best effort counters. Tries the v5 summary endpoint, then v6 auth."""
    password = values.get("pihole_webpassword") or ""
    summary = _http_json("GET", "/admin/api.php?summary")
    if isinstance(summary, dict) and ("dns_queries_today" in summary or
                                      "queries_today" in summary):
        return {"api": "v5", "queries_today":
                summary.get("dns_queries_today", summary.get("queries_today")),
                "blocked_today": summary.get("ads_blocked_today",
                                             summary.get("blocked_today")),
                "domains_blocked": summary.get("domains_being_blocked")}

    if password and password != schema.MASK:
        auth = _http_json("POST", "/api/auth", {"password": password})
        sid = None
        if isinstance(auth, dict):
            sess = auth.get("session") or {}
            sid = sess.get("sid") or auth.get("sid")
        if sid:
            for header_name in ("X-PIHOLE6-AUTH", "Authorization"):
                headers = {header_name: sid} if header_name.startswith("X-") \
                    else {"Authorization": f"Bearer {sid}"}
                stats = _http_json("GET", "/api/stats/summary", None, headers)
                if isinstance(stats, dict) and stats:
                    q = stats.get("queries", {})
                    return {
                        "api": "v6",
                        "queries_today": q.get("total", stats.get("num_dns_queries")),
                        "blocked_today": q.get("blocked",
                                               stats.get("ads_blocked_today")),
                        "raw_keys": sorted(stats.keys())[:8],
                    }
    return {"available": False,
            "note": "Pi-hole counter API not reachable or needs a newer "
                    "endpoint; check http://<pi>/admin directly"}


def _http_json(method, path, body=None, headers=None):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
    hdrs = dict(headers or {})
    payload = None
    if body is not None:
        payload = json.dumps(body)
        hdrs["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read(65536)
    conn.close()
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
