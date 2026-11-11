"""Talk to Docker (socket API) and the host, stdlib only.

- /var/run/docker.sock via a minimal HTTP/1.1 client over AF_UNIX for
  inspect / restart / logs / health.
- A host-mounted `docker` binary via subprocess only for whole-stack compose
  operations (`up -d --no-deps`), degrading gracefully with a visible error.
- The firewall helper script via subprocess with explicit env overrides.

PI_TOR_UI_DRY_RUN=1 disables every socket call and every subprocess; the
public functions all short-circuit before touching anything privileged and
counters record how many privileged calls would have happened.
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import time

SOCKET_PATH = os.environ.get("PI_TOR_DOCKER_SOCKET", "/var/run/docker.sock")

# Test-visible proof of privileged activity in non-dry mode.
counters = {"socket_calls": 0, "subprocess_calls": 0}


def _dry():
    return os.environ.get("PI_TOR_UI_DRY_RUN") == "1"


def _unix_http(method, path, body=b"", timeout=30):
    """Minimal HTTP/1.1 over the docker unix socket. Returns (status, body)."""
    counters["socket_calls"] += 1
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCKET_PATH)
    req = (f"{method} {path} HTTP/1.1\r\nHost: docker\r\n"
           f"Content-Type: application/json\r\nConnection: close\r\n"
           f"Content-Length: {len(body)}\r\n\r\n")
    s.sendall(req.encode() + body)
    # Do NOT half-close the write side. Docker's Go server reads the EOF as a
    # client abort: the identical request returns 200 with an EMPTY body for
    # /containers/<name>/logs and 500 for /version, while the same bytes sent
    # without the half-close return the whole response. Content-Length already
    # delimits the request, so the half-close bought nothing and silently
    # emptied the Logs panel.
    chunks = []
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break       # keep what arrived; a slow daemon must not hang the UI
        if not c:
            break
        chunks.append(c)
    s.close()
    raw = b"".join(chunks)
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        headers[k.strip().lower().decode()] = v.strip().decode()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        rest = _dechunk(rest)
    return status, rest


def _dechunk(data):
    out = []
    while data:
        line, _, data = data.partition(b"\r\n")
        n = int(line.split(b";")[0], 16)
        if n == 0:
            break
        out.append(data[:n])
        data = data[n + 2:]
    return b"".join(out)


def _api(method, path, body=None):
    if body is not None:
        body = json.dumps(body).encode()
    status, raw = _unix_http(method, path, body or b"")
    if status == 204:
        return {"ok": True}, None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {"ok": status < 400}, raw[:2000]
    if status >= 400:
        return None, data
    return data, None


def inspect(name):
    """Container JSON (with State) or None when it does not exist."""
    if _dry():
        return {"skipped": "dry-run"}
    data, err = _api("GET", f"/containers/{name}/json")
    if err is not None or not isinstance(data, dict):
        return None
    state = data.get("State", {})
    health = (state.get("Health") or {}).get("Status")
    return {"running": state.get("Running"), "health": health,
            "started": state.get("StartedAt", "")}


def logs(name, tail=200):
    """Combined container logs (stdout+stderr, last N lines)."""
    if _dry():
        return {"skipped": "dry-run"}
    status, raw = _unix_http(
        "GET", f"/containers/{name}/logs?stdout=1&stderr=1&tail={int(tail)}")
    if status >= 400:
        return {"error": _short(raw)}
    return {"logs": _demux(raw).decode("utf-8", "replace")[-20000:]}


def _demux(raw):
    """Docker log multiplexing (tty=false): 8-byte frames to stream+payload."""
    if len(raw) < 8 or raw[0] not in (0, 1, 2):
        return raw
    out = []
    pos = 0
    frames = []
    while pos + 8 <= len(raw):
        stream = raw[pos]
        length = struct.unpack(">I", raw[pos + 4:pos + 8])[0]
        if length < 0 or pos + 8 + length > len(raw):
            return raw  # not a demuxable stream; return as-is
        payload = raw[pos + 8:pos + 8 + length]
        pos += 8 + length
        if stream in (1, 2):
            frames.append(payload)
    out.extend(frames)
    return b"".join(out)


def restart(name, timeout_secs=10):
    if _dry():
        return {"skipped": "dry-run"}
    data, err = _api("POST", f"/containers/{name}/restart?t={int(timeout_secs)}")
    if err is not None:
        return {"error": _json_short(err)}
    return {"restarted": name}


def poll_health(name, total_seconds=90, interval=2):
    """Poll container health; returns {"healthy": bool, "state": str}."""
    if _dry():
        return {"healthy": True, "state": "skipped (dry-run)"}
    deadline = time.monotonic() + total_seconds
    last = {"healthy": False, "state": "unknown"}
    while True:
        info = inspect(name)
        if info is None:
            last = {"healthy": False, "state": "not found"}
            break
        state = info.get("running") and "running" or "not running"
        health = info.get("health")
        if health is None:
            healthy = bool(info.get("running"))
            state = "running (no healthcheck)"
        else:
            healthy = health == "healthy"
            state = f"running (health: {health})"
        last = {"healthy": healthy, "state": state}
        if healthy or time.monotonic() >= deadline:
            break
        time.sleep(interval)
    return last


def _which_docker():
    return os.environ.get("PI_TOR_DOCKER_BIN") or shutil.which("docker")


def compose_up(services, root):
    """Whole-stack compose recreate via a host-mounted docker binary."""
    if _dry():
        return {"skipped": "dry-run"}
    binary = _which_docker()
    if not binary:
        return {"error": "no docker binary found in PATH; cannot run "
                         "'docker compose up'. Mount the host docker binary "
                         "into the ui container and retry."}
    counters["subprocess_calls"] += 1
    try:
        p = subprocess.run(
            [binary, "compose", "up", "-d", "--no-deps", *services],
            cwd=str(root), capture_output=True, text=True, timeout=180)
    except Exception as exc:  # noqa: BLE001 — surface, never silently fail
        return {"error": f"docker compose failed: {exc}"}
    if p.returncode != 0:
        return {"error": f"docker compose exit {p.returncode}: "
                         f"{(p.stderr or p.stdout or '')[-1000:]}"}
    return {"recreated": list(services), "output": (p.stdout or "")[-2000:]}


RULES_ENV_KEYS = {
    "PI_TOR_INTERFACE": "interface",
    "PI_TOR_SUBNET": "subnet",
    "PI_TOR_GATEWAY": "gateway_ip",
    "PI_TOR_TRANS_PORT": "trans_port",
    "PI_TOR_DNS_PORT": "dns_port",
    "PI_TOR_PROTECTED_HOSTS": "protected_hosts",
}


def rules_env(values):
    """The explicit PI_TOR_* env passed to bin/pi-tor-rules.sh."""
    return {k: values[key] for k, key in RULES_ENV_KEYS.items()}


def run_rules(root, values, action="apply"):
    """Run bin/pi-tor-rules.sh apply|flush with explicit PI_TOR_* env overrides."""
    if _dry():
        return {"skipped": "dry-run"}
    if action not in ("apply", "flush"):
        return {"error": f"unknown rules action {action!r}"}
    # flush writes too (it re-installs the :53 guard instead of removing it),
    # so both actions have to go through the host's backend
    backend = iptables_backend()
    if backend.get("backend") != "nf_tables":
        return {"error": f"refusing to apply: the iptables backend is "
                         f"{backend.get('backend') or 'unavailable'}, not "
                         "nf_tables — a legacy ruleset would diverge from "
                         "the host's",
                "backend": backend}
    script = os.path.join(str(root), "bin", "pi-tor-rules.sh")
    if not os.path.isfile(script):
        return {"error": f"{script} not found (project not mounted?)"}
    env = dict(os.environ)
    env.update(rules_env(values))
    counters["subprocess_calls"] += 1
    try:
        p = subprocess.run([script, action], env=env,
                           capture_output=True, text=True, timeout=180)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"pi-tor-rules.sh failed: {exc}"}
    if p.returncode != 0:
        return {"error": f"pi-tor-rules.sh exit {p.returncode}: "
                         f"{(p.stderr or p.stdout or '')[-1000:]}"}
    return {"applied": True, "action": action, "output": (p.stdout or "")[-2000:]}


def parse_backend(version_line):
    """"iptables -V" output -> 'nf_tables' | 'legacy' | 'unknown'."""
    if "(nf_tables)" in version_line:
        return "nf_tables"
    if "(legacy)" in version_line:
        return "legacy"
    return "unknown"


def iptables_backend(version_output=None):
    """Backend of the iptables binary the rules script would use (same
    IPTABLES_BIN override and resolution order as the script). A legacy
    binary would edit a nat ruleset nothing on the Pi reads — detect it,
    never write through it."""
    if _dry():
        return {"backend": "skipped (dry-run)"}
    binary = (os.environ.get("IPTABLES_BIN")
              or shutil.which("iptables-nft") or shutil.which("iptables"))
    if not binary:
        return {"backend": "unknown",
                "note": "no iptables binary in this container"}
    if version_output is None:
        counters["subprocess_calls"] += 1
        try:
            p = subprocess.run([binary, "-V"], capture_output=True,
                               text=True, timeout=15)
        except Exception as exc:  # noqa: BLE001
            return {"backend": "unknown", "note": str(exc)}
        version_output = (p.stdout or p.stderr).strip()
        if p.returncode != 0:
            return {"backend": "unknown", "version": version_output,
                    "binary": binary}
    return {"backend": parse_backend(version_output),
            "version": version_output, "binary": binary}


def iptables_status():
    """Best-effort state of the PI_TOR_REDIRECT chain in the nat table."""
    if _dry():
        return {"state": "skipped (dry-run)"}
    binary = shutil.which("iptables-nft") or shutil.which("iptables")
    if not binary:
        return {"state": "unknown",
                "note": "no iptables binary in this container"}
    counters["subprocess_calls"] += 1
    try:
        p = subprocess.run([binary, "-t", "nat", "-S", "PI_TOR_REDIRECT"],
                           capture_output=True, text=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        return {"state": "unknown", "note": str(exc)}
    if p.returncode == 0 and (p.stdout or "").strip():
        return {"state": "present"}
    return {"state": "absent"}


def _short(raw):
    try:
        return json.dumps(json.loads(raw.decode("utf-8", "replace")))[:300]
    except ValueError:
        return raw.decode("utf-8", "replace")[:300]


def _json_short(data):
    try:
        return json.dumps(data)[:300]
    except (TypeError, ValueError):
        return str(data)[:300]
