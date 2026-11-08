#!/usr/bin/env python3
"""pi-tor host tether UI — runs on the tethered workstation, not on the Pi.

One loopback-only page to toggle bin/usb_route / bin/usb_route_undo (via
`sudo -n <script>`, fixed argv) and a dead-man revert: when the Pi stops
answering while the tether route is up, the host is restored to its normal
routing automatically.

Two tabs, both stdlib-rendered Gruvbox:
  * Tether (default, /): one toggle, one green/red status row per check (each
    row carries a word, never colour alone), and the append-only event log.
  * Config (/config): the six knobs editable and persisted to
    $XDG_CONFIG_HOME/pi-tor-hostui/config.json (override
    PI_TOR_HOSTUI_CONFIG); a valid save applies to the running probe loop at
    once (listen_port only after a restart) and never disarms a dead-man.

Env (all optional):
  PI_TOR_HOSTUI_PORT        listen port, default 8090
  PI_TOR_HOSTUI_BIND        bind address, default 127.0.0.1 (loopback enforced)
  PI_TOR_HOSTUI_ALLOW_ANY   set to 1 to allow a non-loopback bind
  PI_TOR_HOSTUI_STATE       dead-man state file; the only file this app writes
                            outside the repo. Default sits under
                            $XDG_RUNTIME_DIR (cleared on reboot) or ~/.cache.
  PI_TOR_HOSTUI_LOG         append-only event log (default: events.log next to
                            the state file); bounded, newest tail at /api/log.
  PI_TOR_HOSTUI_CONFIG      config file for the Config tab (default under
                            $XDG_CONFIG_HOME or ~/.config/pi-tor-hostui/).
                            Values saved there override the PI_TOR_* env.
  PI_TOR_HOSTUI_DRY_RUN     1 = never execute the tether scripts or any
                            nmcli/ip/resolvectl command (read-only probes to
                            the Pi may run)
  PI_TOR_PI_ADDR            the Pi side of the gadget subnet, default 10.12.194.1
  PI_TOR_HOST_ADDR          this host's address on the gadget link,
                            default 10.12.194.2
  PI_TOR_UI_PORT            the Pi's config-UI TCP port, default 8080 — the
                            dead-man probes it because ICMP is not redirected
                            and ping alone would be misleading
  PI_TOR_PROBE_INTERVAL     probe interval seconds, default 15
  PI_TOR_REVERT_AFTER       seconds of consecutive failures before revert, default 90

Security:
  * CSRF: GET / issues a per-process random token embedded in the page; every
    POST must return it in the X-PiTor-Token header and — when it sends an
    Origin at all — that Origin must be same-origin. A cross-origin page can
    neither read the token (same-origin policy) nor fake the Origin check.
    No cookies are used.
  * The app runs no sudo itself: it invokes `sudo -n <script>` with a fixed
    argv and sudoers must permit the script (README: /etc/sudoers.d/pi-tor-tether).
  * Dead-man caveat: it only works while this process runs — keep it under
    systemd --user with loginctl enable-linger; without the process nothing reverts.
"""
import fcntl
import hmac
import html
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

UI_DIR = Path(__file__).resolve().parent
ROOT = UI_DIR.parent
MAX_BODY = 10_000
SCRIPT_TIMEOUT = 120
LOG_LIMIT = 200          # lines the UI shows / /api/log returns
EVENT_FILE_LINES = 500   # hard bound of the append-only event file
STATE_DEFAULTS = {"tether": "off", "reverts_used": 0, "revert_reason": None,
                  "since": None, "last_error": None}
EXIT_IP_URL = "https://check.torproject.org/api/ip"
EXIT_IP_TTL = 60
DIRECT_IP_TTL = 300   # baseline for the tor-exit row, taken while untethered
NET_DIR = Path(os.environ.get("PI_TOR_NET_DIR", "/sys/class/net"))

# the six knobs editable on the Config tab
CONFIG_KEYS = ("pi_addr", "host_addr", "pi_ui_port", "probe_interval",
               "revert_after", "listen_port")

# ---------------------------------------------------------------- config


def default_state_file():
    base = os.environ.get("XDG_RUNTIME_DIR")
    if not base:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "pi-tor-hostui" / "dead-man.json"


def default_config_file():
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "pi-tor-hostui" / "config.json"


def config_from_env(env=None):
    env = os.environ if env is None else env
    return SimpleNamespace(
        port=int(env.get("PI_TOR_HOSTUI_PORT", "8090")),
        bind=env.get("PI_TOR_HOSTUI_BIND", "127.0.0.1"),
        allow_any=env.get("PI_TOR_HOSTUI_ALLOW_ANY") == "1",
        dry_run=env.get("PI_TOR_HOSTUI_DRY_RUN") == "1",
        pi_addr=env.get("PI_TOR_PI_ADDR", "10.12.194.1"),
        host_addr=env.get("PI_TOR_HOST_ADDR", "10.12.194.2"),
        pi_ui_port=int(env.get("PI_TOR_UI_PORT", "8080")),
        probe_interval=float(env.get("PI_TOR_PROBE_INTERVAL", "15")),
        revert_after=float(env.get("PI_TOR_REVERT_AFTER", "90")),
        sudo=env.get("PI_TOR_HOSTUI_SUDO", "sudo"),
        route_on=ROOT / "bin" / "usb_route",
        route_off=ROOT / "bin" / "usb_route_undo",
        state_file=Path(env.get("PI_TOR_HOSTUI_STATE") or default_state_file()),
        config_file=Path(env.get("PI_TOR_HOSTUI_CONFIG")
                         or default_config_file()),
    )


def _num(raw, cast):
    try:
        return cast(str(raw).strip())
    except (TypeError, ValueError):
        return None


def validated_field(field, raw):
    """(typed value, None) or (None, message) for one Config-tab field."""
    text = "none" if raw is None else repr(raw)
    if field in ("pi_addr", "host_addr"):
        try:
            addr = ip_address(str(raw).strip())
        except (ValueError, AttributeError):
            addr = None
        if addr is None or addr.version != 4:
            return None, (f"must be an IPv4 address like 10.12.194.1 "
                          f"(got {text})")
        return str(addr), None
    if field in ("pi_ui_port", "listen_port"):
        n = _num(raw, int)
        if n is None or not 1 <= n <= 65535:
            return None, f"must be a TCP port, 1-65535 (got {text})"
        return n, None
    if field == "probe_interval":
        n = _num(raw, float)
        if n is None or not 1 <= n <= 600:
            return None, f"must be 1-600 seconds (got {text})"
        return n, None
    if field == "revert_after":
        n = _num(raw, float)
        if n is None or not 10 <= n <= 3600:
            return None, f"must be 10-3600 seconds (got {text})"
        return n, None
    raise AssertionError(f"unknown config field {field}")


def validate_config(raw):
    """All six fields at once: ({field: value}, {field: message})."""
    clean, errors = {}, {}
    for field in CONFIG_KEYS:
        val, err = validated_field(field, raw.get(field))
        if err:
            errors[field] = err
        else:
            clean[field] = val
    return clean, errors


def save_config_file(path, clean):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({k: clean[k] for k in CONFIG_KEYS},
                              sort_keys=True))
    os.replace(tmp, path)


def load_saved_config(path):
    """Valid values persisted by the Config tab; invalid ones are ignored
    (the Config tab shows the live values either way)."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    clean = {}
    for field in CONFIG_KEYS:
        if field in data:
            val, err = validated_field(field, data[field])
            if not err:
                clean[field] = val
    return clean


def apply_config_values(cfg, clean):
    """Push saved values onto the live config; returns change strings.
    listen_port is set on cfg.port too, but takes effect only on restart
    (the bind happens once, in make_server)."""
    changes = []
    for field, val in clean.items():
        attr = "port" if field == "listen_port" else field
        old = getattr(cfg, attr, None)
        if val != old:
            setattr(cfg, attr, val)
            changes.append(f"{field} {old} → {val}")
    return changes


def bind_refusal(cfg):
    """Why the requested bind address must not be used (str), or None."""
    if cfg.allow_any:
        return None
    try:
        addr = ip_address(cfg.bind)
    except ValueError:
        return (f"bind '{cfg.bind}' is not an IP literal; use 127.0.0.1 "
                f"(or ::1), or set PI_TOR_HOSTUI_ALLOW_ANY=1")
    if not addr.is_loopback:
        return (f"bind '{cfg.bind}' is not loopback — this UI can route and "
                f"un-route the whole workstation via sudo, so it must not listen "
                f"on a network address. Use 127.0.0.1 (or ::1), or set "
                f"PI_TOR_HOSTUI_ALLOW_ANY=1 to override (not recommended)")
    return None

# ---------------------------------------------------------------- host probes


def default_route(path="/proc/net/route"):
    """The IPv4 default route as {iface, gateway} from /proc; None when none."""
    try:
        rows = Path(path).read_text().splitlines()[1:]
    except OSError:
        return None
    for row in rows:
        f = row.split()
        if len(f) >= 8 and f[1] == "00000000":
            gw = (socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
                  if f[2] != "00000000" else None)
            return {"iface": f[0], "gateway": gw}
    return None


def iface_addr(name):
    """IPv4 of a netdev via SIOCGIFADDR; None when it has none."""
    sio = getattr(socket, "SIOCGIFADDR", 0x8915)   # 0x8915 == SIOCGIFADDR
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sck:
            buf = fcntl.ioctl(sck.fileno(), sio,
                              struct.pack("256s", name[:15].encode()))
        return socket.inet_ntoa(buf[20:24])
    except OSError:
        return None


def gadget_iface(subnet_prefix, net_dir=NET_DIR):
    """Interface whose IPv4 address sits in the tether subnet, or None."""
    try:
        names = os.listdir(net_dir)
    except OSError:
        return None
    for name in names:
        addr = iface_addr(name)
        if addr and addr.startswith(subnet_prefix):
            return name
    return None


def link_dns(cfg, iface, resolv_conf="/etc/resolv.conf"):
    """Current DNS servers: per-link from resolvectl (read-only, live only),
    falling back to the system resolver file."""
    if iface and not cfg.dry_run and shutil.which("resolvectl"):
        try:
            p = subprocess.run(["resolvectl", "dns", iface],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"^Link \d+ \(\S+\):\s*(.+)$", p.stdout, re.M)
            if m:
                return m.group(1).split()
        except (OSError, subprocess.SubprocessError):
            pass
    servers = []
    try:
        for line in Path(resolv_conf).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line.startswith("nameserver "):
                servers.append(line.split()[1])
    except OSError:
        pass
    return servers


def iface_with_addr(addr, net_dir=NET_DIR):
    """The interface whose IPv4 equals addr, or None."""
    try:
        names = os.listdir(net_dir)
    except OSError:
        return None
    for name in names:
        if iface_addr(name) == addr:
            return name
    return None


def iface_carrier(name, net_dir=NET_DIR):
    try:
        return Path(net_dir, name, "carrier").read_text().strip() == "1"
    except OSError:
        return False


def tcp_probe(addr, port, timeout=3):
    """(True, None) when a TCP connect answers, else (False, short reason)."""
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            return True, None
    except socket.timeout:
        return False, "timed out"
    except OSError as exc:
        kind = type(exc).__name__   # e.g. ConnectionRefusedError
        return False, (kind[:-5].lower() or kind) if kind.endswith("Error") \
            else str(exc)[:60]


def dns_probe(server, timeout=3, name="www.debian.org"):
    """One real A query straight at the Pi's resolver: an rcode-0 reply proves
    DNS still flows through it. UDP pack/unpack by hand, stdlib only."""
    q = struct.pack(">HHHHHH", secrets.randbits(16), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    q += b"\x00" + struct.pack(">HH", 1, 1)   # QTYPE A, QCLASS IN
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sck:
            sck.settimeout(timeout)
            sck.sendto(q, (server, 53))
            data, _ = sck.recvfrom(1024)
    except socket.timeout:
        return False, "timed out"
    except OSError as exc:
        return False, type(exc).__name__
    if len(data) < 12 or not data[2] & 0x80:      # QR bit: no reply flag
        return False, "short reply"
    rcode = data[3] & 0x0F
    if rcode:
        return False, f"rcode {rcode}"
    return True, None

# ---------------------------------------------------------------- dead-man


class DeadMan:
    """Probes the Pi's config-UI port while the tether session is armed and
    hands the revert to the app after the window. Clock/probe/undo are
    attributes so tests can drive it without sleeps or the network."""

    def __init__(self, cfg, state, log_event):
        self.cfg, self.state, self.log_event = cfg, state, log_event
        self.clock = time.monotonic
        self.probe = self._probe_tcp
        self.undo = lambda: {}
        self.app_revert = lambda reason: None   # wired by TetherApp below
        self.first_failure = None
        self.fail_count = 0
        self.pi_up = None

    def _probe_tcp(self):
        try:
            with socket.create_connection((self.cfg.pi_addr,
                                           self.cfg.pi_ui_port), timeout=3):
                return True
        except OSError:
            return False

    def armed(self):
        return (self.state.get("tether") == "on"
                and not self.state.get("reverts_used"))

    def reset(self):
        self.first_failure = None
        self.fail_count = 0

    def revert_reason(self, elapsed):
        return (f"auto-revert: the Pi ({self.cfg.pi_addr}) stopped answering "
                f"its config UI (port {self.cfg.pi_ui_port}) for "
                f"{elapsed:.0f}s across {self.fail_count} consecutive probes; "
                f"reverting to normal routing")

    def tick(self):
        if not self.armed():
            if self.state.get("tether") != "on":
                self.pi_up = None            # untethered/reverted: not probing
            return
        up = self.probe()
        self.pi_up = up
        now = self.clock()
        if up:
            if self.first_failure is not None:
                self.log_event("dead-man", "Pi is answering again; timer reset")
                self.reset()
            return
        self.fail_count += 1
        if self.first_failure is None:
            self.first_failure = now
            self.log_event("dead-man",
                           f"Pi stopped answering; failure window started "
                           f"(revert after {self.cfg.revert_after:.0f}s)")
            return
        elapsed = now - self.first_failure
        if elapsed >= self.cfg.revert_after:
            reason = self.revert_reason(elapsed)
            self.reset()
            self.app_revert(reason)

# ---------------------------------------------------------------- app


def now_iso():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def sudo_needs_rule(stderr):
    low = (stderr or "").lower()
    return ("password" in low or "not allowed to execute" in low
            or "sudoers" in low)


class TetherApp:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = secrets.token_hex(16)
        self.history = deque(maxlen=LOG_LIMIT)
        self.state = self._load_state()
        self.log_file = (getattr(cfg, "log_file", None)
                         or cfg.state_file.parent / "events.log")
        self.config_file = (getattr(cfg, "config_file", None)
                            or default_config_file())
        if not hasattr(cfg, "host_addr"):
            cfg.host_addr = "10.12.194.2"   # cfgs built outside config_from_env
        self._exit_ip = {}   # {t: ts, ip, error} cache (through the tether)
        self._direct_ip = {} # untethered baseline for the tor-exit row
        self.session_started_here = False  # a POST {"on": true} succeeded here
        self.deadman = DeadMan(cfg, self.state, self.log_event)
        self.deadman.undo = lambda: self.run_tether(False, auto=True)
        self.deadman.app_revert = self.revert_once  # type: ignore[assignment]
        if self.state.get("tether") == "on":
            self.log_event("note", "resuming tether session from "
                           f"{cfg.state_file}; dead-man armed again "
                           "(the revert only happens while this process runs)")

    # -- state file (the only write outside the repo) -----------------------

    def _load_state(self):
        st = dict(STATE_DEFAULTS)
        try:
            data = json.loads(self.cfg.state_file.read_text())
            if isinstance(data, dict):
                for k in STATE_DEFAULTS:
                    st[k] = data.get(k, STATE_DEFAULTS[k])
        except (OSError, ValueError):
            pass
        return st

    def save(self):
        p = self.cfg.state_file
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps(self.state, sort_keys=True))
        os.replace(tmp, p)     # tmp+rename: a crash mid-write cannot disarm the dead-man

    def log_event(self, event, detail=""):
        rec = {"t": now_iso(), "event": event, "detail": detail}
        self.history.appendleft(rec)
        self._log_append(json.dumps(rec, sort_keys=True))

    def _log_append(self, line):
        """Append to the event file and keep it bounded (last 500 lines);
        a lost or unwritable log dir must never take the UI down."""
        p = self.log_file
        try:
            lines = p.read_text().splitlines() if p.exists() else []
            lines.append(line)
            if len(lines) > EVENT_FILE_LINES:
                lines = lines[-EVENT_FILE_LINES:]
                tmp = p.with_name(p.name + ".tmp")
                tmp.write_text("\n".join(lines) + "\n")
                os.replace(tmp, p)
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "a") as fh:
                    fh.write(line + "\n")
        except OSError:
            pass

    def read_log(self):
        """The current tail of the event file, newest first, bounded."""
        try:
            lines = self.log_file.read_text().splitlines()
        except OSError:
            return []
        out = []
        for line in reversed(lines[-LOG_LIMIT:]):
            try:
                out.append(json.loads(line))
            except ValueError:
                continue   # a half-written tail line is skipped
        return out

    # -- tether actions -----------------------------------------------------

    def route_argv(self, on):
        # fixed argv: nothing from user input is ever interpolated
        return [self.cfg.sudo, "-n",
                str(self.cfg.route_on if on else self.cfg.route_off)]

    def run_tether(self, on, auto=False):
        argv = self.route_argv(on)
        if self.cfg.dry_run:
            self.log_event("dry-run", "would run: " + " ".join(argv))
            return {"dry_run": True, "ok": True, "argv": argv,
                    "message": "dry run: nothing executed"}
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=SCRIPT_TIMEOUT)
        except subprocess.TimeoutExpired:
            msg = f"timed out after {SCRIPT_TIMEOUT}s; tether state not changed"
            self.log_event("error", msg)
            return {"ok": False, "argv": argv, "error": msg}
        except OSError as exc:
            msg = (f"cannot start {argv[0]}: {exc}; the tether scripts were "
                   f"not run")
            self.log_event("error", msg)
            return {"ok": False, "argv": argv, "error": msg}

        if proc.returncode == 0:
            if not auto:
                # clean up any previous auto-revert marker or error; usb_route
                # verifies its own work, so the session state is authoritative
                self.state.update(tether="on" if on else "off",
                                  reverts_used=0, revert_reason=None,
                                  last_error=None,
                                  since=now_iso() if on else None)
                self.session_started_here = bool(on)
                self.save()
            self.deadman.reset()
            self.log_event("tether-on" if on else "tether-off",
                           " ".join(argv))
            return {"ok": True, "argv": argv, "exit_code": 0,
                    "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:],
                    "state": self.state["tether"]}

        err = (proc.stderr or proc.stdout or "").strip()
        first = err.splitlines()[-1] if err else f"exit {proc.returncode}"
        if not auto and sudo_needs_rule(err):
            rule = "/etc/sudoers.d/pi-tor-tether"
            msg = (f"sudo refused: {first}. The host UI must run the tether "
                   f"scripts without a password — create {rule} permitting "
                   f"exactly {self.cfg.route_on} and {self.cfg.route_off} for "
                   f"the user running this app, then retry. The tether state "
                   f"was not changed.")
            self.log_event("error", msg)
            return {"ok": False, "exit_code": proc.returncode, "argv": argv,
                    "stderr": err[-2000:], "error": msg,
                    "missing_sudo_rule": True}
        msg = f"{argv[2]} failed (exit {proc.returncode}): {first}"
        self.log_event("error", msg)
        return {"ok": False, "exit_code": proc.returncode, "argv": argv,
                "stdout": proc.stdout[-2000:], "stderr": err[-2000:],
                "error": msg}

    def revert_once(self, reason):
        # the dead-man's single shot per tether session
        if self.cfg.dry_run:
            self.log_event("dry-run", reason + " (dry run: nothing executed)")
            return {"dry_run": True, "ok": True,
                    "message": reason + " — nothing executed"}
        # marked BEFORE the undo runs: a crash here cannot cause a second undo
        self.state["tether"] = "reverted"
        self.state["reverts_used"] = self.state.get("reverts_used", 0) + 1
        self.state["revert_reason"] = reason
        self.state["last_error"] = None
        self.save()
        self.log_event("revert", reason)
        out = self.deadman.undo()
        if not out.get("ok"):  # the one undo attempt failed; do not retry here
            line = ("auto-revert undo failed: "
                    + (out.get("error") or "unknown reason").strip()[:300])
            self.state["last_error"] = line
            self.save()
            self.log_event("revert-failed", line)

    def deadman_loop(self):
        while True:
            self.deadman.tick()
            time.sleep(self.cfg.probe_interval)

    # -- reporting ----------------------------------------------------------

    def tether_state(self, route):
        # /proc says where the default route really points right now; the
        # session records what we did (usb_route verifies its own changes)
        session = str(self.state.get("tether") or "off")
        route_via_pi = bool(route and route.get("gateway") == self.cfg.pi_addr)
        if route_via_pi:
            return "on"
        if session == "reverted":
            return "reverted"
        if session == "on" and not self.session_started_here:
            return "unknown"   # session armed here, restarted later: /proc disagrees
        return session

    def wan_ip(self, cache, ttl, label):
        """Fresh (cached-for-ttl) WAN IP seen from here, (ip, error). While
        tethered this is the exit IP; while untethered it is the direct
        baseline the tor-exit row compares against."""
        now = time.time()
        hit = cache.get("at")
        if hit is not None and now - hit < ttl:
            return cache.get("ip"), cache.get("error")
        try:
            with urllib.request.urlopen(EXIT_IP_URL, timeout=5) as resp:
                ip = json.loads(resp.read(200).decode()).get("IP")
        except Exception as exc:  # noqa: BLE001 — exit ip is best-effort
            cache.update(at=now, ip=None, error=type(exc).__name__)
            return None, type(exc).__name__
        if label == "exit":
            self.log_event("exit-ip", f"exit IP through the tether: {ip}")
        elif ip != cache.get("ip"):
            self.log_event("direct-ip",
                           f"direct WAN IP {ip} (baseline for the tor-exit check)")
        cache.update(at=now, ip=ip, error=None)
        return ip, None

    def exit_ip(self):
        # meaningful only while routed through the Pi
        return self.wan_ip(self._exit_ip, EXIT_IP_TTL, "exit")

    def baseline_direct_ip(self):
        # taken while untethered, so the tor-exit row can spot a difference;
        # never fetched under dry run — the UI then stays fully offline
        if self.cfg.dry_run:
            return self._direct_ip.get("ip")
        ip, _err = self.wan_ip(self._direct_ip, DIRECT_IP_TTL, "direct")
        return ip

    def status(self):
        cfg = self.cfg
        route = default_route()
        tether = self.tether_state(route)
        dm = self.deadman
        armed = dm.armed()
        revert_in = None
        if armed and dm.first_failure is not None:
            revert_in = max(0, round(cfg.revert_after
                                     - (dm.clock() - dm.first_failure)))
        exit_ip = exit_err = None
        if tether == "on" and not cfg.dry_run:
            exit_ip, exit_err = self.exit_ip()
        elif tether != "on" and not cfg.dry_run:
            self.baseline_direct_ip()
        return {
            "dry_run": cfg.dry_run,
            "bind": cfg.bind, "port": cfg.port,
            "state_file": str(cfg.state_file),
            "config_file": str(self.config_file),
            "log_file": str(self.log_file),
            "tether": tether,
            "default_route": route,
            "dns_servers": link_dns(cfg, route and route.get("iface")),
            "gadget_iface": gadget_iface(cfg.pi_addr.rsplit(".", 1)[0] + "."),
            "pi_addr": cfg.pi_addr, "host_addr": cfg.host_addr,
            "pi_ui_port": cfg.pi_ui_port,
            "pi_answers": dm.pi_up,
            "probe_interval": cfg.probe_interval,
            "revert_after": cfg.revert_after,
            "deadman_armed": armed, "revert_in_seconds": revert_in,
            "deadman_note": ("reverts once after %gs of consecutive probe "
                             "failures; only while this process runs"
                             % cfg.revert_after),
            "last_revert": self.state.get("revert_reason"),
            "last_error": self.state.get("last_error"),
            "exit_ip": exit_ip, "exit_ip_error": exit_err,
            "rows": self.status_rows(route, tether, revert_in),
        }

    # -- status rows ---------------------------------------------------------

    def status_rows(self, route, tether, revert_in):
        """One row per check: label, a word that carries the meaning (never
        colour alone, cls ∈ ok/bad/warn/idle), and a why on anything bad."""
        cfg, rows = self.cfg, []
        add = lambda label, word, cls, why="": \
            rows.append(dict(label=label, word=word, cls=cls, why=why))

        iface = iface_with_addr(cfg.host_addr)
        if iface is None:
            add("gadget link", "absent", "idle",
                f"no interface holds the tether address {cfg.host_addr}")
        elif iface_carrier(iface):
            add("gadget link", "up", "ok", f"{iface}: carrier up")
        else:
            add("gadget link", "no carrier", "bad",
                f"{iface} exists but reports no carrier")

        dm = self.deadman
        if dm.armed() and dm.pi_up is not None:
            if dm.pi_up:
                add("pi reachable", "answering", "ok",
                    f"TCP {cfg.pi_addr}:{cfg.pi_ui_port}")
            else:
                add("pi reachable", "not answering", "bad",
                    f"Pi stopped answering {max(1, dm.fail_count)} probe(s)")
        elif iface is not None:
            ok, why = tcp_probe(cfg.pi_addr, cfg.pi_ui_port)
            if ok:
                add("pi reachable", "answering", "ok",
                    f"TCP {cfg.pi_addr}:{cfg.pi_ui_port}")
            else:
                add("pi reachable", "not answering", "bad",
                    f"TCP {cfg.pi_addr}:{cfg.pi_ui_port}: {why}")
        else:
            add("pi reachable", "idle", "idle", "no gadget link to probe")

        if route and route.get("gateway") == cfg.pi_addr:
            add("tether active", "on", "ok",
                f"default route via {cfg.pi_addr} on {route['iface']}")
        elif tether == "on":
            add("tether active", "not via pi", "bad",
                "the session is armed but the default route is no longer "
                "via the Pi")
        elif tether == "reverted":
            add("tether active", "auto-reverted", "bad",
                self.state.get("revert_reason") or "reverted — see the log")
        else:
            add("tether active", "off", "idle", "host is on its normal network")

        if tether != "on":
            add("dns through pi", "idle", "idle",
                "tether off — using normal DNS")
        else:
            ok, why = dns_probe(cfg.pi_addr)
            if ok:
                add("dns through pi", "via pi", "ok",
                    f"a lookup via {cfg.pi_addr}:53 resolved")
            else:
                add("dns through pi", "failing", "bad",
                    f"no answer from {cfg.pi_addr}:53 ({why})")

        if tether != "on":
            add("tor exit", "idle", "idle",
                "only meaningful while tethered")
        elif cfg.dry_run:
            add("tor exit", "unknown", "idle",
                "exit-IP lookup skipped in dry run")
        else:
            ip, err = self.exit_ip()
            direct = self._direct_ip.get("ip")
            if err or not ip:
                add("tor exit", "unavailable", "bad",
                    f"exit-IP lookup failed ({err})")
            elif direct and ip != direct:
                add("tor exit", f"tor exit {ip}", "ok",
                    f"differs from the direct WAN IP {direct}")
            elif direct and ip == direct:
                add("tor exit", "not tor", "bad",
                    f"{ip} equals the direct WAN IP — traffic is not "
                    f"taking the tor path")
            else:
                add("tor exit", "unknown", "idle",
                    "no direct WAN IP baseline yet — it is recorded while "
                    "the host is untethered")

        if self.deadman.armed():
            word = "armed" if revert_in is None else \
                f"armed · revert in {revert_in}s"
            add("dead-man", word, "warn",
                f"reverts once after {cfg.revert_after:.0f}s of consecutive "
                f"probe failures")
        elif self.state.get("tether") == "reverted":
            add("dead-man", "used", "idle",
                "one revert already fired this session; toggle on to re-arm")
        else:
            add("dead-man", "idle", "idle",
                "not probing — the tether is off")
        return rows

    def diagnostics(self, route):
        """Read-only configuration checks for the Config tab, so a
        misconfiguration is visible instead of inferred. Skipped under dry
        run, where nothing may be executed."""
        cfg = self.cfg
        if cfg.dry_run:
            return ["dry run: the nmcli / ip / resolvectl diagnostics are "
                    "skipped"]
        sudoers = Path("/etc/sudoers.d/pi-tor-tether")
        lines = [f"sudoers rule {sudoers}: "
                 + ("present" if sudoers.exists() else "MISSING")]
        try:
            if shutil.which("nmcli"):
                p = subprocess.run(
                    ["nmcli", "--terse", "--fields", "NAME,DEVICE,TYPE",
                     "connection", "show"],
                    capture_output=True, text=True, timeout=10)
                hit = next((l for l in p.stdout.splitlines()
                            if l.startswith("pi-tor-gadget")), None)
                lines.append("nmcli profile pi-tor-gadget: "
                             + (hit or "not found"))
            else:
                lines.append("nmcli: not installed")
            if shutil.which("ip"):
                p = subprocess.run(["ip", "route", "show", "default"],
                                   capture_output=True, text=True, timeout=5)
                lines.append("default route (ip): "
                             + (p.stdout.strip() or "none"))
            else:
                lines.append(f"default route (/proc): {route or 'none'}")
            dns = link_dns(cfg, iface_with_addr(cfg.host_addr))
            lines.append("dns servers: " + (", ".join(dns) or "none"))
        except (OSError, subprocess.SubprocessError) as exc:
            lines.append(f"a diagnostic command failed: "
                         f"{type(exc).__name__}: {exc}")
        return lines

    # -- config tab ----------------------------------------------------------

    def apply_config(self, clean):
        """Save a validated Config-tab form: persist the file, then apply to
        the running process. The probe/dead-man loop re-reads cfg every cycle,
        so probe_interval/pi_addr/pi_ui_port take effect without a restart;
        listen_port needs one. Never touches the session state, so an armed
        dead-man stays armed."""
        changes = apply_config_values(self.cfg, clean)
        save_config_file(self.config_file, clean)
        line = "config saved: " + ("; ".join(changes) or "no value changed")
        if any(c.startswith("listen_port") for c in changes):
            line += " — listen_port applies on restart"
        self.log_event("config", line)
        return changes

# ---------------------------------------------------------------- server


STYLE = """\
:root { --bg:#282828; --fg:#ebdbb2; --accent:#df840c; --muted:#928374; \
--red:#fb4934; --green:#b8bb26; --amber:#d79921; --card:#32302f; \
--border:#504945; --input:#3c3836; --deep:#1d2021; }
body { background:var(--bg); color:var(--fg); \
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; \
margin:0 auto; max-width:720px; padding:0 1rem 2rem; }
header h1 { border-bottom:2px solid var(--accent); padding-bottom:.5rem; }
.accent { color:var(--accent); }
h2 { font-size:1.1rem; margin:1.5rem 0 .5rem; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); \
gap:.5rem; }
.card { background:var(--card); border:1px solid var(--border); \
border-radius:6px; padding:.6rem .9rem; }
.card .k { color:var(--muted); font-size:.8rem; text-transform:uppercase; \
letter-spacing:.05em; }
.card .v { margin-top:.2rem; font-size:1.05rem; word-break:break-word; }
.card.ok .v { color:var(--green); }
.card.bad .v { color:var(--red); }
button { background:var(--accent); color:#282828; border:0; border-radius:4px; \
padding:.5rem 1rem; font-weight:600; cursor:pointer; }
button.secondary { background:var(--input); color:var(--fg); }
button:disabled { opacity:.5; cursor:wait; }
.errors { color:var(--red); margin:.5rem 0; }
.ok-message { color:var(--green); }
.muted { color:var(--muted); }
.badge { display:inline-block; border-radius:3px; padding:.05rem .45rem; \
font-size:.75rem; font-weight:600; text-transform:uppercase; \
letter-spacing:.04em; color:#282828; }
.badge.ok { background:var(--green); }
.badge.warn { background:var(--amber); }
.badge.bad { background:var(--red); }
.badge.off { background:var(--input); color:var(--fg); }
.tabs { display:flex; gap:.4rem; margin:1rem 0 1.2rem; }
.tab { padding:.35rem .9rem; border:1px solid var(--border); border-radius:4px;
color:var(--fg); text-decoration:none; background:var(--card); }
.tab.active { background:var(--accent); color:#282828; font-weight:600;
border-color:var(--accent); }
.row { display:flex; align-items:baseline; gap:.55rem; padding:.3rem 0;
border-bottom:1px dotted var(--border); flex-wrap:wrap; }
.row .rlab { font-weight:600; min-width:9rem; }
.row .why, .foot { font-size:.85rem; }
.field { margin:.6rem 0; }
.field label { display:block; color:var(--muted); font-size:.8rem;
text-transform:uppercase; letter-spacing:.05em; margin-bottom:.15rem; }
.field input { width:100%; box-sizing:border-box; background:var(--input);
border:1px solid var(--border); color:var(--fg); border-radius:4px;
padding:.4rem .55rem; font:inherit; }
.fielderr { color:var(--red); font-size:.85rem; min-height:1.1rem; }
pre { background:var(--deep); padding:.5rem; border-radius:4px; overflow:auto; \
max-height:24rem; white-space:pre-wrap; word-break:break-word; font-size:.85rem; }
footer { margin-top:2rem; border-top:1px solid var(--border); \
padding-top:.8rem; font-size:.8rem; }
"""


PAGE_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="pi-tor-token" content="@@TOKEN@@">
<title>@@TITLE@@</title>
<style>@@STYLE@@</style>
</head>
<body>
<header><h1>pi-tor <span class="accent">tether</span></h1></header>
<nav class="tabs">
  <a class="tab@@A_TETHER@@" href="/">tether</a>
  <a class="tab@@A_CONFIG@@" href="/config">config</a>
</nav>
@@BODY@@
<footer><span class="muted">pi-tor host tether UI · loopback only · POST
requests must carry the X-PiTor-Token issued on this page · the dead-man
revert only works while this process is running.</span></footer>
<script>
@@SCRIPT@@
</script>
</body>
</html>
""".replace("@@STYLE@@", STYLE)

TETHER_SCRIPT = """\
(function () {
  "use strict";
  var token = document.querySelector('meta[name="pi-tor-token"]').content;
  var current = null;
  var timer = null;
  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  var SENTENCES = {
    on: "The host is routed through the Pi: the default route and DNS " +
        "(Pi-hole) ride the gadget link, and TCP goes through tor.",
    off: "The host is on its normal network.",
    reverted: "Auto-reverted to the normal network — the connection log says why.",
    unknown: "A tether session may still be armed, but the default route " +
             "no longer points at the Pi."
  };

  function render(st, log) {
    current = st.tether;
    var html = (st.rows || []).map(function (r) {
      return '<div class="row"><span class="rlab">' + esc(r.label) +
        '</span><span class="badge ' + esc(r.cls) + '">' + esc(r.word) +
        '</span>' + (r.why ? '<span class="why muted">' + esc(r.why) +
        '</span>' : "") + '</div>';
    }).join("");
    if (st.dry_run) {
      html = '<div class="row"><span class="rlab">mode</span>' +
        '<span class="badge warn">DRY RUN</span>' +
        '<span class="why muted">DRY RUN — the tether scripts are never ' +
        'executed</span></div>' + html;
    }
    $("status").innerHTML = html;
    $("sentence").textContent = SENTENCES[st.tether] || esc(st.tether);
    $("log").textContent = (log || []).map(function (e) {
      return e.t + "  [" + e.event + "]  " + (e.detail || "");
    }).join("\\n") || "no events yet";
    var btn = $("toggle");
    btn.disabled = false;
    btn.textContent = st.tether === "on"
      ? "Untether — restore normal routing"
      : "Route host through pi-tor";
  }

  function loadAll() {
    return Promise.all([
      fetch("/api/status").then(function (r) { return r.json(); }),
      fetch("/api/log").then(function (r) { return r.json(); })
    ]).then(function (got) {
      render(got[0], got[1].events || []);
      $("message").className = "muted";
      $("message").textContent = "";
    }).catch(function (err) {
      $("message").className = "errors";
      $("message").textContent = "cannot reach host UI: " + err;
    });
  }

  function startPolling() {
    if (timer) return;
    loadAll();
    timer = setInterval(loadAll, 2000);   // ~2 s while the tab is visible
  }
  function stopPolling() { clearInterval(timer); timer = null; }
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { stopPolling(); } else { startPolling(); }
  });

  $("refresh").onclick = loadAll;
  $("toggle").onclick = function () {
    var btn = $("toggle");
    var on = current === "on";
    btn.disabled = true; btn.textContent = "…";
    fetch("/api/tether", { method: "POST",
      headers: { "Content-Type": "application/json",
                 "X-PiTor-Token": token },
      body: JSON.stringify({ on: on }) })
      .then(function (res) {
        return res.json().then(function (data) {
          $("message").className = (res.ok && data.ok && !data.dry_run)
            ? "ok-message" : (res.ok && data.dry_run ? "ok-message" : "errors");
          $("message").textContent = (data.dry_run ? "dry run: " : "") +
            (data.error || data.message ||
             (data.ok ? "ran: " + (data.argv || []).join(" ") : "failed"));
        });
      })
      .catch(function (err) {
        $("message").className = "errors";
        $("message").textContent = String(err);
      })
      .then(loadAll);
  };

  startPolling();
})();
"""

TETHER_BODY = """\
<section>
  <h2>Tether
    <button id="toggle" type="button" disabled>loading…</button>
    <button id="refresh" type="button" class="secondary">Refresh</button>
  </h2>
  <p id="sentence" class="muted">loading…</p>
  <div id="status"><span class="muted">loading…</span></div>
  <div id="message" class="muted"></div>
  <p class="foot muted">ICMP does not work while tethered — ping will fail;
that is expected. The dead-man probes the Pi's config-UI port over TCP
instead.</p>
</section>

<section id="logview">
  <h2>Connection log (newest first)</h2>
  <pre id="log" class="muted">loading…</pre>
</section>
"""

CONFIG_SCRIPT = """\
(function () {
  "use strict";
  var token = document.querySelector('meta[name="pi-tor-token"]').content;
  var names = %(names)s;
  function $(id) { return document.getElementById(id); }
  function read() {
    var body = {};
    names.forEach(function (n) { body[n] = $("f_" + n).value.trim(); });
    return body;
  }
  function show(res, data) {
    names.forEach(function (n) {
      var el = $("err_" + n);
      if (el) el.textContent = (data.errors || {})[n] || "";
    });
    var msg = $("message");
    if (res.ok && data.ok) {
      msg.className = "ok-message";
      msg.textContent = "saved. " + ((data.changes || []).join("; ")
        || "no value changed");
      setTimeout(function () { location.reload(); }, 900);
    } else {
      msg.className = "errors";
      msg.textContent = data.error || "save failed";
    }
  }
  $("save").onclick = function () {
    var btn = $("save");
    btn.disabled = true;
    fetch("/api/config", { method: "POST",
      headers: { "Content-Type": "application/json",
                 "X-PiTor-Token": token },
      body: JSON.stringify(read()) })
      .then(function (res) {
        return res.json().then(function (data) { show(res, data); });
      })
      .catch(function (err) {
        var msg = $("message");
        msg.className = "errors";
        msg.textContent = String(err);
      })
      .then(function () { btn.disabled = false; });
  };
})();
"""


def config_body(app):
    """The Config tab, rendered at request time: live values, per-field
    error slots, and the read-only diagnostics block."""
    esc = html.escape
    values = {
        "pi_addr": app.cfg.pi_addr,
        "host_addr": app.cfg.host_addr,
        "pi_ui_port": app.cfg.pi_ui_port,
        "probe_interval": app.cfg.probe_interval,
        "revert_after": app.cfg.revert_after,
        "listen_port": app.cfg.port,
    }
    notes = {
        "pi_addr": "the Pi side of the gadget link",
        "host_addr": "this host's address on the gadget link",
        "pi_ui_port": "the port the dead-man probes",
        "probe_interval": "seconds between dead-man probes",
        "revert_after": "seconds of consecutive failures before revert",
        "listen_port": "applies on restart",
    }
    fields = []
    for key in CONFIG_KEYS:
        fields.append(
            '<div class="field">'
            f'<label for="f_{key}">{esc(key)} — {esc(notes[key])}</label>'
            f'<input id="f_{key}" name="{key}" value="{esc(str(values[key]))}">'
            f'<div class="fielderr" id="err_{key}"></div></div>')
    diag = "\n".join("  " + esc(line) for line in app.diagnostics(default_route()))
    script = CONFIG_SCRIPT % {"names": json.dumps(list(CONFIG_KEYS))}
    body = """
<section>
  <h2>Config
    <button id="save" type="button">Save config</button>
  </h2>
  <div id="message" class="muted"></div>
  {fields}
  <p class="foot muted">Validating saves nothing on error; a good save takes
effect for the probe loop immediately — only listen_port needs a restart
(the bind happens once at startup).</p>
</section>

<section>
  <h2>Diagnostics (read-only)</h2>
  <pre class="muted">{diag}
</pre>
</section>
""".format(fields="  \n  ".join(fields), diag=diag)
    return body, script


def page_html(active, title, token, body, script):
    return (PAGE_SHELL
            .replace("@@A_TETHER@@", " active" if active == "tether" else "")
            .replace("@@A_CONFIG@@", " active" if active == "config" else "")
            .replace("@@TITLE@@", title)
            .replace("@@BODY@@", body)
            .replace("@@SCRIPT@@", script)
            .replace("@@TOKEN@@", token))


class Handler(BaseHTTPRequestHandler):
    server_version = "pi-tor-hostui/1.0"
    protocol_version = "HTTP/1.1"

    def _send(self, ctype, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if ctype.startswith("text/html"):
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send("application/json", json.dumps(obj).encode(), code)

    def _page(self):
        self._send("text/html; charset=utf-8",
                   page_html("tether", "pi-tor tether",
                             self.server.pitor.token,
                             TETHER_BODY, TETHER_SCRIPT).encode())

    def _config_page(self):
        body, script = config_body(self.server.pitor)
        self._send("text/html; charset=utf-8",
                   page_html("config", "pi-tor tether — config",
                             self.server.pitor.token,
                             body, script).encode())

    def _csrf_ok(self):
        return hmac_compare(self.headers.get("X-PiTor-Token", ""),
                            self.server.pitor.token)

    def _mutate_gate(self):
        """Every mutation needs the CSRF token, and an Origin header — when
        the client sends one at all — must be same-origin. Returns None when
        allowed, else an (code, message) pair; refusals hit the event log."""
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host", ""):
            self.server.pitor.log_event(
                "refused", f"POST {self.path.split('?')[0]} from cross-origin "
                           f"{origin} refused")
            return 403, f"cross-origin request from {origin} refused"
        if not self._csrf_ok():
            self.server.pitor.log_event(
                "refused", f"POST {self.path.split('?')[0]} without a valid "
                           f"X-PiTor-Token")
            return 403, ("missing or incorrect X-PiTor-Token header "
                         "(GET / issues it)")
        return None

    def _body_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _config_save(self, app):
        body = self._body_json()
        if not isinstance(body, dict):
            self._json(400,
                       {"error": "body must be the JSON config object with "
                                 "all six fields"})
            return
        clean, errors = validate_config(body)
        if errors:
            app.log_event("refused", "config save refused: "
                          + "; ".join(f"{k} {v}" for k, v in errors.items()))
            self._json(400, {"error": "nothing saved — fix the fields",
                             "errors": errors})
            return
        changes = app.apply_config(clean)
        self._json(200, {"ok": True, "changes": changes})

    def do_GET(self):
        try:
            path = self.path.split("?")[0]
            if path == "/":
                self._page()
            elif path == "/config":
                self._config_page()
            elif path == "/api/status":
                self._json(200, self.server.pitor.status())
            elif path == "/api/log":
                self._json(200, {"events": self.server.pitor.read_log()})
            else:
                self._json(404, {"error": "not found"})
        except Exception as exc:  # noqa: BLE001 — one broken route stays up
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self):
        app = self.server.pitor
        try:
            path = self.path.split("?")[0]
            if path not in ("/api/tether", "/api/config"):
                self._json(404, {"error": "not found"})
                return
            gate = self._mutate_gate()
            if gate:
                self._json(gate[0], {"error": gate[1]})
                return
            if path == "/api/tether":
                body = self._body_json()
                if not isinstance(body, dict) or not isinstance(
                        body.get("on"), bool):
                    self._json(400,
                               {"error": 'body must be JSON {"on": true|false}'})
                    return
                self._json(200, app.run_tether(body["on"]))
            else:
                self._config_save(app)
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, format, *args):  # noqa: A002 — stdlib signature
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))


def hmac_compare(a, b):
    return bool(a) and hmac.compare_digest(a, b)


class TetherServer(ThreadingHTTPServer):
    daemon_threads = True
    pitor = None   # TetherApp assigned in make_server


def make_server(host, port, app):
    srv = TetherServer((host, port), Handler)
    srv.pitor = app
    return srv


def main():
    import sys
    cfg = config_from_env()
    saved = load_saved_config(cfg.config_file)
    changes = apply_config_values(cfg, saved)
    if changes:
        print(f"[pi-tor-hostui] {cfg.config_file}: " + "; ".join(changes),
              flush=True)
    refusal = bind_refusal(cfg)
    if refusal:
        print(f"[pi-tor-hostui] refusing to start: {refusal}", file=sys.stderr)
        raise SystemExit(2)
    app = TetherApp(cfg)
    srv = make_server(cfg.bind, cfg.port, app)
    threading.Thread(target=app.deadman_loop, daemon=True).start()
    print(f"[pi-tor-hostui] listening on http://{cfg.bind}:{cfg.port} "
          f"(dry run: {cfg.dry_run}; dead-man state: {cfg.state_file})",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
