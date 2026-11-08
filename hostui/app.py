#!/usr/bin/env python3
"""pi-tor host tether UI — runs on the tethered workstation, not on the Pi.

One loopback-only page to toggle bin/usb_route / bin/usb_route_undo (via
`sudo -n <script>`, fixed argv) and a dead-man revert: when the Pi stops
answering while the tether route is up, the host is restored to its normal
routing automatically.

Env (all optional):
  PI_TOR_HOSTUI_PORT        listen port, default 8090
  PI_TOR_HOSTUI_BIND        bind address, default 127.0.0.1 (loopback enforced)
  PI_TOR_HOSTUI_ALLOW_ANY   set to 1 to allow a non-loopback bind
  PI_TOR_HOSTUI_STATE       dead-man state file; the only file this app writes
                            outside the repo. Default sits under
                            $XDG_RUNTIME_DIR (cleared on reboot) or ~/.cache.
  PI_TOR_HOSTUI_DRY_RUN     1 = never execute the tether scripts (and skip the
                            read-only resolvectl query in /api/status)
  PI_TOR_PI_ADDR            the Pi side of the gadget subnet, default 10.12.194.1
  PI_TOR_UI_PORT            the Pi's config-UI TCP port, default 8080 — the
                            dead-man probes it because ICMP is not redirected
                            and ping alone would be misleading
  PI_TOR_PROBE_INTERVAL     probe interval seconds, default 15
  PI_TOR_REVERT_AFTER       seconds of consecutive failures before revert, default 90

Security:
  * CSRF: GET / issues a per-process random token embedded in the page; every
    POST must return it in the X-PiTor-Token header. A cross-origin page can
    neither read it (same-origin policy) nor set it. No cookies are used.
  * The app runs no sudo itself: it invokes `sudo -n <script>` with a fixed
    argv and sudoers must permit the script (README: /etc/sudoers.d/pi-tor-tether).
  * Dead-man caveat: it only works while this process runs — keep it under
    systemd --user with loginctl enable-linger; without the process nothing reverts.
"""
import fcntl
import hmac
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

UI_DIR = Path(__file__).resolve().parent
ROOT = UI_DIR.parent
MAX_BODY = 10_000
SCRIPT_TIMEOUT = 120
LOG_LIMIT = 100
STATE_DEFAULTS = {"tether": "off", "reverts_used": 0, "revert_reason": None,
                  "since": None, "last_error": None}
EXIT_IP_URL = "https://check.torproject.org/api/ip"
EXIT_IP_TTL = 60
NET_DIR = Path(os.environ.get("PI_TOR_NET_DIR", "/sys/class/net"))

# ---------------------------------------------------------------- config


def default_state_file():
    base = os.environ.get("XDG_RUNTIME_DIR")
    if not base:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "pi-tor-hostui" / "dead-man.json"


def config_from_env(env=None):
    env = os.environ if env is None else env
    return SimpleNamespace(
        port=int(env.get("PI_TOR_HOSTUI_PORT", "8090")),
        bind=env.get("PI_TOR_HOSTUI_BIND", "127.0.0.1"),
        allow_any=env.get("PI_TOR_HOSTUI_ALLOW_ANY") == "1",
        dry_run=env.get("PI_TOR_HOSTUI_DRY_RUN") == "1",
        pi_addr=env.get("PI_TOR_PI_ADDR", "10.12.194.1"),
        pi_ui_port=int(env.get("PI_TOR_UI_PORT", "8080")),
        probe_interval=float(env.get("PI_TOR_PROBE_INTERVAL", "15")),
        revert_after=float(env.get("PI_TOR_REVERT_AFTER", "90")),
        sudo=env.get("PI_TOR_HOSTUI_SUDO", "sudo"),
        route_on=ROOT / "bin" / "usb_route",
        route_off=ROOT / "bin" / "usb_route_undo",
        state_file=Path(env.get("PI_TOR_HOSTUI_STATE") or default_state_file()),
    )


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
        self._exit_ip = {}   # {t: ts, ip, error} cache
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
        self.history.appendleft({"t": now_iso(), "event": event,
                                 "detail": detail})

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

    def exit_ip(self):
        # meaningful only while routed through the Pi
        now = time.time()
        hit = self._exit_ip.get("at")
        if hit is not None and now - hit < EXIT_IP_TTL:
            return self._exit_ip.get("ip"), self._exit_ip.get("error")
        try:
            with urllib.request.urlopen(EXIT_IP_URL, timeout=5) as resp:
                ip = json.loads(resp.read(200).decode()).get("IP")
        except Exception as exc:  # noqa: BLE001 — exit ip is best-effort
            self._exit_ip.update(at=now, error=type(exc).__name__)
            return self._exit_ip.get("ip"), type(exc).__name__
        self._exit_ip.update(at=now, ip=ip, error=None)
        return ip, None

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
        if tether == "on":
            exit_ip, exit_err = self.exit_ip()
        return {
            "dry_run": cfg.dry_run,
            "bind": cfg.bind, "port": cfg.port,
            "state_file": str(cfg.state_file),
            "tether": tether,
            "default_route": route,
            "dns_servers": link_dns(cfg, route and route.get("iface")),
            "gadget_iface": gadget_iface(cfg.pi_addr.rsplit(".", 1)[0] + "."),
            "pi_addr": cfg.pi_addr, "pi_ui_port": cfg.pi_ui_port,
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
        }

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
pre { background:var(--deep); padding:.5rem; border-radius:4px; overflow:auto; \
max-height:24rem; white-space:pre-wrap; word-break:break-word; font-size:.85rem; }
footer { margin-top:2rem; border-top:1px solid var(--border); \
padding-top:.8rem; font-size:.8rem; }
"""


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="pi-tor-token" content="@@TOKEN@@">
<title>pi-tor tether</title>
<style>@@STYLE@@</style>
</head>
<body>
<header><h1>pi-tor <span class="accent">tether</span></h1></header>

<section>
  <h2>Tether
    <button id="toggle" type="button" disabled>loading…</button>
    <button id="refresh" type="button" class="secondary">Refresh</button>
  </h2>
  <div id="status" class="cards"><span class="muted">loading…</span></div>
  <div id="message" class="muted"></div>
</section>

<section id="logview">
  <h2>History (toggles and auto-reverts)</h2>
  <pre id="log" class="muted">loading…</pre>
</section>

<footer><span class="muted">pi-tor host tether UI · loopback only · POST
requests must carry the X-PiTor-Token issued on this page · the dead-man
revert only works while this process is running.</span></footer>

<script>
(function () {
  "use strict";
  var token = document.querySelector('meta[name="pi-tor-token"]').content;
  var current = null;
  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function badge(cls, text) {
    return '<span class="badge ' + cls + '">' + esc(text) + '</span>'; }
  function card(k, v, cls) {
    return '<div class="card ' + (cls || "") + '"><div class="k">' + k +
      '</div><div class="v">' + v + '</div></div>'; }

  function tetherBadge(tether) {
    var map = { on: ["ok", "on", "ok"], off: ["off", "off", ""],
                reverted: ["bad", "reverted automatically", "bad"],
                unknown: ["warn", "unknown", ""] };
    return map[tether] || ["warn", String(tether), ""];
  }

  function render(st, log) {
    current = st.tether;
    var route = st.default_route;
    var tt = tetherBadge(st.tether);
    var cards = [];
    if (st.dry_run) {
      cards.push(card("mode", "DRY RUN — the tether scripts are never executed"));
    }
    cards.push(card("tether", badge(tt[0], tt[1]), tt[2]));
    cards.push(card("default route", esc(route ?
      (route.iface + " via " + (route.gateway || "link")) : "none")));
    cards.push(card("dns", esc((st.dns_servers || []).join(", ") || "none")));
    cards.push(card("pi answers",
      esc(st.pi_answers === null ? "?" : (st.pi_answers ? "yes" : "no")),
      st.pi_answers === true ? "ok" : (st.pi_answers === false ? "bad" : "")));
    cards.push(card("dead-man", st.deadman_armed
      ? badge("warn", "armed · revert in " + (st.revert_in_seconds === null
        ? "—" : st.revert_in_seconds + "s")) : esc("disarmed")),
      "");
    cards.push(card("gadget iface", esc(st.gadget_iface || "none")));
    cards.push(card("tor exit ip", esc(st.exit_ip || "unavailable") +
      (st.exit_ip_error ? ' <span class="muted">(' + esc(st.exit_ip_error) +
      ')</span>' : "")));
    if (st.last_revert) cards.push(card("last auto-revert", esc(st.last_revert), ""));
    if (st.last_error) cards.push(card("last error", esc(st.last_error), "bad"));
    $("status").innerHTML = cards.join("");
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

  loadAll();
  setInterval(loadAll, 5000);
})();
</script>
</body>
</html>
""".replace("@@STYLE@@", STYLE)


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
                   PAGE.replace("@@TOKEN@@", self.server.pitor.token).encode())

    def _csrf_ok(self):
        return hmac_compare(self.headers.get("X-PiTor-Token", ""),
                            self.server.pitor.token)

    def do_GET(self):
        try:
            path = self.path.split("?")[0]
            if path == "/":
                self._page()
            elif path == "/api/status":
                self._json(200, self.server.pitor.status())
            elif path == "/api/log":
                self._json(200, {"events": list(self.server.pitor.history)})
            else:
                self._json(404, {"error": "not found"})
        except Exception as exc:  # noqa: BLE001 — one broken route stays up
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self):
        try:
            if self.path.split("?")[0] != "/api/tether":
                self._json(404, {"error": "not found"})
                return
            if not self._csrf_ok():
                self._json(403, {"error": "missing or incorrect "
                                         "X-PiTor-Token header (GET / issues it)"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            body = None
            if 0 < length <= MAX_BODY:
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw.decode("utf-8"))
                except ValueError:
                    body = None
            if not isinstance(body, dict) or not isinstance(body.get("on"), bool):
                self._json(400,
                           {"error": 'body must be JSON {"on": true|false}'})
                return
            self._json(200, self.server.pitor.run_tether(body["on"]))
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
