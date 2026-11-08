"""Loaders and fixtures for the hostui tests, kept separate from helpers.py
(belongs to the ui app). hostui/app.py is loaded under its own module name
so it can never collide with the ui app's `app` module."""
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import importlib.util
import json
import re
from helpers import REPO

HOSTUI = REPO / "hostui"

_spec = importlib.util.spec_from_file_location("hostui_app", HOSTUI / "app.py")
hostui_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hostui_app)


def make_cfg(tmp, **over):
    """A TetherApp config pointing the scripts at the real repo paths (tests
    never execute them: the live-script tests override the paths with local
    stubs, everything else runs with dry_run=True)."""
    defaults = dict(
        port=0, bind="127.0.0.1", allow_any=False, dry_run=True,
        pi_addr="10.12.194.1", pi_ui_port=8080,
        probe_interval=0.05, revert_after=90.0,
        sudo="sudo",
        route_on=REPO / "bin" / "usb_route",
        route_off=REPO / "bin" / "usb_route_undo",
        state_file=Path(tmp) / "pi-tor-hostui" / "dead-man.json",
    )
    defaults.update(over)
    return SimpleNamespace(**defaults)


def make_app(tmp, **over):
    """TetherApp + armed helper: session_on/off mutate state the way
    run_tether does, without executing anything."""
    cfg = make_cfg(tmp, **over)
    app = hostui_app.TetherApp(cfg)
    return app, cfg


def boot(tmp, **over):
    """Start a real HTTP server on an ephemeral port; returns (app, server,
    port). The caller must call stop()."""
    cfg = make_cfg(tmp, **over)
    app = hostui_app.TetherApp(cfg)
    srv = hostui_app.make_server("127.0.0.1", 0, app)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return app, srv, port, cfg


class BootedTest(unittest.TestCase):
    """Base that owns a tmp dir and an optional live server."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pi-tor-hostui-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def boot(self, **over):
        app, srv, port, cfg = boot(self.tmp, **over)
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return app, srv, port, cfg

    def token_of(self, port):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/")
        resp = urllib.request.urlopen(req, timeout=15)
        for line in resp.read().decode().splitlines():
            if 'name="pi-tor-token"' in line:
                m = re.search(r'content="([0-9a-f]+)"', line)
                if m:
                    return m.group(1)
        self.fail("GET / must issue a CSRF token")
        return ""


def req_raw(port, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                               method=method, data=data,
                               headers=headers or {})
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(r, timeout=15)
    except urllib.error.HTTPError as exc:
        resp = exc
    return resp.status, resp.read().decode("utf-8", "replace")


def req(port, method, path, body=None, headers=None):
    code, raw = req_raw(port, method, path, body, headers)
    return code, json.loads(raw or "{}")


class FakeClock:
    """Dead-man clock seam: advance(s) then tick()."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s
