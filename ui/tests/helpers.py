"""Shared fixtures for the ui tests: path setup, a disposable copy of the
config tree, and a tiny JSON-over-HTTP client against a live test server."""
import base64
import hashlib
import json
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

UI_DIR = Path(__file__).resolve().parents[1]
REPO = UI_DIR.parent
sys.path.insert(0, str(UI_DIR))

CONFIG_FILES = [
    ".env.example",
    "tor/torrc",
    "pihole/etc-dnsmasq.d/02-listen.conf",
    "pihole/etc-dnsmasq.d/02-upstream-tor.conf",
    "pihole/etc-dnsmasq.d/02-usb0.conf",
    "pihole/etc-dnsmasq.d/99-tor-upstream.conf",
    "systemd/pi-tor.env.example",
]


def make_config_tree(dest=None):
    """Copy the committed config tree to a tmp dir and seed a live .env."""
    dest = Path(dest or tempfile.mkdtemp(prefix="pi-tor-ui-test-"))
    for rel in CONFIG_FILES:
        dst = dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst)
    shutil.copy2(REPO / ".env.example", dest / ".env")
    dest.joinpath("bin").mkdir(exist_ok=True)
    shutil.copy2(REPO / "bin" / "pi-tor-rules.sh", dest / "bin" / "pi-tor-rules.sh")
    return dest


def tree_fingerprint(root):
    """{relpath: (mtime_ns, sha256)} for every file under root."""
    root = Path(root)
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            out[str(p.relative_to(root))] = (
                st.st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
    return out


class TestClient:
    """HTTP client for the ui server, with optional Basic auth."""

    def __init__(self, port, auth=("pi-tor", "testpw")):
        self.port = port
        self.auth = auth

    def request(self, method, path, body=None, auth="keep"):
        """auth=None sends no Authorization header; "keep" uses the default."""
        if auth == "keep":
            auth = self.auth
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            token = base64.b64encode(
                f"{auth[0]}:{auth[1]}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=15)
        except urllib.error.HTTPError as exc:
            resp = exc
        raw = resp.read()
        return resp.status, resp.headers, raw

    def json(self, method, path, body=None, **kw):
        code, headers, raw = self.request(method, path, body, **kw)
        parsed = json.loads(raw.decode() or "{}")
        return code, headers, parsed
