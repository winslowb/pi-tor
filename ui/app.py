"""pi-tor config UI — stdlib HTTP server (routing/serve).

HTTP Basic on every route (single user `pi-tor`, password from
PI_TOR_UI_PASSWORD, constant-time compare). Static files come from
ui/static only — no external URLs.

PI_TOR_UI_DRY_RUN=1 disables docker socket calls and subprocesses (the
container can then run with no socket and no NET_ADMIN); file writes still
happen against the mounted project tree.
"""
import base64
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent))

import apply as apply_mod  # noqa: E402
import config_schema as schema  # noqa: E402
import dockerops  # noqa: E402
import render  # noqa: E402
import status as status_mod  # noqa: E402
import uplink as uplink_mod  # noqa: E402

UI_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("PI_TOR_PROJECT_DIR") or UI_DIR.parent)

AUTH_USER = "pi-tor"
AUTH_PASSWORD = os.environ.get("PI_TOR_UI_PASSWORD", "changeme")
REALM = "Basic realm=\"pi-tor\""
MAX_BODY = 1_000_000

STATIC_TYPES = {".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8",
                ".ico": "image/x-icon"}


class Handler(BaseHTTPRequestHandler):
    server_version = "pi-tor-ui/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path, ctype):
        try:
            body = Path(path).read_bytes()
        except OSError:
            self._json(404, {"error": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
            user, _, password = decoded.partition(":")
        except Exception:  # noqa: BLE001 — malformed auth is just a 401
            return False
        ok_user = hmac.compare_digest(user, AUTH_USER)
        ok_pass = hmac.compare_digest(password, AUTH_PASSWORD or "changeme")
        return ok_user and ok_pass

    def _deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", REALM)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return None

    def log_message(self, format, *args):  # noqa: A002 — stdlib signature
        sys.stderr.write("%s - %s\n" % (self.address_string(),
                                        format % args))

    # -- routing -----------------------------------------------------------

    def do_GET(self):
        if not self._authorized():
            self._deny()
            return
        try:
            self._route_get()
        except Exception as exc:  # noqa: BLE001 — one broken route stays up
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self):
        if not self._authorized():
            self._deny()
            return
        try:
            self._route_post()
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def _route_get(self):
        path = urlparse(self.path).path
        if path == "/":
            self._file(UI_DIR / "templates" / "index.html",
                       "text/html; charset=utf-8")
        elif path.startswith("/static/"):
            name = Path(path[len("/static/"):]).name  # traversal-safe
            ext = Path(name).suffix.lower()
            if ext not in STATIC_TYPES:
                self._json(404, {"error": "not found"})
                return
            self._file(UI_DIR / "static" / name, STATIC_TYPES[ext])
        elif path == "/api/config":
            current = render.read_current(ROOT)
            values = {}
            masked = [k for k in schema.SECRET_KEYS]
            for k, v in current["values"].items():
                values[k] = schema.MASK if k in schema.SECRET_KEYS else v
            # field metadata too: never echo secret defaults through the API
            fields = {k: dict(spec) for k, spec in schema.FIELDS.items()}
            for k in schema.SECRET_KEYS:
                fields[k]["default"] = schema.MASK
            self._json(200, {
                "values": values,
                "masked_keys": masked,
                "fields": fields,
                "errors": schema.validate(
                    schema.merge_secrets(current["values"], current["values"])),
                "warnings": current["warnings"],
                "sources": current["sources"],
                "raw": {rel: (render._read(ROOT, rel) or "")
                        for rel in render.RAW_FILES},
            })
        elif path == "/api/status":
            self._json(200, status_mod.dashboard(ROOT))
        elif path == "/api/logs":
            qs = parse_qs(urlparse(self.path).query)
            service = (qs.get("service") or ["tor"])[0]
            if service not in ("tor", "pihole"):
                self._json(400, {"error": "service must be tor or pihole"})
                return
            try:
                lines = int((qs.get("lines") or ["200"])[0])
            except ValueError:
                lines = 200
            self._json(200, dockerops.logs(service, lines))
        else:
            self._json(404, {"error": "not found"})

    def _route_post(self):
        path = urlparse(self.path).path
        # rollback legitimately posts an empty body
        body = self._read_json() or {}
        if path == "/api/preview":
            current = render.read_current(ROOT)
            cfg = schema.merge_secrets(body.get("values") or {},
                                       current["values"])
            errors = schema.validate(cfg)
            if errors:
                self._json(400, {"errors": errors, "warnings": [],
                                 "diffs": {}})
                return
            # host-aware uplink check: a changed uplink must exist on this
            # host (error) or carry a lease/default route (warning)
            uplink_errors, uplink_warnings = uplink_mod.submission(
                cfg, current["values"])
            if uplink_errors:
                self._json(400, {"errors": uplink_errors,
                                 "warnings": uplink_warnings, "diffs": {}})
                return
            self._json(200, {"errors": [], "warnings": uplink_warnings,
                             "diffs": render.diff_all(ROOT, cfg),
                             "dry_run": dockerops._dry()})
        elif path == "/api/apply":
            if body.get("confirm") is not True:
                self._json(400, {"error": "apply requires confirm: true"})
                return
            report = apply_mod.apply_changes(ROOT, body.get("values") or {})
            self._json(200 if report.get("ok") else 400, report)
        elif path == "/api/rollback":
            self._json(200, apply_mod.restore_latest_backup(ROOT))
        elif path == "/api/rules/apply":
            if body.get("confirm") is not True:
                self._json(400, {"error": "rules apply requires confirm: true"})
                return
            values = render.read_current(ROOT)["values"]
            errors = schema.validate(values)
            if errors:
                self._json(400, {"errors": errors})
                return
            self._json(200, dockerops.run_rules(ROOT, values))
        elif path == "/api/rules/flush":
            if body.get("confirm") is not True:
                self._json(400, {"error": "rules flush requires confirm: true"})
                return
            # flush is the recovery path and needs no validation: it stays
            # reachable over HTTP to the Pi's own address because the chain's
            # RETURN rule keeps that traffic out of the redirect, and flush
            # works whatever the current config says
            values = render.read_current(ROOT)["values"]
            self._json(200, dockerops.run_rules(ROOT, values, action="flush"))
        else:
            self._json(404, {"error": "not found"})


def make_server(host="0.0.0.0", port=8080):
    return ThreadingHTTPServer((host, port), Handler)


def main():
    port = int(os.environ.get("PI_TOR_UI_PORT", "8080"))
    httpd = make_server("0.0.0.0", port)
    dry = os.environ.get("PI_TOR_UI_DRY_RUN") == "1"
    sys.stderr.write(f"pi-tor-ui serving 0.0.0.0:{port} "
                     f"root={ROOT} dry_run={dry}\n")
    if not dry:
        # the ui container owns the firewall from here: apply on every start
        # (idempotent), so a compose up is all the stack needs
        try:
            sys.stderr.write("pi-tor-ui startup rules: %s\n" % json.dumps(
                apply_mod.startup_rules_apply(ROOT)))
        except Exception as exc:  # noqa: BLE001 — serving must not wedge on it
            sys.stderr.write("pi-tor-ui startup rules apply failed: "
                             f"{type(exc).__name__}: {exc}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
