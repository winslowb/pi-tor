"""HTTP surface tests: auth, preview-writes-nothing, apply/rollback and
the dry-run no-privileged-calls guarantee. All run with PI_TOR_UI_DRY_RUN=1
against a copy of the config tree."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from helpers import TestClient, make_config_tree, tree_fingerprint

import app
import dockerops


class HttpTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tree = make_config_tree()
        cls._old_root, cls._old_pw = app.ROOT, app.AUTH_PASSWORD
        app.ROOT = cls.tree
        app.AUTH_PASSWORD = "testpw"
        cls._old_dry = os.environ.get("PI_TOR_UI_DRY_RUN")
        os.environ["PI_TOR_UI_DRY_RUN"] = "1"
        cls.httpd = app.make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        import threading
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.client = TestClient(cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        app.ROOT, app.AUTH_PASSWORD = cls._old_root, cls._old_pw
        if cls._old_dry is None:
            os.environ.pop("PI_TOR_UI_DRY_RUN", None)
        else:
            os.environ["PI_TOR_UI_DRY_RUN"] = cls._old_dry
        shutil.rmtree(cls.tree, ignore_errors=True)


class AuthAndSecretsTest(HttpTestBase):

    def test_basic_auth_required(self):
        code, headers, _ = self.client.json("GET", "/api/config", auth=None)
        self.assertEqual(code, 401)
        # wrong user / wrong password
        code, _, _ = self.client.json(
            "GET", "/api/config", auth=("pi-tor", "wrong"))
        self.assertEqual(code, 401)
        code, headers, _ = self.client.json(
            "GET", "/api/config", auth=("pi-tor", "testpw"))
        self.assertEqual(code, 200)

    def test_secrets_not_returned_by_api(self):
        code, _, body = self.client.json("GET", "/api/config")
        self.assertEqual(code, 200)
        values = body["values"]
        self.assertEqual(values["pihole_webpassword"], app.schema.MASK)
        self.assertEqual(values["ui_password"], app.schema.MASK)
        self.assertIn("pihole_webpassword", body["masked_keys"])
        raw = str(body)
        self.assertNotIn("changeme", raw,
                         "the .env default password leaked into /api/config")
        # static/page routes are also auth-gated
        code, _, _ = self.client.request("GET", "/", auth="keep")
        self.assertEqual(code, 200)
        code, _, _ = self.client.request("GET", "/static/app.js", auth=None)
        self.assertEqual(code, 401)


class PreviewTest(HttpTestBase):

    def test_preview_writes_nothing(self):
        before = tree_fingerprint(self.tree)
        code, _, body = self.client.json("POST", "/api/preview", body={
            "values": {"subnet": "10.55.0.0/24", "gateway_ip": "10.55.0.1"}})
        self.assertEqual(code, 200)
        changed = {rel for rel, d in body["diffs"].items() if d}
        self.assertIn("tor/torrc", changed)
        self.assertIn("pihole/etc-dnsmasq.d/02-listen.conf", changed)
        self.assertIn("systemd/pi-tor.env.example", changed)
        # env files untouched: the subnet change does not reach them
        self.assertNotIn(".env", changed)
        self.assertNotIn(".env.example", changed)
        self.assertEqual(tree_fingerprint(self.tree), before,
                         "preview mutated the tree")

        # an invalid post yields errors and still writes nothing
        code, _, body = self.client.json("POST", "/api/preview", body={
            "values": {"subnet": "10.55.0.0/24", "gateway_ip": "10.12.194.1"}})
        self.assertEqual(code, 400)
        self.assertIn("gateway_ip", [e["key"] for e in body["errors"]])
        self.assertEqual(body["diffs"], {})
        self.assertEqual(tree_fingerprint(self.tree), before)


class ApplyRollbackTest(HttpTestBase):

    def test_apply_creates_backup_and_restores(self):
        import hashlib
        import json as _json
        before_fingerprint = tree_fingerprint(self.tree)
        before = before_fingerprint[".env"][1]

        code, _, report = self.client.json("POST", "/api/apply", body={
            "confirm": True,
            "values": {"tz": "Europe/Berlin"}})
        self.assertEqual(code, 200, report)
        self.assertTrue(report["ok"])
        self.assertTrue(report["files"][".env"]["changed"])
        self.assertNotEqual(report["backup"], None)

        backup_dir = report["backup"]
        manifest_path = os.path.join(backup_dir, "manifest.json")
        import json as _json
        manifest = _json.loads(open(manifest_path).read())
        self.assertIn(".env", manifest["originals"])
        self.assertEqual(manifest["originals"][".env"]["sha256"], before)
        backed_up = os.path.join(backup_dir, ".env")
        import hashlib
        self.assertEqual(
            hashlib.sha256(open(backed_up, "rb").read()).hexdigest(), before)

        # dry run: no privileged restarts happened
        self.assertIn("dry_run", str(report))

        # rollback restores the original bytes
        code, _, result = self.client.json("POST", "/api/rollback")
        self.assertEqual(code, 200, result)
        self.assertEqual(result["ok"], True)
        self.assertIn(".env", result["restored"])
        after = tree_fingerprint(self.tree)
        self.assertEqual(after[".env"][1], before)

    def test_apply_requires_confirm(self):
        code, _, body = self.client.json(
            "POST", "/api/apply", body={"values": {"tz": "UTC"}})
        self.assertEqual(code, 400)

    def test_apply_rejects_invalid(self):
        code, _, body = self.client.json("POST", "/api/apply", body={
            "confirm": True,
            "values": {"subnet": "10.0.0.0/33"}})
        self.assertEqual(code, 400)
        self.assertIn("subnet", [e["key"] for e in body["errors"]])


class DryRunTest(HttpTestBase):

    def test_dry_run_makes_no_privileged_calls(self):
        dockerops.counters.update({"socket_calls": 0, "subprocess_calls": 0})
        with mock.patch.object(
                dockerops.subprocess, "run",
                side_effect=AssertionError("subprocess during dry run")):
            code, _, _ = self.client.request("GET", "/")
            self.assertEqual(code, 200)
            code, _, _ = self.client.request("GET", "/static/style.css")
            self.assertEqual(code, 200)
            code, _, status = self.client.json("GET", "/api/status")
            self.assertEqual(code, 200)
            self.assertTrue(status.get("dry_run"))
            self.client.json("GET", "/api/logs?service=tor&lines=50")
            self.client.json("POST", "/api/preview",
                             body={"values": {"tz": "Europe/Rome"}})
            code, _, report = self.client.json("POST", "/api/apply", body={
                "confirm": True, "values": {"tz": "Europe/Rome"}})
            self.assertEqual(code, 200, report)
            code, _, _ = self.client.json("POST", "/api/rollback")
            self.assertEqual(code, 200)
        self.assertEqual(dockerops.counters,
                         {"socket_calls": 0, "subprocess_calls": 0},
                         "dry run touched the docker socket / subprocesses")


if __name__ == "__main__":
    unittest.main()
