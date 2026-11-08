"""The Logs panel, end to end through a socket that behaves like Docker's.

The panel was empty in production while every unit test passed: `_unix_http`
half-closed the socket after sending the request, and Docker's Go server reads
that EOF as a client abort — the same headers return 200 with an empty body for
/containers/<name>/logs and 500 for /version. Only a server that reacts to the
half-close can catch it, so this fake does exactly what Go does.
"""
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

import helpers  # noqa: F401  — puts ui/ on sys.path
import dockerops


def frame(stream, payload):
    """One Docker multiplexed log frame: 8-byte header + payload."""
    return bytes([stream, 0, 0, 0]) + struct.pack(">I", len(payload)) + payload


class FakeDocker:
    """Unix-socket HTTP server that aborts when the client half-closes."""

    def __init__(self, path, body_frames):
        self.path = path
        self.body_frames = body_frames
        self.saw_half_close = False
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _serve(self):
        conn, _ = self.srv.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            part = conn.recv(4096)
            if not part:
                return
            data += part
        # Did the client close its write side before we answered?
        conn.setblocking(False)
        try:
            extra = conn.recv(1)
            self.saw_half_close = (extra == b"")
        except BlockingIOError:
            self.saw_half_close = False
        conn.setblocking(True)
        if self.saw_half_close:
            body = b'{"message":"client abort"}'
            conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\n"
                         b"Content-Type: application/json\r\n"
                         b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                         b"Connection: close\r\n\r\n" + body)
        else:
            payload = b"".join(self.body_frames)
            conn.sendall(b"HTTP/1.1 200 OK\r\n"
                         b"Content-Type: application/vnd.docker.raw-stream\r\n"
                         b"Transfer-Encoding: chunked\r\n"
                         b"Connection: close\r\n\r\n"
                         + format(len(payload), "x").encode() + b"\r\n"
                         + payload + b"\r\n0\r\n\r\n")
        conn.close()
        self.srv.close()


class LogsPanelTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.sock_path = os.path.join(self.dir, "docker.sock")
        self.dockerops = dockerops
        self._orig = dockerops.SOCKET_PATH

    def tearDown(self):
        self.dockerops.SOCKET_PATH = self._orig

    def _serve(self, frames):
        fake = FakeDocker(self.sock_path, frames).start()
        self.dockerops.SOCKET_PATH = self.sock_path
        return fake

    def test_logs_panel_returns_container_output(self):
        frames = [frame(1, b"tor: bootstrapped 100%\n"),
                  frame(2, b"tor: warn something\n")]
        fake = self._serve(frames)
        res = self.dockerops.logs("tor", 10)
        fake.thread.join(timeout=5)
        self.assertFalse(fake.saw_half_close,
                         "the client half-closed: Docker answers 200/500 with "
                         "an empty body, which is what emptied the panel")
        self.assertIn("bootstrapped 100%", res.get("logs", ""))
        self.assertIn("warn something", res.get("logs", ""))
        self.assertNotIn("error", res)

    def test_plain_unframed_body_still_decodes(self):
        # tty=true containers return a raw stream with no 8-byte frames
        fake = self._serve([b"plain line one\nplain line two\n"])
        res = self.dockerops.logs("pihole", 10)
        fake.thread.join(timeout=5)
        self.assertIn("plain line one", res.get("logs", ""))

    def test_no_logs_is_not_an_error(self):
        fake = self._serve([])
        res = self.dockerops.logs("tor", 10)
        fake.thread.join(timeout=5)
        self.assertEqual(res.get("logs"), "")
        self.assertNotIn("error", res)


if __name__ == "__main__":
    unittest.main()
