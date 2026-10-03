import hashlib
import hmac
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from tether import GuardrailViolation, Repo
from tether.notify import Notifier, check_url, event_of, slack_text, to_cef

POLICY = {"rules": [{"path": "out/**", "access": "write"}]}


class Sink:
    def __init__(self):
        self.received = []
        sink = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                sink.received.append((dict(self.headers), body))
                self.send_response(200)
                self.end_headers()

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TestNotify(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = Repo.init(self.root, actor="user:alice")
        self.sink = Sink()

    def tearDown(self):
        self.sink.close()
        self._tmp.cleanup()

    def wait(self, n):
        for t in list(threading.enumerate()):
            if t is not threading.main_thread() and t.name.startswith("Thread") and not t.daemon:
                t.join(6)
        self.assertGreaterEqual(len(self.sink.received), n)

    def test_json_webhook_is_signed(self):
        hook = Notifier(self.repo.meta).add(self.sink.url, ["submit"], "json")
        ws = self.repo.create_workspace("agent:bot", POLICY)
        ws.write("out/a.md", "a")
        ws.submit("done")
        self.wait(1)
        headers, body = self.sink.received[0]
        self.assertEqual(json.loads(body)["event"], "submit")
        expected = hmac.new(bytes.fromhex(hook["secret"]), body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Tether-Signature"], f"sha256={expected}")

    def test_flag_goes_to_slack_and_is_escaped(self):
        Notifier(self.repo.meta).add(self.sink.url, ["flag"], "slack")
        ws = self.repo.create_workspace("agent:<!channel>", POLICY)
        with self.assertRaises(GuardrailViolation):
            ws.write("out/k.md", "AKIAIOSFODNN7EXAMPLE")
        self.wait(1)
        text = json.loads(self.sink.received[0][1])["text"]
        self.assertIn("flagged", text)
        self.assertNotIn("<!channel>", text)

    def test_event_mapping(self):
        self.assertEqual(event_of({"action": "read", "outcome": "denied", "severity": "high"}), "flag")
        self.assertIsNone(event_of({"action": "read", "outcome": "allowed"}))
        self.assertEqual(event_of({"action": "login", "outcome": "denied"}), "login_failed")
        self.assertIn("v3", slack_text("merge", {"actor": "user:a", "version": 3}))

    def test_url_rules(self):
        check_url("https://hooks.slack.com/services/x")
        check_url("http://localhost:9000/x")
        for bad in ["http://example.com/x", "ftp://x", "file:///etc/passwd", "javascript:alert(1)"]:
            with self.assertRaises(ValueError, msg=bad):
                check_url(bad)

    def test_cef_escaping(self):
        line = to_cef({"seq": 1, "ts": "t", "action": "read", "actor": "agent:x", "path": "a=b|c\nd",
                       "outcome": "denied", "severity": "high"}, "0.2.0")
        self.assertTrue(line.startswith("CEF:0|tether|tether|0.2.0|read|read denied|8|"))
        self.assertIn("fname=a\\=b|c\\nd", line)
        self.assertNotIn("\n", line)


if __name__ == "__main__":
    unittest.main()
