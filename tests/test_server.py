import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from tether import Repo
from tether.server import make_server

POLICY = {"rules": [{"path": "docs/**", "access": "read"}, {"path": "out/**", "access": "write"}]}


class TestServer(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "docs").mkdir()
        (self.root / "docs" / "a.txt").write_text("hello\n")
        self.repo = Repo.init(self.root, actor="user:alice")
        self.ws = self.repo.create_workspace("agent:bot", POLICY, task="summarize")
        self.ws.write("out/summary.md", "<script>alert(1)</script>\n")
        self.server = make_server(str(self.root), "user:alice", port=0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def request(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        h = {"Host": host or f"localhost:{self.port}"}
        if body is not None:
            h.update({"Content-Type": "application/json", "X-Tether-Token": self.server.token})
        h.update(headers or {})
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res.status, data

    def test_page_and_listing(self):
        status, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(self.server.token.encode(), page)
        status, data = self.request("GET", "/api/workspaces")
        rows = json.loads(data)
        self.assertEqual(rows[0]["id"], self.ws.id)
        self.assertEqual(rows[0]["changes"]["added"], 1)

    def test_detail_includes_diff_and_activity(self):
        status, data = self.request("GET", f"/api/workspaces/{self.ws.id}")
        d = json.loads(data)
        self.assertEqual(d["files"][0]["path"], "out/summary.md")
        self.assertIn("+<script>alert(1)</script>", d["files"][0]["lines"])
        self.assertEqual([e["action"] for e in d["activity"]], ["create", "write"])

    def test_rejects_foreign_host(self):
        status, _ = self.request("GET", "/api/workspaces", host="evil.example:80")
        self.assertEqual(status, 403)

    def test_post_requires_token(self):
        status, _ = self.request("POST", f"/api/workspaces/{self.ws.id}/merge", body={},
                                 headers={"X-Tether-Token": "wrong"})
        self.assertEqual(status, 403)
        self.assertEqual(self.ws.status, "open")

    def test_post_requires_json(self):
        status, _ = self.request("POST", f"/api/workspaces/{self.ws.id}/merge", body={},
                                 headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_merge_and_rollback(self):
        status, data = self.request("POST", f"/api/workspaces/{self.ws.id}/merge", body={})
        self.assertEqual(status, 200, data)
        self.assertTrue((self.root / "out" / "summary.md").exists())
        self.assertEqual(self.repo.version(json.loads(data)["version"])["approved_by"], "user:alice")
        status, data = self.request("POST", "/api/rollback", body={"version": 0})
        self.assertEqual(status, 200, data)
        self.assertFalse((self.root / "out" / "summary.md").exists())

    def test_discard_and_errors(self):
        status, _ = self.request("POST", f"/api/workspaces/{self.ws.id}/discard", body={"reason": "nope"})
        self.assertEqual(status, 200)
        status, data = self.request("POST", f"/api/workspaces/{self.ws.id}/merge", body={})
        self.assertEqual(status, 409)
        self.assertIn("discarded", json.loads(data)["error"])

    def test_verify(self):
        status, data = self.request("GET", "/api/verify")
        self.assertTrue(json.loads(data)["ok"])


if __name__ == "__main__":
    unittest.main()
