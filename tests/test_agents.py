import io
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from tether import AccessDenied, GuardrailViolation, Repo, TetherError
from tether.agent_api import make_server
from tether.client import Client
from tether.mcp import MCPServer

POLICY = {
    "rules": [{"path": "contracts/**", "access": "read"}, {"path": "reports/**", "access": "write"}],
    "guardrails": {"max_file_bytes": 1000},
}
AUTO = {**POLICY, "auto_approve": {"paths": ["reports/**"], "max_changes": 2}}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "drive"
        (self.root / "contracts").mkdir(parents=True)
        (self.root / "reports").mkdir()
        (self.root / "secret").mkdir()
        (self.root / "contracts" / "a.txt").write_text("Fee: 10\n")
        (self.root / "reports" / "old.md").write_text("old\n")
        (self.root / "secret" / "s.txt").write_text("hidden\n")
        self.repo = Repo.init(self.root, actor="user:alice")

    def tearDown(self):
        self._tmp.cleanup()


class TestTokens(Base):
    def test_issue_and_authenticate(self):
        ws = self.repo.create_workspace("agent:bot", POLICY)
        token = self.repo.issue_token(ws.id)
        self.assertEqual(self.repo.authenticate(token).id, ws.id)
        self.assertNotIn(token, (self.repo.meta / "workspaces" / f"{ws.id}.json").read_text())

    def test_bad_tokens(self):
        ws = self.repo.create_workspace("agent:bot", POLICY)
        token = self.repo.issue_token(ws.id)
        for bad in ["", "nope", token[:-1] + ("A" if token[-1] != "A" else "B"),
                    "tth_000000000000_" + "x" * 43]:
            with self.assertRaises(AccessDenied, msg=bad):
                self.repo.authenticate(bad)

    def test_tokens_cannot_cross_workspaces(self):
        a = self.repo.create_workspace("agent:a", POLICY)
        b = self.repo.create_workspace("agent:b", POLICY)
        token_a = self.repo.issue_token(a.id)
        forged = "tth_" + b.id[3:] + token_a[len("tth_") + 12:]
        with self.assertRaises(AccessDenied):
            self.repo.authenticate(forged)

    def test_revoke_and_close_invalidate(self):
        ws = self.repo.create_workspace("agent:bot", POLICY)
        t1 = self.repo.issue_token(ws.id)
        self.repo.revoke_tokens(ws.id)
        with self.assertRaises(AccessDenied):
            self.repo.authenticate(t1)
        t2 = self.repo.issue_token(ws.id)
        self.repo.discard(ws.id)
        with self.assertRaises(AccessDenied):
            self.repo.authenticate(t2)
        with self.assertRaises(TetherError):
            self.repo.issue_token(ws.id)


class TestAutoApprove(Base):
    def test_merges_when_within_policy(self):
        ws = self.repo.create_workspace("agent:bot", AUTO)
        ws.write("reports/new.md", "new\n")
        r = ws.submit("done")
        self.assertEqual(r["status"], "merged")
        self.assertEqual((self.root / "reports" / "new.md").read_text(), "new\n")
        self.assertEqual(self.repo.version(r["version"])["approved_by"], "policy:auto-approve")

    def test_no_rule_means_human_review(self):
        ws = self.repo.create_workspace("agent:bot", POLICY)
        ws.write("reports/new.md", "new\n")
        r = ws.submit()
        self.assertEqual(r["status"], "awaiting_review")
        self.assertEqual(ws.status, "open")
        self.assertIsNotNone(ws.state["submitted_at"])

    def test_blocked_cases(self):
        cases = {
            "flags": lambda ws: self.assertRaises(GuardrailViolation, ws.write, "reports/x.md", "y" * 2000),
            "deletes": lambda ws: ws.delete("reports/old.md"),
            "too many": lambda ws: [ws.write(f"reports/{i}.md", "x") for i in range(3)],
        }
        for name, act in cases.items():
            with self.subTest(name):
                ws = self.repo.create_workspace("agent:bot", AUTO)
                ws.write("reports/ok.md", "ok\n")
                act(ws)
                self.assertEqual(ws.submit()["status"], "awaiting_review")

    def test_outside_paths(self):
        policy = {**AUTO, "rules": AUTO["rules"] + [{"path": "notes/**", "access": "write"}]}
        ws = self.repo.create_workspace("agent:bot", policy)
        ws.write("notes/n.md", "n\n")
        r = ws.submit()
        self.assertEqual(r["status"], "awaiting_review")
        self.assertIn("outside", r["reason"])

    def test_fork_cannot_grant_itself_auto_approve(self):
        parent = self.repo.create_workspace("agent:lead", POLICY)  # no auto_approve
        child = self.repo.fork_workspace(parent.id, "agent:helper", AUTO)
        child.write("reports/c.md", "c\n")
        self.assertEqual(child.submit()["status"], "awaiting_review")

    def test_conflict_falls_back_to_review(self):
        ws = self.repo.create_workspace("agent:bot", {**AUTO, "auto_approve": {"paths": ["reports/**"]}})
        ws.write("reports/old.md", "agent\n")
        (self.root / "reports" / "old.md").write_text("human\n")
        r = ws.submit()
        self.assertEqual(r["status"], "awaiting_review")
        self.assertIn("both sides", r["reason"])


class TestGC(Base):
    def test_removes_only_unreferenced(self):
        ws = self.repo.create_workspace("agent:bot", POLICY)
        ws.write("reports/r.md", "draft 1\n")
        ws.write("reports/r.md", "draft 2\n")
        r = self.repo.gc()
        self.assertEqual(r["removed"], 1)
        self.assertEqual(ws.read_text("reports/r.md"), "draft 2\n")
        self.repo.merge(ws.id, reviewer="user:alice")
        self.repo.rollback(0)
        self.assertTrue(self.repo.audit.verify().ok)


class TestAuditKeyLocation(unittest.TestCase):
    def test_key_outside_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "keys" / "audit.key"
            key.parent.mkdir()
            with mock.patch.dict(os.environ, {"TETHER_AUDIT_KEY_FILE": str(key)}):
                repo = Repo.init(Path(tmp) / "drive", actor="user:alice")
                self.assertTrue(key.exists())
                self.assertFalse((repo.meta / "audit.key").exists())
                self.assertTrue(repo.audit.verify().ok)


class TestAgentAPI(Base):
    def setUp(self):
        super().setUp()
        self.ws = self.repo.create_workspace("agent:bot", AUTO)
        self.token = self.repo.issue_token(self.ws.id)
        self.server = make_server(str(self.root), port=0, max_body=4096)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client = Client(self.url, self.token)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def test_full_agent_session(self):
        c = self.client
        self.assertEqual(c.info()["agent"], "agent:bot")
        self.assertEqual(c.list(), ["contracts/a.txt", "reports/old.md"])
        self.assertEqual(c.list("contracts/"), ["contracts/a.txt"])
        self.assertEqual(c.read_text("contracts/a.txt"), "Fee: 10\n")
        c.write("reports/summary file.md", "Fee is 10\n")
        self.assertEqual(c.changes(), [{"status": "added", "path": "reports/summary file.md"}])
        self.assertIn("+Fee is 10", c.render_diff())
        r = c.submit("summary written")
        self.assertEqual(r["status"], "merged")
        self.assertEqual((self.root / "reports" / "summary file.md").read_text(), "Fee is 10\n")
        with self.assertRaises(AccessDenied):  # token revoked once merged
            c.info()

    def test_denials(self):
        c = self.client
        with self.assertRaises(AccessDenied):
            c.read("secret/s.txt")
        with self.assertRaises(AccessDenied):
            c.write("contracts/a.txt", "Fee: 0\n")
        with self.assertRaises(FileNotFoundError):
            c.read("contracts/missing.txt")
        with self.assertRaises(GuardrailViolation):
            c.write("reports/key.md", "AKIAIOSFODNN7EXAMPLE")
        for evil in ["../secret/s.txt", "..%2fsecret/s.txt", "reports/../secret/s.txt", "%2e%2e/secret/s.txt"]:
            req = urllib.request.Request(f"{self.url}/v1/files/{evil}",
                                         headers={"Authorization": f"Bearer {self.token}"})
            with self.assertRaises(urllib.error.HTTPError, msg=evil) as cm:
                urllib.request.urlopen(req)
            self.assertIn(cm.exception.code, (400, 403, 404))

    def test_unauthorized(self):
        with self.assertRaises(AccessDenied):
            Client(self.url, "tth_" + self.ws.id[3:] + "_" + "x" * 43).list()
        req = urllib.request.Request(f"{self.url}/v1/files")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 401)
        self.assertTrue(any(e["action"] == "auth" for e in self.repo.audit.entries()))

    def test_body_limit(self):
        with self.assertRaises(TetherError) as cm:
            self.client.write("reports/big.md", "x" * 5000)
        self.assertIn("exceeds", str(cm.exception))


class TestMCP(Base):
    def setUp(self):
        super().setUp()
        self.ws = self.repo.create_workspace("agent:claude", POLICY, task="summarize contracts")
        self.mcp = MCPServer(self.ws)

    def rpc(self, method, params=None, msg_id=1):
        return self.mcp.handle({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})

    def call(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})["result"]
        return r["content"][0]["text"], r["isError"]

    def test_handshake_and_listing(self):
        init = self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                       "clientInfo": {"name": "test", "version": "0"}})["result"]
        self.assertEqual(init["protocolVersion"], "2025-03-26")
        self.assertIn("tools", init["capabilities"])
        self.assertIsNone(self.mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        names = {t["name"] for t in self.rpc("tools/list")["result"]["tools"]}
        self.assertEqual(names, {"list_files", "read_file", "write_file", "delete_file", "show_changes",
                                 "workspace_info", "submit_for_review"})

    def test_tools(self):
        self.assertEqual(self.call("list_files"), ("contracts/a.txt\nreports/old.md", False))
        self.assertEqual(self.call("read_file", path="contracts/a.txt"), ("Fee: 10\n", False))
        text, err = self.call("read_file", path="secret/s.txt")
        self.assertTrue(err)
        self.assertIn("Access denied", text)
        self.assertFalse(self.call("write_file", path="reports/s.md", content="sum\n")[1])
        self.assertIn("+sum", self.call("show_changes")[0])
        self.assertIn("summarize contracts", self.call("workspace_info")[0])
        text, err = self.call("submit_for_review", note="done")
        self.assertFalse(err)
        self.assertIn("Waiting for a human", text)

    def test_errors(self):
        self.assertEqual(self.rpc("nope")["error"]["code"], -32601)
        self.assertEqual(self.rpc("tools/call", {"name": "rm_rf"})["error"]["code"], -32602)
        self.assertTrue(self.call("read_file")[1])

    def test_stdio_loop(self):
        lines = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            "not json",
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "list_files", "arguments": {"prefix": "contracts/"}}}),
        ]
        out = io.StringIO()
        self.mcp.serve(io.StringIO("\n".join(lines) + "\n"), out)
        replies = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([r.get("id") for r in replies], [1, None, 2])
        self.assertEqual(replies[1]["error"]["code"], -32700)
        self.assertEqual(replies[2]["result"]["content"][0]["text"], "contracts/a.txt")


if __name__ == "__main__":
    unittest.main()
