import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tether import (
    AccessDenied,
    GuardrailViolation,
    InvalidPath,
    MergeBlocked,
    MergeConflict,
    Policy,
    Repo,
)
from tether.cli import main
from tether.policy import glob_to_regex
from tether.store import normalize_path

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

POLICY = {
    "rules": [
        {"path": "**", "access": "read"},
        {"path": "secrets/**", "access": "none"},
        {"path": "reports/**", "access": "write"},
    ],
    "guardrails": {"max_reads": 5},
}


class RepoTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "files"
        (self.root / "contracts").mkdir(parents=True)
        (self.root / "secrets").mkdir()
        (self.root / "reports").mkdir()
        (self.root / "contracts" / "acme.txt").write_text("Term: 12 months\nFee: $10,000\n")
        (self.root / "secrets" / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
        (self.root / "reports" / "q1.md").write_text("# Q1\n")
        self.repo = Repo.init(self.root, actor="user:alice")

    def tearDown(self):
        self._tmp.cleanup()


class TestPaths(unittest.TestCase):
    def test_normalize_rejects_escapes(self):
        for bad in ["", "/etc/passwd", "../x", "a/../../x", "a\\b", ".tether/audit.key", "a\x00b", "."]:
            with self.assertRaises(InvalidPath, msg=bad):
                normalize_path(bad)
        self.assertEqual(normalize_path("a/./b//c"), "a/b/c")

    def test_globs(self):
        self.assertTrue(glob_to_regex("contracts/**").match("contracts/a/b.txt"))
        self.assertFalse(glob_to_regex("contracts/*").match("contracts/a/b.txt"))
        self.assertTrue(glob_to_regex("**/*.env").match("prod.env"))
        self.assertTrue(glob_to_regex("**/*.env").match("a/b/prod.env"))
        self.assertFalse(glob_to_regex("*.md").match("reports/q1.md"))

    def test_last_rule_wins_and_default_deny(self):
        p = Policy.from_dict(POLICY)
        self.assertEqual(p.access_for("contracts/acme.txt"), "read")
        self.assertEqual(p.access_for("secrets/prod.env"), "none")
        self.assertEqual(p.access_for("reports/q1.md"), "write")
        self.assertEqual(Policy.from_dict({"rules": []}).access_for("anything"), "none")


class TestWorkspace(RepoTestCase):
    def test_fork_isolates_originals(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        ws.write("reports/summary.md", "Acme: 12 months\n")
        self.assertFalse((self.root / "reports" / "summary.md").exists())
        self.assertEqual([c.path for c in ws.diff()], ["reports/summary.md"])

    def test_scoped_access(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        self.assertIn("Fee", ws.read_text("contracts/acme.txt"))
        self.assertNotIn("secrets/prod.env", ws.list())
        with self.assertRaises(AccessDenied):
            ws.read("secrets/prod.env")
        with self.assertRaises(AccessDenied):
            ws.write("contracts/acme.txt", "Fee: $0\n")
        with self.assertRaises(AccessDenied):
            ws.read("../../etc/passwd")
        self.assertEqual(len(ws.flags), 1, "path traversal attempts are flagged")

    def test_every_action_is_audited(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        ws.read("contracts/acme.txt")
        with self.assertRaises(AccessDenied):
            ws.read("secrets/prod.env")
        ws.write("reports/summary.md", "hi")
        entries = self.repo.audit.entries(workspace=ws.id)
        self.assertEqual([(e["action"], e.get("outcome")) for e in entries],
                         [("create", None), ("read", "allowed"), ("read", "denied"), ("write", "allowed")])
        self.assertEqual(entries[1]["sha256"], ws.state["manifest"]["contracts/acme.txt"])

    def test_secret_write_blocked_and_flagged(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        with self.assertRaises(GuardrailViolation):
            ws.write("reports/leak.md", f"found key {AWS_KEY}")
        self.assertEqual(len(ws.flags), 1)
        with self.assertRaises(MergeBlocked):
            self.repo.merge(ws.id, reviewer="user:alice")
        self.repo.merge(ws.id, reviewer="user:alice", allow_flagged=True)

    def test_read_budget(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        for _ in range(5):
            ws.read("contracts/acme.txt")
        with self.assertRaises(GuardrailViolation):
            ws.read("contracts/acme.txt")
        self.assertIn("max_reads", ws.flags[0]["reason"])

    def test_block_secret_reads(self):
        ws = self.repo.create_workspace(
            "agent:x", {"rules": [{"path": "**", "access": "read"}], "guardrails": {"block_secret_reads": True}})
        with self.assertRaises(GuardrailViolation):
            ws.read("secrets/prod.env")

    def test_file_directory_conflicts(self):
        ws = self.repo.create_workspace("agent:x", {"rules": [{"path": "**", "access": "write"}]})
        with self.assertRaises(AccessDenied):
            ws.write("reports/q1.md/evil", "x")
        with self.assertRaises(AccessDenied):
            ws.write("reports", "x")

    def test_merge_applies_changes_and_versions(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        ws.write("reports/summary.md", "summary\n")
        ws.write("reports/q1.md", "# Q1 (revised)\n")
        v = self.repo.merge(ws.id, reviewer="user:alice")
        self.assertEqual((self.root / "reports" / "summary.md").read_text(), "summary\n")
        self.assertEqual((self.root / "reports" / "q1.md").read_text(), "# Q1 (revised)\n")
        self.assertEqual(self.repo.version(v)["approved_by"], "user:alice")
        self.assertEqual(ws.status, "merged")
        with self.assertRaises(AccessDenied):
            ws.write("reports/late.md", "too late")

    def test_delete_and_merge(self):
        ws = self.repo.create_workspace("agent:x", {"rules": [{"path": "reports/**", "access": "write"}]})
        ws.delete("reports/q1.md")
        self.repo.merge(ws.id, reviewer="user:alice")
        self.assertFalse((self.root / "reports" / "q1.md").exists())

    def test_agent_cannot_approve_itself(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        with self.assertRaises(MergeBlocked):
            self.repo.merge(ws.id, reviewer="agent:summarizer")

    def test_merge_conflict_with_out_of_band_edit(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        ws.write("reports/q1.md", "agent version\n")
        (self.root / "reports" / "q1.md").write_text("human version\n")
        with self.assertRaises(MergeConflict) as cm:
            self.repo.merge(ws.id, reviewer="user:alice")
        self.assertEqual(cm.exception.paths, ["reports/q1.md"])
        self.assertEqual((self.root / "reports" / "q1.md").read_text(), "human version\n")

    def test_non_overlapping_edits_merge_cleanly(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        ws.write("reports/summary.md", "s\n")
        (self.root / "contracts" / "new.txt").write_text("human added\n")
        self.repo.merge(ws.id, reviewer="user:alice")
        self.assertTrue((self.root / "contracts" / "new.txt").exists())
        self.assertTrue((self.root / "reports" / "summary.md").exists())

    def test_discard(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        ws.write("reports/summary.md", "s\n")
        self.repo.discard(ws.id, actor="user:alice", reason="wrong numbers")
        self.assertFalse((self.root / "reports" / "summary.md").exists())
        with self.assertRaises(MergeBlocked):
            self.repo.merge(ws.id, reviewer="user:alice")

    def test_rollback(self):
        v0 = self.repo.head()
        ws = self.repo.create_workspace("agent:x", {"rules": [{"path": "**", "access": "write"},
                                                               {"path": "secrets/**", "access": "none"}]})
        ws.write("contracts/acme.txt", "Fee: $0\n")
        ws.delete("reports/q1.md")
        self.repo.merge(ws.id, reviewer="user:alice")
        n = self.repo.rollback(v0, actor="user:alice")
        self.assertEqual((self.root / "contracts" / "acme.txt").read_text(), "Term: 12 months\nFee: $10,000\n")
        self.assertTrue((self.root / "reports" / "q1.md").exists())
        self.assertEqual(self.repo.version(n)["rolled_back_to"], v0)
        self.assertEqual(len(self.repo.history()), n + 1, "rollback adds a version, never erases history")

    def test_merge_refuses_symlinked_directory(self):
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        os.symlink(outside, self.root / "out")
        ws = self.repo.create_workspace("agent:x", {"rules": [{"path": "**", "access": "write"},
                                                               {"path": "secrets/**", "access": "none"}]})
        ws.write("out/pwned.txt", "x")
        with self.assertRaises(InvalidPath):
            self.repo.merge(ws.id, reviewer="user:alice")
        self.assertFalse((outside / "pwned.txt").exists())

    def test_fork_cannot_widen_access(self):
        parent = self.repo.create_workspace("agent:lead", POLICY)
        parent.write("reports/draft.md", "draft\n")
        child = self.repo.fork_workspace(parent.id, "agent:helper", {"rules": [{"path": "**", "access": "write"}]})
        self.assertEqual(child.read_text("reports/draft.md"), "draft\n")
        with self.assertRaises(AccessDenied):
            child.read("secrets/prod.env")
        with self.assertRaises(AccessDenied):
            child.write("contracts/acme.txt", "x")
        child.write("reports/draft.md", "better draft\n")
        self.assertEqual(parent.read_text("reports/draft.md"), "draft\n")


class TestAudit(RepoTestCase):
    def _work(self):
        ws = self.repo.create_workspace("agent:summarizer", POLICY)
        ws.read("contracts/acme.txt")
        ws.write("reports/summary.md", "s\n")
        return ws

    def test_untampered_log_verifies(self):
        self._work()
        result = self.repo.audit.verify()
        self.assertTrue(result.ok, result.problems)
        self.assertEqual(result.head, self.repo.audit.head())

    def test_edited_entry_detected(self):
        self._work()
        path = self.repo.audit.path
        lines = path.read_text().splitlines()
        entry = json.loads(lines[3])
        entry["path"] = "contracts/innocent.txt"
        lines[3] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")
        result = self.repo.audit.verify()
        self.assertFalse(result.ok)
        self.assertTrue(any("signature" in p for p in result.problems))

    def test_deleted_entry_detected(self):
        self._work()
        path = self.repo.audit.path
        lines = path.read_text().splitlines()
        del lines[2]
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(self.repo.audit.verify().ok)

    def test_truncation_detected_with_anchor(self):
        self._work()
        anchored = self.repo.audit.head()
        path = self.repo.audit.path
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:-1]) + "\n")
        self.assertTrue(self.repo.audit.verify().ok, "a truncated chain is still internally valid")
        self.assertFalse(self.repo.audit.verify(expect_head=anchored).ok)


class TestCLI(RepoTestCase):
    def run_cli(self, *argv, stdin=None):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--root", str(self.root), "--actor", "user:alice", *argv])
        return code, out.getvalue()

    def test_end_to_end(self):
        code, ws_id = self.run_cli("create", "--agent", "agent:bot", "--read", "contracts/**",
                                   "--write", "reports/**")
        self.assertEqual(code, 0)
        ws_id = ws_id.strip()
        code, files = self.run_cli("files", ws_id)
        self.assertEqual(files.split(), ["contracts/acme.txt", "reports/q1.md"])
        src = Path(self._tmp.name) / "summary.md"
        src.write_text("summary\n")
        self.assertEqual(self.run_cli("put", ws_id, "reports/summary.md", str(src))[0], 0)
        code, diff = self.run_cli("diff", ws_id)
        self.assertIn("+summary", diff)
        self.assertEqual(self.run_cli("merge", ws_id)[0], 0)
        self.assertTrue((self.root / "reports" / "summary.md").exists())
        code, out = self.run_cli("verify")
        self.assertEqual(code, 0)
        self.assertIn("ok:", out)
        code, history = self.run_cli("history")
        self.assertIn("approved_by=user:alice", history)

    def test_denied_returns_error(self):
        _, ws_id = self.run_cli("create", "--agent", "agent:bot", "--read", "contracts/**")
        code, _ = self.run_cli("cat", ws_id.strip(), "secrets/prod.env")
        self.assertEqual(code, 1)
        code, out = self.run_cli("log", "--denied")
        self.assertIn("secrets/prod.env", out)


if __name__ == "__main__":
    unittest.main()
