import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from tether import Repo, TetherError
from tether.server import make_server
from tether.users import UserStore

POLICY = {"rules": [{"path": "docs/**", "access": "read"}, {"path": "out/**", "access": "write"}]}
PW = "correct horse battery"


class TestUserStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.users = UserStore(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_add_verify(self):
        self.users.add("alice", PW, "reviewer")
        self.assertEqual(self.users.verify("alice", PW), "reviewer")
        self.assertIsNone(self.users.verify("alice", PW + "x"))
        self.assertIsNone(self.users.verify("nobody", PW))
        self.assertNotIn(PW, self.users.path.read_text())
        self.assertEqual(self.users.path.stat().st_mode & 0o777, 0o600)

    def test_validation(self):
        with self.assertRaises(ValueError):
            self.users.add("alice", "short", "reviewer")
        with self.assertRaises(ValueError):
            self.users.add("Alice!", PW, "reviewer")
        with self.assertRaises(ValueError):
            self.users.add("alice", PW, "god")
        self.users.add("alice", PW, "viewer")
        with self.assertRaises(ValueError):
            self.users.add("alice", PW, "viewer")

    def test_role_and_password_changes(self):
        self.users.add("alice", PW, "viewer")
        self.users.set_role("alice", "admin")
        self.users.set_password("alice", PW + " two")
        self.assertEqual(self.users.verify("alice", PW + " two"), "admin")
        self.users.remove("alice")
        self.assertFalse(self.users.has_users())


class TestTeamMode(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "docs").mkdir()
        (self.root / "docs" / "a.txt").write_text("hello\n")
        self.repo = Repo.init(self.root, actor="user:alice")
        users = UserStore(self.repo.meta)
        users.add("alice", PW, "admin")
        users.add("rita", PW, "reviewer")
        users.add("vic", PW, "viewer")
        self.ws = self.repo.create_workspace("agent:bot", POLICY)
        self.ws.write("out/s.md", "s\n")
        self.server = make_server(str(self.root), "user:ignored", port=0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def req(self, method, path, body=None, cookie=None, csrf=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        h = {"Host": f"localhost:{self.port}"}
        if body is not None:
            h["Content-Type"] = "application/json"
        if cookie:
            h["Cookie"] = cookie
        if csrf:
            h["X-Tether-Token"] = csrf
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        res = conn.getresponse()
        data = res.read()
        headers = dict(res.getheaders())
        conn.close()
        return res.status, (json.loads(data) if data and data[:1] in b"{[" else data), headers

    def login(self, name):
        status, data, headers = self.req("POST", "/api/login", {"username": name, "password": PW})
        self.assertEqual(status, 200, data)
        cookie = headers["Set-Cookie"].split(";")[0]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        return cookie, data["csrf"]

    def test_requires_sign_in(self):
        self.assertTrue(self.server.team)
        self.assertEqual(self.req("GET", "/api/workspaces")[0], 401)
        self.assertEqual(self.req("GET", "/api/me")[0], 401)
        status, page, _ = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.token.encode(), page)  # local token is never exposed in team mode

    def test_login_and_roles(self):
        cookie, csrf = self.login("vic")
        self.assertEqual(self.req("GET", "/api/me", cookie=cookie)[1]["role"], "viewer")
        self.assertEqual(self.req("GET", "/api/workspaces", cookie=cookie)[0], 200)
        self.assertEqual(self.req("POST", f"/api/workspaces/{self.ws.id}/merge", {}, cookie, csrf)[0], 403)

        cookie, csrf = self.login("rita")
        self.assertEqual(self.req("POST", "/api/rollback", {"version": 0}, cookie, csrf)[0], 403)
        self.assertEqual(self.req("POST", f"/api/workspaces/{self.ws.id}/merge", {}, cookie)[0], 403)  # no csrf
        status, data, _ = self.req("POST", f"/api/workspaces/{self.ws.id}/merge", {}, cookie, csrf)
        self.assertEqual(status, 200, data)
        self.assertEqual(self.repo.version(data["version"])["approved_by"], "user:rita")

        cookie, csrf = self.login("alice")
        self.assertEqual(self.req("POST", "/api/rollback", {"version": 0}, cookie, csrf)[0], 200)

    def test_logout(self):
        cookie, csrf = self.login("rita")
        self.assertEqual(self.req("POST", "/api/logout", {}, cookie, csrf)[0], 200)
        self.assertEqual(self.req("GET", "/api/me", cookie=cookie)[0], 401)

    def test_removed_user_loses_session(self):
        cookie, _ = self.login("rita")
        UserStore(self.repo.meta).remove("rita")
        self.assertEqual(self.req("GET", "/api/me", cookie=cookie)[0], 401)

    def test_lockout_and_audit(self):
        for _ in range(5):
            self.assertEqual(self.req("POST", "/api/login", {"username": "rita", "password": "wrong password!"})[0], 401)
        self.assertEqual(self.req("POST", "/api/login", {"username": "rita", "password": PW})[0], 429)
        logins = [e for e in self.repo.audit.entries() if e["action"] == "login"]
        self.assertEqual(len(logins), 6)
        self.assertTrue(all(e["outcome"] == "denied" for e in logins))

    def test_forged_cookie(self):
        self.assertEqual(self.req("GET", "/api/me", cookie="tether_session=forged")[0], 401)


class TestExposure(unittest.TestCase):
    def test_refuses_public_bind_without_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            Repo.init(tmp, actor="user:alice")
            with self.assertRaises(TetherError):
                make_server(tmp, "user:alice", host="0.0.0.0", port=0)


if __name__ == "__main__":
    unittest.main()
