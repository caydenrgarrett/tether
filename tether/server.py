"""Review web app: ``tether serve``.

Serves one page plus a small JSON API for reviewing agent workspaces:
seeing diffs, flags, policies and activity, merging or discarding, browsing
versions, rolling back and verifying the audit log.

Two modes:

* **Local** (no users added, bound to localhost): acts as the person who
  started it, with full rights. State-changing requests need a per-process
  token embedded in the served page.
* **Team** (after ``tether user add``): everyone signs in. Sessions are
  HttpOnly, SameSite=Strict cookies; every state-changing request also
  needs that session's CSRF token; roles decide who may merge, discard or
  roll back; failed logins are rate limited and audited. Binding beyond
  localhost requires team mode.

Every request must carry an expected Host header (blocks DNS rebinding).
Pass a certificate and key to serve HTTPS directly.
"""

from __future__ import annotations

import json
import re
import secrets
import ssl
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from .users import UserStore, role_at_least
from .workspace import Repo, TetherError, Workspace

MAX_BODY = 64 * 1024
FONTS = {"Geist-Variable.woff2", "GeistMono-Variable.woff2"}
SESSION_TTL = 12 * 3600
LOCKOUT_FAILURES = 5
LOCKOUT_WINDOW = 15 * 60
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


def workspace_summary(ws: Workspace) -> dict:
    st = ws.state
    changes = ws.diff()
    return {
        "id": st["id"],
        "agent": st["agent"],
        "task": st.get("task"),
        "status": st["status"],
        "created": st["created"],
        "closed_at": st.get("closed_at"),
        "closed_by": st.get("closed_by"),
        "base_version": st["base_version"],
        "merged_version": st.get("merged_version"),
        "parent": st.get("parent"),
        "submitted_at": st.get("submitted_at"),
        "submit_note": st.get("submit_note"),
        "counters": st["counters"],
        "flags": len(st["flags"]),
        "changes": {s: sum(c.status == s for c in changes) for s in ("added", "modified", "deleted")},
    }


def workspace_detail(repo: Repo, ws: Workspace) -> dict:
    st = ws.state
    files = []
    for c in ws.diff():
        lines = ws.change_lines(c)
        files.append({"status": c.status, "path": c.path, "binary": lines is None, "lines": lines or []})
    return {
        **workspace_summary(ws),
        "flag_list": st["flags"],
        "policies": st["policies"],
        "files": files,
        "activity": repo.audit.entries(workspace=ws.id),
    }


class Sessions:
    """In-memory sessions and login throttling (one process, so no shared store needed)."""

    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._failures: dict[str, list[float]] = {}

    def create(self, user: str, role: str) -> dict:
        s = {"id": secrets.token_urlsafe(32), "user": user, "role": role, "csrf": secrets.token_urlsafe(24),
             "expires": time.time() + SESSION_TTL}
        self._sessions[s["id"]] = s
        return s

    def get(self, sid: str | None) -> dict | None:
        s = self._sessions.get(sid or "")
        if s and s["expires"] < time.time():
            self._sessions.pop(s["id"], None)
            return None
        return s

    def drop(self, sid: str | None) -> None:
        self._sessions.pop(sid or "", None)

    def drop_user(self, user: str) -> None:
        for sid in [k for k, v in self._sessions.items() if v["user"] == user]:
            self._sessions.pop(sid, None)

    def locked(self, *keys: str) -> bool:
        cutoff = time.time() - LOCKOUT_WINDOW
        for k in keys:
            recent = [t for t in self._failures.get(k, []) if t > cutoff]
            self._failures[k] = recent
            if len(recent) >= LOCKOUT_FAILURES:
                return True
        return False

    def fail(self, *keys: str) -> None:
        for k in keys:
            self._failures.setdefault(k, []).append(time.time())

    def clear(self, *keys: str) -> None:
        for k in keys:
            self._failures.pop(k, None)


def make_handler(root: str, local_actor: str | None, token: str, allowed_hosts: set[str], secure_cookies: bool):
    """local_actor: identity for local mode; None means team mode (sign-in required)."""
    template = resources.files("tether").joinpath("ui.html").read_text()
    sessions = Sessions()
    cookie_name = "__Host-tether" if secure_cookies else "tether_session"

    def page() -> bytes:
        return template.replace("__TETHER_TOKEN__", token if local_actor else "").encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "tether"

        def log_message(self, fmt, *args):  # keep the terminal quiet
            pass

        # -- helpers -------------------------------------------------------

        def _send(self, status: int, body: bytes, ctype: str, headers: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if secure_cookies:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "connect-src 'self'; img-src data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status: int = 200, headers: dict | None = None):
            self._send(status, json.dumps(obj).encode(), "application/json", headers)

        def _error(self, status: int, message: str):
            self._json({"error": message}, status)

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ValueError("request too large")
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw or b"{}")
            if not isinstance(data, dict):
                raise ValueError("expected a JSON object")
            return data

        def _sid(self) -> str | None:
            c = SimpleCookie()
            try:
                c.load(self.headers.get("Cookie", ""))
            except Exception:
                return None
            return c[cookie_name].value if cookie_name in c else None

        def _who(self) -> dict | None:
            """The signed-in identity: {actor, role, csrf}, or None."""
            if local_actor:
                return {"actor": local_actor, "role": "admin", "csrf": token, "mode": "local"}
            s = sessions.get(self._sid())
            if not s:
                return None
            u = UserStore(Repo(root).meta).get(s["user"])
            if not u:  # removed since sign-in
                sessions.drop(s["id"])
                return None
            return {"actor": f"user:{u['name']}", "role": u["role"], "csrf": s["csrf"], "mode": "team"}

        def _cookie(self, value: str, max_age: int) -> str:
            parts = [f"{cookie_name}={value}", "Path=/", "HttpOnly", "SameSite=Strict", f"Max-Age={max_age}"]
            if secure_cookies:
                parts.append("Secure")
            return "; ".join(parts)

        # -- routes --------------------------------------------------------

        def do_GET(self):
            if not self._host_ok():
                return self._error(HTTPStatus.FORBIDDEN, "bad Host header")
            url = urlparse(self.path)
            if url.path == "/":
                return self._send(200, page(), "text/html; charset=utf-8")
            if url.path.startswith("/static/fonts/") and url.path.rsplit("/", 1)[1] in FONTS:
                font = resources.files("tether").joinpath("static", "fonts", url.path.rsplit("/", 1)[1])
                return self._send(200, font.read_bytes(), "font/woff2")
            who = self._who()
            if url.path == "/api/me":
                if not who:
                    return self._error(HTTPStatus.UNAUTHORIZED, "sign in required")
                return self._json(who)
            if not who:
                return self._error(HTTPStatus.UNAUTHORIZED, "sign in required")
            try:
                repo = Repo(root)
                if url.path == "/api/workspaces":
                    return self._json([workspace_summary(ws) for ws in reversed(repo.workspaces())])
                m = re.fullmatch(r"/api/workspaces/(ws_[0-9a-f]{12})", url.path)
                if m:
                    return self._json(workspace_detail(repo, repo.workspace(m.group(1))))
                if url.path == "/api/history":
                    versions = []
                    for v in reversed(repo.history()):
                        v["files"] = len(v.pop("manifest"))
                        versions.append(v)
                    return self._json(versions)
                if url.path == "/api/log":
                    q = parse_qs(url.query)
                    entries = repo.audit.entries()
                    if q.get("denied"):
                        entries = [e for e in entries if e.get("outcome") == "denied"]
                    return self._json(list(reversed(entries))[:500])
                if url.path == "/api/verify":
                    r = repo.audit.verify()
                    return self._json({"ok": r.ok, "entries": r.entries, "head": r.head, "problems": r.problems})
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            except TetherError as e:
                return self._error(HTTPStatus.NOT_FOUND, str(e))

        def do_POST(self):
            if not self._host_ok():
                return self._error(HTTPStatus.FORBIDDEN, "bad Host header")
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "expected application/json")
            url = urlparse(self.path)
            try:
                body = self._body()
            except (ValueError, UnicodeDecodeError) as e:
                return self._error(HTTPStatus.BAD_REQUEST, str(e))
            if url.path == "/api/login":
                return self._login(body)
            who = self._who()
            if not who:
                return self._error(HTTPStatus.UNAUTHORIZED, "sign in required")
            if not secrets.compare_digest(self.headers.get("X-Tether-Token", ""), who["csrf"]):
                return self._error(HTTPStatus.FORBIDDEN, "missing or invalid token")
            if url.path == "/api/logout":
                sessions.drop(self._sid())
                return self._json({"ok": True}, headers={"Set-Cookie": self._cookie("", 0)})
            try:
                repo = Repo(root)
                m = re.fullmatch(r"/api/workspaces/(ws_[0-9a-f]{12})/(merge|discard)", url.path)
                if m:
                    if not role_at_least(who["role"], "reviewer"):
                        return self._error(HTTPStatus.FORBIDDEN, "your role can't approve or discard workspaces")
                    ws_id, action = m.groups()
                    if action == "merge":
                        n = repo.merge(ws_id, reviewer=who["actor"], allow_flagged=bool(body.get("allow_flagged")))
                        return self._json({"ok": True, "version": n})
                    reason = body.get("reason")
                    repo.discard(ws_id, actor=who["actor"], reason=str(reason)[:500] if reason else None)
                    return self._json({"ok": True})
                if url.path == "/api/rollback":
                    if not role_at_least(who["role"], "admin"):
                        return self._error(HTTPStatus.FORBIDDEN, "only admins can roll back")
                    version = body.get("version")
                    if not isinstance(version, int) or isinstance(version, bool):
                        raise ValueError("version must be an integer")
                    return self._json({"ok": True, "version": repo.rollback(version, actor=who["actor"])})
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            except (TetherError, PermissionError, ValueError) as e:
                return self._error(HTTPStatus.CONFLICT, str(e))

        def _login(self, body: dict):
            if local_actor:
                return self._error(HTTPStatus.BAD_REQUEST, "sign-in is off; add a user to enable it")
            name = str(body.get("username") or "").strip().lower()[:64]
            password = str(body.get("password") or "")[:1024]
            ip = self.client_address[0]
            repo = Repo(root)
            if sessions.locked(f"user:{name}", f"ip:{ip}"):
                repo.audit.append("login", f"user:{name}" if name else "anonymous", outcome="denied",
                                  reason="too many failed attempts", remote=ip)
                return self._error(HTTPStatus.TOO_MANY_REQUESTS, "Too many failed attempts. Try again in 15 minutes.")
            role = UserStore(repo.meta).verify(name, password) if name and password else None
            if role is None:
                sessions.fail(f"user:{name}", f"ip:{ip}")
                repo.audit.append("login", f"user:{name}" if name else "anonymous", outcome="denied",
                                  reason="wrong username or password", remote=ip)
                return self._error(HTTPStatus.UNAUTHORIZED, "Wrong username or password.")
            sessions.clear(f"user:{name}", f"ip:{ip}")
            s = sessions.create(name, role)
            repo.audit.append("login", f"user:{name}", outcome="allowed", remote=ip)
            return self._json({"actor": f"user:{name}", "role": role, "csrf": s["csrf"], "mode": "team"},
                              headers={"Set-Cookie": self._cookie(s["id"], SESSION_TTL)})

    return Handler


def make_server(root: str, actor: str, host: str = "127.0.0.1", port: int = 8700, token: str | None = None,
                allowed_hosts: list[str] | None = None, certfile: str | None = None,
                keyfile: str | None = None, secure_cookies: bool | None = None) -> HTTPServer:
    """Build the review server (single-threaded, so repository locking stays simple).

    Team mode turns on automatically once any user exists. Binding beyond
    localhost without users is refused.
    """
    repo = Repo(root)  # fail fast if this isn't a repository
    team = UserStore(repo.meta).has_users()
    if host not in LOCAL_HOSTS and not team:
        raise TetherError("refusing to serve beyond localhost without sign-in; add a user with `tether user add`")
    token = token or secrets.token_urlsafe(24)
    server = HTTPServer((host, port), lambda *a: None)  # placeholder handler until we know the port
    actual_port = server.server_address[1]
    tls = bool(certfile)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    names = {host, "localhost", "127.0.0.1"} if host in LOCAL_HOSTS else {host}
    allowed = {f"{n}:{actual_port}" for n in names}
    for h in allowed_hosts or []:
        allowed.add(h)
        if ":" not in h:
            allowed.update({f"{h}:{actual_port}", f"{h}:443" if tls or secure_cookies else f"{h}:80"})
    secure = tls if secure_cookies is None else secure_cookies
    server.RequestHandlerClass = make_handler(root, None if team else actor, token, allowed, secure)
    server.token = token
    server.team = team
    return server
