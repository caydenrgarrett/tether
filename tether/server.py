"""Local review web app: ``tether serve``.

Serves one page plus a small JSON API for reviewing agent workspaces:
seeing diffs, flags, policies and activity, merging or discarding, browsing
versions, rolling back and verifying the audit log.

The server binds to 127.0.0.1 by default and acts as a single reviewer
identity. Because it can change real files, every request must carry the
right Host header (blocks DNS rebinding) and every state-changing request
must carry a per-process token that only the served page knows (blocks
cross-site requests from other tabs).
"""

from __future__ import annotations

import json
import re
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from .workspace import Repo, TetherError, Workspace

MAX_BODY = 64 * 1024


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


def make_handler(root: str, reviewer: str, token: str, allowed_hosts: set[str]):
    page = resources.files("tether").joinpath("ui.html").read_text()
    reviewer_js = json.dumps(reviewer)[1:-1].replace("<", "\\u003c")
    page = page.replace("__TETHER_TOKEN__", token).replace("__TETHER_REVIEWER__", reviewer_js)

    class Handler(BaseHTTPRequestHandler):
        server_version = "tether"

        def log_message(self, fmt, *args):  # keep the terminal quiet
            pass

        # -- helpers -------------------------------------------------------

        def _send(self, status: int, body: bytes, ctype: str):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status: int = 200):
            self._send(status, json.dumps(obj).encode(), "application/json")

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

        # -- routes --------------------------------------------------------

        def do_GET(self):
            if not self._host_ok():
                return self._error(HTTPStatus.FORBIDDEN, "bad Host header")
            url = urlparse(self.path)
            try:
                repo = Repo(root)
                if url.path == "/":
                    return self._send(200, page.encode(), "text/html; charset=utf-8")
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
            if not secrets.compare_digest(self.headers.get("X-Tether-Token", ""), token):
                return self._error(HTTPStatus.FORBIDDEN, "missing or invalid token")
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "expected application/json")
            url = urlparse(self.path)
            try:
                body = self._body()
                repo = Repo(root)
                m = re.fullmatch(r"/api/workspaces/(ws_[0-9a-f]{12})/(merge|discard)", url.path)
                if m:
                    ws_id, action = m.groups()
                    if action == "merge":
                        n = repo.merge(ws_id, reviewer=reviewer, allow_flagged=bool(body.get("allow_flagged")))
                        return self._json({"ok": True, "version": n})
                    reason = body.get("reason")
                    repo.discard(ws_id, actor=reviewer, reason=str(reason)[:500] if reason else None)
                    return self._json({"ok": True})
                if url.path == "/api/rollback":
                    version = body.get("version")
                    if not isinstance(version, int):
                        raise ValueError("version must be an integer")
                    return self._json({"ok": True, "version": repo.rollback(version, actor=reviewer)})
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            except (TetherError, PermissionError, ValueError) as e:
                return self._error(HTTPStatus.CONFLICT, str(e))

    return Handler


def make_server(root: str, reviewer: str, host: str = "127.0.0.1", port: int = 8700,
                token: str | None = None) -> HTTPServer:
    """Build the review server (single-threaded, so repository locking stays simple)."""
    Repo(root)  # fail fast if this isn't a repository
    token = token or secrets.token_urlsafe(24)
    server = HTTPServer((host, port), lambda *a: None)  # placeholder handler until we know the port
    actual_port = server.server_address[1]
    names = {host, "localhost", "127.0.0.1"} if host in ("127.0.0.1", "localhost") else {host}
    allowed = {f"{n}:{actual_port}" for n in names}
    server.RequestHandlerClass = make_handler(root, reviewer, token, allowed)
    server.token = token
    return server
