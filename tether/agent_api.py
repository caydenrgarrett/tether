"""HTTP API for agents: ``tether agent-api``.

Each request carries ``Authorization: Bearer <token>``. The token
(from ``tether token WS``) identifies exactly one workspace, so an agent can
only ever see and change its own fork, under its own policy. Run agents in a
container or on another machine and give them only the URL and the token;
they never get filesystem access to the real files or to ``.tether/``.

    GET    /v1/workspace            workspace info and policy
    GET    /v1/files?prefix=P       files the agent may read
    GET    /v1/files/<path>         read (raw bytes)
    PUT    /v1/files/<path>         write (raw body)
    DELETE /v1/files/<path>         delete
    GET    /v1/changes              changed files and a unified diff
    POST   /v1/submit {"note": ...} done; auto-merges if policy allows

Errors are JSON ``{"error": ..., "code": ...}`` with codes ``unauthorized``
(401), ``denied`` / ``guardrail`` (403), ``not_found`` (404),
``closed`` (409), ``too_large`` (413), ``bad_request`` (400).

Serve HTTPS with --tls-cert/--tls-key, or put a TLS reverse proxy in front,
before exposing it beyond localhost.
"""

from __future__ import annotations

import json
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .workspace import AccessDenied, GuardrailViolation, Repo, TetherError

DEFAULT_MAX_BODY = 64 * 1024 * 1024


def make_handler(root: str, max_body: int):
    class Handler(BaseHTTPRequestHandler):
        server_version = "tether-agent-api"

        def log_message(self, fmt, *args):
            pass

        def _send(self, status: int, body: bytes = b"", ctype: str = "application/json"):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, status: int = 200):
            self._send(status, json.dumps(obj).encode())

        def _error(self, status: int, code: str, message: str):
            self._json({"error": message, "code": code}, status)

        def _read_body(self) -> bytes:
            length = self.headers.get("Content-Length")
            if length is None:
                raise ValueError("Content-Length is required")
            length = int(length)
            if length < 0:
                raise ValueError("bad Content-Length")
            if length > max_body:
                raise OverflowError(f"body exceeds {max_body} bytes")
            return self.rfile.read(length)

        def _workspace(self, repo: Repo):
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            try:
                return repo.authenticate(token)
            except AccessDenied:
                repo.audit.append("auth", "anonymous", outcome="denied", reason="invalid token",
                                  remote=self.client_address[0])
                raise

        def _handle(self):
            url = urlparse(self.path)
            try:
                repo = Repo(root)
            except TetherError as e:
                return self._error(500, "server_error", str(e))
            try:
                ws = self._workspace(repo)
            except AccessDenied:
                if self.command in ("PUT", "POST"):
                    self.close_connection = True
                return self._error(HTTPStatus.UNAUTHORIZED, "unauthorized", "missing or invalid token")
            try:
                return self._route(ws, url)
            except GuardrailViolation as e:
                return self._error(HTTPStatus.FORBIDDEN, "guardrail", str(e))
            except AccessDenied as e:
                code = "closed" if "workspace is " in str(e) else "denied"
                status = HTTPStatus.CONFLICT if code == "closed" else HTTPStatus.FORBIDDEN
                return self._error(status, code, str(e))
            except FileNotFoundError as e:
                return self._error(HTTPStatus.NOT_FOUND, "not_found", f"no such file: {e}")
            except OverflowError as e:
                self.close_connection = True
                return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", str(e))
            except (ValueError, UnicodeDecodeError) as e:
                return self._error(HTTPStatus.BAD_REQUEST, "bad_request", str(e))
            except TetherError as e:
                return self._error(HTTPStatus.CONFLICT, "closed", str(e))

        def _route(self, ws, url):
            path, method = url.path, self.command
            if path.startswith("/v1/files/"):
                rel = unquote(path[len("/v1/files/"):])
                if method == "GET":
                    return self._send(200, ws.read(rel), "application/octet-stream")
                if method == "PUT":
                    ws.write(rel, self._read_body())
                    return self._send(HTTPStatus.NO_CONTENT)
                if method == "DELETE":
                    ws.delete(rel)
                    return self._send(HTTPStatus.NO_CONTENT)
            elif path == "/v1/files" and method == "GET":
                prefix = parse_qs(url.query).get("prefix", [""])[0]
                return self._json({"files": ws.list(prefix)})
            elif path == "/v1/workspace" and method == "GET":
                return self._json(ws.info())
            elif path == "/v1/changes" and method == "GET":
                return self._json({"changes": ws.changes(), "diff": ws.render_diff()})
            elif path == "/v1/submit" and method == "POST":
                raw = self._read_body() if self.headers.get("Content-Length") else b"{}"
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("expected a JSON object")
                note = body.get("note")
                return self._json(ws.submit(str(note) if note is not None else None))
            else:
                return self._error(HTTPStatus.NOT_FOUND, "not_found", "no such endpoint")
            return self._error(HTTPStatus.METHOD_NOT_ALLOWED, "bad_request", f"{method} not allowed here")

        do_GET = do_PUT = do_DELETE = do_POST = _handle

    return Handler


def make_server(root: str, host: str = "127.0.0.1", port: int = 8701, max_body: int = DEFAULT_MAX_BODY,
                certfile: str | None = None, keyfile: str | None = None) -> ThreadingHTTPServer:
    Repo(root)  # fail fast if this isn't a repository
    server = ThreadingHTTPServer((host, port), make_handler(root, max_body))
    server.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server
