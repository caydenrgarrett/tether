"""Python client for the agent HTTP API.

It has the same methods as ``Workspace``, so agent code runs unchanged
whether it holds a local workspace or a remote token:

    from tether.client import Client
    ws = Client("http://127.0.0.1:8701", token)
    ws.list("contracts/")
    ws.write("reports/summary.md", "...")
    ws.submit("summary ready")
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

from .workspace import AccessDenied, GuardrailViolation, TetherError


class Client:
    def __init__(self, url: str | None = None, token: str | None = None, timeout: float = 60):
        self.url = (url or os.environ.get("TETHER_URL") or "http://127.0.0.1:8701").rstrip("/")
        self.token = token or os.environ.get("TETHER_TOKEN")
        if not self.token:
            raise TetherError("no token: pass token= or set TETHER_TOKEN")
        self.timeout = timeout

    def _request(self, method: str, path: str, body: bytes | None = None,
                 ctype: str = "application/octet-stream") -> bytes:
        req = urllib.request.Request(self.url + path, data=body, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        if body is not None:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                return res.read()
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read())
            except ValueError:
                err = {"error": e.reason, "code": ""}
            message, code = err.get("error", str(e.reason)), err.get("code", "")
            if code == "guardrail":
                raise GuardrailViolation(message) from None
            if code in ("denied", "unauthorized"):
                raise AccessDenied(message) from None
            if code == "not_found":
                raise FileNotFoundError(message) from None
            raise TetherError(message) from None

    def _json(self, method: str, path: str, obj=None):
        body = json.dumps(obj).encode() if obj is not None else None
        return json.loads(self._request(method, path, body, "application/json"))

    @staticmethod
    def _file(path: str) -> str:
        return "/v1/files/" + quote(path, safe="/")

    # Same surface as tether.Workspace -------------------------------------

    def info(self) -> dict:
        return self._json("GET", "/v1/workspace")

    def list(self, prefix: str = "") -> list[str]:
        query = "?" + urlencode({"prefix": prefix}) if prefix else ""
        return self._json("GET", "/v1/files" + query)["files"]

    def read(self, path: str) -> bytes:
        return self._request("GET", self._file(path))

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        return self.read(path).decode(encoding)

    def write(self, path: str, data: bytes | str) -> None:
        self._request("PUT", self._file(path), data.encode("utf-8") if isinstance(data, str) else data)

    def delete(self, path: str) -> None:
        self._request("DELETE", self._file(path))

    def changes(self) -> list[dict]:
        return self._json("GET", "/v1/changes")["changes"]

    def render_diff(self) -> str:
        return self._json("GET", "/v1/changes")["diff"]

    def submit(self, note: str | None = None) -> dict:
        return self._json("POST", "/v1/submit", {"note": note})
