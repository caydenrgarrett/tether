"""Webhook notifications and audit-log export formats.

Webhooks are stored in ``.tether/config.json``. Each one picks which events
it wants and a format: ``slack`` (a Slack incoming-webhook message) or
``json`` (the raw audit entry, signed with HMAC-SHA256 in the
``X-Tether-Signature`` header so the receiver can check it came from tether).

Events: flag, submit, merge, discard, rollback, login_failed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import sys
import threading
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from .store import read_json, write_json

EVENTS = ("flag", "submit", "merge", "discard", "rollback", "login_failed")
FORMATS = ("slack", "json")


def event_of(entry: dict) -> str | None:
    """Map an audit entry to a notification event, or None."""
    action, outcome = entry.get("action"), entry.get("outcome")
    if entry.get("severity") == "high":
        return "flag"
    if action == "submit":
        return "submit"
    if action == "merge" and outcome == "allowed":
        return "merge"
    if action == "discard":
        return "discard"
    if action == "rollback":
        return "rollback"
    if action == "login" and outcome == "denied":
        return "login_failed"
    return None


def _slack_escape(text: str) -> str:
    # Agent-supplied text must not be able to @channel people or forge links.
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_text(event: str, e: dict) -> str:
    who, ws, path = _slack_escape(e.get("actor", "")), e.get("workspace"), e.get("path")
    where = f" `{_slack_escape(path)}`" if path else ""
    ref = f" in `{ws}`" if ws else ""
    if event == "flag":
        return f":triangular_flag_on_post: *{who}* was blocked and flagged{ref}: {e.get('action')}{where} ({_slack_escape(e.get('reason', ''))})"
    if event == "submit":
        note = f" \u201c{_slack_escape(e['note'])}\u201d" if e.get("note") else ""
        return f":inbox_tray: *{who}* submitted{ref} for review.{note}"
    if event == "merge":
        return f":white_check_mark: *{who}* merged{ref} as v{e.get('version')}."
    if event == "discard":
        return f":wastebasket: *{who}* discarded{ref}."
    if event == "rollback":
        return f":rewind: *{who}* rolled the files back to v{e.get('rolled_back_to')} (now v{e.get('version')})."
    if event == "login_failed":
        return f":lock: Failed sign-in for *{who}* from {_slack_escape(e.get('remote', 'unknown'))}."
    return f"{event}: {who}"


def check_url(url: str) -> None:
    u = urlparse(url)
    if u.scheme == "https" and u.hostname:
        return
    if u.scheme == "http" and u.hostname:
        try:
            if ipaddress.ip_address(u.hostname).is_loopback:
                return
        except ValueError:
            if u.hostname == "localhost":
                return
    raise ValueError("webhook URLs must use https (http is allowed only for localhost)")


class Notifier:
    def __init__(self, meta: Path):
        self.path = Path(meta) / "config.json"

    def _load(self) -> dict:
        return read_json(self.path) if self.path.exists() else {}

    def _save(self, cfg: dict) -> None:
        write_json(self.path, cfg)
        self.path.chmod(0o600)

    def hooks(self) -> list[dict]:
        return self._load().get("webhooks", [])

    def add(self, url: str, events: list[str] | None = None, fmt: str = "slack") -> dict:
        check_url(url)
        events = list(events or EVENTS)
        bad = set(events) - set(EVENTS)
        if bad:
            raise ValueError(f"unknown events: {sorted(bad)}; choose from {', '.join(EVENTS)}")
        if fmt not in FORMATS:
            raise ValueError(f"format must be one of {', '.join(FORMATS)}")
        cfg = self._load()
        hook = {"id": secrets.token_hex(4), "url": url, "events": events, "format": fmt, "secret": secrets.token_hex(32)}
        cfg.setdefault("webhooks", []).append(hook)
        self._save(cfg)
        return hook

    def remove(self, hook_id: str) -> None:
        cfg = self._load()
        hooks = cfg.get("webhooks", [])
        kept = [h for h in hooks if h["id"] != hook_id]
        if len(kept) == len(hooks):
            raise ValueError(f"no such webhook: {hook_id}")
        cfg["webhooks"] = kept
        self._save(cfg)

    @staticmethod
    def payload(hook: dict, event: str, entry: dict) -> tuple[bytes, dict]:
        if hook["format"] == "slack":
            body = json.dumps({"text": slack_text(event, entry)}).encode()
        else:
            body = json.dumps({"event": event, "entry": entry}, sort_keys=True).encode()
        sig = hmac.new(bytes.fromhex(hook["secret"]), body, hashlib.sha256).hexdigest()
        return body, {"Content-Type": "application/json", "X-Tether-Event": event,
                      "X-Tether-Signature": f"sha256={sig}", "User-Agent": "tether-webhook"}

    @staticmethod
    def _post(url: str, body: bytes, headers: dict) -> None:
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            urllib.request.urlopen(req, timeout=5).close()
        except Exception as exc:  # never let a webhook break the operation that triggered it
            print(f"tether: webhook to {urlparse(url).hostname} failed: {exc}", file=sys.stderr)

    def dispatch(self, entry: dict, wait: bool = False) -> list[threading.Thread]:
        event = event_of(entry)
        if event is None:
            return []
        threads = []
        for hook in self.hooks():
            if event in hook["events"]:
                body, headers = self.payload(hook, event, entry)
                t = threading.Thread(target=self._post, args=(hook["url"], body, headers))
                t.start()
                threads.append(t)
        if wait:
            for t in threads:
                t.join(6)
        return threads


# -- export formats -------------------------------------------------------

_CEF_SEVERITY = {"high": 8, "warning": 5}


def _cef_header(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def to_cef(e: dict, version: str) -> str:
    """One audit entry as an ArcSight CEF line (accepted by most SIEMs)."""
    severity = _CEF_SEVERITY.get(e.get("severity", ""), 3 if e.get("outcome") != "denied" else 5)
    ext = {"rt": e.get("ts"), "suser": e.get("actor"), "act": e.get("action"), "outcome": e.get("outcome"),
           "fname": e.get("path"), "cs1Label": "workspace", "cs1": e.get("workspace"), "msg": e.get("reason"),
           "src": e.get("remote"), "cn1Label": "seq", "cn1": e.get("seq"), "cs2Label": "hash", "cs2": e.get("hash")}
    tail = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v is not None)
    name = f"{e.get('action')} {e.get('outcome', '')}".strip()
    return f"CEF:0|tether|tether|{version}|{_cef_header(e.get('action'))}|{_cef_header(name)}|{severity}|{tail}"
