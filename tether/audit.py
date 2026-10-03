"""Append-only, tamper-evident audit log.

Each entry is one JSON line carrying a sequence number, the hash of the
previous entry, and an HMAC-SHA256 over its own canonical encoding. Editing,
reordering or deleting any entry breaks the chain from that point on, which
``verify`` reports.

Truncating the tail of the log leaves a valid (shorter) chain, so the current
head hash should also be anchored somewhere the agent cannot write (a ticket,
a separate log service, a signed commit) and passed to ``verify(expect_head=)``.

In this prototype the HMAC key sits in ``.tether/audit.key``; in production
it belongs in a KMS or a separate service the agents have no access to.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head: str
    problems: list[str] = field(default_factory=list)


class AuditLog:
    def __init__(self, path: Path, key_path: Path):
        self.path = Path(path)
        self.key_path = Path(key_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        self._key = self.key_path.read_bytes()
        self.path.touch(exist_ok=True)
        self.listener = None  # called with each new entry (e.g. to send notifications)

    def _mac(self, entry: dict) -> str:
        return hmac.new(self._key, _canonical(entry), hashlib.sha256).hexdigest()

    @staticmethod
    def _last_line(f) -> str | None:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return None
        chunk = min(size, 65536)
        while True:
            f.seek(size - chunk)
            data = f.read(chunk)
            lines = data.rstrip(b"\n").split(b"\n")
            if len(lines) > 1 or chunk == size:
                return lines[-1].decode()
            chunk = min(size, chunk * 2)

    def append(self, action: str, actor: str, **fields) -> dict:
        """Append one entry. Fields with value None are omitted."""
        with open(self.path, "a+b") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                last = self._last_line(f)
                if last:
                    prev = json.loads(last)
                    seq, prev_hash = prev["seq"] + 1, prev["hash"]
                else:
                    seq, prev_hash = 0, GENESIS
                entry = {"seq": seq, "ts": now(), "action": action, "actor": actor, "prev": prev_hash}
                entry.update({k: v for k, v in fields.items() if v is not None})
                entry["hash"] = self._mac(entry)
                f.seek(0, os.SEEK_END)
                f.write(_canonical(entry) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        if self.listener:
            try:
                self.listener(entry)
            except Exception:
                pass
        return entry

    def entries(self, **filters) -> list[dict]:
        out = []
        with open(self.path, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                e = json.loads(line)
                if all(e.get(k) == v for k, v in filters.items() if v is not None):
                    out.append(e)
        return out

    def head(self) -> str:
        with open(self.path, "rb") as f:
            last = self._last_line(f)
        return json.loads(last)["hash"] if last else GENESIS

    def verify(self, expect_head: str | None = None) -> VerifyResult:
        problems: list[str] = []
        prev_hash, expected_seq, count = GENESIS, 0, 0
        with open(self.path, "rb") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    problems.append(f"line {lineno}: blank line")
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    problems.append(f"line {lineno}: not valid JSON")
                    continue
                count += 1
                claimed = entry.pop("hash", None)
                if entry.get("seq") != expected_seq:
                    problems.append(f"line {lineno}: sequence {entry.get('seq')} (expected {expected_seq})")
                if entry.get("prev") != prev_hash:
                    problems.append(f"line {lineno}: broken link to previous entry")
                if claimed is None or not hmac.compare_digest(claimed, self._mac(entry)):
                    problems.append(f"line {lineno}: signature mismatch (entry was modified)")
                prev_hash = claimed or ""
                expected_seq = (entry.get("seq") if isinstance(entry.get("seq"), int) else expected_seq) + 1
        if expect_head is not None and prev_hash != expect_head:
            problems.append("head does not match the anchored head (log truncated or rewritten)")
        return VerifyResult(ok=not problems, entries=count, head=prev_hash, problems=problems)
