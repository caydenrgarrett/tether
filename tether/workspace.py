"""Repositories, versions and agent workspaces.

A ``Repo`` tracks a real directory of files. Every state of that directory is
recorded as a numbered *version* (a manifest of content hashes). An agent never
touches the directory: it gets a ``Workspace``, a copy-on-write fork of the
latest version, and can only read and write through the workspace API, which
enforces its policy and guardrails and records every call in the audit log.
When the agent is done, a reviewer inspects the diff and merges it (or
discards it). Any version can be restored later with ``rollback``.
"""

from __future__ import annotations

import difflib
import getpass
import hmac
import os
import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog, now
from .guardrails import find_secrets
from .policy import LEVELS, Policy, effective_access
from .store import (
    META_DIR,
    InvalidPath,
    Manifest,
    ObjectStore,
    atomic_write,
    normalize_path,
    read_json,
    scan_directory,
    sha256,
    write_json,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

WORKSPACE_ID = re.compile(r"^ws_[0-9a-f]{12}$")
TOKEN = re.compile(r"^tth_([0-9a-f]{12})_[A-Za-z0-9_\-]{32,}$")
AUTO_REVIEWER = "policy:auto-approve"


class TetherError(Exception):
    pass


class NotARepo(TetherError):
    pass


class AccessDenied(TetherError, PermissionError):
    pass


class GuardrailViolation(AccessDenied):
    pass


class MergeBlocked(TetherError):
    pass


class MergeConflict(MergeBlocked):
    def __init__(self, paths: list[str]):
        super().__init__("changed on both sides since the workspace was forked: " + ", ".join(paths))
        self.paths = paths


def default_actor() -> str:
    return os.environ.get("TETHER_USER") or f"user:{getpass.getuser()}"


@dataclass(frozen=True)
class Change:
    status: str  # "added" | "modified" | "deleted"
    path: str
    old: str | None
    new: str | None


def diff_manifests(old: Manifest, new: Manifest) -> list[Change]:
    changes = []
    for path in sorted(set(old) | set(new)):
        a, b = old.get(path), new.get(path)
        if a == b:
            continue
        status = "added" if a is None else "deleted" if b is None else "modified"
        changes.append(Change(status, path, a, b))
    return changes


class Repo:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.meta = self.root / META_DIR
        if not self.meta.is_dir():
            raise NotARepo(f"{self.root} is not a tether repository (run `tether init`)")
        self.objects = ObjectStore(self.meta / "objects")
        # The HMAC key should live where agents can't reach it; point
        # TETHER_AUDIT_KEY_FILE at it (default: inside .tether/ for local use).
        key = os.environ.get("TETHER_AUDIT_KEY_FILE") or self.meta / "audit.key"
        self.audit = AuditLog(self.meta / "audit.log", Path(key))
        self._lock_depth = 0

    # -- setup -------------------------------------------------------------

    @classmethod
    def init(cls, root: str | Path, actor: str | None = None) -> "Repo":
        root = Path(root).resolve()
        meta = root / META_DIR
        if meta.exists():
            raise TetherError(f"{root} is already a tether repository")
        root.mkdir(parents=True, exist_ok=True)
        meta.mkdir(mode=0o700)
        (meta / "versions").mkdir()
        (meta / "workspaces").mkdir()
        repo = cls(root)
        actor = actor or default_actor()
        repo.audit.append("init", actor, root=str(root))
        repo.snapshot(actor, "initial import")
        return repo

    @classmethod
    def find(cls, start: str | Path | None = None) -> "Repo":
        here = Path(start or os.getcwd()).resolve()
        for d in (here, *here.parents):
            if (d / META_DIR).is_dir():
                return cls(d)
        raise NotARepo(f"no tether repository found at or above {here}")

    @contextmanager
    def _locked(self):
        if self._lock_depth or fcntl is None:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        with open(self.meta / "lock", "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            self._lock_depth = 1
            try:
                yield
            finally:
                self._lock_depth = 0
                fcntl.flock(f, fcntl.LOCK_UN)

    # -- versions ----------------------------------------------------------

    def _version_path(self, n: int) -> Path:
        return self.meta / "versions" / f"{n:08d}.json"

    def head(self) -> int:
        names = sorted(p.stem for p in (self.meta / "versions").glob("*.json"))
        return int(names[-1]) if names else -1

    def version(self, n: int) -> dict:
        p = self._version_path(n)
        if n < 0 or not p.exists():
            raise TetherError(f"no such version: {n}")
        return read_json(p)

    def history(self) -> list[dict]:
        return [self.version(n) for n in range(self.head() + 1)]

    def _record_version(self, manifest: Manifest, actor: str, message: str, **extra) -> int:
        n = self.head() + 1
        entry = {"version": n, "parent": n - 1 if n else None, "ts": now(), "actor": actor,
                 "message": message, "manifest": manifest}
        entry.update({k: v for k, v in extra.items() if v is not None})
        write_json(self._version_path(n), entry)
        return n

    def snapshot(self, actor: str | None = None, message: str = "snapshot") -> int:
        """Record the directory's current state, if it changed since the last version.

        Called before every fork, merge and rollback so edits made directly on
        disk (by people, outside tether) are never lost or silently overwritten.
        """
        actor = actor or default_actor()
        with self._locked():
            manifest = scan_directory(self.root, self.objects)
            head = self.head()
            if head >= 0 and self.version(head)["manifest"] == manifest:
                return head
            n = self._record_version(manifest, actor, message)
            self.audit.append("snapshot", actor, version=n, message=message, files=len(manifest))
            return n

    def _safe_target(self, rel: str) -> Path:
        """Resolve rel under root, refusing to go through any symlink."""
        target = self.root
        for part in rel.split("/"):
            target = target / part
            if target.is_symlink():
                raise InvalidPath(f"refusing to write through symlink: {target}")
        return target

    def _materialize(self, current: Manifest, desired: Manifest) -> None:
        for change in diff_manifests(current, desired):
            target = self._safe_target(change.path)
            if change.new is None:
                target.unlink(missing_ok=True)
                parent = target.parent
                while parent != self.root and not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent
            else:
                atomic_write(target, self.objects.get(change.new))

    def rollback(self, version: int, actor: str | None = None) -> int:
        """Restore the directory to an earlier version, recorded as a new version."""
        actor = actor or default_actor()
        with self._locked():
            target = self.version(version)["manifest"]
            current_v = self.snapshot(actor, "pre-rollback snapshot")
            current = self.version(current_v)["manifest"]
            self._materialize(current, target)
            n = self._record_version(target, actor, f"rollback to v{version}", rolled_back_to=version)
            self.audit.append("rollback", actor, version=n, rolled_back_to=version,
                              changes=len(diff_manifests(current, target)))
            return n

    # -- workspaces --------------------------------------------------------

    def _ws_path(self, ws_id: str) -> Path:
        if not WORKSPACE_ID.match(ws_id or ""):
            raise TetherError(f"invalid workspace id: {ws_id!r}")
        return self.meta / "workspaces" / f"{ws_id}.json"

    def _new_workspace(self, state: dict, actor: str) -> "Workspace":
        ws_id = "ws_" + secrets.token_hex(6)
        state = {"id": ws_id, "status": "open", "created": now(), "counters": {"reads": 0, "writes": 0},
                 "flags": [], **state}
        write_json(self._ws_path(ws_id), state)
        self.audit.append(
            "fork" if state.get("parent") else "create", actor, workspace=ws_id, agent=state["agent"],
            task=state.get("task"), base_version=state["base_version"], parent=state.get("parent"),
            policy=state["policies"][-1],
        )
        return Workspace(self, ws_id)

    def create_workspace(self, agent: str, policy: Policy | dict, task: str | None = None,
                         actor: str | None = None) -> "Workspace":
        """Fork the latest version into a new sandboxed workspace for an agent."""
        actor = actor or default_actor()
        policy = policy if isinstance(policy, Policy) else Policy.from_dict(policy)
        with self._locked():
            base = self.snapshot(actor, "pre-fork snapshot")
            return self._new_workspace(
                {"agent": agent, "task": task, "base_version": base, "parent": None,
                 "policies": [policy.to_dict()], "manifest": dict(self.version(base)["manifest"])},
                actor,
            )

    def fork_workspace(self, parent_id: str, agent: str, policy: Policy | dict, task: str | None = None,
                       actor: str | None = None) -> "Workspace":
        """Fork an existing workspace (e.g. for a sub-agent).

        The child inherits the parent's policy chain, so its access is the
        intersection of every policy above it.
        """
        actor = actor or default_actor()
        policy = policy if isinstance(policy, Policy) else Policy.from_dict(policy)
        with self._locked():
            parent = self.workspace(parent_id).state
            if parent["status"] != "open":
                raise TetherError(f"cannot fork a {parent['status']} workspace")
            return self._new_workspace(
                {"agent": agent, "task": task, "base_version": parent["base_version"], "parent": parent_id,
                 "policies": parent["policies"] + [policy.to_dict()], "manifest": dict(parent["manifest"])},
                actor,
            )

    def workspace(self, ws_id: str) -> "Workspace":
        if not self._ws_path(ws_id).exists():
            raise TetherError(f"no such workspace: {ws_id}")
        return Workspace(self, ws_id)

    def workspaces(self) -> list["Workspace"]:
        paths = sorted((self.meta / "workspaces").glob("ws_*.json"), key=lambda p: read_json(p)["created"])
        return [Workspace(self, p.stem) for p in paths]

    def merge(self, ws_id: str, reviewer: str, allow_flagged: bool = False) -> int:
        """Apply a workspace's changes to the real directory after review."""
        with self._locked():
            ws = self.workspace(ws_id)
            st = ws.state

            def refuse(exc: MergeBlocked):
                self.audit.append("merge", reviewer, workspace=ws_id, agent=st["agent"],
                                  outcome="denied", reason=str(exc))
                raise exc

            if st["status"] != "open":
                refuse(MergeBlocked(f"workspace is {st['status']}"))
            if reviewer == st["agent"]:
                refuse(MergeBlocked("an agent cannot approve its own changes"))
            if st["flags"] and not allow_flagged:
                refuse(MergeBlocked(f"workspace has {len(st['flags'])} guardrail flag(s); "
                                    "review them and pass allow_flagged to merge anyway"))

            base = self.version(st["base_version"])["manifest"]
            changes = diff_manifests(base, st["manifest"])
            current_v = self.snapshot(reviewer, "pre-merge snapshot")
            current = self.version(current_v)["manifest"]
            conflicts = [c.path for c in changes if current.get(c.path) != base.get(c.path)]
            if conflicts:
                refuse(MergeConflict(conflicts))

            merged = dict(current)
            for c in changes:
                if c.new is None:
                    merged.pop(c.path, None)
                else:
                    merged[c.path] = c.new
            if changes:
                self._materialize(current, merged)
                n = self._record_version(merged, reviewer, f"merge {ws_id} ({st['agent']})",
                                         workspace=ws_id, agent=st["agent"], approved_by=reviewer)
            else:
                n = current_v
            st.update(status="merged", merged_version=n, closed_at=now(), closed_by=reviewer, token_hashes=[])
            ws._save(st)
            self.audit.append("merge", reviewer, workspace=ws_id, agent=st["agent"], outcome="allowed",
                              version=n, changes=[{"status": c.status, "path": c.path} for c in changes],
                              flags_overridden=len(st["flags"]) if st["flags"] else None)
            return n

    def auto_approval_blocker(self, ws_id: str) -> str | None:
        """Why this workspace can't merge without a human, or None if it can.

        Every policy in the chain must allow it, so a sub-agent can't grant
        itself auto-approval by forking with a looser policy.
        """
        st = self.workspace(ws_id).state
        policies = [Policy.from_dict(p) for p in st["policies"]]
        if any(p.auto_approve is None for p in policies):
            return "policy requires human review"
        if st["flags"]:
            return "workspace has guardrail flags"
        changes = diff_manifests(self.version(st["base_version"])["manifest"], st["manifest"])
        if not changes:
            return "no changes"
        for p in policies:
            a = p.auto_approve
            if a.max_changes is not None and len(changes) > a.max_changes:
                return f"{len(changes)} changes exceeds auto-approve max_changes={a.max_changes}"
            for c in changes:
                if c.status == "deleted" and not a.allow_deletes:
                    return f"deleting {c.path} needs human review"
                if not a.covers(c.path):
                    return f"{c.path} is outside the auto-approve paths"
        return None

    # -- agent credentials -------------------------------------------------

    def issue_token(self, ws_id: str, actor: str | None = None) -> str:
        """Create a bearer token that grants an agent access to one workspace.

        Only a hash is stored; the token is shown once.
        """
        actor = actor or default_actor()
        with self._locked():
            ws = self.workspace(ws_id)
            st = ws.state
            if st["status"] != "open":
                raise TetherError(f"workspace is {st['status']}")
            token = f"tth_{ws_id[3:]}_{secrets.token_urlsafe(32)}"
            st.setdefault("token_hashes", []).append(sha256(token.encode()))
            ws._save(st)
            self.audit.append("token", actor, workspace=ws_id, agent=st["agent"])
            return token

    def revoke_tokens(self, ws_id: str, actor: str | None = None) -> int:
        actor = actor or default_actor()
        with self._locked():
            ws = self.workspace(ws_id)
            st = ws.state
            n = len(st.get("token_hashes", []))
            st["token_hashes"] = []
            ws._save(st)
            self.audit.append("revoke", actor, workspace=ws_id, agent=st["agent"], tokens=n)
            return n

    def authenticate(self, token: str) -> "Workspace":
        m = TOKEN.match(token or "")
        if not m:
            raise AccessDenied("invalid token")
        path = self._ws_path("ws_" + m.group(1))
        if not path.exists():
            raise AccessDenied("invalid token")
        digest = sha256(token.encode())
        if not any(hmac.compare_digest(digest, h) for h in read_json(path).get("token_hashes", [])):
            raise AccessDenied("invalid token")
        return Workspace(self, "ws_" + m.group(1))

    # -- maintenance -------------------------------------------------------

    def gc(self, actor: str | None = None) -> dict:
        """Delete blobs no version or workspace refers to.

        These are intermediate contents an agent overwrote before it finished.
        Their hashes stay in the audit log, but the bytes are gone afterwards.
        """
        actor = actor or default_actor()
        with self._locked():
            live: set[str] = set()
            for n in range(self.head() + 1):
                live.update(self.version(n)["manifest"].values())
            for p in (self.meta / "workspaces").glob("ws_*.json"):
                live.update(read_json(p)["manifest"].values())
            removed = freed = 0
            for blob in self.objects.path.glob("??/*"):
                if blob.parent.name + blob.name not in live:
                    freed += blob.stat().st_size
                    blob.unlink()
                    removed += 1
            self.audit.append("gc", actor, removed=removed, bytes=freed)
            return {"removed": removed, "bytes": freed}

    def discard(self, ws_id: str, actor: str | None = None, reason: str | None = None) -> None:
        actor = actor or default_actor()
        with self._locked():
            ws = self.workspace(ws_id)
            st = ws.state
            if st["status"] != "open":
                raise TetherError(f"workspace is {st['status']}")
            st.update(status="discarded", closed_at=now(), closed_by=actor, token_hashes=[])
            ws._save(st)
            self.audit.append("discard", actor, workspace=ws_id, agent=st["agent"], reason=reason)


class Workspace:
    """The only interface an agent gets to files."""

    def __init__(self, repo: Repo, ws_id: str):
        self.repo = repo
        self.id = ws_id

    @property
    def state(self) -> dict:
        return read_json(self.repo._ws_path(self.id))

    def _save(self, st: dict) -> None:
        write_json(self.repo._ws_path(self.id), st)

    @property
    def agent(self) -> str:
        return self.state["agent"]

    @property
    def status(self) -> str:
        return self.state["status"]

    @property
    def flags(self) -> list[dict]:
        return self.state["flags"]

    def _policies(self, st: dict) -> list[Policy]:
        return [Policy.from_dict(p) for p in st["policies"]]

    # -- enforcement -------------------------------------------------------

    def _deny(self, st: dict, action: str, path: str | None, reason: str, exc=AccessDenied, flag=False):
        if flag:
            st["flags"].append({"ts": now(), "action": action, "path": path, "reason": reason})
            self._save(st)
        self.repo.audit.append(action, st["agent"], workspace=self.id, path=path, outcome="denied",
                               reason=reason, severity="high" if flag else "warning")
        raise exc(f"{action} {path or ''}: {reason}".strip())

    def _authorize(self, st: dict, action: str, path: str, needed: str) -> str:
        if st["status"] != "open":
            self._deny(st, action, path, f"workspace is {st['status']}")
        try:
            norm = normalize_path(path)
        except InvalidPath as e:
            self._deny(st, action, str(path), str(e), flag=True)
        level = effective_access(self._policies(st), norm)
        if LEVELS[level] < LEVELS[needed]:
            self._deny(st, action, norm, f"policy grants {level!r}, needs {needed!r}")
        return norm

    def _limit(self, st: dict, action: str, path: str, counter: str, setting: str) -> None:
        for p in self._policies(st):
            limit = getattr(p.guardrails, setting)
            if limit is not None and st["counters"][counter] >= limit:
                self._deny(st, action, path, f"{setting}={limit} exceeded", GuardrailViolation, flag=True)

    # -- agent API ---------------------------------------------------------

    def read(self, path: str) -> bytes:
        with self.repo._locked():
            st = self.state
            norm = self._authorize(st, "read", path, "read")
            if norm not in st["manifest"]:
                self.repo.audit.append("read", st["agent"], workspace=self.id, path=norm, outcome="not_found")
                raise FileNotFoundError(norm)
            self._limit(st, "read", norm, "reads", "max_reads")
            digest = st["manifest"][norm]
            data = self.repo.objects.get(digest)
            if any(p.guardrails.block_secret_reads for p in self._policies(st)):
                found = find_secrets(data)
                if found:
                    self._deny(st, "read", norm, "file contains credentials: " + ", ".join(found),
                               GuardrailViolation, flag=True)
            st["counters"]["reads"] += 1
            self._save(st)
            self.repo.audit.append("read", st["agent"], workspace=self.id, path=norm, outcome="allowed",
                                   sha256=digest, bytes=len(data))
            return data

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        return self.read(path).decode(encoding)

    def write(self, path: str, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        with self.repo._locked():
            st = self.state
            norm = self._authorize(st, "write", path, "write")
            self._limit(st, "write", norm, "writes", "max_writes")
            for p in self._policies(st):
                g = p.guardrails
                if g.max_file_bytes is not None and len(data) > g.max_file_bytes:
                    self._deny(st, "write", norm, f"{len(data)} bytes exceeds max_file_bytes={g.max_file_bytes}",
                               GuardrailViolation, flag=True)
            if any(p.guardrails.block_secrets for p in self._policies(st)):
                found = find_secrets(data)
                if found:
                    self._deny(st, "write", norm, "content contains credentials: " + ", ".join(found),
                               GuardrailViolation, flag=True)
            manifest = st["manifest"]
            parts = norm.split("/")
            for i in range(1, len(parts)):
                if "/".join(parts[:i]) in manifest:
                    self._deny(st, "write", norm, f"{'/'.join(parts[:i])} is a file, not a directory")
            if any(p.startswith(norm + "/") for p in manifest):
                self._deny(st, "write", norm, "path is a directory")
            digest = self.repo.objects.put(data)
            before = manifest.get(norm)
            manifest[norm] = digest
            st["counters"]["writes"] += 1
            self._save(st)
            self.repo.audit.append("write", st["agent"], workspace=self.id, path=norm, outcome="allowed",
                                   before=before, after=digest, bytes=len(data))

    def delete(self, path: str) -> None:
        with self.repo._locked():
            st = self.state
            norm = self._authorize(st, "delete", path, "write")
            if norm not in st["manifest"]:
                self.repo.audit.append("delete", st["agent"], workspace=self.id, path=norm, outcome="not_found")
                raise FileNotFoundError(norm)
            self._limit(st, "delete", norm, "writes", "max_writes")
            before = st["manifest"].pop(norm)
            st["counters"]["writes"] += 1
            self._save(st)
            self.repo.audit.append("delete", st["agent"], workspace=self.id, path=norm, outcome="allowed",
                                   before=before)

    def list(self, prefix: str = "") -> list[str]:
        """Paths the agent may read. Files it cannot read are invisible."""
        with self.repo._locked():
            st = self.state
            if st["status"] != "open":
                self._deny(st, "list", prefix or None, f"workspace is {st['status']}")
            policies = self._policies(st)
            visible = [p for p in sorted(st["manifest"])
                       if p.startswith(prefix) and LEVELS[effective_access(policies, p)] >= LEVELS["read"]]
            self.repo.audit.append("list", st["agent"], workspace=self.id, prefix=prefix or None,
                                   outcome="allowed", count=len(visible))
            return visible

    def exists(self, path: str) -> bool:
        return path in self.list(path)

    def submit(self, note: str | None = None) -> dict:
        """Agent signals it's done. Merges right away if auto-approve allows it."""
        with self.repo._locked():
            st = self.state
            if st["status"] != "open":
                self._deny(st, "submit", None, f"workspace is {st['status']}")
            note = note[:2000] if note else None
            st.update(submitted_at=now(), submit_note=note)
            self._save(st)
            self.repo.audit.append("submit", st["agent"], workspace=self.id, note=note,
                                   changes=len(self.diff()))
            blocker = self.repo.auto_approval_blocker(self.id)
            if blocker is None:
                try:
                    n = self.repo.merge(self.id, reviewer=AUTO_REVIEWER)
                    return {"status": "merged", "version": n, "approved_by": AUTO_REVIEWER}
                except MergeBlocked as e:
                    blocker = str(e)
            self.repo.audit.append("auto_approve", AUTO_REVIEWER, workspace=self.id, outcome="skipped",
                                   reason=blocker)
            return {"status": "awaiting_review", "reason": blocker}

    def info(self) -> dict:
        st = self.state
        return {k: st.get(k) for k in ("id", "agent", "task", "status", "base_version", "parent", "created",
                                       "counters", "flags", "policies", "submitted_at", "submit_note",
                                       "merged_version", "closed_at", "closed_by")}

    def changes(self) -> list[dict]:
        return [{"status": c.status, "path": c.path} for c in self.diff()]

    # -- review ------------------------------------------------------------

    def diff(self) -> list[Change]:
        st = self.state
        return diff_manifests(self.repo.version(st["base_version"])["manifest"], st["manifest"])

    def change_lines(self, c: Change, context: int = 3) -> list[str] | None:
        """Unified diff lines for one change, or None for a binary file."""
        old = self.repo.objects.get(c.old) if c.old else b""
        new = self.repo.objects.get(c.new) if c.new else b""
        try:
            a, b = old.decode("utf-8"), new.decode("utf-8")
        except UnicodeDecodeError:
            return None
        lines = difflib.unified_diff(
            a.splitlines(keepends=True), b.splitlines(keepends=True),
            fromfile=f"a/{c.path}" if c.old else "/dev/null",
            tofile=f"b/{c.path}" if c.new else "/dev/null", n=context,
        )
        return [line.rstrip("\n") for line in lines]

    def render_diff(self, context: int = 3) -> str:
        out = []
        for c in self.diff():
            out.append(f"{c.status}: {c.path}")
            lines = self.change_lines(c, context)
            out.extend(lines if lines is not None else ["  binary file"])
        return "\n".join(out)
