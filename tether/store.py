"""Content-addressed object store and manifests.

A *manifest* maps a normalized relative path to the SHA-256 of its contents.
Snapshots, versions and workspaces are all just manifests, so forking a
workspace copies a small dict of hashes rather than any file data
(copy-on-write: a blob is only stored again when its contents change).
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import tempfile
from pathlib import Path

Manifest = dict[str, str]

META_DIR = ".tether"


class IntegrityError(Exception):
    """A stored object no longer matches its hash."""


class InvalidPath(ValueError):
    """A path that could escape the workspace or is otherwise malformed."""


def normalize_path(path: str) -> str:
    """Return a canonical relative POSIX path, or raise InvalidPath.

    Rejects absolute paths, parent traversal, backslashes, NUL bytes and
    anything inside the metadata directory, so an agent can never address a
    file outside its workspace.
    """
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        raise InvalidPath(f"invalid path: {path!r}")
    if path.startswith("/"):
        raise InvalidPath(f"absolute paths are not allowed: {path!r}")
    parts = path.split("/")
    if any(p == ".." for p in parts):
        raise InvalidPath(f"parent traversal is not allowed: {path!r}")
    norm = posixpath.normpath(path)
    if norm in ("", ".") or norm.startswith("../"):
        raise InvalidPath(f"invalid path: {path!r}")
    if norm == META_DIR or norm.startswith(META_DIR + "/"):
        raise InvalidPath(f"reserved path: {path!r}")
    return norm


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def write_json(path: Path, obj) -> None:
    atomic_write(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


def read_json(path: Path):
    return json.loads(path.read_text())


class ObjectStore:
    """Immutable blobs keyed by SHA-256."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)

    def _blob_path(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise IntegrityError(f"malformed object id: {digest!r}")
        return self.path / digest[:2] / digest[2:]

    def put(self, data: bytes) -> str:
        digest = sha256(data)
        p = self._blob_path(digest)
        if not p.exists():
            atomic_write(p, data, mode=0o444)
        return digest

    def get(self, digest: str) -> bytes:
        data = self._blob_path(digest).read_bytes()
        if sha256(data) != digest:
            raise IntegrityError(f"object {digest} is corrupted")
        return data


def scan_directory(root: Path, store: ObjectStore) -> Manifest:
    """Store every regular file under root and return its manifest.

    Symlinks are skipped on purpose: following them could pull files from
    outside the tracked directory into an agent's view.
    """
    root = Path(root)
    manifest: Manifest = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != META_DIR]
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_symlink() or not full.is_file():
                continue
            rel = name if rel_dir == "." else f"{Path(rel_dir).as_posix()}/{name}"
            manifest[rel] = store.put(full.read_bytes())
    return manifest
