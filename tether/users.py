"""Reviewer accounts for the review app.

Users live in ``.tether/users.json`` (mode 0600), with scrypt password
hashes. Roles, from least to most privileged:

    viewer    read workspaces, diffs, history and the audit log
    reviewer  + approve (merge) and discard workspaces
    admin     + roll back versions
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

from .audit import now
from .store import read_json, write_json

ROLES = {"viewer": 0, "reviewer": 1, "admin": 2}
USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MIN_PASSWORD = 12
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, maxmem=64 * 1024 * 1024, **_SCRYPT).hex()


def role_at_least(role: str | None, needed: str) -> bool:
    return role in ROLES and ROLES[role] >= ROLES[needed]


class UserStore:
    def __init__(self, meta: Path):
        self.path = Path(meta) / "users.json"
        self._dummy_salt = secrets.token_bytes(16)

    def _load(self) -> dict:
        return read_json(self.path) if self.path.exists() else {"users": {}}

    def _save(self, data: dict) -> None:
        write_json(self.path, data)
        os.chmod(self.path, 0o600)

    def has_users(self) -> bool:
        return bool(self._load()["users"])

    def list(self) -> list[dict]:
        users = self._load()["users"]
        return [{"name": n, "role": u["role"], "created": u["created"]} for n, u in sorted(users.items())]

    def get(self, name: str) -> dict | None:
        u = self._load()["users"].get(name)
        return {"name": name, "role": u["role"]} if u else None

    def add(self, name: str, password: str, role: str) -> None:
        if not USERNAME.match(name):
            raise ValueError("usernames are lowercase letters, digits, '.', '_' or '-' (max 64)")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        if len(password) < MIN_PASSWORD:
            raise ValueError(f"passwords must be at least {MIN_PASSWORD} characters")
        data = self._load()
        if name in data["users"]:
            raise ValueError(f"user {name} already exists")
        salt = secrets.token_bytes(16)
        data["users"][name] = {"role": role, "salt": salt.hex(), "hash": _hash(password, salt), "created": now()}
        self._save(data)

    def set_password(self, name: str, password: str) -> None:
        if len(password) < MIN_PASSWORD:
            raise ValueError(f"passwords must be at least {MIN_PASSWORD} characters")
        data = self._load()
        if name not in data["users"]:
            raise ValueError(f"no such user: {name}")
        salt = secrets.token_bytes(16)
        data["users"][name].update(salt=salt.hex(), hash=_hash(password, salt))
        self._save(data)

    def set_role(self, name: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        data = self._load()
        if name not in data["users"]:
            raise ValueError(f"no such user: {name}")
        data["users"][name]["role"] = role
        self._save(data)

    def remove(self, name: str) -> None:
        data = self._load()
        if data["users"].pop(name, None) is None:
            raise ValueError(f"no such user: {name}")
        self._save(data)

    def verify(self, name: str, password: str) -> str | None:
        """Return the user's role if the password is right, else None.

        Unknown users still cost one scrypt so timing doesn't reveal which
        usernames exist.
        """
        u = self._load()["users"].get(name)
        if u is None:
            _hash(password, self._dummy_salt)
            return None
        ok = hmac.compare_digest(_hash(password, bytes.fromhex(u["salt"])), u["hash"])
        return u["role"] if ok else None
