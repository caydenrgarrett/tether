"""Per-agent, per-task access policies.

A policy is an ordered list of path rules plus guardrail settings. Access is
deny-by-default and the *last* matching rule wins, so broad grants can be
narrowed afterwards:

    {"rules": [{"path": "**",         "access": "read"},
               {"path": "secrets/**", "access": "none"},
               {"path": "out/**",     "access": "write"}]}

Glob syntax: ``*`` and ``?`` never cross a ``/``; ``**`` matches any number of
directories.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

LEVELS = {"none": 0, "read": 1, "write": 2}


def glob_to_regex(pattern: str) -> re.Pattern:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


@dataclass(frozen=True)
class Rule:
    path: str
    access: str

    def __post_init__(self):
        if self.access not in LEVELS:
            raise ValueError(f"unknown access level {self.access!r}; use one of {sorted(LEVELS)}")

    def matches(self, path: str) -> bool:
        return glob_to_regex(self.path).match(path) is not None


@dataclass
class Guardrails:
    block_secrets: bool = True        # refuse writes that contain credentials
    block_secret_reads: bool = False  # refuse reads of files that contain credentials
    max_reads: int | None = None      # flag + deny once an agent reads more than this
    max_writes: int | None = None
    max_file_bytes: int | None = None

    @classmethod
    def from_dict(cls, d: dict | None) -> "Guardrails":
        d = dict(d or {})
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown guardrail settings: {sorted(unknown)}")
        return cls(**d)

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


@dataclass
class AutoApprove:
    """Changes that may merge without a human when the agent submits.

    Every change must fall under one of ``paths``; deletes need
    ``allow_deletes``; and there may be at most ``max_changes`` files.
    A flagged workspace is never auto-approved.
    """
    paths: list[str] = field(default_factory=list)
    max_changes: int | None = None
    allow_deletes: bool = False

    @classmethod
    def from_dict(cls, d: dict | None) -> "AutoApprove | None":
        if d is None:
            return None
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown auto_approve settings: {sorted(unknown)}")
        return cls(**d)

    def to_dict(self) -> dict:
        return {"paths": list(self.paths), "max_changes": self.max_changes, "allow_deletes": self.allow_deletes}

    def covers(self, path: str) -> bool:
        return any(glob_to_regex(g).match(path) for g in self.paths)


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    guardrails: Guardrails = field(default_factory=Guardrails)
    auto_approve: AutoApprove | None = None

    def access_for(self, path: str) -> str:
        level = "none"
        for rule in self.rules:
            if rule.matches(path):
                level = rule.access
        return level

    def allows(self, path: str, needed: str) -> bool:
        return LEVELS[self.access_for(path)] >= LEVELS[needed]

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        unknown = set(d) - {"rules", "guardrails", "auto_approve"}
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        return cls(
            rules=[Rule(r["path"], r["access"]) for r in d.get("rules", [])],
            guardrails=Guardrails.from_dict(d.get("guardrails")),
            auto_approve=AutoApprove.from_dict(d.get("auto_approve")),
        )

    def to_dict(self) -> dict:
        return {
            "rules": [{"path": r.path, "access": r.access} for r in self.rules],
            "guardrails": self.guardrails.to_dict(),
            "auto_approve": self.auto_approve.to_dict() if self.auto_approve else None,
        }


def effective_access(chain: list[Policy], path: str) -> str:
    """Access through a chain of policies is the minimum of each.

    Used for forks: a child workspace can never see or change more than the
    workspace it was forked from, whatever its own policy says.
    """
    if not chain:
        return "none"
    return min((p.access_for(path) for p in chain), key=LEVELS.__getitem__)
