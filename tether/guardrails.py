"""Content checks applied to agent reads and writes."""

from __future__ import annotations

import re

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("anthropic-api-key", re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-api-key", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
    ("slack-token", re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe-secret-key", re.compile(rb"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    (
        "generic-credential-assignment",
        re.compile(
            rb"(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\b"
            rb"\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{16,}"
        ),
    ),
]


def find_secrets(data: bytes) -> list[str]:
    """Return the names of credential patterns found in data (deduplicated)."""
    return [name for name, pattern in SECRET_PATTERNS if pattern.search(data)]
