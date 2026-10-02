"""tether: governed file workspaces for AI agents."""

from .audit import AuditLog, VerifyResult
from .policy import Guardrails, Policy, Rule
from .store import IntegrityError, InvalidPath
from .workspace import (
    AccessDenied,
    Change,
    GuardrailViolation,
    MergeBlocked,
    MergeConflict,
    NotARepo,
    Repo,
    TetherError,
    Workspace,
)

__all__ = [
    "AccessDenied", "AuditLog", "Change", "GuardrailViolation", "Guardrails", "IntegrityError",
    "InvalidPath", "MergeBlocked", "MergeConflict", "NotARepo", "Policy", "Repo", "Rule",
    "TetherError", "VerifyResult", "Workspace",
]
__version__ = "0.1.0"
