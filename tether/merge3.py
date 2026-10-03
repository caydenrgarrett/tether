"""Line-based three-way merge for text files.

Changes from both sides are computed against the common base. If they touch
different regions, both are applied. If they overlap or touch (the same
rule git uses), the merge fails and the caller treats the file as a conflict.
Identical changes made on both sides are applied once.
"""

from __future__ import annotations

from difflib import SequenceMatcher

MAX_LINES = 20000  # beyond this, treat as a conflict rather than risk a very slow diff


def _changes(base: list[str], other: list[str]) -> list[tuple[int, int, tuple[str, ...]]]:
    sm = SequenceMatcher(None, base, other, autojunk=False)
    return [(i1, i2, tuple(other[j1:j2])) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal"]


def merge_lines(base: list[str], ours: list[str], theirs: list[str]) -> list[str] | None:
    a, b = _changes(base, ours), _changes(base, theirs)
    shared = set(a) & set(b)
    a = [c for c in a if c not in shared]
    b = [c for c in b if c not in shared]
    for s1, e1, _ in a:
        for s2, e2, _ in b:
            if s1 <= e2 and s2 <= e1:  # overlapping or adjacent regions
                return None
    out: list[str] = []
    pos = 0
    for s, e, repl in sorted([*a, *b, *shared], key=lambda c: (c[0], c[1])):
        out.extend(base[pos:s])
        out.extend(repl)
        pos = e
    out.extend(base[pos:])
    return out


def merge_text(base: bytes, ours: bytes, theirs: bytes) -> bytes | None:
    """Merge three UTF-8 texts, or return None on conflict or binary input."""
    try:
        texts = [x.decode("utf-8") for x in (base, ours, theirs)]
    except UnicodeDecodeError:
        return None
    lines = [t.splitlines(keepends=True) for t in texts]
    if any(len(x) > MAX_LINES for x in lines):
        return None
    merged = merge_lines(*lines)
    return None if merged is None else "".join(merged).encode("utf-8")
