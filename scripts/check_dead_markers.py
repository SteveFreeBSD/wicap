#!/usr/bin/env python3
"""Block explicit dead/legacy markers from committed sources."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BANNED_PATTERNS = [
    re.compile(r"\bREMOVE_BEFORE_COMMIT\b"),
    re.compile(r"\bDEAD_CODE\b"),
    re.compile(r"\bLEGACY_FALLBACK\b"),
    re.compile(r"\bTEMP_HACK\b"),
    re.compile(r"\bWIP_ONLY\b"),
]

TEXT_SUFFIXES = {
    ".py",
    ".sh",
    ".md",
    ".yml",
    ".yaml",
    ".ini",
    ".toml",
    ".sql",
    ".js",
    ".ts",
    ".css",
    ".html",
}

EXCLUDED_PREFIXES = (
    "vendor/",
    "wicap-ui/vendor/",
    "nexus/wordlists/",
    "captures/",
    "captures_verify/",
)


def git_tracked_files() -> list[Path]:
    out = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
    )
    paths = [Path(p) for p in out.decode("utf-8", errors="ignore").split("\x00") if p]
    return paths


def should_scan(path: Path) -> bool:
    posix = path.as_posix()
    if any(posix.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return False
    return path.suffix.lower() in TEXT_SUFFIXES


def main() -> int:
    violations: list[str] = []
    for rel_path in git_tracked_files():
        if not should_scan(rel_path):
            continue
        abs_path = ROOT / rel_path
        if not abs_path.exists():
            # In a dirty worktree, tracked paths may already be deleted.
            continue
        text = abs_path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in BANNED_PATTERNS:
                if pattern.search(line):
                    violations.append(
                        f"{rel_path}:{line_no}: matched '{pattern.pattern}'"
                    )
    if violations:
        print("Dead/legacy markers found:")
        for violation in violations:
            print(f"  - {violation}")
        return 1
    print("Dead/legacy marker check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
