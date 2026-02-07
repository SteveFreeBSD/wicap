#!/usr/bin/env python3
"""Ensure runtime and bulky local artifacts are not tracked by git."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BLOCKED_EXACT = {
    "SOAK_ERRORS.txt",
    "processor.state.json",
    "dwell_state.json",
    ".soak_status.json",
    ".soak_pid",
    "tests/mock_cracks.pot",
    "tests/mock_hash.22000",
    "tests/triangulation_report.html",
}

BLOCKED_PREFIXES = (
    "captures/",
    "captures_verify/",
    "logs/",
    "logs_soak_",
    "nexus/wordlists/",
)

BLOCKED_SUFFIXES = (
    ".log",
    ".state.json",
)


def tracked_paths() -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [p for p in out.decode("utf-8", errors="ignore").split("\x00") if p]


def is_blocked(path: str) -> bool:
    if path in BLOCKED_EXACT:
        return True
    if any(path.startswith(prefix) for prefix in BLOCKED_PREFIXES):
        return True
    if path.endswith(BLOCKED_SUFFIXES):
        return True
    return False


def main() -> int:
    blocked = [p for p in tracked_paths() if is_blocked(p)]
    if blocked:
        print("Tracked artifacts violate repository hygiene:")
        for path in blocked:
            print(f"  - {path}")
        return 1
    print("Repository hygiene check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
