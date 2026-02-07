#!/usr/bin/env python3
"""Validate local markdown links in docs and README."""

from __future__ import annotations

import re
from pathlib import Path

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def markdown_files(root: Path) -> list[Path]:
    files = [root / "README.md"]
    files.extend(sorted((root / "docs").rglob("*.md")))
    return [f for f in files if f.exists()]


def _normalize_target(raw_target: str) -> str | None:
    target = raw_target.strip().strip("<>").strip()
    if not target:
        return None
    if target.startswith("#"):
        return None
    if URI_SCHEME_RE.match(target):
        return None
    target = target.split("#", 1)[0].split("?", 1)[0]
    return target or None


def _resolve_target(doc_path: Path, target: str, root: Path) -> Path:
    if target.startswith("/"):
        return root / target.lstrip("/")
    return (doc_path.parent / target).resolve()


def check_links(root: Path) -> list[str]:
    failures: list[str] = []
    for doc in markdown_files(root):
        text = doc.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            for match in LINK_RE.finditer(line):
                raw_target = match.group(1)
                target = _normalize_target(raw_target)
                if not target:
                    continue
                resolved = _resolve_target(doc, target, root)
                if not resolved.exists():
                    rel_doc = doc.relative_to(root)
                    failures.append(
                        f"{rel_doc}:{line_no}: missing link target '{raw_target}' -> "
                        f"{resolved}"
                    )
    return failures


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failures = check_links(root)
    if failures:
        print("Broken local markdown links found:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("Docs link check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
