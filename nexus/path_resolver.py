"""Runtime path resolvers for portable deployments."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from pathlib import Path

_DEFAULT_PIPAL_PATH = Path("/opt/pipal/pipal.rb")
_DEFAULT_WORDLIST_PATHS = (
    Path("/usr/share/wordlists"),
    Path("/opt/seclists/Passwords"),
)


def _env_map(env: Mapping[str, str] | None = None) -> Mapping[str, str]:
    return env if env is not None else os.environ


def resolve_pipal_command(env: Mapping[str, str] | None = None) -> list[str] | None:
    """Return an executable command list for Pipal, if available."""
    mapping = _env_map(env)
    explicit = mapping.get("WICAP_PIPAL_PATH", "").strip()
    if explicit:
        explicit_path = Path(explicit).expanduser()
        if explicit_path.exists():
            if explicit_path.suffix.lower() == ".rb":
                return ["ruby", str(explicit_path)]
            return [str(explicit_path)]

    on_path = shutil.which("pipal")
    if on_path:
        return [on_path]

    if _DEFAULT_PIPAL_PATH.exists():
        return ["ruby", str(_DEFAULT_PIPAL_PATH)]
    return None


def pipal_probe_description(env: Mapping[str, str] | None = None) -> str:
    """Human-readable lookup summary used in diagnostics."""
    mapping = _env_map(env)
    probes = ["PATH"]
    explicit = mapping.get("WICAP_PIPAL_PATH", "").strip()
    if explicit:
        probes.append(f"WICAP_PIPAL_PATH={explicit}")
    probes.append(str(_DEFAULT_PIPAL_PATH))
    return ", ".join(probes)


def resolve_wordlist_search_paths(
    primary: Path,
    env: Mapping[str, str] | None = None,
) -> list[Path]:
    """Resolve wordlist search paths from env with portable defaults."""
    mapping = _env_map(env)
    raw = mapping.get("WICAP_WORDLIST_SEARCH_PATHS", "").strip()

    paths: list[Path] = [Path(primary)]
    if raw:
        for token in raw.split(os.pathsep):
            value = token.strip()
            if not value:
                continue
            paths.append(Path(value).expanduser())
    else:
        paths.extend(_DEFAULT_WORDLIST_PATHS)

    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(resolved)
    return deduped
