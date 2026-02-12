from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path for standalone pytest runs.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexus.path_resolver import resolve_pipal_command, resolve_wordlist_search_paths


def test_resolve_pipal_command_prefers_env_override(tmp_path: Path, monkeypatch) -> None:
    pipal = tmp_path / "tools" / "pipal.rb"
    pipal.parent.mkdir(parents=True, exist_ok=True)
    pipal.write_text("#!/usr/bin/env ruby\n", encoding="utf-8")

    monkeypatch.setenv("WICAP_PIPAL_PATH", str(pipal))
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert resolve_pipal_command() == ["ruby", str(pipal)]


def test_resolve_pipal_command_uses_path_binary(monkeypatch) -> None:
    monkeypatch.delenv("WICAP_PIPAL_PATH", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/pipal")
    assert resolve_pipal_command() == ["/usr/local/bin/pipal"]


def test_resolve_wordlist_search_paths_from_env(tmp_path: Path, monkeypatch) -> None:
    primary = tmp_path / "captures" / "wordlists"
    external = tmp_path / "external" / "lists"
    alt = tmp_path / "alt" / "lists"

    monkeypatch.setenv("WICAP_WORDLIST_SEARCH_PATHS", f"{external}:{alt}")
    paths = resolve_wordlist_search_paths(primary)
    assert paths == [primary, external, alt]
