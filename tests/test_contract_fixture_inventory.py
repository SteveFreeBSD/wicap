from __future__ import annotations

from pathlib import Path


_CONTRACT_DIR = Path(__file__).resolve().parents[1] / "ops" / "contracts"
_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "contracts"


def _contract_files() -> set[str]:
    return {path.name for path in _CONTRACT_DIR.glob("wicap.*.v1.json")}


def _fixture_files() -> set[str]:
    return {path.name for path in _FIXTURE_DIR.glob("wicap.*.v1.json")}


def test_contract_fixture_inventory_matches_contract_directory() -> None:
    assert _fixture_files() == _contract_files()
