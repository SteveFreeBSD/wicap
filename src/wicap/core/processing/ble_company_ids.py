"""
Bluetooth Company ID lookup helpers.

Supports a small built-in mapping and an optional external override file.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

_CACHE: dict[str, str] | None = None

DEFAULT_COMPANY_IDS: dict[str, str] = {
    "0006": "Microsoft",
    "000D": "Texas Instruments",
    "001D": "Cambridge Silicon Radio",
    "004C": "Apple",
    "0059": "Nordic Semiconductor",
    "0075": "Samsung Electronics",
    "0087": "Garmin",
    "00E0": "Google",
    "0131": "Sonos",
    "015D": "Fitbit",
    "0171": "Logitech",
}


def normalize_company_id(value: str | None) -> str | None:
    """Normalize a company ID to 0xXXXX (uppercase)."""
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    token = value.split(",")[0].strip()
    token = token.replace("(", "").replace(")", "")
    if token.lower().startswith("0x"):
        token = token[2:]
        base = 16
    else:
        base = 16 if any(c in token.lower() for c in "abcdef") else 10
    try:
        num = int(token, base)
    except ValueError:
        return None
    return f"0x{num:04X}"


def _load_external_map(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return {str(k).upper().replace("0X", ""): str(v) for k, v in data.items()}
    mapping: dict[str, str] = {}
    with path.open(newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row or len(row) < 2:
                continue
            key = normalize_company_id(row[0])
            if key:
                mapping[key.replace("0x", "")] = row[1].strip()
    return mapping


def _load_map() -> dict[str, str]:
    path = os.getenv("WICAP_BT_COMPANY_IDS_PATH")
    if path:
        try:
            external = _load_external_map(Path(path))
            if external:
                return external
        except Exception:
            pass
    try:
        repo_root = Path(__file__).resolve().parents[4]
        default_path = repo_root / "vendor" / "bluetooth" / "company_ids.json"
        if default_path.exists():
            external = _load_external_map(default_path)
            if external:
                return external
    except Exception:
        pass
    return {k.upper(): v for k, v in DEFAULT_COMPANY_IDS.items()}


def lookup_company(value: str | None) -> str | None:
    """Return company name for a company ID value."""
    global _CACHE
    if _CACHE is None:
        _CACHE = _load_map()
    normalized = normalize_company_id(value)
    if not normalized:
        return None
    key = normalized.replace("0x", "")
    return _CACHE.get(key.upper())
