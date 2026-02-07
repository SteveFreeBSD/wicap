"""Bluetooth text/label normalization helpers for UI presentation."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

_BT_SIG_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"
_CANONICAL_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    flags=re.IGNORECASE,
)
_SHORT_HEX_RE = re.compile(r"^(?:0x)?([0-9a-f]{4}|[0-9a-f]{8})$", flags=re.IGNORECASE)

# Common Bluetooth SIG 16-bit services (high-confidence set).
_GATT_SERVICE_NAMES: dict[str, str] = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180A": "Device Information",
    "180D": "Heart Rate",
    "180F": "Battery Service",
    "1810": "Blood Pressure",
    "1811": "Alert Notification",
    "1812": "Human Interface Device",
    "1816": "Cycling Speed and Cadence",
    "181A": "Environmental Sensing",
    "181C": "User Data",
    "181D": "Weight Scale",
    "181E": "Bond Management",
    "1826": "Fitness Machine",
}

# Common 16-bit member-assigned UUIDs used in advertising.
_MEMBER_SERVICE_NAMES: dict[str, str] = {
    "FEAA": "Eddystone",
    "FCD2": "Fast Pair",
}


def sanitize_bt_name(name: str | None, *, max_len: int = 64) -> str | None:
    """Return a UI-safe Bluetooth name or None if the value is unusable."""
    if name is None:
        return None

    text = unicodedata.normalize("NFKC", str(name))
    if not text:
        return None

    # Replace known decode artifacts and remove non-printable/control chars.
    text = text.replace("\ufffd", " ")
    cleaned_chars: list[str] = []
    for ch in text:
        if not ch.isprintable():
            cleaned_chars.append(" ")
            continue
        if unicodedata.category(ch).startswith("C"):
            cleaned_chars.append(" ")
            continue
        cleaned_chars.append(ch)

    cleaned = " ".join("".join(cleaned_chars).split())
    # Normalize to ASCII for stable rendering in operational dashboards.
    cleaned = (
        unicodedata.normalize("NFKD", cleaned)
        .encode("ascii", "ignore")
        .decode("ascii")
    )
    # Keep a narrow printable subset to avoid rendering junk symbols.
    cleaned = "".join(
        ch if (ch.isalnum() or ch in " []()-._'&+/") else " "
        for ch in cleaned
    )
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return None

    # Drop clearly non-actionable junk names.
    if len(cleaned) < 3:
        return None
    if re.search(r"(.)\1{6,}", cleaned):
        return None
    compact = cleaned.replace(" ", "")
    if re.fullmatch(r"[0-9A-Fa-f]{8,}", compact):
        return None
    alnum_count = sum(1 for ch in cleaned if ch.isalnum())
    if alnum_count < max(2, len(cleaned) // 3):
        return None
    punctuation_count = sum(1 for ch in cleaned if not ch.isalnum() and not ch.isspace())
    if punctuation_count > alnum_count:
        return None
    if re.fullmatch(r"[0-9A-Fa-f:\-]{6,}", cleaned):
        return None

    tokens = cleaned.split()
    if tokens:
        max_token_len = max(len(token) for token in tokens)
        avg_token_len = sum(len(token) for token in tokens) / len(tokens)
        short_tokens = sum(1 for token in tokens if len(token) <= 2)
        if max_token_len < 3:
            return None
        if len(tokens) >= 5 and max_token_len < 4:
            return None
        if len(tokens) >= 6 and avg_token_len < 2.5:
            return None
        if len(tokens) >= 5 and short_tokens / len(tokens) > 0.6:
            return None

    if len(cleaned) > max_len:
        cleaned = cleaned[: max(1, max_len - 3)].rstrip() + "..."
    return cleaned


def _canonicalize_uuid(raw_uuid: object) -> str | None:
    if raw_uuid is None:
        return None
    raw = str(raw_uuid).strip().lower()
    if not raw:
        return None

    if _CANONICAL_UUID_RE.match(raw):
        return raw

    short_match = _SHORT_HEX_RE.match(raw)
    if short_match:
        hex_part = short_match.group(1).lower()
        if len(hex_part) == 4:
            return f"0000{hex_part}{_BT_SIG_BASE_SUFFIX}"
        return f"{hex_part}{_BT_SIG_BASE_SUFFIX}"

    return raw


def _short_code_from_uuid(canonical_uuid: str) -> str | None:
    if not canonical_uuid.endswith(_BT_SIG_BASE_SUFFIX):
        return None
    head = canonical_uuid[:8]
    if len(head) != 8:
        return None
    if head.startswith("0000"):
        return head[4:].upper()
    return head.upper()


def format_bt_service_label(raw_uuid: object) -> str | None:
    """Convert a raw UUID into a concise human-readable label."""
    canonical = _canonicalize_uuid(raw_uuid)
    if not canonical:
        return None

    short_code = _short_code_from_uuid(canonical)
    if short_code:
        if len(short_code) == 4:
            display = f"0x{short_code}"
            name = _GATT_SERVICE_NAMES.get(short_code) or _MEMBER_SERVICE_NAMES.get(short_code)
            if name:
                return f"{name} ({display})"
            return None
        return None

    return None


def format_bt_service_labels(raw_services: Iterable[object] | None, *, include_unknown: bool = False) -> list[str]:
    """Normalize and dedupe raw UUID values into UI labels."""
    labels: list[str] = []
    seen: set[str] = set()
    unknown_seen: set[str] = set()
    for raw_service in raw_services or []:
        label = format_bt_service_label(raw_service)
        if label:
            if label in seen:
                continue
            seen.add(label)
            labels.append(label)
            continue

        if include_unknown:
            canonical = _canonicalize_uuid(raw_service)
            if not canonical or canonical in unknown_seen:
                continue
            unknown_seen.add(canonical)
            short_code = _short_code_from_uuid(canonical)
            if short_code:
                labels.append(f"UUID 0x{short_code}")
            elif len(canonical) > 20:
                labels.append(f"{canonical[:8]}...{canonical[-4:]}")
            else:
                labels.append(canonical)

    return labels


def count_unknown_bt_services(raw_services: Iterable[object] | None) -> int:
    """Count unique unknown/unmapped Bluetooth services."""
    unknown_seen: set[str] = set()
    for raw_service in raw_services or []:
        if format_bt_service_label(raw_service):
            continue
        canonical = _canonicalize_uuid(raw_service)
        if not canonical:
            continue
        unknown_seen.add(canonical)
    return len(unknown_seen)
