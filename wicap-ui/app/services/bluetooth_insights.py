"""Bluetooth analyst-facing confidence and summary helpers."""

from __future__ import annotations

from typing import Any

_UNKNOWN_VENDOR_TOKENS = {
    "",
    "unknown",
    "n/a",
    "none",
}


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def is_randomized_bt_addr_type(addr_type: str | None) -> bool:
    """Return True when addr_type indicates private/randomized addressing."""
    if not addr_type:
        return False
    lowered = str(addr_type).strip().lower()
    if not lowered:
        return False
    return any(token in lowered for token in ("random", "private", "resolvable", "rpa", "nrpa"))


def _confidence_tier(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _summary_for_tier(
    tier: str,
    *,
    randomized: bool,
    observations: int,
    known_services: int,
) -> str:
    if tier == "high":
        return "High-confidence profile suitable for vendor attribution and repeat-presence tracking."
    if tier == "medium":
        if randomized:
            return "Moderate confidence: useful for proximity trends, but private/random addressing limits stable identity."
        return "Moderate confidence: enough evidence for tracking trends, but attribution is still partial."
    if randomized:
        return "Low confidence: sparse or private/random BLE activity. Treat as transient until more observations accumulate."
    if observations <= 2 and known_services == 0:
        return "Low confidence: single-burst or minimal activity with limited identifying fields."
    return "Low confidence: weak attribution signal. Prioritize additional capture time before conclusions."


def build_bt_device_insight(
    *,
    vendor: str | None,
    local_name: str | None,
    addr_type: str | None,
    observation_count: object,
    known_service_count: object,
    unknown_service_count: object = 0,
    has_manufacturer_hash: bool = False,
) -> dict[str, Any]:
    """
    Build confidence metadata for BLE UI cards/tables.

    Confidence reflects data quality for attribution/tracking, not threat severity.
    """
    observations = max(0, _safe_int(observation_count, 0))
    known_services = max(0, _safe_int(known_service_count, 0))
    unknown_services = max(0, _safe_int(unknown_service_count, 0))
    randomized = is_randomized_bt_addr_type(addr_type)

    score = 15
    highlights: list[str] = []

    if observations >= 100:
        score += 35
        highlights.append("Heavy observation history")
    elif observations >= 30:
        score += 28
        highlights.append("Strong observation history")
    elif observations >= 10:
        score += 22
        highlights.append("Consistent observation history")
    elif observations >= 3:
        score += 14
        highlights.append("Repeat observations present")
    elif observations > 0:
        score += 8

    vendor_key = (vendor or "").strip().lower()
    if vendor_key not in _UNKNOWN_VENDOR_TOKENS:
        score += 15
        highlights.append("Vendor attribution available")

    if local_name:
        score += 12
        highlights.append("Stable local name observed")

    if known_services >= 3:
        score += 12
        highlights.append("Multiple known services advertised")
    elif known_services >= 1:
        score += 8
        highlights.append("Known service advertised")

    if has_manufacturer_hash:
        score += 8
        highlights.append("Manufacturer payload fingerprint present")

    if randomized:
        score -= 18
        highlights.append("Private/random address reduces identity stability")
    elif addr_type and any(token in str(addr_type).lower() for token in ("public", "static")):
        score += 10
        highlights.append("Public/static address type")

    if known_services == 0 and unknown_services >= 3:
        score -= 6
        highlights.append("Only vendor-specific UUIDs observed")

    score = max(0, min(100, score))
    tier = _confidence_tier(score)

    return {
        "score": score,
        "tier": tier,
        "summary": _summary_for_tier(
            tier,
            randomized=randomized,
            observations=observations,
            known_services=known_services,
        ),
        "is_randomized": randomized,
        "highlights": highlights[:4],
    }
