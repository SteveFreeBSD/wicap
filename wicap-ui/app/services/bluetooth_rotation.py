"""Bluetooth address-rotation correlation helpers."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

_UNKNOWN_VENDOR_TOKENS = {"", "unknown", "n/a", "none"}


def _normalize_token(value: str | None) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().lower().split())


def build_rotation_fingerprint(
    *,
    vendor: str | None,
    local_name: str | None,
    manufacturer_data_hash: str | None,
    services: Iterable[str] | None,
) -> str | None:
    """
    Build a deterministic fingerprint for possible BLE address-rotation grouping.

    The fingerprint intentionally avoids using the address itself.
    """
    vendor_key = _normalize_token(vendor)
    if vendor_key in _UNKNOWN_VENDOR_TOKENS:
        vendor_key = ""

    name_key = _normalize_token(local_name)
    if len(name_key) < 3:
        name_key = ""

    hash_key = _normalize_token(manufacturer_data_hash)
    if len(hash_key) >= 8:
        hash_key = hash_key[:12]
    else:
        hash_key = ""

    service_tokens = sorted(
        _normalize_token(service)
        for service in (services or [])
        if _normalize_token(service)
    )
    service_key = "|".join(service_tokens[:3])

    strong_signals = sum(1 for token in (hash_key, name_key, service_key) if token)
    if not hash_key and strong_signals < 2:
        return None

    payload = "|".join((vendor_key, name_key, hash_key, service_key))
    digest = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()
    return digest[:12]


def annotate_rotation_clusters(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Annotate device rows with address-rotation correlation fields.

    Adds:
    - rotation_cluster_size
    - rotation_peer_count
    - rotation_suspected
    - rotation_correlation_score
    - rotation_summary
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        fingerprint = build_rotation_fingerprint(
            vendor=device.get("vendor"),
            local_name=device.get("name") or device.get("local_name"),
            manufacturer_data_hash=device.get("manufacturer_data_hash"),
            services=device.get("services"),
        )
        device["_rotation_fp"] = fingerprint
        if not fingerprint:
            continue
        groups.setdefault(fingerprint, []).append(device)

    for device in devices:
        fingerprint = device.get("_rotation_fp")
        members = groups.get(fingerprint, []) if fingerprint else []
        cluster_size = len(members) if members else 1
        peer_count = max(0, cluster_size - 1)
        randomized = bool(device.get("is_randomized"))
        confidence = int(device.get("confidence_score") or 0)

        suspected = peer_count >= 1 and (randomized or confidence < 80)
        score = 0
        if peer_count > 0:
            score = 35 + (peer_count * 18)
            if randomized:
                score += 20
            if confidence < 60:
                score += 10
            score = max(0, min(100, score))

        if peer_count == 0:
            summary = "No correlated alternate BLE addresses detected in the current analysis window."
        elif suspected:
            summary = (
                f"Possible BLE address rotation: {peer_count} correlated peer address"
                f"{'' if peer_count == 1 else 'es'} share a similar fingerprint."
            )
        else:
            summary = (
                f"Fingerprint overlap with {peer_count} peer address"
                f"{'' if peer_count == 1 else 'es'}, but rotation risk is currently low."
            )

        device["rotation_cluster_size"] = cluster_size
        device["rotation_peer_count"] = peer_count
        device["rotation_suspected"] = suspected
        device["rotation_correlation_score"] = score
        device["rotation_summary"] = summary
        device.pop("_rotation_fp", None)

    return devices
