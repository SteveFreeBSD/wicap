"""Bluetooth timeline and recurrence analytics helpers."""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _normalize_dt(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value
    try:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None


def _intervals_seconds(timestamps: Iterable[datetime]) -> list[float]:
    valid = [ts for ts in timestamps if isinstance(ts, datetime)]
    valid.sort()
    if len(valid) < 2:
        return []
    intervals: list[float] = []
    for idx in range(1, len(valid)):
        delta = (valid[idx] - valid[idx - 1]).total_seconds()
        if delta > 0:
            intervals.append(delta)
    return intervals


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _bucket_start(ts: datetime, bucket_minutes: int) -> datetime:
    return ts.replace(
        minute=(ts.minute // bucket_minutes) * bucket_minutes,
        second=0,
        microsecond=0,
    )


def _recurrence_summary(label: str, *, handoffs: int, peer_ratio: float) -> str:
    if label == "rotation-handoff":
        return (
            f"Recurring primary-to-peer handoff windows detected ({handoffs}); "
            f"peer overlap ratio {peer_ratio:.2f} supports rotation analysis."
        )
    if label == "steady":
        return "Stable recurrence pattern with low cadence drift; useful for baseline tracking."
    if label == "intermittent":
        return "Periodic recurrence observed with moderate variance; monitor for shift events."
    if label == "bursty":
        return "Burst-dominant cadence with low recurrence stability; prioritize anomaly overlays."
    return "Insufficient cadence history for recurrence profiling."


def build_bt_recurrence_profile(
    *,
    behavior_label: str | None,
    observation_rate_per_hour: object,
    interval_median_sec: object,
    interval_jitter_sec: object,
    rotation_peer_count: object,
    is_randomized: bool,
) -> dict[str, Any]:
    """
    Build coarse recurrence fields for BLE list APIs and summary rows.

    This profile is intentionally lightweight and derived from already-computed
    behavior + rotation fields so it can run across large device lists.
    """
    label_raw = (behavior_label or "sparse").strip().lower()
    rate = max(0.0, _safe_float(observation_rate_per_hour, 0.0))
    interval_median = _safe_float(interval_median_sec, 0.0)
    interval_jitter = _safe_float(interval_jitter_sec, 0.0)
    peer_count = max(0, int(_safe_float(rotation_peer_count, 0.0)))

    score = 38
    if label_raw == "steady":
        score += 24
    elif label_raw == "intermittent":
        score += 10
    elif label_raw == "bursty":
        score -= 6
    else:
        score -= 16

    if interval_median > 0:
        jitter_ratio = interval_jitter / max(interval_median, 1.0)
        if jitter_ratio <= 0.6:
            score += 12
        elif jitter_ratio <= 1.2:
            score += 6
        else:
            score -= 10

    if rate >= 20.0:
        score += 8
    elif rate < 3.0:
        score -= 8

    if peer_count >= 1:
        score += min(12, peer_count * 4)
    if is_randomized:
        score -= 5

    score = max(0, min(100, int(round(score))))

    if peer_count >= 2 and label_raw in {"intermittent", "bursty"}:
        label = "rotation-handoff"
    elif label_raw == "sparse":
        label = "sparse"
    elif score >= 70:
        label = "steady"
    elif score >= 45:
        label = "intermittent"
    else:
        label = "bursty"

    handoff_count = max(0, peer_count - 1) if label == "rotation-handoff" else 0
    peer_ratio = 0.0
    if label == "rotation-handoff":
        peer_ratio = min(1.0, round(0.2 + (peer_count * 0.12), 2))

    return {
        "recurrence_label": label,
        "recurrence_score": score,
        "recurrence_summary": _recurrence_summary(
            label,
            handoffs=handoff_count,
            peer_ratio=peer_ratio,
        ),
        "recurrence_handoff_count": handoff_count,
        "recurrence_peer_presence_ratio": peer_ratio,
    }


def annotate_bt_recurrence(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate BLE list rows with recurrence summary fields."""
    for device in devices:
        recurrence = build_bt_recurrence_profile(
            behavior_label=device.get("behavior_label"),
            observation_rate_per_hour=device.get("observation_rate_per_hour"),
            interval_median_sec=device.get("interval_median_sec"),
            interval_jitter_sec=device.get("interval_jitter_sec"),
            rotation_peer_count=device.get("rotation_peer_count"),
            is_randomized=bool(device.get("is_randomized")),
        )
        device.update(recurrence)
    return devices


def build_bt_timeline_overlay(
    *,
    primary_addr: str,
    primary_timestamps: Iterable[datetime],
    peer_timestamps: dict[str, Iterable[datetime]],
    now: datetime | None = None,
    window_minutes: int = 180,
    bucket_minutes: int = 15,
) -> dict[str, Any]:
    """
    Build timeline overlays for behavior and address-rotation shift analysis.
    """
    window_minutes = max(30, int(window_minutes))
    bucket_minutes = max(5, int(bucket_minutes))

    primary = [ts for ts in (_normalize_dt(ts) for ts in primary_timestamps) if ts]
    primary.sort()

    peer_map: dict[str, list[datetime]] = {}
    for addr, timestamps in (peer_timestamps or {}).items():
        cleaned = [ts for ts in (_normalize_dt(ts) for ts in timestamps) if ts]
        cleaned.sort()
        if cleaned:
            peer_map[addr] = cleaned

    all_ts = primary[:]
    for timestamps in peer_map.values():
        all_ts.extend(timestamps)

    end_ts = _normalize_dt(now) or datetime.now(timezone.utc).replace(tzinfo=None)
    if all_ts:
        end_ts = max(all_ts)
    start_ts = end_ts - timedelta(minutes=window_minutes)

    window_primary = [ts for ts in primary if ts >= start_ts]
    window_peers = {
        addr: [ts for ts in timestamps if ts >= start_ts]
        for addr, timestamps in peer_map.items()
    }
    window_peers = {addr: timestamps for addr, timestamps in window_peers.items() if timestamps}

    bucket_cursor = _bucket_start(start_ts, bucket_minutes)
    bucket_end = _bucket_start(end_ts, bucket_minutes)
    step = timedelta(minutes=bucket_minutes)

    buckets: list[datetime] = []
    while bucket_cursor <= bucket_end:
        buckets.append(bucket_cursor)
        bucket_cursor += step
    if not buckets:
        buckets = [_bucket_start(end_ts, bucket_minutes)]

    primary_counts = dict.fromkeys(buckets, 0)
    peer_counts = dict.fromkeys(buckets, 0)
    peer_sets: dict[datetime, set[str]] = {bucket: set() for bucket in buckets}

    for ts in window_primary:
        bucket = _bucket_start(ts, bucket_minutes)
        if bucket in primary_counts:
            primary_counts[bucket] += 1

    for addr, timestamps in window_peers.items():
        for ts in timestamps:
            bucket = _bucket_start(ts, bucket_minutes)
            if bucket in peer_counts:
                peer_counts[bucket] += 1
                peer_sets[bucket].add(addr)

    timeline_buckets: list[dict[str, Any]] = []
    for bucket in buckets:
        p_count = primary_counts[bucket]
        peer_count = peer_counts[bucket]
        timeline_buckets.append(
            {
                "bucket_start": bucket.isoformat(),
                "primary_count": p_count,
                "peer_count": peer_count,
                "total_count": p_count + peer_count,
                "active_peer_count": len(peer_sets[bucket]),
            }
        )

    anomalies: list[dict[str, Any]] = []

    non_zero_totals = [row["total_count"] for row in timeline_buckets if row["total_count"] > 0]
    baseline = float(median(non_zero_totals)) if non_zero_totals else 0.0

    handoff_count = 0
    for idx, row in enumerate(timeline_buckets):
        timestamp = row["bucket_start"]
        total_count = row["total_count"]
        if baseline > 0 and total_count >= max(4, int(math.ceil(baseline * 2.5))):
            anomalies.append(
                {
                    "type": "activity_spike",
                    "severity": "medium",
                    "timestamp": timestamp,
                    "summary": (
                        f"Activity spike in {bucket_minutes}m bucket ({total_count} observations "
                        f"vs baseline {baseline:.1f})."
                    ),
                }
            )

        if idx == 0:
            continue
        prev = timeline_buckets[idx - 1]
        if prev["primary_count"] >= 2 and row["primary_count"] == 0 and row["peer_count"] >= 2:
            handoff_count += 1
            anomalies.append(
                {
                    "type": "rotation_handoff",
                    "severity": "high",
                    "timestamp": timestamp,
                    "summary": (
                        "Primary address dropped while correlated peer activity increased, "
                        "suggesting an address-rotation handoff window."
                    ),
                }
            )

    intervals = _intervals_seconds(window_primary)
    interval_median = median(intervals) if intervals else None
    interval_jitter = _stddev(intervals) if intervals else None
    if intervals and interval_median is not None:
        gap_threshold = max(180.0, float(interval_median) * 4.0)
        for idx, delta in enumerate(intervals):
            if delta >= gap_threshold:
                anomalies.append(
                    {
                        "type": "silence_gap",
                        "severity": "low",
                        "timestamp": window_primary[idx + 1].isoformat(),
                        "summary": (
                            f"Gap of {int(round(delta))}s detected before this observation "
                            "relative to prior cadence."
                        ),
                    }
                )

    active_buckets = [row for row in timeline_buckets if row["total_count"] > 0]
    peer_active = [row for row in active_buckets if row["peer_count"] > 0]
    peer_presence_ratio = (
        len(peer_active) / len(active_buckets)
        if active_buckets
        else 0.0
    )

    recurrence_score = 35
    if len(window_primary) >= 20:
        recurrence_score += 20
    elif len(window_primary) >= 8:
        recurrence_score += 12
    else:
        recurrence_score -= 12

    if interval_median is not None:
        jitter_ratio = 0.0
        if interval_jitter is not None:
            jitter_ratio = interval_jitter / max(float(interval_median), 1.0)
        if interval_median <= 15 and jitter_ratio < 1.0:
            recurrence_score += 18
        elif interval_median <= 60:
            recurrence_score += 8
        elif interval_median > 300:
            recurrence_score -= 10
        if jitter_ratio > 1.5:
            recurrence_score -= 6

    recurrence_score += min(18, handoff_count * 6)
    if peer_presence_ratio >= 0.3:
        recurrence_score += 8
    recurrence_score = max(0, min(100, int(round(recurrence_score))))

    if len(window_primary) < 3:
        recurrence_label = "sparse"
    elif handoff_count >= 2:
        recurrence_label = "rotation-handoff"
    elif recurrence_score >= 70:
        recurrence_label = "steady"
    elif recurrence_score >= 45:
        recurrence_label = "intermittent"
    else:
        recurrence_label = "bursty"

    return {
        "primary_addr": primary_addr,
        "bucket_minutes": bucket_minutes,
        "window_minutes": window_minutes,
        "timeline_buckets": timeline_buckets,
        "timeline_anomalies": anomalies[:10],
        "recurrence_label": recurrence_label,
        "recurrence_score": recurrence_score,
        "recurrence_summary": _recurrence_summary(
            recurrence_label,
            handoffs=handoff_count,
            peer_ratio=peer_presence_ratio,
        ),
        "recurrence_handoff_count": handoff_count,
        "recurrence_peer_presence_ratio": round(peer_presence_ratio, 2),
    }
