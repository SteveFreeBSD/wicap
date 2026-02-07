"""Bluetooth behavior analytics helpers for analyst-facing UI surfaces."""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import datetime
from statistics import median
from typing import Any


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _dwell_minutes(first_seen: datetime | None, last_seen: datetime | None) -> float:
    if not first_seen or not last_seen:
        return 0.0
    try:
        delta = (last_seen - first_seen).total_seconds()
    except Exception:
        return 0.0
    if delta <= 0:
        return 0.0
    return delta / 60.0


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


def _behavior_label(
    observation_count: int,
    dwell_minutes: float,
    interval_median_sec: float | None,
    interval_jitter_sec: float | None,
) -> str:
    if observation_count < 3 or dwell_minutes < 1:
        return "sparse"
    if interval_median_sec is None:
        if dwell_minutes >= 60 and observation_count >= 60:
            return "steady"
        if observation_count >= 20 and dwell_minutes <= 10:
            return "bursty"
        return "intermittent"

    mean_interval = max(interval_median_sec, 0.1)
    jitter_ratio = (interval_jitter_sec or 0.0) / mean_interval
    if interval_median_sec <= 5.0 and jitter_ratio < 0.5:
        return "steady"
    if jitter_ratio >= 1.1 or interval_median_sec > 60.0:
        return "bursty"
    return "intermittent"


def _behavior_summary(label: str, *, randomized: bool, rate: float, dwell_minutes: float) -> str:
    if label == "steady":
        if randomized:
            return "Steady BLE cadence with private/random addressing; strong proximity signal with weaker long-term identity stability."
        return "Steady BLE cadence supports repeat-presence tracking and stronger attribution confidence."
    if label == "bursty":
        return "Bursty BLE activity suggests event-driven broadcasts or transient sessions; correlate with timeline spikes."
    if label == "intermittent":
        return "Intermittent BLE cadence indicates periodic presence; useful for dwell trend analysis over longer windows."
    if randomized:
        return "Sparse/private BLE activity. Treat as transient until more samples accumulate."
    if rate <= 2.0 and dwell_minutes <= 5.0:
        return "Sparse BLE activity with low dwell. Attribution remains weak."
    return "Sparse BLE activity. Collect more observations before operational conclusions."


def build_bt_behavior_insight(
    *,
    first_seen: datetime | None,
    last_seen: datetime | None,
    observation_count: object,
    is_randomized: bool,
    timestamps: Iterable[datetime] | None = None,
) -> dict[str, Any]:
    """
    Build cadence and stability metrics used by BLE list and dossier surfaces.
    """
    obs = max(0, int(_safe_float(observation_count, 0.0)))
    dwell = _dwell_minutes(first_seen, last_seen)
    hours = max(dwell / 60.0, 1.0 / 60.0)
    rate_per_hour = obs / hours if obs > 0 else 0.0

    intervals = _intervals_seconds(timestamps or [])
    interval_median_sec = median(intervals) if intervals else None
    interval_jitter_sec = _stddev(intervals) if intervals else None

    label = _behavior_label(obs, dwell, interval_median_sec, interval_jitter_sec)

    # Rotation risk is an identity-stability metric, not a threat score.
    risk = 20
    if is_randomized:
        risk += 35
    if obs < 5:
        risk += 18
    elif obs >= 50:
        risk -= 8
    if dwell < 10:
        risk += 12
    elif dwell >= 120:
        risk -= 10
    if label == "steady" and not is_randomized:
        risk -= 8
    if label == "bursty":
        risk += 6
    risk = max(0, min(100, int(round(risk))))

    return {
        "behavior_label": label,
        "behavior_summary": _behavior_summary(
            label,
            randomized=is_randomized,
            rate=rate_per_hour,
            dwell_minutes=dwell,
        ),
        "dwell_minutes": round(dwell, 2),
        "observation_rate_per_hour": round(rate_per_hour, 2),
        "rotation_risk_score": risk,
        "interval_median_sec": round(float(interval_median_sec), 2) if interval_median_sec is not None else None,
        "interval_jitter_sec": round(float(interval_jitter_sec), 2) if interval_jitter_sec is not None else None,
    }
