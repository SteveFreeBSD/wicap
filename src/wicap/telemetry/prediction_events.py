"""Prediction event contract helpers for proactive anomaly risk forecasts."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PREDICTION_CONTRACT_VERSION = "wicap.prediction.v1"
_DEFAULT_HORIZONS = (300, 1800)


def _score_value(score: object, field: str, default: object = None) -> object:
    if isinstance(score, Mapping):
        return score.get(field, default)
    return getattr(score, field, default)


def _window_payload(score: object) -> dict[str, Any]:
    window = _score_value(score, "window", {})
    if isinstance(window, Mapping):
        return dict(window)
    return {}


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _iso_utc(ts: float | None = None) -> str:
    value = float(ts) if ts is not None else datetime.now(timezone.utc).timestamp()
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _score_components(score: object) -> dict[str, float]:
    raw = _score_value(score, "score_components", {})
    if not isinstance(raw, Mapping):
        return {}
    return {str(key): round(_safe_float(value), 6) for key, value in raw.items()}


def _confidence_band(center: float, confidence: int) -> dict[str, float]:
    # Lower confidence widens prediction band.
    spread = max(5.0, (100.0 - max(0, min(100, int(confidence)))) * 0.15)
    return {
        "low": round(max(0.0, center - spread), 4),
        "high": round(min(100.0, center + spread), 4),
    }


def _top_contributors(score: object) -> list[dict[str, Any]]:
    components = _score_components(score)
    if components:
        ranked = sorted(components.items(), key=lambda item: abs(float(item[1])), reverse=True)[:5]
        return [{"name": name, "weight": round(float(value), 6)} for name, value in ranked]

    window = _window_payload(score)
    features = window.get("features", {})
    if isinstance(features, Mapping):
        ranked = sorted(
            ((str(name), _safe_float(value)) for name, value in features.items()),
            key=lambda item: abs(float(item[1])),
            reverse=True,
        )[:5]
        return [{"name": name, "weight": round(float(value), 6)} for name, value in ranked]
    return []


def _evidence_refs(score: object) -> list[dict[str, Any]]:
    window = _window_payload(score)
    refs = []
    evidence = window.get("evidence_event_ids")
    if isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes, bytearray)):
        for item in evidence:
            text = str(item).strip()
            if text:
                refs.append({"kind": "event_id", "value": text})
    return refs


def normalize_prediction_event(
    score: object,
    *,
    horizon_sec: int,
    sensor_id: str = "wicap-local",
) -> dict[str, Any]:
    """Normalize one risk forecast into `wicap.prediction.v1`."""
    window = _window_payload(score)
    category = str(_score_value(score, "attack_type", "anomaly_stream") or "anomaly_stream").strip() or "anomaly_stream"
    scope = str(window.get("scope", "global")).strip() or "global"
    bssid = str(window.get("bssid", "")).strip()
    signature = f"prediction|{category}|{scope}|{bssid or 'global'}|{int(horizon_sec)}"
    score_value = _safe_float(_score_value(score, "score", 0.0))
    confidence = _safe_int(_score_value(score, "confidence", 0))
    horizon_factor = 1.0 if int(horizon_sec) <= 300 else 0.9
    risk_score = max(0.0, min(100.0, score_value * horizon_factor))
    ts_value = _safe_float(window.get("window_end"), default=0.0)
    if ts_value <= 0:
        ts_value = datetime.now(timezone.utc).timestamp()

    payload: dict[str, Any] = {
        "prediction_contract_version": PREDICTION_CONTRACT_VERSION,
        "ts": _iso_utc(ts_value),
        "sensor_id": str(sensor_id).strip() or "wicap-local",
        "scope": scope,
        "category": category,
        "signature": signature,
        "risk_score": round(risk_score, 6),
        "horizon_sec": int(horizon_sec),
        "top_contributors": _top_contributors(score),
        "confidence_band": _confidence_band(risk_score, confidence),
        "evidence_refs": _evidence_refs(score),
        "summary": str(_score_value(score, "explanation", "") or "").strip(),
    }
    return payload


def build_prediction_events(
    *,
    scores: Sequence[object],
    horizons_sec: Sequence[int] | None = None,
    sensor_id: str = "wicap-local",
) -> list[dict[str, Any]]:
    """Build prediction contract events from a sequence of anomaly scores."""
    if not scores:
        return []
    horizons = [int(value) for value in (horizons_sec or _DEFAULT_HORIZONS) if int(value) > 0]
    if not horizons:
        horizons = list(_DEFAULT_HORIZONS)
    latest = scores[-1]
    return [
        normalize_prediction_event(
            latest,
            horizon_sec=int(horizon),
            sensor_id=sensor_id,
        )
        for horizon in horizons
    ]


def append_prediction_events(*, output_path: Path, events: Sequence[Mapping[str, Any]]) -> int:
    """Append prediction contract events to JSONL output path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output_path.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(dict(event), separators=(",", ":")) + "\n")
            written += 1
    return int(written)
