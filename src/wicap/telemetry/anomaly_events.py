"""WiCAP anomaly event contract normalization and append helpers."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ANOMALY_CONTRACT_VERSION = "wicap.anomaly.v1"
ANOMALY_CONTRACT_VERSION_V2 = "wicap.anomaly.v2"
ANOMALY_CONTRACT_VERSION_V3 = "wicap.anomaly.v3"


def _score_value(score: object, field: str, default: object = None) -> object:
    if isinstance(score, Mapping):
        return score.get(field, default)
    return getattr(score, field, default)


def _window_payload(score: object) -> dict[str, Any]:
    value = _score_value(score, "window", {})
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _to_iso_utc(epoch_ts: float) -> str:
    return datetime.fromtimestamp(epoch_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_wicap_anomaly_event(
    score: object,
    *,
    sensor_id: str = "wicap-local",
) -> dict[str, Any]:
    """Normalize one stream anomaly score into `wicap.anomaly.v1`."""
    window = _window_payload(score)
    window_start = _safe_float(window.get("window_start"), default=0.0)
    window_end = _safe_float(window.get("window_end"), default=0.0)
    if window_end <= 0.0:
        window_end = window_start
    if window_end <= 0.0:
        window_end = datetime.now(timezone.utc).timestamp()
    if window_start <= 0.0:
        window_start = max(0.0, window_end - 300.0)

    scope = str(window.get("scope", "global")).strip() or "global"
    bssid = str(window.get("bssid", "")).strip()
    ssid = str(window.get("ssid", "")).strip()
    category = str(_score_value(score, "attack_type", "anomaly_stream") or "anomaly_stream").strip() or "anomaly_stream"
    signature = f"{category}|{scope}|{bssid or 'global'}"

    feature_vector: dict[str, Any] = {}
    raw_features = window.get("features")
    if isinstance(raw_features, Mapping):
        for key, value in raw_features.items():
            feature_vector[str(key)] = _safe_float(value)

    evidence_event_ids: list[str] = []
    raw_evidence = window.get("evidence_event_ids")
    if isinstance(raw_evidence, Sequence) and not isinstance(raw_evidence, (str, bytes, bytearray)):
        for item in raw_evidence:
            text = str(item).strip()
            if text:
                evidence_event_ids.append(text)

    payload: dict[str, Any] = {
        "anomaly_contract_version": ANOMALY_CONTRACT_VERSION,
        "ts": _to_iso_utc(window_end),
        "category": category,
        "signature": signature,
        "sensor_id": str(sensor_id).strip() or "wicap-local",
        "scope": scope,
        "score": round(_safe_float(_score_value(score, "score", 0.0)), 6),
        "confidence": _safe_int(_score_value(score, "confidence", 0), default=0),
        "severity": _safe_int(_score_value(score, "severity", 1), default=1),
        "is_anomaly": bool(_score_value(score, "is_anomaly", False)),
        "baseline_ready": bool(_score_value(score, "baseline_ready", False)),
        "baseline_maturity": round(_safe_float(_score_value(score, "baseline_maturity", 0.0)), 6),
        "baseline_sample_count": _safe_int(_score_value(score, "baseline_sample_count", 0), default=0),
        "explanation": str(_score_value(score, "explanation", "") or "").strip(),
        "feature_window": {
            "window_start": round(window_start, 6),
            "window_end": round(window_end, 6),
            "event_count": _safe_int(window.get("event_count"), default=0),
        },
        "feature_vector": feature_vector,
        "evidence_event_ids": evidence_event_ids,
    }
    if bssid:
        payload["bssid"] = bssid
    if ssid:
        payload["ssid"] = ssid
    return payload


def normalize_wicap_anomaly_event_v2(
    score: object,
    *,
    sensor_id: str = "wicap-local",
) -> dict[str, Any]:
    """Normalize one stream anomaly score into `wicap.anomaly.v2`."""
    payload = normalize_wicap_anomaly_event(score, sensor_id=sensor_id)
    payload["anomaly_contract_version"] = ANOMALY_CONTRACT_VERSION_V2
    payload["primary_score"] = round(_safe_float(_score_value(score, "primary_score", payload.get("score", 0.0))), 6)

    raw_shadow = _score_value(score, "shadow_scores", {})
    shadow_scores: dict[str, float] = {}
    if isinstance(raw_shadow, Mapping):
        for key, value in raw_shadow.items():
            shadow_scores[str(key)] = round(_safe_float(value), 6)

    raw_votes = _score_value(score, "model_votes", {})
    model_votes: dict[str, bool] = {}
    if isinstance(raw_votes, Mapping):
        for key, value in raw_votes.items():
            model_votes[str(key)] = bool(value)

    score_components = _score_value(score, "score_components", {})
    if not isinstance(score_components, Mapping):
        score_components = {}

    drift_state = _score_value(score, "drift_state", {})
    if not isinstance(drift_state, Mapping):
        drift_state = {}

    if not shadow_scores:
        shadow_scores["primary"] = round(_safe_float(payload.get("score", 0.0)), 6)
    if not model_votes:
        model_votes["primary"] = bool(payload.get("is_anomaly", False))

    agreement = 0.0
    if model_votes:
        positives = sum(1 for value in model_votes.values() if bool(value))
        agreement = max(positives, len(model_votes) - positives) / float(len(model_votes))

    payload["shadow_scores"] = shadow_scores
    payload["model_votes"] = model_votes
    payload["model_ids"] = sorted(shadow_scores.keys())
    payload["vote_agreement"] = round(float(agreement), 6)
    payload["score_components"] = {
        str(key): round(_safe_float(value), 6)
        for key, value in dict(score_components).items()
    }
    payload["drift_state"] = {
        "status": str(drift_state.get("status", "stable")),
        "delta": round(_safe_float(drift_state.get("delta", 0.0)), 6),
        "long_mean": round(_safe_float(drift_state.get("long_mean", 0.0)), 6),
        "short_mean": round(_safe_float(drift_state.get("short_mean", 0.0)), 6),
        "sample_count": _safe_int(drift_state.get("sample_count", 0), default=0),
    }
    return payload


def normalize_wicap_anomaly_event_v3(
    score: object,
    *,
    sensor_id: str = "wicap-local",
) -> dict[str, Any]:
    """Normalize one stream anomaly score into `wicap.anomaly.v3`."""
    payload = normalize_wicap_anomaly_event_v2(score, sensor_id=sensor_id)
    payload["anomaly_contract_version"] = ANOMALY_CONTRACT_VERSION_V3
    primary_score = round(_safe_float(payload.get("primary_score", payload.get("score", 0.0))), 6)
    vote_agreement = round(_safe_float(payload.get("vote_agreement", 0.0)), 6)
    fusion_score = _safe_float(_score_value(score, "fusion_score", None), default=-1.0)
    if fusion_score < 0:
        fusion_score = (primary_score * 0.7) + (vote_agreement * 100.0 * 0.3)

    predictive_horizon = _safe_int(_score_value(score, "predictive_horizon_sec", 300), default=300)
    route_confidence = _safe_float(_score_value(score, "route_confidence", vote_agreement), default=vote_agreement)
    drift_state = payload.get("drift_state", {})
    drift_delta = _safe_float((drift_state or {}).get("delta", 0.0))
    drift_status = str((drift_state or {}).get("status", "stable")).strip().lower()
    guard_status = "guarded" if drift_status in {"drift", "triggered"} else "stable"
    bounded_delta = min(100.0, max(0.0, abs(drift_delta)))
    payload["fusion_score"] = round(float(max(0.0, min(100.0, fusion_score))), 6)
    payload["predictive_horizon_sec"] = int(max(60, predictive_horizon))
    payload["route_confidence"] = round(float(max(0.0, min(1.0, route_confidence))), 6)
    payload["drift_guard"] = {
        "status": guard_status,
        "bounded_delta": round(float(bounded_delta), 6),
        "rollback_ready": bool(guard_status != "stable"),
    }
    return payload


def append_anomaly_events(
    *,
    output_path: Path,
    scores: Sequence[object],
    sensor_id: str = "wicap-local",
    anomalies_only: bool = True,
) -> int:
    """Append normalized anomaly events to a JSONL artifact path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output_path.open("a", encoding="utf-8") as handle:
        for score in scores:
            payload = normalize_wicap_anomaly_event(score, sensor_id=sensor_id)
            if anomalies_only and not bool(payload.get("is_anomaly")):
                continue
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            written += 1
    return int(written)


def append_anomaly_events_v2(
    *,
    output_path: Path,
    scores: Sequence[object],
    sensor_id: str = "wicap-local",
    anomalies_only: bool = True,
) -> int:
    """Append normalized anomaly events to `wicap.anomaly.v2` JSONL artifact path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output_path.open("a", encoding="utf-8") as handle:
        for score in scores:
            payload = normalize_wicap_anomaly_event_v2(score, sensor_id=sensor_id)
            if anomalies_only and not bool(payload.get("is_anomaly")):
                continue
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            written += 1
    return int(written)


def append_anomaly_events_v3(
    *,
    output_path: Path,
    scores: Sequence[object],
    sensor_id: str = "wicap-local",
    anomalies_only: bool = True,
) -> int:
    """Append normalized anomaly events to `wicap.anomaly.v3` JSONL artifact path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output_path.open("a", encoding="utf-8") as handle:
        for score in scores:
            payload = normalize_wicap_anomaly_event_v3(score, sensor_id=sensor_id)
            if anomalies_only and not bool(payload.get("is_anomaly")):
                continue
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            written += 1
    return int(written)
