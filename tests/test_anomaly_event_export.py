from __future__ import annotations

import json
from pathlib import Path

from src.wicap.telemetry.anomaly_events import (
    ANOMALY_CONTRACT_VERSION,
    ANOMALY_CONTRACT_VERSION_V2,
    append_anomaly_events,
    append_anomaly_events_v2,
    normalize_wicap_anomaly_event,
    normalize_wicap_anomaly_event_v2,
)
from src.wicap.telemetry.prediction_events import (
    PREDICTION_CONTRACT_VERSION,
    append_prediction_events,
    build_prediction_events,
)


def _sample_anomaly(*, is_anomaly: bool) -> dict[str, object]:
    return {
        "window": {
            "scope": "global",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "lab-net",
            "window_start": 1768800000.0,
            "window_end": 1768800300.0,
            "event_count": 12,
            "features": {
                "deauth_rate": 4.2,
                "event_count": 30.0,
            },
            "evidence_event_ids": ["event-1", "event-2"],
        },
        "score": 82.4,
        "confidence": 78,
        "severity": 4,
        "explanation": "deauth_rate=4.2 (+2.0σ)",
        "is_anomaly": is_anomaly,
        "baseline_ready": True,
        "baseline_maturity": 0.92,
        "baseline_sample_count": 240,
        "attack_type": "anomaly_stream",
    }


def test_normalize_wicap_anomaly_event_emits_contract_shape() -> None:
    payload = normalize_wicap_anomaly_event(_sample_anomaly(is_anomaly=True), sensor_id="sensor-a")
    required = {
        "anomaly_contract_version",
        "ts",
        "category",
        "signature",
        "sensor_id",
        "scope",
        "score",
        "confidence",
        "severity",
        "is_anomaly",
        "feature_window",
        "feature_vector",
    }
    assert required.issubset(set(payload.keys()))
    assert payload["anomaly_contract_version"] == ANOMALY_CONTRACT_VERSION
    assert payload["sensor_id"] == "sensor-a"
    assert payload["category"] == "anomaly_stream"
    assert payload["feature_window"]["event_count"] == 12
    assert payload["feature_vector"]["deauth_rate"] == 4.2
    assert payload["evidence_event_ids"] == ["event-1", "event-2"]


def test_append_anomaly_events_writes_only_flagged_anomalies_by_default(tmp_path: Path) -> None:
    output_path = tmp_path / "wicap_anomaly_events.jsonl"
    scores = [_sample_anomaly(is_anomaly=False), _sample_anomaly(is_anomaly=True)]

    written = append_anomaly_events(output_path=output_path, scores=scores, sensor_id="sensor-z")
    assert int(written) == 1
    lines = [line for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["sensor_id"] == "sensor-z"
    assert bool(row["is_anomaly"]) is True


def test_normalize_wicap_anomaly_event_v2_emits_shadow_and_drift_fields() -> None:
    score = _sample_anomaly(is_anomaly=True)
    score["shadow_scores"] = {"mad_robust": 71.2, "ewma_drift": 18.5}
    score["model_votes"] = {"primary": True, "mad_robust": True, "ewma_drift": False}
    score["vote_agreement"] = 0.6667
    score["score_components"] = {"z_rms": 2.0, "baseline_maturity": 0.92}
    score["drift_state"] = {
        "status": "drift",
        "delta": 13.2,
        "long_mean": 40.0,
        "short_mean": 53.2,
        "sample_count": 64,
    }
    payload = normalize_wicap_anomaly_event_v2(score, sensor_id="sensor-b")
    assert payload["anomaly_contract_version"] == ANOMALY_CONTRACT_VERSION_V2
    assert float(payload["primary_score"]) == float(payload["score"])
    assert payload["shadow_scores"]["mad_robust"] == 71.2
    assert payload["drift_state"]["status"] == "drift"
    assert payload["model_votes"]["primary"] is True


def test_append_anomaly_events_v2_writes_jsonl_rows(tmp_path: Path) -> None:
    output_path = tmp_path / "wicap_anomaly_events_v2.jsonl"
    scores = [_sample_anomaly(is_anomaly=False), _sample_anomaly(is_anomaly=True)]
    written = append_anomaly_events_v2(output_path=output_path, scores=scores, sensor_id="sensor-v2")
    assert int(written) == 1
    rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["anomaly_contract_version"] == ANOMALY_CONTRACT_VERSION_V2


def test_build_prediction_events_and_append_jsonl(tmp_path: Path) -> None:
    scores = [_sample_anomaly(is_anomaly=True)]
    events = build_prediction_events(scores=scores, horizons_sec=[300, 1800], sensor_id="sensor-p")
    assert len(events) == 2
    assert {int(item["horizon_sec"]) for item in events} == {300, 1800}
    assert all(item["prediction_contract_version"] == PREDICTION_CONTRACT_VERSION for item in events)

    output_path = tmp_path / "wicap_predictions.jsonl"
    written = append_prediction_events(output_path=output_path, events=events)
    assert int(written) == 2
    rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 2
