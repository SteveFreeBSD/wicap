from __future__ import annotations

import json
from pathlib import Path

from src.wicap.telemetry.anomaly_events import (
    ANOMALY_CONTRACT_VERSION,
    append_anomaly_events,
    normalize_wicap_anomaly_event,
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

