from __future__ import annotations

import json
from pathlib import Path

from nexus.intel import intel_worker


class _FakeScorer:
    def __init__(self) -> None:
        self.persist_calls = 0

    def score_recent_windows(self, _now_ts: float):  # type: ignore[no-untyped-def]
        return [
            {
                "window": {
                    "scope": "global",
                    "window_start": 1768800000.0,
                    "window_end": 1768800300.0,
                    "event_count": 14,
                    "features": {"deauth_rate": 4.1},
                    "evidence_event_ids": ["event-1"],
                },
                "score": 81.2,
                "primary_score": 81.2,
                "confidence": 77,
                "severity": 4,
                "explanation": "deauth_rate drift",
                "is_anomaly": True,
                "baseline_ready": True,
                "baseline_maturity": 0.93,
                "baseline_sample_count": 120,
                "attack_type": "anomaly_stream",
                "shadow_scores": {"mad_robust": 75.0, "ewma_drift": 20.0},
                "model_votes": {"primary": True, "mad_robust": True, "ewma_drift": False},
                "vote_agreement": 0.6667,
                "score_components": {"z_rms": 2.4},
                "drift_state": {
                    "status": "drift",
                    "delta": 13.0,
                    "long_mean": 41.0,
                    "short_mean": 54.0,
                    "sample_count": 64,
                },
            }
        ]

    def persist_anomalies(self, _scores):  # type: ignore[no-untyped-def]
        self.persist_calls += 1
        return 0


def test_intel_worker_once_writes_v1_v2_v3_and_prediction_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captures = tmp_path / "captures"
    anomaly_v1 = captures / "wicap_anomaly_events.jsonl"
    anomaly_v2 = captures / "wicap_anomaly_events_v2.jsonl"
    anomaly_v3 = captures / "wicap_anomaly_events_v3.jsonl"
    prediction = captures / "wicap_predictions.jsonl"

    monkeypatch.setenv("WICAP_CAPTURES_DIR", str(captures))
    monkeypatch.setenv("WICAP_ANOMALY_EVENTS_PATH", str(anomaly_v1))
    monkeypatch.setenv("WICAP_ANOMALY_EVENTS_V2_PATH", str(anomaly_v2))
    monkeypatch.setenv("WICAP_ANOMALY_EVENTS_V3_PATH", str(anomaly_v3))
    monkeypatch.setenv("WICAP_PREDICTION_EVENTS_PATH", str(prediction))
    monkeypatch.setenv("WICAP_PREDICTION_HORIZONS_SEC", "300,1800")
    monkeypatch.setenv("WICAP_SENSOR_ID", "sensor-test")

    fake_scorer = _FakeScorer()
    monkeypatch.setattr(intel_worker, "build_feature_store", lambda _redis: object())
    monkeypatch.setattr(intel_worker, "build_baseline_updater", lambda _store, _redis: None)
    monkeypatch.setattr(intel_worker, "build_stream_scorer", lambda **_kwargs: fake_scorer)

    rc = intel_worker.run_intel_worker_loop(once=True, interval_seconds=0.5)
    assert rc == 0
    assert fake_scorer.persist_calls == 1

    assert anomaly_v1.exists()
    assert anomaly_v2.exists()
    assert anomaly_v3.exists()
    assert prediction.exists()

    row_v2 = json.loads(anomaly_v2.read_text(encoding="utf-8").splitlines()[0])
    assert row_v2["anomaly_contract_version"] == "wicap.anomaly.v2"
    assert "drift_state" in row_v2
    row_v3 = json.loads(anomaly_v3.read_text(encoding="utf-8").splitlines()[0])
    assert row_v3["anomaly_contract_version"] == "wicap.anomaly.v3"
    assert "fusion_score" in row_v3

    prediction_rows = [json.loads(line) for line in prediction.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert {int(item["horizon_sec"]) for item in prediction_rows} == {300, 1800}
    assert all(item["prediction_contract_version"] == "wicap.prediction.v1" for item in prediction_rows)
