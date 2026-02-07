import time

from nexus.intel.feature_engineering import FEATURE_NAMES, FeatureWindow, MemoryFeatureStore
from nexus.intel.feedback_calibration import CalibrationSnapshot, CalibrationStore, FeedbackMetrics
from nexus.intel.stream_baseline import BaselineSnapshot, BaselineStore
from nexus.intel.stream_scoring import StreamAnomalyScorer, score_window


def _baseline_snapshot(sample_count: int, min_windows: int, updated_at: float) -> BaselineSnapshot:
    means = dict.fromkeys(FEATURE_NAMES, 0.0)
    stds = dict.fromkeys(FEATURE_NAMES, 1.0)
    return BaselineSnapshot(
        scope="global",
        bssid=None,
        horizon_sec=3600,
        window_sec=300,
        min_windows=min_windows,
        sample_count=sample_count,
        updated_at=updated_at,
        ready=sample_count >= min_windows,
        feature_means=means,
        feature_stds=stds,
    )


def test_score_window_maturity_reduces_confidence():
    snapshot = _baseline_snapshot(sample_count=5, min_windows=10, updated_at=100.0)
    window = {
        "window_start": 0.0,
        "window_end": 300.0,
        "event_count": 100,
        "features": dict.fromkeys(FEATURE_NAMES, 3.0),
    }
    result = score_window(
        window,
        snapshot,
        score_scale=3.0,
        score_threshold=70.0,
        min_confidence=40,
        now_ts=120.0,
    )
    assert result.score >= 90.0
    assert result.baseline_ready is False
    assert result.confidence < result.score
    assert result.is_anomaly is False


def test_stream_scorer_scores_recent_windows(tmp_path):
    store = MemoryFeatureStore()
    updated_at = time.time()
    window = FeatureWindow(
        scope="global",
        window_start=updated_at - 300.0,
        window_end=updated_at,
        event_count=10,
        features=dict.fromkeys(FEATURE_NAMES, 10.0),
        bssid=None,
        ssid=None,
        evidence_event_ids=["evt-1"],
    )
    store.write_window(window)

    snapshot = _baseline_snapshot(sample_count=20, min_windows=10, updated_at=updated_at)
    baseline_store = BaselineStore(tmp_path)
    baseline_store.save(snapshot)

    scorer = StreamAnomalyScorer(
        store=store,
        baseline_store=baseline_store,
        connection_string="DRIVER={SQL Server};",
        score_threshold=50.0,
        score_scale=2.0,
        min_confidence=40,
    )
    results = scorer.score_recent_windows(now_ts=updated_at + 10.0)
    assert len(results) == 1
    result = results[0]
    assert result.is_anomaly
    assert result.severity >= 3


def test_stream_scorer_uses_calibration_threshold(tmp_path):
    store = MemoryFeatureStore()
    updated_at = time.time()
    window = FeatureWindow(
        scope="global",
        window_start=updated_at - 300.0,
        window_end=updated_at,
        event_count=5,
        features=dict.fromkeys(FEATURE_NAMES, 1.0),
        bssid=None,
        ssid=None,
        evidence_event_ids=["evt-2"],
    )
    store.write_window(window)

    baseline_store = BaselineStore(tmp_path / "baseline")
    baseline_store.save(_baseline_snapshot(sample_count=20, min_windows=10, updated_at=updated_at))

    calibration_store = CalibrationStore(tmp_path / "calibration")
    metrics = FeedbackMetrics(
        total_anomalies=10,
        feedback_total=10,
        confirmed=8,
        benign=1,
        noisy=1,
        precision=0.8,
        recall_proxy=0.8,
        coverage=1.0,
    )
    calibration_store.save(
        CalibrationSnapshot(
            attack_type="anomaly_stream",
            scope="global",
            bssid=None,
            since_hours=24,
            computed_at=updated_at,
            min_feedback=10,
            current_threshold=70.0,
            recommended_threshold=20.0,
            threshold_delta=-50.0,
            reason="increase_sensitivity",
            metrics=metrics,
        )
    )

    scorer = StreamAnomalyScorer(
        store=store,
        baseline_store=baseline_store,
        connection_string="DRIVER={SQL Server};",
        score_threshold=70.0,
        score_scale=3.0,
        min_confidence=10,
        calibration_store=calibration_store,
        calibration_refresh_sec=0,
    )
    results = scorer.score_recent_windows(now_ts=updated_at + 10.0)
    assert len(results) == 1
    assert results[0].is_anomaly
