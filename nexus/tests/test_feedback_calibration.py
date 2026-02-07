from nexus.intel.feedback_calibration import (
    CalibrationSnapshot,
    CalibrationStore,
    FeedbackMetrics,
    compute_metrics,
    recommend_threshold,
)


def test_compute_metrics_precision_and_recall():
    metrics = compute_metrics(
        total_anomalies=10,
        feedback_counts={"confirmed": 4, "benign": 3, "noisy": 1},
    )
    assert metrics.feedback_total == 8
    assert metrics.precision == 0.5
    assert metrics.recall_proxy == 0.4
    assert metrics.coverage == 0.8


def test_recommend_threshold_increases_on_benign_rate():
    metrics = FeedbackMetrics(
        total_anomalies=20,
        feedback_total=10,
        confirmed=2,
        benign=6,
        noisy=2,
        precision=0.2,
        recall_proxy=0.1,
        coverage=0.5,
    )
    recommended, delta, reason = recommend_threshold(70.0, metrics, min_feedback=5, delta_step=5.0)
    assert delta > 0
    assert recommended > 70.0
    assert reason.startswith("reduce_false_positives")


def test_calibration_store_roundtrip(tmp_path):
    metrics = FeedbackMetrics(
        total_anomalies=5,
        feedback_total=5,
        confirmed=4,
        benign=1,
        noisy=0,
        precision=0.8,
        recall_proxy=0.8,
        coverage=1.0,
    )
    snapshot = CalibrationSnapshot(
        attack_type="anomaly_stream",
        scope="global",
        bssid=None,
        since_hours=24,
        computed_at=123.0,
        min_feedback=10,
        current_threshold=70.0,
        recommended_threshold=65.0,
        threshold_delta=-5.0,
        reason="increase_sensitivity",
        metrics=metrics,
    )
    store = CalibrationStore(tmp_path)
    store.save(snapshot)
    loaded = store.load("anomaly_stream", "global", None)
    assert loaded is not None
    assert loaded.recommended_threshold == 65.0
    assert loaded.metrics.confirmed == 4
