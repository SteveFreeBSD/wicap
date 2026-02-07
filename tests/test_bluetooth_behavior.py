from datetime import datetime, timedelta

from app.services.bluetooth_behavior import build_bt_behavior_insight


def _base(start_offset_minutes: int = 0):
    start = datetime(2026, 2, 6, 12, 0, 0) + timedelta(minutes=start_offset_minutes)
    return start, start + timedelta(hours=2)


def test_behavior_insight_reports_steady_cadence():
    first_seen, last_seen = _base()
    timestamps = [first_seen + timedelta(seconds=2 * i) for i in range(1, 40)]
    insight = build_bt_behavior_insight(
        first_seen=first_seen,
        last_seen=last_seen,
        observation_count=160,
        is_randomized=False,
        timestamps=timestamps,
    )
    assert insight["behavior_label"] == "steady"
    assert insight["rotation_risk_score"] <= 25
    assert insight["interval_median_sec"] is not None


def test_behavior_insight_reports_bursty_private_activity():
    first_seen = datetime(2026, 2, 6, 12, 0, 0)
    last_seen = first_seen + timedelta(minutes=4)
    timestamps = [
        first_seen + timedelta(seconds=s)
        for s in (1, 2, 3, 120, 121, 250, 251)
    ]
    insight = build_bt_behavior_insight(
        first_seen=first_seen,
        last_seen=last_seen,
        observation_count=7,
        is_randomized=True,
        timestamps=timestamps,
    )
    assert insight["behavior_label"] in {"bursty", "intermittent"}
    assert insight["rotation_risk_score"] >= 60
    assert "private" in insight["behavior_summary"].lower() or "bursty" in insight["behavior_summary"].lower()


def test_behavior_insight_sparse_without_timing_data():
    first_seen = datetime(2026, 2, 6, 12, 0, 0)
    last_seen = first_seen + timedelta(minutes=2)
    insight = build_bt_behavior_insight(
        first_seen=first_seen,
        last_seen=last_seen,
        observation_count=2,
        is_randomized=False,
        timestamps=[],
    )
    assert insight["behavior_label"] == "sparse"
    assert insight["interval_median_sec"] is None
    assert insight["observation_rate_per_hour"] > 0
