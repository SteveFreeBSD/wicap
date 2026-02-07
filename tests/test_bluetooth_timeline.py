from datetime import datetime, timedelta

from app.services.bluetooth_timeline import (
    annotate_bt_recurrence,
    build_bt_recurrence_profile,
    build_bt_timeline_overlay,
)


def test_build_bt_recurrence_profile_rotation_handoff_candidate():
    profile = build_bt_recurrence_profile(
        behavior_label="intermittent",
        observation_rate_per_hour=12.0,
        interval_median_sec=30.0,
        interval_jitter_sec=12.0,
        rotation_peer_count=3,
        is_randomized=True,
    )
    assert profile["recurrence_label"] == "rotation-handoff"
    assert profile["recurrence_score"] >= 45
    assert profile["recurrence_handoff_count"] >= 1


def test_build_bt_timeline_overlay_detects_rotation_handoffs():
    start = datetime(2026, 2, 6, 12, 0, 0)
    primary = [
        start + timedelta(minutes=1),
        start + timedelta(minutes=2),
        start + timedelta(minutes=31),
        start + timedelta(minutes=32),
    ]
    peers = {
        "bb:bb:bb:bb:bb:01": [
            start + timedelta(minutes=16),
            start + timedelta(minutes=17),
            start + timedelta(minutes=46),
            start + timedelta(minutes=47),
        ]
    }
    overlay = build_bt_timeline_overlay(
        primary_addr="aa:aa:aa:aa:aa:aa",
        primary_timestamps=primary,
        peer_timestamps=peers,
        now=start + timedelta(minutes=60),
        window_minutes=90,
        bucket_minutes=15,
    )
    assert overlay["recurrence_handoff_count"] >= 2
    assert overlay["recurrence_label"] == "rotation-handoff"
    assert any(item["type"] == "rotation_handoff" for item in overlay["timeline_anomalies"])


def test_annotate_bt_recurrence_adds_contract_fields():
    rows = [
        {
            "behavior_label": "steady",
            "observation_rate_per_hour": 24.0,
            "interval_median_sec": 8.0,
            "interval_jitter_sec": 2.0,
            "rotation_peer_count": 0,
            "is_randomized": False,
        }
    ]
    annotate_bt_recurrence(rows)
    row = rows[0]
    assert row["recurrence_label"] in {"steady", "intermittent"}
    assert "recurrence_score" in row
    assert "recurrence_summary" in row


def test_build_bt_timeline_overlay_sparse_defaults():
    ts = datetime(2026, 2, 6, 12, 0, 0)
    overlay = build_bt_timeline_overlay(
        primary_addr="aa:bb:cc:dd:ee:ff",
        primary_timestamps=[ts],
        peer_timestamps={},
        now=ts + timedelta(minutes=30),
        window_minutes=60,
        bucket_minutes=15,
    )
    assert overlay["recurrence_label"] == "sparse"
    assert overlay["timeline_buckets"]
