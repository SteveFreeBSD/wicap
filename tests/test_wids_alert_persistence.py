import time

from src.wicap.core.processing.persistence import build_wids_alert_row


def test_build_wids_alert_row_basic():
    event = {
        "event_type": "wids_deauth_flood",
        "ts_epoch": 1700000000.0,
        "score": 40,
        "channel": 6,
        "keys": {
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "TestNet",
            "sa": "11:22:33:44:55:66",
            "da": "ff:ee:dd:cc:bb:aa",
        },
        "alert": {
            "title": "Deauth Flood",
            "description": "Burst detected",
            "event_count": 12,
            "severity": 4,
        },
    }
    row = build_wids_alert_row(event)
    assert row is not None
    assert row["alert_type"] == "deauth_flood"
    assert row["severity"] == 4
    assert row["event_count"] == 12
    assert row["title"] == "Deauth Flood"
    assert row["description"] == "Burst detected"
    assert row["alert_signature"] == "deauth_flood|aa:bb:cc:dd:ee:ff|TestNet|11:22:33:44:55:66|ff:ee:dd:cc:bb:aa|6"
    assert row["alert_id"] == build_wids_alert_row(event)["alert_id"]


def test_build_wids_alert_row_score_fallback():
    event = {
        "event_type": "wids_evil_twin",
        "ts_epoch": time.time(),
        "score": 25,
        "channel": 11,
        "keys": {"bssid": "aa:aa:aa:aa:aa:aa"},
    }
    row = build_wids_alert_row(event)
    assert row is not None
    assert row["severity"] == 2
    assert row["alert_type"] == "evil_twin"


def test_build_wids_alert_row_non_wids():
    assert build_wids_alert_row({"event_type": "new_ssid"}) is None


def test_build_wids_alert_row_clips_and_coerces():
    event = {
        "event_type": "wids_" + ("x" * 120),
        "ts_epoch": "not-a-number",
        "score": "bad",
        "channel": "NaN",
        "keys": {
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "S" * 1000,
            "sa": "11:22:33:44:55:66",
            "da": "ff:ee:dd:cc:bb:aa",
        },
        "alert": {
            "title": "T" * 500,
            "description": "D" * 2000,
            "event_count": "oops",
            "severity": "oops",
        },
    }

    row = build_wids_alert_row(event)
    assert row is not None
    assert len(row["alert_type"]) <= 50
    assert len(row["title"]) == 200
    assert len(row["description"]) == 500
    assert len(row["ssid"]) == 64
    assert len(row["alert_signature"]) <= 256
    assert row["channel"] == 0
    assert row["event_count"] == 1
    assert row["severity"] == 1
