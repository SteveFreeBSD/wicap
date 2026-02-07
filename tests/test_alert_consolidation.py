from datetime import datetime, timezone

from app.services.alert_consolidation import (  # noqa: E402
    consolidate_alerts,
    filter_suppressed,
    load_suppression_rules,
)


def test_consolidate_prefers_ml_over_rule():
    ml_alerts = [
        {
            "id": "atk-1",
            "source": "attack_timeline",
            "alert_type": "anomaly_stream",
            "confidence": 90,
            "timestamp": 1000.0,
            "bssid": "aa:bb:cc:dd:ee:ff",
        }
    ]
    rule_alerts = [
        {
            "id": "wids-1",
            "source": "curated_events",
            "alert_type": "deauth_flood",
            "timestamp": 1050.0,
            "bssid": "aa:bb:cc:dd:ee:ff",
        }
    ]
    merged = consolidate_alerts(
        ml_alerts,
        rule_alerts,
        confidence_min=80,
        window_sec=300,
        enabled=True,
    )
    assert len(merged) == 1
    assert merged[0]["source"] == "attack_timeline"


def test_consolidate_keeps_rule_when_no_high_confidence():
    ml_alerts = [
        {
            "id": "atk-2",
            "source": "attack_timeline",
            "alert_type": "anomaly_stream",
            "confidence": 40,
            "timestamp": 2000.0,
            "bssid": "aa:bb:cc:dd:ee:ff",
        }
    ]
    rule_alerts = [
        {
            "id": "wids-2",
            "source": "curated_events",
            "alert_type": "deauth_flood",
            "timestamp": 2050.0,
            "bssid": "aa:bb:cc:dd:ee:ff",
        }
    ]
    merged = consolidate_alerts(
        ml_alerts,
        rule_alerts,
        confidence_min=80,
        window_sec=300,
        enabled=True,
    )
    assert len(merged) == 2


def test_filter_suppressed_matches_time_window(tmp_path):
    rule_path = tmp_path / "suppress.json"
    rule_path.write_text(
        """
        [
          {
            "id": "microwave",
            "alert_type": "deauth_flood",
            "start_hour": 12,
            "end_hour": 14
          }
        ]
        """.strip()
    )
    rules = load_suppression_rules(str(rule_path), cache_sec=0)
    noon = datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc).timestamp()
    alerts = [
        {
            "id": "wids-3",
            "source": "curated_events",
            "alert_type": "deauth_flood",
            "timestamp": noon,
        }
    ]
    filtered, suppressed = filter_suppressed(alerts, rules, enabled=True, now_ts=noon)
    assert filtered == []
    assert suppressed == 1
