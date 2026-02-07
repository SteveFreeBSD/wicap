import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nexus.intel.ghost_hunter import (  # noqa: E402
    FeatureWindow,
    GhostHunter,
    _seq_delta,
)


def test_seq_delta_wraparound():
    assert _seq_delta(4095, 1) == 2


def test_feature_extraction_counts():
    hunter = GhostHunter(config=MagicMock(), window_sec=60, min_events=1)
    events = [
        {
            "event_id": "a",
            "ts_epoch": 1.0,
            "event_type": "deauth",
            "channel": 1,
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "TestNet",
            "sa": "11:22:33:44:55:66",
            "seq_num": 10,
            "beacon_interval": 100,
            "assoc_request": False,
        },
        {
            "event_id": "b",
            "ts_epoch": 2.0,
            "event_type": "scored_event",
            "channel": 1,
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "TestNet",
            "sa": "22:33:44:55:66:77",
            "seq_num": 12,
            "beacon_interval": 110,
            "assoc_request": True,
        },
        {
            "event_id": "c",
            "ts_epoch": 3.0,
            "event_type": "deauth",
            "channel": 6,
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "TestNet",
            "sa": "11:22:33:44:55:66",
            "seq_num": 20,
            "beacon_interval": None,
            "assoc_request": False,
        },
        {
            "event_id": "d",
            "ts_epoch": 4.0,
            "event_type": "scored_event",
            "channel": 6,
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "TestNet",
            "sa": "11:22:33:44:55:66",
            "seq_num": None,
            "beacon_interval": None,
            "assoc_request": False,
        },
    ]

    windows = hunter._extract_feature_windows(events, 0.0, 60.0)
    assert len(windows) == 1
    fw = windows[0]
    assert fw.event_count == 4
    assert fw.features["unique_clients"] == 2.0
    assert fw.features["unique_ssids"] == 1.0
    assert fw.features["deauth_rate"] == 2.0 / 60.0
    assert fw.features["assoc_rate"] == 1.0 / 60.0
    assert fw.features["channel_count"] == 2.0
    assert fw.features["seq_jitter_avg"] == 5.0
    assert fw.features["seq_jitter_max"] == 8.0
    assert fw.features["beacon_interval_avg"] == 105.0
    assert fw.features["beacon_interval_jitter"] == 5.0


def test_anomaly_scoring_flags_outlier():
    pytest.importorskip("sklearn")
    hunter = GhostHunter(config=MagicMock(), window_sec=300, min_events=1)
    normals = []
    for i in range(10):
        normals.append(
            FeatureWindow(
                bssid=f"aa:bb:cc:dd:ee:{i:02x}",
                window_start=0.0,
                window_end=300.0,
                ssid="TestNet",
                event_count=100 + i,
                features={
                    "event_count": 100.0 + i,
                    "unique_clients": 5.0 + (i % 3),
                    "unique_ssids": 1.0,
                    "deauth_rate": 0.05 + (i * 0.001),
                    "assoc_rate": 0.02 + (i * 0.0005),
                    "channel_count": 1.0,
                    "seq_jitter_avg": 1.0,
                    "seq_jitter_max": 2.0,
                    "beacon_interval_avg": 100.0,
                    "beacon_interval_jitter": 1.0,
                },
                evidence_event_ids=[],
            )
        )

    bundle = hunter.train_from_feature_windows(normals)

    outlier = FeatureWindow(
        bssid="aa:bb:cc:dd:ee:ff",
        window_start=0.0,
        window_end=300.0,
        ssid="TestNet",
        event_count=2000,
        features={
            "event_count": 2000.0,
            "unique_clients": 250.0,
            "unique_ssids": 4.0,
            "deauth_rate": 5.0,
            "assoc_rate": 3.0,
            "channel_count": 6.0,
            "seq_jitter_avg": 50.0,
            "seq_jitter_max": 120.0,
            "beacon_interval_avg": 200.0,
            "beacon_interval_jitter": 60.0,
        },
        evidence_event_ids=[],
    )

    results = hunter.score_feature_windows([outlier], bundle)
    assert results[0].is_anomaly
    assert results[0].confidence >= 60
    assert "deauth_rate" in results[0].explanation
