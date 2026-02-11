import math

from nexus.intel.feature_engineering import (
    FeatureWindow,
    FileFeatureStore,
    MemoryFeatureStore,
    MultiScaleFeatureEngineer,
    StreamingFeatureEngineer,
    build_feature_engineer,
)


def _event(ts, event_type, bssid, sa, channel, seq_num, beacon_interval, assoc_request=False):
    return {
        "event_id": f"{event_type}-{ts}",
        "ts_epoch": ts,
        "event_type": event_type,
        "channel": channel,
        "keys": {
            "bssid": bssid,
            "ssid": "TestNet",
            "sa": sa,
        },
        "frame": {
            "seq_num": seq_num,
            "beacon_interval": beacon_interval,
            "assoc_request": assoc_request,
        },
    }


def test_stream_feature_window_rollover():
    store = MemoryFeatureStore()
    engineer = StreamingFeatureEngineer(store, window_sec=60, min_events=1)

    events = [
        _event(100.0, "deauth", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1, 10, 100),
        _event(110.0, "association", "aa:bb:cc:dd:ee:ff", "22:33:44:55:66:77", 1, 20, 110, True),
        _event(170.0, "scored_event", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 6, 30, 100),
    ]

    for event in events:
        engineer.ingest_event(event)
    engineer.flush_all()

    windows = store.export_windows(0, 1000)
    # Two windows * two scopes (global + bssid)
    assert len(windows) == 4

    bssid_window = next(
        w for w in windows if w["scope"] == "bssid" and w["window_start"] == 60.0
    )
    features = bssid_window["features"]
    assert features["event_count"] == 2.0
    assert features["unique_clients"] == 2.0
    assert math.isclose(features["deauth_rate"], 1.0 / 60.0, rel_tol=1e-6)
    assert math.isclose(features["assoc_rate"], 1.0 / 60.0, rel_tol=1e-6)
    assert features["channel_count"] == 1.0
    assert features["channel_top_ratio"] == 1.0
    assert features["seq_jitter_avg"] == 10.0
    assert features["seq_jitter_max"] == 10.0
    assert features["beacon_interval_avg"] == 105.0
    assert features["beacon_interval_jitter"] == 5.0
    assert -1.0 <= features["hour_sin"] <= 1.0
    assert -1.0 <= features["hour_cos"] <= 1.0


def test_file_feature_store_export(tmp_path):
    store = FileFeatureStore(tmp_path, retention_sec=0)
    window = FeatureWindow(
        scope="global",
        window_start=100.0,
        window_end=160.0,
        event_count=2,
        features={"event_count": 2.0},
        bssid=None,
        ssid=None,
        evidence_event_ids=[],
    )
    store.write_window(window)

    results = store.export_windows(0, 200)
    assert len(results) == 1
    assert results[0]["window_start"] == 100.0


def test_multiscale_feature_engineer_fans_out_to_sidecars() -> None:
    primary_store = MemoryFeatureStore()
    sidecar_store = MemoryFeatureStore()
    primary = StreamingFeatureEngineer(primary_store, window_sec=300, min_events=1)
    sidecar = StreamingFeatureEngineer(sidecar_store, window_sec=60, min_events=1)
    multi = MultiScaleFeatureEngineer(primary=primary, sidecars=[sidecar])

    event = _event(100.0, "deauth", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1, 10, 100)
    multi.ingest_event(event)
    multi.flush_all()

    assert multi.window_sec == 300
    assert multi.window_secs == (60, 300)
    assert len(primary_store.export_windows(0, 1000)) == 2
    assert len(sidecar_store.export_windows(0, 1000)) == 2


def test_build_feature_engineer_enables_default_30_60_300_sidecars(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WICAP_FEATURE_STREAM_ENABLED", "true")
    monkeypatch.setenv("WICAP_FEATURE_STORE", "memory")
    monkeypatch.setenv("WICAP_FEATURE_MIN_EVENTS", "1")
    monkeypatch.setenv("WICAP_FEATURE_STORE_PATH", str(tmp_path))
    monkeypatch.delenv("WICAP_FEATURE_WINDOWS_SEC", raising=False)
    monkeypatch.delenv("WICAP_FEATURE_WINDOW_SEC", raising=False)

    engineer = build_feature_engineer(redis_url=None)
    assert engineer is not None
    window_secs = getattr(engineer, "window_secs", ())
    assert window_secs == (30, 60, 300)
