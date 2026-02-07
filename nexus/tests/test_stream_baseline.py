from nexus.intel.feature_engineering import FeatureWindow, MemoryFeatureStore
from nexus.intel.stream_baseline import BaselineStore, BaselineUpdater


def _window(end_ts: float, count: int) -> FeatureWindow:
    return FeatureWindow(
        scope="global",
        window_start=end_ts - 60.0,
        window_end=end_ts,
        event_count=count,
        features={"event_count": float(count)},
    )


def test_baseline_refresh_cold_start(tmp_path):
    store = MemoryFeatureStore()
    baseline_store = BaselineStore(tmp_path)
    updater = BaselineUpdater(
        store=store,
        baseline_store=baseline_store,
        horizon_sec=3600,
        min_windows=3,
        refresh_sec=0,
        window_sec=60,
    )

    store.write_window(_window(100.0, 5))
    snapshot = updater.refresh(200.0)
    assert snapshot is not None
    assert snapshot.ready is False
    assert snapshot.sample_count == 1

    loaded = baseline_store.load("global", None)
    assert loaded is not None
    assert loaded.ready is False


def test_baseline_refresh_ready(tmp_path):
    store = MemoryFeatureStore()
    baseline_store = BaselineStore(tmp_path)
    updater = BaselineUpdater(
        store=store,
        baseline_store=baseline_store,
        horizon_sec=3600,
        min_windows=2,
        refresh_sec=0,
        window_sec=60,
    )

    store.write_window(_window(100.0, 5))
    store.write_window(_window(160.0, 15))
    snapshot = updater.refresh(200.0)
    assert snapshot is not None
    assert snapshot.ready is True
    assert snapshot.sample_count == 2
    assert abs(snapshot.feature_means["event_count"] - 10.0) < 1e-6
