from pathlib import Path

import tests.soak_test as soak


def _base_results():
    soak.results["duration_minutes"] = 30
    soak.results["metrics"] = {
        "start": {"docker_stats": {"wicap-ui": {"mem": "200MiB / 1GiB"}}, "app_stats": {"total_events": 100}},
        "end": {"docker_stats": {"wicap-ui": {"mem": "260MiB / 1GiB"}}, "app_stats": {"total_events": 460}},
    }
    soak.results["memory_snapshots"] = {
        "start": {"summary": {"rss_mb": 210.0}},
        "end": {"summary": {"rss_mb": 260.0}},
        "checkpoints": [],
    }
    soak.results["playwright_checks"] = [{"passed": True}, {"passed": True}]
    soak.results["telemetry"] = {"eps_samples": [{"eps": 0.2}, {"eps": 0.3}]}


def test_baseline_snapshot_and_compare(tmp_path: Path):
    _base_results()
    current = soak._compute_baseline_snapshot()
    assert current["ui_rss_end_mb"] == 260.0
    assert current["ui_check_pass_rate"] == 1.0
    assert current["eps_avg"] == 0.25

    baseline = dict(current)
    # regress if RSS grows too much
    soak.MAX_RSS_GROWTH_PCT = 10
    current["ui_rss_end_mb"] = 300.0
    regressions = soak._compare_to_baseline(current, baseline)
    assert any("RSS" in r for r in regressions)


def test_baseline_write_and_read(tmp_path: Path):
    _base_results()
    snapshot = soak._compute_baseline_snapshot()
    path = tmp_path / "baseline.json"
    soak._write_baseline(path, snapshot)
    loaded = soak._load_baseline(path)
    assert loaded["ui_rss_end_mb"] == snapshot["ui_rss_end_mb"]
