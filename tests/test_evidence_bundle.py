from pathlib import Path

from nexus.intel.evidence_bundle import EvidenceBundle, build_bundle_archive


def test_build_bundle_archive(tmp_path: Path):
    bundle = EvidenceBundle(
        start_ts=1.0,
        end_ts=2.0,
        generated_at=3.0,
        events=[{"event_id": "evt-1", "ts_epoch": 1.5}],
        alerts=[{"alert_id": "a1", "severity": 3}],
        anomalies=[{"id": 1, "attack_type": "anomaly"}],
        metadata={"event_count": 1, "alert_count": 1, "anomaly_count": 1},
    )
    output_path = tmp_path / "bundle.zip"
    build_bundle_archive(bundle, output_path)

    assert output_path.exists()
    import zipfile
    with zipfile.ZipFile(output_path, "r") as zf:
        names = set(zf.namelist())
        assert "metadata.json" in names
        assert "events.json" in names
        assert "alerts.json" in names
        assert "anomalies.json" in names
