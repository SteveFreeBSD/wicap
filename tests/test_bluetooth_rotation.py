from app.services.bluetooth_rotation import annotate_rotation_clusters, build_rotation_fingerprint


def test_build_rotation_fingerprint_requires_strong_signals():
    fp_none = build_rotation_fingerprint(
        vendor="Unknown",
        local_name="A",
        manufacturer_data_hash=None,
        services=[],
    )
    assert fp_none is None

    fp = build_rotation_fingerprint(
        vendor="Acme",
        local_name="Beacon Alpha",
        manufacturer_data_hash="abcdef1234567890",
        services=["Battery Service (0x180F)"],
    )
    assert fp is not None
    assert len(fp) == 12


def test_annotate_rotation_clusters_marks_suspected_for_private_peers():
    devices = [
        {
            "addr": "aa:aa:aa:aa:aa:01",
            "vendor": "Acme",
            "name": "Beacon Alpha",
            "manufacturer_data_hash": "abcdef1234567890",
            "services": ["Battery Service (0x180F)"],
            "is_randomized": True,
            "confidence_score": 58,
        },
        {
            "addr": "aa:aa:aa:aa:aa:02",
            "vendor": "Acme",
            "name": "Beacon Alpha",
            "manufacturer_data_hash": "abcdef1234567890",
            "services": ["Battery Service (0x180F)"],
            "is_randomized": True,
            "confidence_score": 54,
        },
    ]
    annotated = annotate_rotation_clusters(devices)
    assert annotated[0]["rotation_cluster_size"] == 2
    assert annotated[0]["rotation_peer_count"] == 1
    assert annotated[0]["rotation_suspected"] is True
    assert annotated[0]["rotation_correlation_score"] >= 50


def test_annotate_rotation_clusters_defaults_to_no_rotation():
    devices = [
        {
            "addr": "aa:aa:aa:aa:aa:09",
            "vendor": "VendorOne",
            "name": "DeviceOne",
            "manufacturer_data_hash": "1111111111111111",
            "services": ["Battery Service (0x180F)"],
            "is_randomized": False,
            "confidence_score": 90,
        },
        {
            "addr": "bb:bb:bb:bb:bb:09",
            "vendor": "VendorTwo",
            "name": "DeviceTwo",
            "manufacturer_data_hash": "2222222222222222",
            "services": ["Heart Rate (0x180D)"],
            "is_randomized": False,
            "confidence_score": 91,
        },
    ]
    annotated = annotate_rotation_clusters(devices)
    assert annotated[0]["rotation_cluster_size"] == 1
    assert annotated[0]["rotation_peer_count"] == 0
    assert annotated[0]["rotation_suspected"] is False
    assert annotated[0]["rotation_correlation_score"] == 0
