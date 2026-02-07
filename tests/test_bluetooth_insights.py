from app.services.bluetooth_insights import build_bt_device_insight, is_randomized_bt_addr_type


def test_is_randomized_bt_addr_type_detects_private_variants():
    assert is_randomized_bt_addr_type("random")
    assert is_randomized_bt_addr_type("resolvable private")
    assert is_randomized_bt_addr_type("NRPA")
    assert not is_randomized_bt_addr_type("public")
    assert not is_randomized_bt_addr_type(None)


def test_build_bt_device_insight_high_confidence_profile():
    insight = build_bt_device_insight(
        vendor="Apple",
        local_name="AirPods Pro",
        addr_type="public",
        observation_count=120,
        known_service_count=2,
        unknown_service_count=0,
        has_manufacturer_hash=True,
    )
    assert insight["tier"] == "high"
    assert insight["score"] >= 75
    assert insight["is_randomized"] is False
    assert "High-confidence profile" in insight["summary"]
    assert len(insight["highlights"]) <= 4


def test_build_bt_device_insight_medium_confidence_profile():
    insight = build_bt_device_insight(
        vendor="Acme Devices",
        local_name=None,
        addr_type=None,
        observation_count=6,
        known_service_count=1,
        unknown_service_count=0,
        has_manufacturer_hash=False,
    )
    assert insight["tier"] == "medium"
    assert 45 <= insight["score"] < 75
    assert "Moderate confidence" in insight["summary"]


def test_build_bt_device_insight_low_confidence_randomized_sparse():
    insight = build_bt_device_insight(
        vendor="Unknown",
        local_name=None,
        addr_type="resolvable random",
        observation_count=1,
        known_service_count=0,
        unknown_service_count=4,
        has_manufacturer_hash=False,
    )
    assert insight["tier"] == "low"
    assert insight["score"] < 45
    assert insight["is_randomized"] is True
    assert "private/random" in insight["summary"].lower()
