from nexus.intel.ble_triangulation import estimate_location, rssi_to_distance


def test_rssi_to_distance_monotonic():
    near = rssi_to_distance(-40)
    far = rssi_to_distance(-80)
    assert near is not None
    assert far is not None
    assert near < far


def test_estimate_location_requires_two_sensors():
    readings = [{"sensor_id": "a", "lat": 0.0, "lon": 0.0, "rssi": -55, "sample_count": 3}]
    assert estimate_location(readings) is None


def test_estimate_location_weighted_centroid():
    readings = [
        {"sensor_id": "a", "lat": 0.0, "lon": 0.0, "rssi": -40, "sample_count": 10},
        {"sensor_id": "b", "lat": 0.0, "lon": 10.0, "rssi": -80, "sample_count": 10},
        {"sensor_id": "c", "lat": 10.0, "lon": 0.0, "rssi": -85, "sample_count": 5},
    ]
    result = estimate_location(readings)
    assert result is not None
    assert result["sensor_count"] == 3
    assert result["lon"] < 5
    assert result["lat"] < 5
