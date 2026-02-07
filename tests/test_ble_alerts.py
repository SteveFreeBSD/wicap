import os
import sys

sys.path.append(os.path.abspath("src"))

from wicap.core.processing.persistence import build_ble_alert_row


def test_build_ble_alert_row_basic():
    row = build_ble_alert_row(
        "ble_name_change",
        "AA:BB:CC:DD:EE:FF",
        "Local name changed from 'Old' to 'New'",
        1700000000.0,
        local_name="New",
        severity=3,
    )

    assert row["alert_type"] == "ble_name_change"
    assert row["source_mac"] == "AA:BB:CC:DD:EE:FF"
    assert row["ssid"] == "New"
    assert row["severity"] == 3
    assert row["alert_id"]
    assert row["alert_signature"]


def test_build_ble_alert_row_clips_long_fields():
    very_long_name = "N" * 300
    very_long_desc = "D" * 2000

    row = build_ble_alert_row(
        "ble_services_change",
        "AA:BB:CC:DD:EE:FF",
        very_long_desc,
        1700000000.0,
        local_name=very_long_name,
        severity=5,
    )

    assert len(row["alert_signature"]) <= 256
    assert len(row["description"]) == 500
    assert len(row["ssid"]) == 64
