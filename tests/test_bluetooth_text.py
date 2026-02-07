from app.services.bluetooth_text import (
    count_unknown_bt_services,
    format_bt_service_label,
    format_bt_service_labels,
    sanitize_bt_name,
)


def test_sanitize_bt_name_removes_control_and_replacement_chars():
    raw = "\u0002\ufffd[LG]\nwebOS\tTV"
    assert sanitize_bt_name(raw) == "[LG] webOS TV"


def test_sanitize_bt_name_returns_none_when_empty_after_cleanup():
    assert sanitize_bt_name("\u0000\u0001\ufffd\t\n") is None


def test_sanitize_bt_name_filters_short_or_non_actionable_names():
    assert sanitize_bt_name("::--::") is None
    assert sanitize_bt_name("ab") is None
    assert sanitize_bt_name("n L") is None


def test_sanitize_bt_name_filters_hex_and_repeated_noise():
    assert sanitize_bt_name("AABBCCDDEEFF0011") is None
    assert sanitize_bt_name("zzzzzzzzzzzz") is None


def test_sanitize_bt_name_filters_gibberish_token_patterns():
    assert sanitize_bt_name("h lL$h ` ? oz g{ vy JY g \\r 6U \\t ^ r n \\\\$") is None


def test_format_bt_service_label_known_gatt_service():
    assert format_bt_service_label("0000180f-0000-1000-8000-00805f9b34fb") == "Battery Service (0x180F)"


def test_format_bt_service_label_unknown_sig_short_code():
    assert format_bt_service_label("0000feb9-0000-1000-8000-00805f9b34fb") is None


def test_format_bt_service_labels_dedupes_and_normalizes():
    labels = format_bt_service_labels(
        [
            "0000180f-0000-1000-8000-00805f9b34fb",
            "0x180f",
            "0000feb9-0000-1000-8000-00805f9b34fb",
            None,
            "",
        ]
    )
    assert labels == ["Battery Service (0x180F)"]


def test_count_unknown_bt_services_counts_unique_unknowns():
    count = count_unknown_bt_services(
        [
            "0000180f-0000-1000-8000-00805f9b34fb",  # known
            "0000feb9-0000-1000-8000-00805f9b34fb",  # unknown
            "0xFEB9",  # same unknown canonical
            "fddf",  # unknown
            None,
        ]
    )
    assert count == 2
