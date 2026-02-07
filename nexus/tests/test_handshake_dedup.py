from nexus.eapol_parser import HandshakeCapture
from nexus.handshake_extractor import (
    _select_handshake_action,
    _storage_handshake_type,
)


def _make_full_capture(pmkid=None):
    capture = HandshakeCapture(
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNet",
        client_mac="11:22:33:44:55:66",
    )
    capture.msg_flags = 1 | 2
    capture.anonce = b"\x01" * 32
    capture.snonce = b"\x02" * 32
    capture.mic = b"\x03" * 16
    capture.eapol_m2 = b"\x04" * 64
    capture.pmkid = pmkid
    return capture


def _make_pmkid_capture(pmkid):
    capture = HandshakeCapture(
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNet",
        client_mac="11:22:33:44:55:66",
    )
    capture.msg_flags = 1
    capture.pmkid = pmkid
    return capture


def test_storage_handshake_type_prefers_full_over_pmkid():
    capture = _make_full_capture(pmkid="a" * 32)
    assert _storage_handshake_type(capture) == "4way_full"
    assert capture.handshake_type == "4way_full"


def test_select_action_updates_when_new_quality_higher():
    capture = _make_full_capture()
    existing_rows = [
        {
            "id": 10,
            "msg_flags": 1,
            "anonce": None,
            "snonce": None,
            "mic": None,
            "eapol_data": None,
            "pmkid": "b" * 32,
        }
    ]
    action, row = _select_handshake_action(capture, existing_rows)
    assert action == "update"
    assert row["id"] == 10


def test_select_action_skips_exact_duplicate_full():
    capture = _make_full_capture()
    existing_rows = [
        {
            "id": 1,
            "msg_flags": 3,
            "anonce": capture.anonce,
            "snonce": capture.snonce,
            "mic": capture.mic,
            "eapol_data": capture.eapol_m2,
            "pmkid": None,
        }
    ]
    action, _ = _select_handshake_action(capture, existing_rows)
    assert action == "skip"


def test_select_action_skips_exact_duplicate_pmkid():
    capture = _make_pmkid_capture("c" * 32)
    existing_rows = [
        {
            "id": 2,
            "msg_flags": 1,
            "anonce": None,
            "snonce": None,
            "mic": None,
            "eapol_data": None,
            "pmkid": "c" * 32,
        }
    ]
    action, _ = _select_handshake_action(capture, existing_rows)
    assert action == "skip"


def test_select_action_updates_even_if_pmkid_matches_when_full():
    capture = _make_full_capture(pmkid="d" * 32)
    existing_rows = [
        {
            "id": 3,
            "msg_flags": 1,
            "anonce": None,
            "snonce": None,
            "mic": None,
            "eapol_data": None,
            "pmkid": "d" * 32,
        }
    ]
    action, row = _select_handshake_action(capture, existing_rows)
    assert action == "update"
    assert row["id"] == 3


def test_hashcat_prefers_full_over_pmkid():
    capture = _make_full_capture(pmkid="e" * 32)
    hashcat = capture.to_hashcat_22000()
    assert hashcat is not None
    assert hashcat.startswith("WPA*02*")


def test_hashcat_uses_pmkid_when_full_missing():
    capture = _make_pmkid_capture("f" * 32)
    hashcat = capture.to_hashcat_22000()
    assert hashcat is not None
    assert hashcat.startswith("WPA*01*")
