import struct

from parser import FrameParser


def _mac(byte_val: int) -> bytes:
    return bytes([byte_val] * 6)


def _build_frame(to_ds: bool, from_ds: bool) -> bytes:
    frame_control = (2 << 2) | (0 << 4)
    if to_ds:
        frame_control |= 0x0100
    if from_ds:
        frame_control |= 0x0200

    header = struct.pack("<H", frame_control) + b"\x00\x00"
    header += _mac(1) + _mac(2) + _mac(3)
    header += b"\x00\x00"
    if to_ds and from_ds:
        header += _mac(4)

    radiotap = b"\x00\x00" + struct.pack("<H", 8) + b"\x00\x00\x00\x00"
    return radiotap + header


def test_address_mapping_no_ds():
    parser = FrameParser()
    frame = parser.parse(_build_frame(False, False), timestamp=0.0, channel=1)
    assert frame.dst_mac == "01:01:01:01:01:01"
    assert frame.src_mac == "02:02:02:02:02:02"
    assert frame.bssid == "03:03:03:03:03:03"


def test_address_mapping_to_ds():
    parser = FrameParser()
    frame = parser.parse(_build_frame(True, False), timestamp=0.0, channel=1)
    assert frame.dst_mac == "03:03:03:03:03:03"
    assert frame.src_mac == "02:02:02:02:02:02"
    assert frame.bssid == "01:01:01:01:01:01"


def test_address_mapping_from_ds():
    parser = FrameParser()
    frame = parser.parse(_build_frame(False, True), timestamp=0.0, channel=1)
    assert frame.dst_mac == "01:01:01:01:01:01"
    assert frame.src_mac == "03:03:03:03:03:03"
    assert frame.bssid == "02:02:02:02:02:02"


def test_address_mapping_wds():
    parser = FrameParser()
    frame = parser.parse(_build_frame(True, True), timestamp=0.0, channel=1)
    assert frame.dst_mac == "03:03:03:03:03:03"
    assert frame.src_mac == "04:04:04:04:04:04"
    assert frame.bssid is None
