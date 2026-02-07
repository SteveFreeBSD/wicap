import struct

from parser import FrameParser


def _mac(byte_val: int) -> bytes:
    return bytes([byte_val] * 6)


def _build_beacon_frame(seq_num: int, beacon_interval: int) -> bytes:
    frame_control = (0 << 2) | (8 << 4)  # Management + Beacon subtype
    header = struct.pack("<H", frame_control) + b"\x00\x00"
    header += _mac(1) + _mac(2) + _mac(3)
    seq_control = (seq_num & 0x0FFF) << 4
    header += struct.pack("<H", seq_control)

    fixed = struct.pack("<QHH", 0, beacon_interval, 0)
    radiotap = b"\x00\x00" + struct.pack("<H", 8) + b"\x00\x00\x00\x00"
    return radiotap + header + fixed


def test_parser_extracts_seq_and_beacon_interval():
    parser = FrameParser()
    frame = parser.parse(_build_beacon_frame(100, 125), timestamp=0.0, channel=1)
    assert frame.seq_num == 100
    assert frame.beacon_interval == 125
