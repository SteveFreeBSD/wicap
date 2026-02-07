import re

from nexus.utils import rust_ext


def test_mac_bytes_to_str():
    mac = rust_ext.mac_bytes_to_str(b"\x00\x11\x22\x33\x44\x55")
    assert mac == "00:11:22:33:44:55"


def test_xxh64_hex_consistent():
    value = rust_ext.xxh64_hex(b"wicap")
    assert len(value) == 16
    assert re.fullmatch(r"[0-9a-f]+", value)
    assert value == rust_ext.xxh64_hex(b"wicap")
