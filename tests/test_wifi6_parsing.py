import struct
import unittest

from parser import FrameParser


def _mac(byte_val: int) -> bytes:
    return bytes([byte_val] * 6)

def _build_mgmt_header() -> bytes:
    """Build a basic management frame header (Beacon)."""
    # Frame Control: Type=0 (Mgmt), Subtype=8 (Beacon) -> 0x0080 (Little Endian -> 80 00)
    # Actually:
    # Type: 00 (Mgmt)
    # Subtype: 1000 (Beacon) -> 8
    # FC = (Version << 0) | (Type << 2) | (Subtype << 4)
    # FC = 0 | 0 | (8 << 4) = 128 = 0x80
    fc = struct.pack("<H", 0x0080)

    header = fc + b"\x00\x00" # Duration
    header += _mac(1) + _mac(2) + _mac(3) # Addrs
    header += b"\x00\x00" # Seq Ctrl
    return header

def _build_radiotap() -> bytes:
    """Minimal radiotap header."""
    # Version 0, Pad 0, Len 8, Present 0
    return b"\x00\x00" + struct.pack("<H", 8) + b"\x00\x00\x00\x00"

def _build_beacon_body(ies: bytes = b"") -> bytes:
    """Fixed params + IEs."""
    timestamp = b"\x00" * 8
    beacon_interval = b"\x64\x00" # 100ms
    cap_info = b"\x00\x00"
    return timestamp + beacon_interval + cap_info + ies

class TestWifi6Parsing(unittest.TestCase):
    def setUp(self):
        self.parser = FrameParser()

    def test_legacy_frame(self):
        """Test that a standard frame is NOT marked as Wifi 6."""
        # SSID IE (0) len 4 "TEST"
        ies = b"\x00\x04TEST"

        raw = _build_radiotap() + _build_mgmt_header() + _build_beacon_body(ies)
        frame = self.parser.parse(raw, timestamp=1.0, channel=6)

        self.assertIsNotNone(frame)
        self.assertFalse(frame.is_wifi6)
        self.assertEqual(frame.ssid, "TEST")

    def test_he_capabilities_detection(self):
        """Test detection via HE Capabilities element (Ext ID 35)."""
        # Element ID 255 (Extension), Len 3, Ext ID 35 (HE Cap), Data AA BB
        # 35 = 0x23
        he_ie = b"\xff\x03\x23\xaa\xbb"

        raw = _build_radiotap() + _build_mgmt_header() + _build_beacon_body(he_ie)
        frame = self.parser.parse(raw, timestamp=1.0, channel=6)

        self.assertIsNotNone(frame)
        self.assertTrue(frame.is_wifi6, "Should detect Wifi 6 via HE Capabilities")

    def test_he_operation_detection(self):
        """Test detection via HE Operation element (Ext ID 36)."""
        # Element ID 255 (Extension), Len 3, Ext ID 36 (HE Op), Data CC DD
        # 36 = 0x24
        he_ie = b"\xff\x03\x24\xcc\xdd"

        raw = _build_radiotap() + _build_mgmt_header() + _build_beacon_body(he_ie)
        frame = self.parser.parse(raw, timestamp=1.0, channel=6)

        self.assertIsNotNone(frame)
        self.assertTrue(frame.is_wifi6, "Should detect Wifi 6 via HE Operation")

    def test_other_extension_ie(self):
        """Test that random extension IEs don't trigger Wifi 6."""
        # Element ID 255, Len 3, Ext ID 10 (Something else), Data ...
        other_ie = b"\xff\x03\x0a\x11\x22"

        raw = _build_radiotap() + _build_mgmt_header() + _build_beacon_body(other_ie)
        frame = self.parser.parse(raw, timestamp=1.0, channel=6)

        self.assertIsNotNone(frame)
        self.assertFalse(frame.is_wifi6, "Should NOT detect Wifi 6 for unrelated extension IE")

if __name__ == "__main__":
    unittest.main()
