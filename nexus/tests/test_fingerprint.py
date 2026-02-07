"""
Tests for Device Capability Fingerprinting
"""
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[2]))

from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Elt

from nexus.intel.fingerprint import DeviceFingerprinter


@pytest.fixture
def fingerprinter():
    return DeviceFingerprinter()

def test_ignore_non_assoc_req(fingerprinter):
    """Ensure we ignore Beacons and other frames."""
    pkt = RadioTap() / Dot11(type=0, subtype=8) / Dot11Beacon()
    assert fingerprinter.process_packet(pkt) is None

def test_basic_fingerprint(fingerprinter):
    """Test fingerprinting with basic IEs."""
    # Construct a synthetic Assoc Req
    # Tags: SSID(0), Rates(1), Vendor(221)
    pkt = RadioTap() / Dot11(type=0, subtype=0) / Dot11AssoReq() / \
          Dot11Elt(ID=0, info=b"test_ssid") / \
          Dot11Elt(ID=1, info=b"\x82\x84") / \
          Dot11Elt(ID=221, info=b"\x00\x50\xf2\x02")

    sig = fingerprinter.process_packet(pkt)

    assert sig is not None
    assert sig.ordered_tags == [0, 1, 221]
    # Capabilities should be None
    assert sig.ht_caps is None
    assert sig.vht_caps is None
    assert sig.he_caps is None

    # Check Raw String Format (Tags|HT|VHT|HE|EXT)
    expected_raw = "0,1,221|HT:|VHT:|HE:|EXT:"
    assert sig.raw_string == expected_raw

def test_ht_capability(fingerprinter):
    """Test extracting HT capabilities (Tag 45)."""
    # HT Cap info is typically 26 bytes
    ht_info = b"\x11" * 26

    pkt = RadioTap() / Dot11(type=0, subtype=0) / Dot11AssoReq() / \
          Dot11Elt(ID=45, info=ht_info)

    sig = fingerprinter.process_packet(pkt)
    assert sig is not None
    assert sig.ordered_tags == [45]
    assert sig.ht_caps == ht_info.hex().upper()
    assert f"HT:{ht_info.hex().upper()}" in sig.raw_string

def test_he_capability(fingerprinter):
    """Test extracting HE capabilities (Tag 255, Ext ID 35)."""
    # HE Cap: ExtTag(255) -> OUI/Data where char 0 is ExtID(35)
    # Construct payload: [35] + [0xAA, 0xBB...]
    he_data = b"\xaa\xbb\xcc"
    payload = bytes([35]) + he_data

    pkt = RadioTap() / Dot11(type=0, subtype=0) / Dot11AssoReq() / \
          Dot11Elt(ID=255, info=payload)

    sig = fingerprinter.process_packet(pkt)
    assert sig is not None
    assert sig.he_caps == "AABBCC"
    assert "HE:AABBCC" in sig.raw_string

def test_determinism(fingerprinter):
    """Ensure consistent hashing for identical packets."""
    pkt1 = RadioTap() / Dot11(type=0, subtype=0) / Dot11AssoReq() / \
           Dot11Elt(ID=1, info=b"\x01") / Dot11Elt(ID=45, info=b"\xFF")

    pkt2 = RadioTap() / Dot11(type=0, subtype=0) / Dot11AssoReq() / \
           Dot11Elt(ID=1, info=b"\x01") / Dot11Elt(ID=45, info=b"\xFF")

    sig1 = fingerprinter.process_packet(pkt1)
    sig2 = fingerprinter.process_packet(pkt2)

    assert sig1.hash == sig2.hash
    assert sig1.raw_string == sig2.raw_string
