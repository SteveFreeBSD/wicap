"""
WiFiWizard Phase 1 - Frame Parser

Minimal real-time parsing of 802.11 management frames.
Extracts: SSID, BSSID, RSSI, security info, probe requests.
"""

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)

# Rust extension availability tracking
try:
    from nexus.utils import rust_ext
    _RUST_AVAILABLE = rust_ext is not None and getattr(rust_ext, "HAS_RUST_EXT", False)
except ImportError:
    rust_ext = None
    _RUST_AVAILABLE = False

_RUST_STATUS_LOGGED = False


def _log_rust_status_once() -> None:
    """Emit parser acceleration status once per process."""
    global _RUST_STATUS_LOGGED
    if _RUST_STATUS_LOGGED:
        return
    _RUST_STATUS_LOGGED = True
    if _RUST_AVAILABLE:
        logger.info("Rust parser acceleration enabled (wicap_rust extension loaded)")
    else:
        logger.debug("Rust parser acceleration unavailable; using Python parser path")


@lru_cache(maxsize=4096)
def _format_mac_cached(mac_bytes: bytes) -> str:
    """Format MAC address bytes to string with an LRU cache."""
    if _RUST_AVAILABLE and rust_ext is not None:
        return rust_ext.mac_bytes_to_str(mac_bytes)
    return ':'.join(f'{b:02x}' for b in mac_bytes)


class FrameType(IntEnum):
    """802.11 frame types."""
    MANAGEMENT = 0
    CONTROL = 1
    DATA = 2


class MgmtSubtype(IntEnum):
    """802.11 management frame subtypes."""
    ASSOC_REQ = 0
    ASSOC_RESP = 1
    REASSOC_REQ = 2
    REASSOC_RESP = 3
    PROBE_REQ = 4
    PROBE_RESP = 5
    BEACON = 8
    ATIM = 9
    DISASSOC = 10
    AUTH = 11
    DEAUTH = 12
    ACTION = 13


@dataclass
class SecurityInfo:
    """Extracted security information."""
    is_open: bool = True
    has_wep: bool = False
    has_wpa: bool = False
    has_wpa2: bool = False
    has_wpa3: bool = False
    cipher: str = ""  # CCMP, TKIP, etc.
    akm: str = ""  # PSK, EAP, SAE, etc.


@dataclass
class ParsedFrame:
    """Parsed 802.11 frame with extracted fields."""
    timestamp: float
    channel: int
    rssi: int | None  # None if RSSI could not be reliably extracted

    # Frame type
    frame_type: int
    frame_subtype: int

    # Addresses
    bssid: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None

    # Management frame fields
    ssid: str | None = None
    is_hidden_ssid: bool = False
    security: SecurityInfo = field(default_factory=SecurityInfo)

    # Probe request specific
    is_probe_request: bool = False
    is_assoc_request: bool = False  # Added for fingerprinting
    probe_is_broadcast: bool = True

    # Capabilities
    is_wifi6: bool = False  # 802.11ax

    # Sequence control (optional)
    seq_num: int | None = None
    beacon_interval: int | None = None

    # IE patterns for randomization detection
    ie_tags: list[int] = field(default_factory=list)
    vendor_ouis: list[str] = field(default_factory=list)

    # Data frame telemetry
    is_encrypted: bool = False
    frame_length: int = 0

    # Deauth/Disassoc
    is_deauth: bool = False
    is_disassoc: bool = False
    reason_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'ts': self.timestamp,
            'ch': self.channel,
            'rssi': self.rssi,
            'type': self.frame_type,
            'subtype': self.frame_subtype,
            'bssid': self.bssid,
            'src': self.src_mac,
            'ssid': self.ssid,
            'hidden': self.is_hidden_ssid,
            'open': self.security.is_open,
            'wifi6': self.is_wifi6,
            'probe': self.is_probe_request,
            'deauth': self.is_deauth,
            'seq': self.seq_num,
            'beacon_interval': self.beacon_interval,
        }


class FrameParser:
    """
    Minimal 802.11 frame parser for scout mode.

    Parses raw bytes from radiotap + 802.11 frames.
    Focuses on management frames for scouting.
    """

    # OUI database for vendor lookup - IEEE comprehensive database (38,704 entries)
    # Fallback to empty dict if nexus not available (standalone parser use)
    try:
        from nexus.oui_database import OUI_DATABASE as VENDOR_OUIS
    except ImportError:
        VENDOR_OUIS = {}

    def __init__(self):
        self._frame_count = 0
        _log_rust_status_once()

    def parse(self, raw_bytes: bytes, timestamp: float, channel: int) -> ParsedFrame | None:
        """
        Parse raw frame bytes into ParsedFrame.

        Args:
            raw_bytes: Raw frame bytes including radiotap header.
            timestamp: Capture timestamp.
            channel: Current channel.

        Returns:
            ParsedFrame or None if parsing fails.
        """
        try:
            return self._parse_internal(raw_bytes, timestamp, channel)
        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return None

    def _parse_internal(self, raw_bytes: bytes, timestamp: float, channel: int) -> ParsedFrame | None:
        """Internal parsing logic."""
        if len(raw_bytes) < 24:
            return None

        # Parse radiotap header
        radiotap_len, rssi = self._parse_radiotap(raw_bytes)
        if radiotap_len < 0:
            return None

        dot11_start = radiotap_len
        if len(raw_bytes) < dot11_start + 24:
            return None

        # Parse 802.11 header
        frame_control = struct.unpack('<H', raw_bytes[dot11_start:dot11_start+2])[0]
        frame_type = (frame_control >> 2) & 0x03
        frame_subtype = (frame_control >> 4) & 0x0F

        # Extract addresses
        addr1 = self._format_mac(raw_bytes[dot11_start+4:dot11_start+10])
        addr2 = self._format_mac(raw_bytes[dot11_start+10:dot11_start+16])
        addr3 = self._format_mac(raw_bytes[dot11_start+16:dot11_start+22])
        to_ds = bool(frame_control & 0x0100)
        from_ds = bool(frame_control & 0x0200)
        addr4 = None
        if to_ds and from_ds and len(raw_bytes) >= dot11_start + 30:
            addr4 = self._format_mac(raw_bytes[dot11_start+24:dot11_start+30])

        # Address mapping based on To/From DS bits
        if not to_ds and not from_ds:
            dst_mac = addr1
            src_mac = addr2
            bssid = addr3
        elif to_ds and not from_ds:
            dst_mac = addr3
            src_mac = addr2
            bssid = addr1
        elif not to_ds and from_ds:
            dst_mac = addr1
            src_mac = addr3
            bssid = addr2
        else:
            # WDS: BSSID is not present; use addr4 if available
            dst_mac = addr3
            src_mac = addr4 or addr2
            bssid = None

        # Sequence control (12-bit sequence number)
        seq_num = None
        if len(raw_bytes) >= dot11_start + 24:
            seq_control = struct.unpack('<H', raw_bytes[dot11_start+22:dot11_start+24])[0]
            seq_num = (seq_control >> 4) & 0x0FFF

        frame = ParsedFrame(
            timestamp=timestamp,
            channel=channel,
            rssi=rssi,
            frame_type=frame_type,
            frame_subtype=frame_subtype,
            dst_mac=dst_mac,
            src_mac=src_mac,
            bssid=bssid,
            seq_num=seq_num,
            frame_length=len(raw_bytes),
        )

        # Parse management frame body
        if frame_type == FrameType.MANAGEMENT:
            body_start = dot11_start + 24
            self._parse_management(raw_bytes, body_start, frame)

        # Data frame detection
        elif frame_type == FrameType.DATA:
            # Check protected frame bit
            frame.is_encrypted = bool(frame_control & 0x4000)

        self._frame_count += 1
        return frame

    def _parse_radiotap(self, raw_bytes: bytes) -> tuple:
        """
        Parse radiotap header, return (length, rssi).

        RSSI is returned as None if it cannot be reliably extracted.
        This avoids misleading values when the heuristic fails.
        """
        if len(raw_bytes) < 8:
            return (-1, None)

        # Radiotap header
        version = raw_bytes[0]
        if version != 0:
            return (-1, None)

        radiotap_len = struct.unpack('<H', raw_bytes[2:4])[0]
        if radiotap_len > len(raw_bytes):
            return (-1, None)

        # Try to extract RSSI from common radiotap field locations
        # This is a heuristic - may not work for all adapters/drivers
        # Return None if no valid-looking RSSI is found
        rssi = None

        # Common offsets where antenna signal (dBm) appears
        # These vary by driver/adapter - ath9k_htc often uses offset 14 or 18
        for offset in [14, 18, 22, 26, 30, 34]:
            if offset < radiotap_len:
                val = raw_bytes[offset]
                # Convert to signed
                if val > 127:
                    val = val - 256
                # Valid RSSI range check (typical: -127 to -10 dBm)
                if -127 <= val <= -10:
                    rssi = val
                    break

        return (radiotap_len, rssi)

    def _format_mac(self, mac_bytes: bytes) -> str:
        """Format MAC address bytes to string."""
        return _format_mac_cached(mac_bytes)

    def _parse_management(self, raw_bytes: bytes, body_start: int, frame: ParsedFrame) -> None:
        """Parse management frame body for IEs."""
        subtype = frame.frame_subtype

        # Skip fixed parameters based on subtype
        if subtype == MgmtSubtype.BEACON or subtype == MgmtSubtype.PROBE_RESP:
            # Timestamp (8) + Beacon Interval (2) + Capability (2) = 12 bytes
            if body_start + 10 <= len(raw_bytes):
                frame.beacon_interval = struct.unpack(
                    '<H', raw_bytes[body_start+8:body_start+10]
                )[0]
            ie_start = body_start + 12
        elif subtype == MgmtSubtype.ASSOC_REQ:
            frame.is_assoc_request = True
            ie_start = body_start + 4  # Capab(2) + Listen(2)
        elif subtype == MgmtSubtype.PROBE_REQ:
            frame.is_probe_request = True
            ie_start = body_start
        elif subtype == MgmtSubtype.DEAUTH:
            frame.is_deauth = True
            if body_start + 2 <= len(raw_bytes):
                frame.reason_code = struct.unpack('<H', raw_bytes[body_start:body_start+2])[0]
            return
        elif subtype == MgmtSubtype.DISASSOC:
            frame.is_disassoc = True
            if body_start + 2 <= len(raw_bytes):
                frame.reason_code = struct.unpack('<H', raw_bytes[body_start:body_start+2])[0]
            return
        else:
            return

        # Parse Information Elements
        self._parse_ies(raw_bytes, ie_start, frame)

    def _parse_ies(self, raw_bytes: bytes, start: int, frame: ParsedFrame) -> None:
        """Parse Information Elements."""
        pos = start

        while pos + 2 <= len(raw_bytes):
            ie_id = raw_bytes[pos]
            ie_len = raw_bytes[pos + 1]

            if pos + 2 + ie_len > len(raw_bytes):
                break

            ie_data = raw_bytes[pos + 2:pos + 2 + ie_len]
            frame.ie_tags.append(ie_id)

            # SSID (ID=0)
            if ie_id == 0:
                if ie_len == 0 or all(b == 0 for b in ie_data):
                    frame.is_hidden_ssid = True
                    frame.ssid = ""
                else:
                    try:
                        frame.ssid = ie_data.decode('utf-8', errors='replace')
                    except (UnicodeDecodeError, AttributeError):
                        frame.ssid = ie_data.hex()

                # Check if probe is broadcast
                if frame.is_probe_request:
                    frame.probe_is_broadcast = (ie_len == 0)

            # RSN IE (ID=48) - WPA2
            elif ie_id == 48:
                frame.security.is_open = False
                frame.security.has_wpa2 = True
                self._parse_rsn_ie(ie_data, frame.security)

            # Extension IE (ID=255) - Wifi 6 (HE)
            elif ie_id == 255 and ie_len >= 1:
                ext_id = ie_data[0]
                if ext_id == 35:  # HE Capabilities
                    frame.is_wifi6 = True
                elif ext_id == 36:  # HE Operation
                    frame.is_wifi6 = True

            # Vendor Specific (ID=221)
            elif ie_id == 221 and ie_len >= 4:
                oui = ':'.join(f'{b:02x}' for b in ie_data[:3])
                frame.vendor_ouis.append(oui)

                # WPA IE (Microsoft OUI + type 1)
                if ie_data[:4] == b'\x00\x50\xf2\x01':
                    frame.security.is_open = False
                    frame.security.has_wpa = True

            pos += 2 + ie_len

    def _parse_rsn_ie(self, data: bytes, security: SecurityInfo) -> None:
        """Parse RSN IE for cipher/AKM."""
        if len(data) < 8:
            return

        # Skip version (2 bytes) and group cipher (4 bytes)
        pos = 6

        # Pairwise cipher count
        if pos + 2 > len(data):
            return
        pw_count = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2

        # Parse pairwise ciphers
        for _ in range(pw_count):
            if pos + 4 > len(data):
                return
            cipher_oui = data[pos:pos+3]
            cipher_type = data[pos+3]

            if cipher_oui == b'\x00\x0f\xac':
                if cipher_type == 4:
                    security.cipher = "CCMP"
                elif cipher_type == 2:
                    security.cipher = "TKIP"
                elif cipher_type == 8:
                    security.cipher = "GCMP"
            pos += 4

        # AKM count
        if pos + 2 > len(data):
            return
        akm_count = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2

        # Parse AKM suites
        for _ in range(akm_count):
            if pos + 4 > len(data):
                return
            akm_oui = data[pos:pos+3]
            akm_type = data[pos+3]

            if akm_oui == b'\x00\x0f\xac':
                if akm_type == 1:
                    security.akm = "EAP"
                elif akm_type == 2:
                    security.akm = "PSK"
                elif akm_type == 8:
                    security.akm = "SAE"
                    security.has_wpa3 = True
            pos += 4

    @property
    def frame_count(self) -> int:
        """Total frames parsed."""
        return self._frame_count
