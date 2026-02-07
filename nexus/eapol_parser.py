"""
NEXUS EAPOL Frame Parser

Parses 802.1X EAPOL-Key frames from raw packet data to extract
WPA/WPA2 4-way handshake components and PMKIDs.

References:
- IEEE 802.11i-2004 (WPA2 specification)
- IEEE 802.1X-2010 (EAPOL specification)
- hashcat wiki for hash formats
"""

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag

logger = logging.getLogger('nexus.eapol_parser')


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

# Ethertype for 802.1X (EAPOL)
EAPOL_ETHERTYPE = 0x888E

# EAPOL packet types
class EAPOLType(IntEnum):
    """EAPOL packet types."""
    EAP_PACKET = 0
    EAPOL_START = 1
    EAPOL_LOGOFF = 2
    EAPOL_KEY = 3
    EAPOL_ASF_ALERT = 4


# EAPOL-Key descriptor types
class KeyDescType(IntEnum):
    """Key descriptor types."""
    RC4 = 1         # WPA (deprecated)
    IEEE_802_11 = 2  # RSN (WPA2/WPA3)


# Key Information field bits (802.11i)
class KeyInfo(IntFlag):
    """Key Information field bit flags."""
    KEY_DESCRIPTOR_VERSION = 0x0007  # Bits 0-2
    KEY_TYPE = 0x0008                # Bit 3: 1=Pairwise, 0=Group
    KEY_INDEX = 0x0030               # Bits 4-5
    INSTALL = 0x0040                 # Bit 6
    KEY_ACK = 0x0080                 # Bit 7
    KEY_MIC = 0x0100                 # Bit 8
    SECURE = 0x0200                  # Bit 9
    ERROR = 0x0400                   # Bit 10
    REQUEST = 0x0800                 # Bit 11
    ENCRYPTED_KEY_DATA = 0x1000      # Bit 12


# RSN Information Element OUI for PMKID
RSN_OUI_PMKID = bytes([0x00, 0x0F, 0xAC, 0x04])


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EAPOLKeyFrame:
    """
    Parsed EAPOL-Key frame.

    Used for WPA/WPA2 4-way handshake.
    """
    # Source packet info
    timestamp: float
    src_mac: str
    dst_mac: str
    bssid: str

    # EAPOL header
    version: int
    packet_type: int
    packet_length: int

    # EAPOL-Key fields
    descriptor_type: int
    key_info: int
    key_length: int
    replay_counter: bytes  # 8 bytes
    key_nonce: bytes       # 32 bytes (ANonce or SNonce)
    key_iv: bytes          # 16 bytes
    key_rsc: bytes         # 8 bytes
    key_id: bytes          # 8 bytes (reserved)
    key_mic: bytes         # 16 bytes
    key_data_length: int
    key_data: bytes        # Variable length

    # Derived properties
    message_number: int = 0  # 1, 2, 3, or 4
    pmkid: str | None = None  # Extracted from M1 Key Data

    # Raw EAPOL frame for hashcat
    raw_eapol: bytes = field(default_factory=bytes)

    @property
    def is_pairwise(self) -> bool:
        """Check if this is a pairwise key (vs group key)."""
        return bool(self.key_info & KeyInfo.KEY_TYPE)

    @property
    def has_mic(self) -> bool:
        """Check if MIC is present."""
        return bool(self.key_info & KeyInfo.KEY_MIC)

    @property
    def has_ack(self) -> bool:
        """Check if ACK flag is set (AP -> STA)."""
        return bool(self.key_info & KeyInfo.KEY_ACK)

    @property
    def has_install(self) -> bool:
        """Check if INSTALL flag is set."""
        return bool(self.key_info & KeyInfo.INSTALL)

    @property
    def has_encrypted_data(self) -> bool:
        """Check if key data is encrypted."""
        return bool(self.key_info & KeyInfo.ENCRYPTED_KEY_DATA)

    @property
    def is_secure(self) -> bool:
        """Check if SECURE flag is set."""
        return bool(self.key_info & KeyInfo.SECURE)

    @property
    def key_descriptor_version(self) -> int:
        """Get key descriptor version (1=TKIP/HMAC-MD5, 2=CCMP/HMAC-SHA1, 3=AES-128-CMAC)."""
        return self.key_info & KeyInfo.KEY_DESCRIPTOR_VERSION

    def determine_message_number(self) -> int:
        """
        Determine which message in the 4-way handshake this is.

        M1: has_ack, !has_mic, !has_install, !has_secure (AP -> STA, ANonce)
        M2: !has_ack, has_mic, !has_install, !has_secure (STA -> AP, SNonce)
        M3: has_ack, has_mic, has_install, has_secure (AP -> STA, ANonce again)
        M4: !has_ack, has_mic, !has_install, has_secure (STA -> AP, confirm)
        """
        if self.has_ack and not self.has_mic:
            return 1
        elif not self.has_ack and self.has_mic and not self.has_install and not self.is_secure:
            return 2
        elif self.has_ack and self.has_mic and self.has_install:
            return 3
        elif not self.has_ack and self.has_mic and self.is_secure:
            return 4
        return 0  # Unknown

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'src_mac': self.src_mac,
            'dst_mac': self.dst_mac,
            'bssid': self.bssid,
            'message_number': self.message_number,
            'has_mic': self.has_mic,
            'has_ack': self.has_ack,
            'has_install': self.has_install,
            'is_secure': self.is_secure,
            'key_nonce': self.key_nonce.hex() if self.key_nonce else None,
            'key_mic': self.key_mic.hex() if self.key_mic else None,
            'pmkid': self.pmkid,
            'replay_counter': self.replay_counter.hex() if self.replay_counter else None,
        }


@dataclass
class HandshakeCapture:
    """
    Complete or partial WPA handshake capture.

    A complete 4-way handshake needs:
    - M1 (for ANonce)
    - M2 (for SNonce and MIC)
    - OR just PMKID from M1 (for hashcat mode 22000)
    """
    bssid: str
    ssid: str | None
    client_mac: str

    # Message flags (bitmap: M1=1, M2=2, M3=4, M4=8)
    msg_flags: int = 0

    # Key material
    anonce: bytes | None = None  # From M1 or M3
    snonce: bytes | None = None  # From M2 or M4
    mic: bytes | None = None     # From M2
    pmkid: str | None = None     # From M1 key data (if present)

    # EAPOL frames for cracking
    eapol_m2: bytes | None = None  # Full M2 EAPOL frame

    # Timestamps
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Source tracking
    pcap_file: str | None = None

    @property
    def handshake_type(self) -> str:
        """Determine handshake type for cracking."""
        if self.has_complete_handshake:
            return '4way_full'
        elif self.pmkid:
            return 'pmkid'
        elif self.anonce and self.snonce and self.mic:
            return '4way_partial'
        return 'incomplete'

    @property
    def has_m1(self) -> bool:
        return bool(self.msg_flags & 1)

    @property
    def has_m2(self) -> bool:
        return bool(self.msg_flags & 2)

    @property
    def has_m3(self) -> bool:
        return bool(self.msg_flags & 4)

    @property
    def has_m4(self) -> bool:
        return bool(self.msg_flags & 8)

    @property
    def has_complete_handshake(self) -> bool:
        """Check if we have enough for a 4-way crack."""
        # Need M1+M2+M3, or M2+M3+M4, or at minimum M1+M2
        return (self.has_m1 and self.has_m2) or (self.has_m2 and self.has_m3)

    @property
    def is_crackable(self) -> bool:
        """Check if this capture can be submitted to hashcat."""
        return self.handshake_type in ('pmkid', '4way_full', '4way_partial')

    def add_message(self, frame: EAPOLKeyFrame) -> None:
        """Add a handshake message to this capture."""
        if frame.message_number == 1:
            self.msg_flags |= 1
            self.anonce = frame.key_nonce
            if frame.pmkid:
                self.pmkid = frame.pmkid
        elif frame.message_number == 2:
            self.msg_flags |= 2
            self.snonce = frame.key_nonce
            self.mic = frame.key_mic
            self.eapol_m2 = frame.raw_eapol
        elif frame.message_number == 3:
            self.msg_flags |= 4
            # M3 also has ANonce, can use if missing M1
            if not self.anonce:
                self.anonce = frame.key_nonce
        elif frame.message_number == 4:
            self.msg_flags |= 8
            # M4 also has SNonce, can use if missing M2
            if not self.snonce:
                self.snonce = frame.key_nonce

        # Update timestamps
        if self.first_seen == 0 or frame.timestamp < self.first_seen:
            self.first_seen = frame.timestamp
        if frame.timestamp > self.last_seen:
            self.last_seen = frame.timestamp

    def to_hashcat_22000(self) -> str | None:
        """
        Export in hashcat 22000 format (WPA-PBKDF2-PMKID+EAPOL).

        Format varies based on what we captured:
        - PMKID: WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID_HEX
        - EAPOL: WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID_HEX*NONCE_AP*EAPOL*MESSAGE_PAIR
        """
        if not self.ssid:
            return None

        bssid_clean = self.bssid.replace(':', '').lower()
        client_clean = self.client_mac.replace(':', '').lower()
        ssid_hex = self.ssid.encode().hex()

        # Full handshake capture
        if self.has_complete_handshake and self.anonce and self.mic and self.eapol_m2:
            anonce_hex = self.anonce.hex()
            mic_hex = self.mic.hex()
            eapol_hex = self.eapol_m2.hex()

            # Message pair indicator
            # 0 = M1/M2 (verified), 2 = M2/M3 (not verified)
            msg_pair = '00' if self.has_m1 else '02'

            return f"WPA*02*{mic_hex}*{bssid_clean}*{client_clean}*{ssid_hex}*{anonce_hex}*{eapol_hex}*{msg_pair}"

        # PMKID capture (fallback when full handshake is unavailable)
        if self.pmkid:
            return f"WPA*01*{self.pmkid}*{bssid_clean}*{client_clean}*{ssid_hex}***"

        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Parser Class
# ═══════════════════════════════════════════════════════════════════════════════

class EAPOLParser:
    """
    Parse EAPOL frames from raw packet data.

    Supports both:
    - Raw Ethernet frames
    - 802.11 data frames with LLC/SNAP header
    """

    def __init__(self):
        self.logger = logger

    def parse_eapol_key(
        self,
        data: bytes,
        timestamp: float,
        src_mac: str,
        dst_mac: str,
        bssid: str,
    ) -> EAPOLKeyFrame | None:
        """
        Parse EAPOL-Key frame from raw EAPOL data.

        Args:
            data: Raw EAPOL frame bytes (starting after LLC/SNAP or after ethertype)
            timestamp: Packet timestamp
            src_mac: Source MAC address
            dst_mac: Destination MAC address
            bssid: BSSID of the network

        Returns:
            EAPOLKeyFrame if valid, None otherwise
        """
        try:
            return self._parse_eapol_key_internal(
                data, timestamp, src_mac, dst_mac, bssid
            )
        except Exception as e:
            self.logger.debug(f"Failed to parse EAPOL frame: {e}")
            return None

    def _parse_eapol_key_internal(
        self,
        data: bytes,
        timestamp: float,
        src_mac: str,
        dst_mac: str,
        bssid: str,
    ) -> EAPOLKeyFrame | None:
        """Internal EAPOL-Key parsing."""
        if len(data) < 4:
            return None

        # EAPOL header: Version (1) | Type (1) | Length (2)
        version = data[0]
        packet_type = data[1]
        packet_length = struct.unpack('>H', data[2:4])[0]

        # We only care about EAPOL-Key (type 3)
        if packet_type != EAPOLType.EAPOL_KEY:
            return None

        # EAPOL-Key body starts at offset 4
        key_data_start = 4
        remaining = data[key_data_start:]

        if len(remaining) < 95:  # Minimum EAPOL-Key frame size
            return None

        # Parse EAPOL-Key frame
        # Descriptor Type (1) | Key Info (2) | Key Length (2) |
        # Replay Counter (8) | Key Nonce (32) | Key IV (16) |
        # Key RSC (8) | Key ID (8) | Key MIC (16) | Key Data Length (2) | Key Data (var)

        descriptor_type = remaining[0]
        key_info = struct.unpack('>H', remaining[1:3])[0]
        key_length = struct.unpack('>H', remaining[3:5])[0]

        replay_counter = remaining[5:13]
        key_nonce = remaining[13:45]
        key_iv = remaining[45:61]
        key_rsc = remaining[61:69]
        key_id = remaining[69:77]
        key_mic = remaining[77:93]
        key_data_length = struct.unpack('>H', remaining[93:95])[0]

        key_data = b''
        if key_data_length > 0 and len(remaining) >= 95 + key_data_length:
            key_data = remaining[95:95 + key_data_length]

        # Create the frame object
        frame = EAPOLKeyFrame(
            timestamp=timestamp,
            src_mac=src_mac,
            dst_mac=dst_mac,
            bssid=bssid,
            version=version,
            packet_type=packet_type,
            packet_length=packet_length,
            descriptor_type=descriptor_type,
            key_info=key_info,
            key_length=key_length,
            replay_counter=replay_counter,
            key_nonce=key_nonce,
            key_iv=key_iv,
            key_rsc=key_rsc,
            key_id=key_id,
            key_mic=key_mic,
            key_data_length=key_data_length,
            key_data=key_data,
            raw_eapol=data,
        )

        # Determine message number
        frame.message_number = frame.determine_message_number()

        # Extract PMKID from M1 if present
        if frame.message_number == 1 and key_data:
            frame.pmkid = self._extract_pmkid(key_data)

        return frame

    def _extract_pmkid(self, key_data: bytes) -> str | None:
        """
        Extract PMKID from M1 Key Data field.

        PMKID is in an RSN Information Element with:
        - Tag type 0xDD (Vendor Specific) or Tag type 48 (RSN)
        - OUI 00:0F:AC
        - Data type 4 (PMKID List)
        """
        offset = 0
        while offset < len(key_data) - 6:
            tag_type = key_data[offset]
            tag_len = key_data[offset + 1]

            if offset + 2 + tag_len > len(key_data):
                break

            tag_data = key_data[offset + 2:offset + 2 + tag_len]

            # Look for RSN PMKID
            # In RSN IE (tag 48), PMKID list is near the end
            # More commonly in Vendor Specific IE with PMKID OUI
            if tag_type == 0xDD and tag_len >= 20:  # Vendor Specific
                # Check for PMKID OUI (00:0F:AC:04)
                if tag_data[:4] == RSN_OUI_PMKID:
                    pmkid = tag_data[4:20]
                    return pmkid.hex()

            # Also check raw PMKID pattern in key data
            # PMKID pattern: 01 00 followed by PMKID OUI and 16 bytes PMKID
            if tag_type == 0x01 and tag_len == 0x00:
                # This might be PMKID count, check next bytes
                pass

            offset += 2 + tag_len

        # Alternative: look for raw PMKID pattern in key data
        # Pattern: XX XX 00 0F AC 04 + 16-byte PMKID
        for i in range(len(key_data) - 20):
            if key_data[i:i+4] == RSN_OUI_PMKID:
                pmkid = key_data[i+4:i+20]
                # Validate it's not all zeros
                if pmkid != bytes(16):
                    return pmkid.hex()

        return None

    def find_eapol_in_80211(self, frame_data: bytes) -> tuple[int, bytes] | None:
        """
        Find EAPOL data within an 802.11 data frame.

        Returns (offset, eapol_data) tuple if found, None otherwise.
        """
        # 802.11 data frame structure:
        # Frame Control (2) | Duration (2) | Addr1 (6) | Addr2 (6) | Addr3 (6) |
        # Seq Control (2) | [Addr4 (6)] | [QoS (2)] | LLC/SNAP (8) | Data

        if len(frame_data) < 24:  # Minimum 802.11 header
            return None

        # Check frame control - should be data frame (type 2)
        fc = struct.unpack('<H', frame_data[0:2])[0]
        frame_type = (fc >> 2) & 0x03
        frame_subtype = (fc >> 4) & 0x0F

        if frame_type != 2:  # Not a data frame
            return None

        # Calculate header length based on To/From DS and QoS
        to_ds = (fc >> 8) & 0x01
        from_ds = (fc >> 9) & 0x01
        is_qos = frame_subtype >= 8  # QoS data

        header_len = 24  # Base header
        if to_ds and from_ds:
            header_len += 6  # Add Addr4
        if is_qos:
            header_len += 2  # Add QoS control

        if len(frame_data) < header_len + 8:  # Need LLC/SNAP header
            return None

        # Check for LLC/SNAP header: AA AA 03 00 00 00 88 8E
        llc_snap = frame_data[header_len:header_len + 8]
        if llc_snap[:6] != bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]):
            return None

        ethertype = struct.unpack('>H', llc_snap[6:8])[0]
        if ethertype != EAPOL_ETHERTYPE:
            return None

        # EAPOL data starts after LLC/SNAP
        eapol_offset = header_len + 8
        eapol_data = frame_data[eapol_offset:]

        return (eapol_offset, eapol_data)
