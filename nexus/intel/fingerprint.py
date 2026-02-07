"""
Device Capability Fingerprinting Engine
Extracts stable device signatures from 802.11 Association Request frames.
"""
import hashlib
import logging
from dataclasses import dataclass

from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Elt

logger = logging.getLogger('nexus.intel.fingerprint')

@dataclass
class CapabilitySignature:
    """Represents a device's unique capability signature."""
    raw_string: str  # The canonical string used for hashing
    hash: str        # SHA256 hash of the raw string

    # Human readable components for debugging/analysis
    ordered_tags: list[int]
    ht_caps: str | None
    vht_caps: str | None
    he_caps: str | None
    ext_caps: str | None

class DeviceFingerprinter:
    """
    Extracts deep capability fingerprints from 802.11 frames.
    Focuses on Association Requests (assoc-req) which contain the richest data.
    """

    # IE Tag Constants
    TAG_SSID = 0
    TAG_RATES = 1
    TAG_EXT_RATES = 50
    TAG_HT_CAP = 45
    TAG_VHT_CAP = 191
    TAG_HE_CAP = 255  # Extension tag (255) + Ext ID (35)
    TAG_EXT_CAP = 127
    TAG_VENDOR = 221

    def process_packet(self, pkt) -> CapabilitySignature | None:
        """
        Extract fingerprint from a Scapy packet.
        Returns None if packet is not an Association Request.
        """
        if not pkt.haslayer(Dot11AssoReq):
            return None

        try:
            return self._extract_fingerprint(pkt)
        except Exception as e:
            logger.error(f"Error fingerprinting packet: {e}", exc_info=True)
            return None

    def _extract_fingerprint(self, pkt) -> CapabilitySignature:
        """Core extraction logic."""
        pkt[Dot11]

        # 1. Ordered Tags List
        # Iterate over all Elt layers to get sequence of tags
        ordered_tags = []
        payload = pkt.getlayer(Dot11AssoReq).payload

        # Iterating Scapy Dot11Elt layers
        cursor = payload
        while isinstance(cursor, Dot11Elt):
            ordered_tags.append(cursor.ID)
            cursor = cursor.payload

        # 2. Capability Extraction
        ht_caps = self._get_ie_bytes(pkt, self.TAG_HT_CAP)
        vht_caps = self._get_ie_bytes(pkt, self.TAG_VHT_CAP)
        ext_caps = self._get_ie_bytes(pkt, self.TAG_EXT_CAP)

        # HE Caps is tricky: Tag 255 (Extension) + ID 35
        he_caps = self._get_extension_ie_bytes(pkt, 35)

        # 3. Canonicalization
        # Format: "TAGS|HT:hex|VHT:hex|HE:hex|EXT:hex"
        parts = []

        # Part A: Tags (comma separated)
        parts.append(",".join(map(str, ordered_tags)))

        # Part B: Capabilities (uppercase hex or empty)
        parts.append(f"HT:{ht_caps.hex().upper() if ht_caps else ''}")
        parts.append(f"VHT:{vht_caps.hex().upper() if vht_caps else ''}")
        parts.append(f"HE:{he_caps.hex().upper() if he_caps else ''}")
        parts.append(f"EXT:{ext_caps.hex().upper() if ext_caps else ''}")

        # Final String
        raw_string = "|".join(parts)

        # 4. Hashing
        sig_hash = hashlib.sha256(raw_string.encode('utf-8')).hexdigest()

        return CapabilitySignature(
            raw_string=raw_string,
            hash=sig_hash,
            ordered_tags=ordered_tags,
            ht_caps=ht_caps.hex().upper() if ht_caps else None,
            vht_caps=vht_caps.hex().upper() if vht_caps else None,
            he_caps=he_caps.hex().upper() if he_caps else None,
            ext_caps=ext_caps.hex().upper() if ext_caps else None
        )

    def _get_ie_bytes(self, pkt, tag_id: int) -> bytes | None:
        """Finds the FIRST occurrence of a specific IE tag and returns its payload (info)."""
        payload = pkt.getlayer(Dot11AssoReq).payload
        while isinstance(payload, Dot11Elt):
            if payload.ID == tag_id:
                return payload.info
            payload = payload.payload
        return None

    def _get_extension_ie_bytes(self, pkt, ext_tag_id: int) -> bytes | None:
        """
        Finds IE with ID=255 and specific Extension ID (first byte of info).
        Returns bytes starting AFTER the extension ID.
        """
        payload = pkt.getlayer(Dot11AssoReq).payload
        while isinstance(payload, Dot11Elt):
            if payload.ID == 255:
                # payload.info structure: [ExtID (1 byte)] [Data (n bytes)]
                if len(payload.info) >= 1 and payload.info[0] == ext_tag_id:
                    return payload.info[1:] # Return data excluding ExtID
            payload = payload.payload
        return None
