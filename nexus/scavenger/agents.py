"""
Scavenger Analysis Agents ("The Digest")
Modular agents that extract specific intelligence from packet streams.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

try:
    from scapy.all import Dot11, Packet, RadioTap
    from scapy.layers.dot11 import Dot11Elt
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = None

if TYPE_CHECKING:
    from nexus.eapol_parser import EAPOLParser


@dataclass
class ClientPNL:
    """
    Preferred Network List (PNL) for a single client device.

    Tracks SSIDs the client has probed for, which reveals networks
    the device has previously connected to.
    """
    mac: str
    probed_ssids: dict[str, datetime] = field(default_factory=dict)  # SSID -> last_seen
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    channels_seen: set[int] = field(default_factory=set)
    rssi_history: list[int] = field(default_factory=list)
    timestamp_history: list[datetime] = field(default_factory=list)  # For POL analysis
    total_probes: int = 0
    is_randomized_mac: bool = False

    @property
    def avg_rssi(self) -> float | None:
        """Average RSSI across all observations."""
        if not self.rssi_history:
            return None
        return sum(self.rssi_history) / len(self.rssi_history)

    @property
    def pnl_count(self) -> int:
        """Number of unique SSIDs in the PNL."""
        return len(self.probed_ssids)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            'mac': self.mac,
            'probed_ssids': {
                ssid: ts.isoformat() if ts else None
                for ssid, ts in self.probed_ssids.items()
            },
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'channels_seen': sorted(self.channels_seen),
            'avg_rssi': self.avg_rssi,
            'total_probes': self.total_probes,
            'pnl_count': self.pnl_count,
            'is_randomized_mac': self.is_randomized_mac,
        }


class BaseAgent:
    """Base class for all Scavenger agents."""

    def __init__(self):
        self.name = "BaseAgent"
        self._stats = {
            'packets_processed': 0,
            'intelligence_extracted': 0,
        }

    def process(self, packet: Any) -> dict[str, Any] | None:
        """
        Process a single packet and return intelligence or None.

        Args:
            packet: scapy Packet object

        Returns:
            Dict with extracted intelligence, or None if packet not relevant
        """
        raise NotImplementedError

    def get_stats(self) -> dict[str, Any]:
        """Return processing statistics."""
        return self._stats.copy()

    def reset(self) -> None:
        """Reset agent state."""
        self._stats = {
            'packets_processed': 0,
            'intelligence_extracted': 0,
        }


def _is_randomized_mac(mac: str) -> bool:
    """
    Check if a MAC address is randomized.

    Randomized MACs have the second bit of the first octet set (locally administered).
    """
    if not mac or mac == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        first_octet = int(mac.split(':')[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _is_broadcast_or_multicast(mac: str | None) -> bool:
    """Return True if MAC is broadcast, multicast, or invalid."""
    if not mac:
        return True
    mac = mac.lower()
    if mac == "ff:ff:ff:ff:ff:ff":
        return True
    try:
        first_octet = int(mac.split(':')[0], 16)
    except (ValueError, IndexError):
        return True
    return bool(first_octet & 0x01)


def _channel_from_frequency(freq: float | None) -> int | None:
    """Convert center frequency (MHz) to Wi-Fi channel number."""
    if freq is None:
        return None
    try:
        value = float(freq)
    except (TypeError, ValueError):
        return None
    if 2412 <= value <= 2484:
        if value == 2484:
            return 14
        return int((value - 2407) // 5)
    if 5000 <= value <= 5895:
        return int((value - 5000) // 5)
    if 5955 <= value <= 7115:
        return int((value - 5950) // 5)
    return None


@dataclass
class AssociationRecord:
    """Tracks association history for a client/BSSID pair."""
    client_mac: str
    bssid: str
    ssid: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    association_count: int = 0
    last_assoc_type: str | None = None
    has_mgmt: bool = False

    def update(self, timestamp: datetime, assoc_type: str, ssid: str | None) -> None:
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp
        if self.ssid is None and ssid:
            self.ssid = ssid
        self.association_count += 1
        self.last_assoc_type = assoc_type


class AgentShadow(BaseAgent):
    """
    Client tracker agent ("Shadow").

    Tracks Probe Requests to build Preferred Network Lists (PNL) for clients.
    Also records timestamps for Pattern-of-Life (POL) analysis.

    Probe Requests reveal SSIDs that a device has previously connected to,
    exposing the user's location history and habits.
    """

    # 802.11 frame type/subtype for probe request
    MGMT_TYPE = 0
    PROBE_REQ_SUBTYPE = 4

    def __init__(self):
        super().__init__()
        self.name = "Shadow"
        self.client_profiles: dict[str, ClientPNL] = {}

    def _extract_ssid(self, packet: 'Packet') -> str | None:
        """Extract SSID from packet's Information Elements."""
        try:
            if packet.haslayer(Dot11Elt):
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:  # SSID element
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        # Filter out broadcast/null probes
                        if ssid and ssid.strip():
                            return ssid
                        return None
                    elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None
        except Exception:
            pass
        return None

    def _extract_channel(self, packet: 'Packet') -> int | None:
        """Extract channel from RadioTap header."""
        try:
            if packet.haslayer(RadioTap):
                rt = packet.getlayer(RadioTap)
                channel = _channel_from_frequency(getattr(rt, "ChannelFrequency", None))
                if channel is not None:
                    return channel
        except Exception:
            pass
        return None

    def _extract_rssi(self, packet: 'Packet') -> int | None:
        """Extract RSSI from RadioTap header."""
        try:
            if packet.haslayer(RadioTap):
                rt = packet.getlayer(RadioTap)
                if hasattr(rt, 'dBm_AntSignal'):
                    return rt.dBm_AntSignal
        except Exception:
            pass
        return None

    def _get_or_create_profile(self, mac: str) -> ClientPNL:
        """Get existing profile or create new one for MAC."""
        if mac not in self.client_profiles:
            self.client_profiles[mac] = ClientPNL(
                mac=mac,
                is_randomized_mac=_is_randomized_mac(mac)
            )
        return self.client_profiles[mac]

    def process(self, packet: 'Packet') -> dict[str, Any] | None:
        """
        Process a packet and extract probe request intelligence.

        Args:
            packet: scapy Packet with 802.11 layers

        Returns:
            Dict with probe data if probe request found, None otherwise
        """
        self._stats['packets_processed'] += 1

        if not SCAPY_AVAILABLE:
            return None

        # Check if this is a probe request
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet.getlayer(Dot11)

        # Probe Request: type=0 (Management), subtype=4
        if dot11.type != self.MGMT_TYPE or dot11.subtype != self.PROBE_REQ_SUBTYPE:
            return None

        # Extract source MAC (addr2 in management frames)
        src_mac = dot11.addr2
        if not src_mac or src_mac == "ff:ff:ff:ff:ff:ff":
            return None

        # Normalize MAC address
        src_mac = src_mac.lower()

        # Extract SSID (may be empty for broadcast probes)
        ssid = self._extract_ssid(packet)

        # Extract additional info
        channel = self._extract_channel(packet)
        rssi = self._extract_rssi(packet)

        # Get timestamp
        timestamp = None
        if hasattr(packet, 'time'):
            try:
                timestamp = datetime.fromtimestamp(float(packet.time))
            except (ValueError, OSError):
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()

        # Update client profile
        profile = self._get_or_create_profile(src_mac)

        # Update timestamps
        if profile.first_seen is None:
            profile.first_seen = timestamp
        profile.last_seen = timestamp

        # Update probe count
        profile.total_probes += 1

        # Update PNL if directed probe (not broadcast)
        if ssid:
            profile.probed_ssids[ssid] = timestamp

        # Update channel tracking
        if channel is not None:
            profile.channels_seen.add(channel)

        # Update RSSI history (keep last 100)
        if rssi is not None:
            profile.rssi_history.append(rssi)
            if len(profile.rssi_history) > 100:
                profile.rssi_history = profile.rssi_history[-100:]

        # Update timestamp history for POL analysis (keep last 500)
        profile.timestamp_history.append(timestamp)
        if len(profile.timestamp_history) > 500:
            profile.timestamp_history = profile.timestamp_history[-500:]

        self._stats['intelligence_extracted'] += 1

        # Return extracted intelligence
        return {
            'type': 'probe_request',
            'src_mac': src_mac,
            'ssid': ssid,
            'channel': channel,
            'rssi': rssi,
            'timestamp': timestamp,
            'is_directed': ssid is not None,
            'is_randomized_mac': profile.is_randomized_mac,
        }

    def get_client_pnl(self, mac: str) -> ClientPNL | None:
        """Get PNL for a specific client MAC."""
        return self.client_profiles.get(mac.lower())

    def get_all_profiles(self) -> dict[str, ClientPNL]:
        """Get all client profiles."""
        return self.client_profiles.copy()

    def get_ssid_popularity(self) -> dict[str, int]:
        """
        Get popularity ranking of probed SSIDs.

        Returns:
            Dict mapping SSID to number of unique clients that probed for it
        """
        ssid_counts: dict[str, int] = defaultdict(int)
        for profile in self.client_profiles.values():
            for ssid in profile.probed_ssids:
                ssid_counts[ssid] += 1
        return dict(sorted(ssid_counts.items(), key=lambda x: -x[1]))

    def reset(self) -> None:
        """Reset agent state including all profiles."""
        super().reset()
        self.client_profiles.clear()


class AgentCartographer(BaseAgent):
    """
    Topology mapper agent ("Cartographer").

    Parses Beacons and Probe Responses to map APs and Clients.
    Updates topology based on Association Request/Response frames.
    """

    def __init__(self):
        super().__init__()
        self.name = "Cartographer"
        self.associations: dict[tuple, AssociationRecord] = {}

    def _extract_ssid(self, packet: 'Packet') -> str | None:
        """Extract SSID from packet's Information Elements."""
        try:
            if packet.haslayer(Dot11Elt):
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:  # SSID element
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        if ssid and ssid.strip():
                            return ssid
                        return None
                    elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None
        except Exception:
            pass
        return None

    def _get_timestamp(self, packet: 'Packet') -> datetime:
        if hasattr(packet, 'time'):
            try:
                return datetime.fromtimestamp(float(packet.time))
            except (ValueError, OSError):
                return datetime.now()
        return datetime.now()

    def _infer_association(self, packet: 'Packet') -> tuple | None:
        """Return (client, bssid, assoc_type, ssid, timestamp, trust) or None."""
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet.getlayer(Dot11)
        timestamp = self._get_timestamp(packet)
        ssid = self._extract_ssid(packet)

        # Management frames
        if dot11.type == 0:
            bssid = dot11.addr3
            client = None
            assoc_type = None

            if dot11.subtype in (0, 2):  # AssoReq, ReassoReq
                client = dot11.addr2
                assoc_type = "assoc_req"
            elif dot11.subtype in (1, 3):  # AssoResp, ReassoResp
                client = dot11.addr1
                assoc_type = "assoc_resp"
            elif dot11.subtype == 11:  # Auth
                client = dot11.addr2
                assoc_type = "auth"
            else:
                return None

            if _is_broadcast_or_multicast(client) or _is_broadcast_or_multicast(bssid):
                return None
            return (client, bssid, assoc_type, ssid, timestamp, "mgmt")

        # Data frames
        if dot11.type == 2:
            fc = dot11.FCfield
            to_ds = (fc & 0x01) != 0
            from_ds = (fc & 0x02) != 0
            if to_ds and from_ds:
                return None

            if to_ds and not from_ds:
                bssid = dot11.addr1
                client = dot11.addr2
            elif from_ds and not to_ds:
                bssid = dot11.addr2
                client = dot11.addr1
            else:
                return None

            if _is_broadcast_or_multicast(client) or _is_broadcast_or_multicast(bssid):
                return None
            return (client, bssid, "data", ssid, timestamp, "data")

        return None

    def process(self, packet: Any) -> dict[str, Any] | None:
        """Process packet for topology intelligence."""
        self._stats['packets_processed'] += 1
        if not SCAPY_AVAILABLE:
            return None

        result = self._infer_association(packet)
        if result is None:
            return None

        client, bssid, assoc_type, ssid, timestamp, trust = result
        client = client.lower()
        bssid = bssid.lower()
        key = (client, bssid)

        record = self.associations.get(key)
        if record is None:
            record = AssociationRecord(client_mac=client, bssid=bssid)
            self.associations[key] = record

        if assoc_type == "data" and record.has_mgmt:
            return None

        if trust == "mgmt":
            record.has_mgmt = True

        record.update(timestamp, assoc_type, ssid)
        self._stats['intelligence_extracted'] += 1

        return {
            'type': 'association',
            'client_mac': record.client_mac,
            'bssid': record.bssid,
            'ssid': record.ssid,
            'assoc_type': record.last_assoc_type,
            'timestamp': timestamp,
        }

    def export_associations(self) -> list[dict[str, Any]]:
        """Export association records for persistence."""
        output = []
        for record in self.associations.values():
            output.append({
                'client_mac': record.client_mac,
                'bssid': record.bssid,
                'ssid': record.ssid,
                'first_seen': record.first_seen,
                'last_seen': record.last_seen,
                'association_count': record.association_count,
                'assoc_type': record.last_assoc_type,
            })
        return output


class AgentCrypt(BaseAgent):
    """
    Secrets scavenger agent ("Crypt").

    Rescans for EAPOL handshakes (M1-M4) and PMKIDs that
    Trifecta might have missed due to timing issues.

    Integrates with nexus.eapol_parser for frame parsing.
    """

    # EAPOL ethertype
    EAPOL_ETHERTYPE = 0x888E

    # LLC/SNAP header for EAPOL over 802.11
    LLC_SNAP_EAPOL = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E])

    def __init__(self):
        super().__init__()
        self.name = "Crypt"

        # Lazy import to avoid circular dependencies
        self._parser = None

        # Track handshakes by BSSID
        self.handshakes: dict[str, HandshakeState] = {}

        # Track extracted PMKIDs (BSSID -> list of PMKIDs)
        self.pmkids: dict[str, list[str]] = defaultdict(list)

        # Statistics
        self._stats.update({
            'eapol_frames': 0,
            'm1_frames': 0,
            'm2_frames': 0,
            'm3_frames': 0,
            'm4_frames': 0,
            'pmkids_extracted': 0,
            'complete_handshakes': 0,
        })

    @property
    def parser(self) -> Optional["EAPOLParser"]:
        """Lazy-load the EAPOL parser."""
        if self._parser is None:
            try:
                from nexus.eapol_parser import EAPOLParser
                self._parser = EAPOLParser()
            except ImportError:
                self._parser = None
        return self._parser

    def _extract_eapol_data(self, packet: 'Packet') -> tuple | None:
        """
        Extract EAPOL data from a packet.

        Returns:
            Tuple of (eapol_data, src_mac, dst_mac, bssid, timestamp) or None
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            # Check for EAPOL layer
            if not packet.haslayer(Dot11):
                return None

            dot11 = packet.getlayer(Dot11)

            # Data frame: type=2
            if dot11.type != 2:
                return None

            # Get MAC addresses from frame
            # For data frames:
            # ToDS=0, FromDS=0: addr1=DA, addr2=SA, addr3=BSSID
            # ToDS=0, FromDS=1: addr1=DA, addr2=BSSID, addr3=SA
            # ToDS=1, FromDS=0: addr1=BSSID, addr2=SA, addr3=DA
            # ToDS=1, FromDS=1: addr1=RA, addr2=TA, addr3=DA, addr4=SA

            to_ds = dot11.FCfield & 0x01
            from_ds = (dot11.FCfield >> 1) & 0x01

            if to_ds == 0 and from_ds == 1:
                # From AP to client
                dst_mac = dot11.addr1
                bssid = dot11.addr2
                src_mac = dot11.addr3
            elif to_ds == 1 and from_ds == 0:
                # From client to AP
                bssid = dot11.addr1
                src_mac = dot11.addr2
                dst_mac = dot11.addr3
            else:
                # Use standard assignment
                dst_mac = dot11.addr1
                src_mac = dot11.addr2
                bssid = dot11.addr3

            # Look for LLC/SNAP header with EAPOL ethertype
            raw_payload = bytes(dot11.payload) if dot11.payload else b''

            # Skip QoS header if present (subtype 8 = QoS Data)
            if dot11.subtype == 8 and len(raw_payload) >= 2:
                raw_payload = raw_payload[2:]

            # Check for LLC/SNAP EAPOL
            if len(raw_payload) < 8:
                return None

            if raw_payload[:8] == self.LLC_SNAP_EAPOL:
                eapol_data = raw_payload[8:]
            elif raw_payload[:2] == bytes([0x88, 0x8E]):
                # Direct EAPOL ethertype
                eapol_data = raw_payload[2:]
            else:
                return None

            if len(eapol_data) < 4:
                return None

            # Get timestamp
            timestamp = float(packet.time) if hasattr(packet, 'time') else 0.0

            return (eapol_data, src_mac, dst_mac, bssid, timestamp)

        except Exception:
            return None

    def process(self, packet: 'Packet') -> dict[str, Any] | None:
        """
        Process packet for EAPOL handshake/PMKID intelligence.

        Args:
            packet: scapy Packet with 802.11 data frame

        Returns:
            Dict with handshake info if EAPOL found, None otherwise
        """
        self._stats['packets_processed'] += 1

        if not self.parser:
            return None

        # Try to extract EAPOL data
        result = self._extract_eapol_data(packet)
        if result is None:
            return None

        eapol_data, src_mac, dst_mac, bssid, timestamp = result

        # Parse the EAPOL frame
        frame = self.parser.parse_eapol_key(
            eapol_data, timestamp, src_mac, dst_mac, bssid
        )

        if frame is None:
            return None

        self._stats['eapol_frames'] += 1
        self._stats['intelligence_extracted'] += 1

        # Track by message number
        msg_num = frame.message_number
        if msg_num == 1:
            self._stats['m1_frames'] += 1
        elif msg_num == 2:
            self._stats['m2_frames'] += 1
        elif msg_num == 3:
            self._stats['m3_frames'] += 1
        elif msg_num == 4:
            self._stats['m4_frames'] += 1

        # Extract PMKID from M1 if present
        pmkid = None
        if frame.pmkid:
            pmkid = frame.pmkid
            if pmkid not in self.pmkids[bssid]:
                self.pmkids[bssid].append(pmkid)
                self._stats['pmkids_extracted'] += 1

        # Update handshake tracking
        if bssid not in self.handshakes:
            self.handshakes[bssid] = HandshakeState(bssid=bssid)

        hs_state = self.handshakes[bssid]
        was_complete = hs_state.is_complete
        hs_state.add_message(frame)

        # Check if we just completed a handshake
        if not was_complete and hs_state.is_complete:
            self._stats['complete_handshakes'] += 1

        return {
            'type': 'eapol',
            'bssid': bssid,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'message_number': msg_num,
            'timestamp': datetime.fromtimestamp(timestamp) if timestamp > 0 else datetime.now(),
            'pmkid': pmkid,
            'anonce': frame.key_nonce.hex() if msg_num in (1, 3) else None,
            'snonce': frame.key_nonce.hex() if msg_num == 2 else None,
            'has_mic': frame.has_mic,
            'pairwise': frame.is_pairwise,
        }

    def get_handshake_state(self, bssid: str) -> Optional['HandshakeState']:
        """Get handshake state for a BSSID."""
        return self.handshakes.get(bssid.lower() if bssid else None)

    def get_complete_handshakes(self) -> list[str]:
        """Get list of BSSIDs with complete handshakes."""
        return [
            bssid for bssid, state in self.handshakes.items()
            if state.is_complete
        ]

    def get_pmkids(self, bssid: str = None) -> dict[str, list[str]]:
        """
        Get extracted PMKIDs.

        Args:
            bssid: Optional filter by BSSID

        Returns:
            Dict mapping BSSID to list of PMKIDs
        """
        if bssid:
            return {bssid: self.pmkids.get(bssid.lower(), [])}
        return dict(self.pmkids)

    def reset(self) -> None:
        """Reset agent state."""
        super().reset()
        self.handshakes.clear()
        self.pmkids.clear()
        self._stats.update({
            'eapol_frames': 0,
            'm1_frames': 0,
            'm2_frames': 0,
            'm3_frames': 0,
            'm4_frames': 0,
            'pmkids_extracted': 0,
            'complete_handshakes': 0,
        })


@dataclass
class HandshakeState:
    """
    Tracks the state of a 4-way handshake for a specific BSSID.
    """
    bssid: str
    m1_frame: Any = None
    m2_frame: Any = None
    m3_frame: Any = None
    m4_frame: Any = None
    client_mac: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def is_complete(self) -> bool:
        """Check if we have enough for a crackable handshake."""
        # Need M1 (ANonce) + M2 (SNonce, MIC) at minimum
        return self.m1_frame is not None and self.m2_frame is not None

    @property
    def has_all_four(self) -> bool:
        """Check if all 4 messages are captured."""
        return all([self.m1_frame, self.m2_frame, self.m3_frame, self.m4_frame])

    def add_message(self, frame: Any) -> None:
        """Add a handshake message to the state."""
        now = datetime.now()
        if self.first_seen is None:
            self.first_seen = now
        self.last_seen = now

        msg_num = frame.message_number

        # Track client MAC from M2 (client -> AP)
        if msg_num == 2 and frame.src_mac:
            self.client_mac = frame.src_mac

        if msg_num == 1:
            self.m1_frame = frame
        elif msg_num == 2:
            self.m2_frame = frame
        elif msg_num == 3:
            self.m3_frame = frame
        elif msg_num == 4:
            self.m4_frame = frame

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'bssid': self.bssid,
            'client_mac': self.client_mac,
            'has_m1': self.m1_frame is not None,
            'has_m2': self.m2_frame is not None,
            'has_m3': self.m3_frame is not None,
            'has_m4': self.m4_frame is not None,
            'is_complete': self.is_complete,
            'has_all_four': self.has_all_four,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }


class AgentSnoopy(BaseAgent):
    """
    Metadata extractor agent ("Snoopy").

    Looks for DNS queries, User-Agents, and other cleartext
    data leaks in captured traffic.
    """

    def __init__(self):
        super().__init__()
        self.name = "Snoopy"
        # To be implemented in future milestone

    def process(self, packet: Any) -> dict[str, Any] | None:
        """Process packet for metadata intelligence."""
        self._stats['packets_processed'] += 1
        # Placeholder - will be implemented in future milestone
        return None
