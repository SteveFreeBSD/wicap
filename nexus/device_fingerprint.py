"""
NEXUS Device Fingerprinter

Identifies and profiles wireless devices based on probe requests,
Information Elements, and behavioral patterns. Detects MAC randomization
and builds client profiles for security analysis.
"""

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False

from .config import NexusConfig, get_nexus_config
from .oui_database import OUI_DATABASE

logger = logging.getLogger('nexus.device_fingerprint')


# ═══════════════════════════════════════════════════════════════════════════════
# OUI Database - IEEE Organizationally Unique Identifier Registry
# ═══════════════════════════════════════════════════════════════════════════════
# MAC randomization detection patterns
# Locally administered bit (bit 1 of first octet) indicates randomized MAC
LOCALLY_ADMINISTERED_MASK = 0x02


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProbeRequest:
    """A probe request seen from a device."""
    timestamp: float
    ssid: str
    channel: int
    rssi: int | None = None
    ie_tags: list[int] = field(default_factory=list)


@dataclass
class DeviceFingerprint:
    """Unique fingerprint composed of IE tags and behavior."""
    ie_hash: str
    supported_rates: list[int] = field(default_factory=list)
    extended_rates: list[int] = field(default_factory=list)
    ht_capabilities: str | None = None
    vht_capabilities: str | None = None
    vendor_specific: list[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.ie_hash)


@dataclass
class ClientProfile:
    """Complete profile of a wireless client device."""
    mac_address: str

    # Identity
    vendor: str | None = None
    device_type: str | None = None  # phone, laptop, iot, ap
    device_family: str | None = None  # iPhone, Galaxy, etc.
    is_randomized_mac: bool = False

    # Fingerprint
    fingerprint: DeviceFingerprint | None = None
    fingerprint_confidence: float = 0.0

    # Behavior
    probed_ssids: set[str] = field(default_factory=set)
    connected_bssids: set[str] = field(default_factory=set)
    channels_seen: set[int] = field(default_factory=set)

    # Timing
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_frames: int = 0

    # Location/signal
    avg_rssi: int | None = None
    strongest_rssi: int | None = None

    # Threat indicators
    threat_score: int = 0
    threat_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            'mac_address': self.mac_address,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'device_family': self.device_family,
            'is_randomized_mac': self.is_randomized_mac,
            'fingerprint_hash': self.fingerprint.ie_hash if self.fingerprint else None,
            'fingerprint_confidence': self.fingerprint_confidence,
            'probed_ssids': list(self.probed_ssids),
            'connected_bssids': list(self.connected_bssids),
            'channels_seen': list(self.channels_seen),
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'total_frames': self.total_frames,
            'avg_rssi': self.avg_rssi,
            'strongest_rssi': self.strongest_rssi,
            'threat_score': self.threat_score,
            'threat_factors': self.threat_factors,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Device Fingerprinter Class
# ═══════════════════════════════════════════════════════════════════════════════

class DeviceFingerprinter:
    """
    Identifies and profiles wireless devices based on their behavior
    and Information Element fingerprints.
    """

    def __init__(self, config: NexusConfig | None = None):
        self.config = config or get_nexus_config()
        self._conn: pyodbc.Connection | None = None

        # In-memory profile cache
        self._profiles: dict[str, ClientProfile] = {}

        # RSSI tracking for averaging
        self._rssi_samples: dict[str, list[int]] = defaultdict(list)

    def _get_connection(self) -> 'pyodbc.Connection':
        """Get or create SQL connection."""
        if not PYODBC_AVAILABLE:
            raise ImportError("pyodbc is required")

        needs_reconnect = self._conn is None
        if not needs_reconnect:
            try:
                needs_reconnect = getattr(self._conn, 'closed', False)
            except Exception:
                needs_reconnect = True

        if needs_reconnect:
            self._conn = pyodbc.connect(
                self.config.get_sql_connection_string(),
                autocommit=False
            )
        return self._conn

    def close(self) -> None:
        """Close SQL connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def lookup_vendor(self, mac: str) -> str | None:
        """
        Look up vendor from MAC address OUI.

        Args:
            mac: MAC address in any format

        Returns:
            Vendor name or None
        """
        # Normalize MAC
        mac_clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')
        if len(mac_clean) < 6:
            return None

        # Try OUI lookup (first 3 bytes = 6 hex chars)
        oui = f'{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}'
        return OUI_DATABASE.get(oui)

    def is_randomized_mac(self, mac: str) -> bool:
        """
        Check if MAC address is locally administered (randomized).

        A locally administered MAC has the second-least-significant bit
        of the first octet set to 1.

        Args:
            mac: MAC address

        Returns:
            True if MAC is randomized
        """
        mac_clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')
        if len(mac_clean) < 2:
            return False

        try:
            first_octet = int(mac_clean[0:2], 16)
            return bool(first_octet & LOCALLY_ADMINISTERED_MASK)
        except ValueError:
            return False

    def create_fingerprint(
        self,
        ie_tags: list[int],
        supported_rates: list[int] | None = None,
        extended_rates: list[int] | None = None,
        ht_caps: str | None = None,
        vht_caps: str | None = None,
        vendor_ies: list[str] | None = None,
    ) -> DeviceFingerprint:
        """
        Create a device fingerprint from Information Elements.

        Args:
            ie_tags: List of IE tag numbers present in frame
            supported_rates: Supported rates from IE 1
            extended_rates: Extended rates from IE 50
            ht_caps: HT Capabilities (IE 45) as hex
            vht_caps: VHT Capabilities (IE 191) as hex
            vendor_ies: Vendor-specific IEs as hex strings

        Returns:
            DeviceFingerprint object
        """
        # Create hash from ordered IE tags
        ie_str = ','.join(str(t) for t in sorted(ie_tags))
        ie_hash = hashlib.sha256(ie_str.encode()).hexdigest()[:16]

        return DeviceFingerprint(
            ie_hash=ie_hash,
            supported_rates=supported_rates or [],
            extended_rates=extended_rates or [],
            ht_capabilities=ht_caps,
            vht_capabilities=vht_caps,
            vendor_specific=vendor_ies or [],
        )

    def get_or_create_profile(self, mac: str) -> ClientProfile:
        """
        Get existing profile or create new one.

        Args:
            mac: MAC address

        Returns:
            ClientProfile for this MAC
        """
        mac_upper = mac.upper()

        if mac_upper not in self._profiles:
            self._profiles[mac_upper] = ClientProfile(
                mac_address=mac_upper,
                vendor=self.lookup_vendor(mac_upper),
                is_randomized_mac=self.is_randomized_mac(mac_upper),
                first_seen=datetime.now(),
            )

        return self._profiles[mac_upper]

    def update_from_probe_request(
        self,
        mac: str,
        ssid: str | None,
        channel: int,
        rssi: int | None = None,
        ie_tags: list[int] | None = None,
        timestamp: float | None = None,
    ) -> ClientProfile:
        """
        Update client profile from a probe request frame.

        Args:
            mac: Source MAC address
            ssid: Probed SSID (None for broadcast)
            channel: Channel frame was captured on
            rssi: Signal strength
            ie_tags: Information Element tags present
            timestamp: Frame timestamp

        Returns:
            Updated ClientProfile
        """
        profile = self.get_or_create_profile(mac)

        # Update SSID list
        if ssid:
            profile.probed_ssids.add(ssid)

        # Update channels
        profile.channels_seen.add(channel)

        # Update timing
        profile.total_frames += 1
        profile.last_seen = datetime.now()

        # Update RSSI
        if rssi is not None:
            self._rssi_samples[mac.upper()].append(rssi)
            samples = self._rssi_samples[mac.upper()][-100:]  # Keep last 100
            profile.avg_rssi = sum(samples) // len(samples)
            profile.strongest_rssi = max(samples)

        # Update fingerprint
        if ie_tags:
            profile.fingerprint = self.create_fingerprint(ie_tags)
            profile.fingerprint_confidence = min(1.0, profile.total_frames / 10.0)

        # Calculate threat score
        self._update_threat_score(profile)

        return profile

    def update_from_data_frame(
        self,
        src_mac: str,
        dst_mac: str,
        bssid: str,
        channel: int,
        rssi: int | None = None,
    ) -> ClientProfile | None:
        """
        Update profile from a data frame (indicates connection).

        Args:
            src_mac: Source MAC
            dst_mac: Destination MAC
            bssid: BSSID of the network
            channel: Channel
            rssi: Signal strength

        Returns:
            Updated ClientProfile for the client (non-AP) party
        """
        # Determine which MAC is the client
        if src_mac.upper() == bssid.upper():
            client_mac = dst_mac  # Traffic from AP to client
        else:
            client_mac = src_mac  # Traffic from client to AP

        profile = self.get_or_create_profile(client_mac)

        # Record connection
        profile.connected_bssids.add(bssid.upper())
        profile.channels_seen.add(channel)
        profile.total_frames += 1
        profile.last_seen = datetime.now()

        # Update RSSI
        if rssi is not None:
            self._rssi_samples[client_mac.upper()].append(rssi)
            samples = self._rssi_samples[client_mac.upper()][-100:]
            profile.avg_rssi = sum(samples) // len(samples)
            profile.strongest_rssi = max(samples)

        return profile

    def _update_threat_score(self, profile: ClientProfile) -> None:
        """
        Calculate threat score for a client based on behavior.

        Threat indicators:
        - Many probed SSIDs (information leakage)
        - Randomized MAC with many probes (recon)
        - Strong signal but no connections (sniffing)
        - Probing sensitive network names
        """
        profile.threat_factors = []
        score = 0

        # Many probed SSIDs = information leakage
        if len(profile.probed_ssids) > 20:
            score += 30
            profile.threat_factors.append('EXCESSIVE_PROBING')
        elif len(profile.probed_ssids) > 10:
            score += 15
            profile.threat_factors.append('HIGH_PROBE_COUNT')

        # Randomized MAC with heavy probing = potential recon
        if profile.is_randomized_mac and len(profile.probed_ssids) > 5:
            score += 25
            profile.threat_factors.append('RANDOMIZED_RECON')

        # Strong signal but no connections = possible passive sniffing
        if profile.strongest_rssi and profile.strongest_rssi > -50:
            if not profile.connected_bssids:
                score += 20
                profile.threat_factors.append('STRONG_UNCONNECTED')

        # Probing for known attack tool SSIDs
        suspicious_ssids = {
            'FreeWifi', 'FREE_WIFI', 'Free WiFi',
            'STARBUCKS', 'attwifi', 'xfinitywifi',
            'GoogleStarbucks', 'Marriott_Guest', 'HiltonHonors',
        }
        if profile.probed_ssids & suspicious_ssids:
            score += 15
            profile.threat_factors.append('SUSPICIOUS_PROBES')

        # Probing many channels rapidly
        if len(profile.channels_seen) > 10:
            score += 10
            profile.threat_factors.append('CHANNEL_HOPPING')

        profile.threat_score = min(100, score)

    def infer_device_type(self, profile: ClientProfile) -> str:
        """
        Infer device type from vendor and behavior.

        Returns: 'phone', 'laptop', 'tablet', 'iot', 'ap', 'unknown'
        """
        vendor = (profile.vendor or '').lower()

        # Helper for substring matching
        def _matches(keywords):
            return any(k in vendor for k in keywords)

        # Phone vendors
        if _matches(['apple', 'samsung', 'google', 'oneplus', 'xiaomi', 'huawei', 'oppo', 'vivo', 'lg electronics', 'motorola']):
            # Could be phone or tablet
            # Phones typically probe more SSIDs
            if len(profile.probed_ssids) > 3:
                return 'phone'
            return 'mobile'  # Phone or tablet

        # IoT vendors
        if _matches(['amazon', 'ring', 'nest', 'wyze', 'tuya', 'espressif', 'shenzhen', 'belkin', 'wemo', 'philips lighting']):
            return 'iot'

        # Streaming devices
        if _matches(['roku', 'apple tv', 'chromecast', 'fire tv', 'nvidia', 'sonos']):
            return 'streaming'

        # Network equipment
        if _matches(['cisco', 'netgear', 'tp-link', 'ubiquiti', 'arris', 'calix', 'ruckus', 'mist', 'aruba', 'mikrotik']):
            return 'network'

        # Laptop makers
        if _matches(['intel', 'microsoft', 'dell', 'hp', 'lenovo', 'asus', 'acer', 'msi', 'razer']):
            return 'laptop'

        # Randomized MACs are usually phones
        if profile.is_randomized_mac:
            return 'phone'

        return 'unknown'

    def get_all_profiles(self) -> list[ClientProfile]:
        """Get all tracked client profiles."""
        return list(self._profiles.values())

    def get_high_threat_clients(self, min_score: int = 30) -> list[ClientProfile]:
        """Get clients with threat score above threshold."""
        return [p for p in self._profiles.values() if p.threat_score >= min_score]

    def save_profile(self, profile: ClientProfile) -> bool:
        """
        Save client profile to SQL database.

        Returns True on success.
        """
        if not PYODBC_AVAILABLE:
            logger.warning("pyodbc not available, cannot save profile")
            return False

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                MERGE INTO client_profiles AS target
                USING (SELECT ? AS mac_addr) AS source
                ON target.mac_addr = source.mac_addr
                WHEN MATCHED THEN
                    UPDATE SET
                        vendor = ?,
                        device_type = ?,
                        device_family = ?,
                        is_randomized = ?,
                        fingerprint_hash = ?,
                        probed_ssids = ?,
                        connected_bssids = ?,
                        channels_seen = ?,
                        first_seen = COALESCE(target.first_seen, ?),
                        last_seen = ?,
                        total_frames = ?,
                        avg_rssi = ?,
                        strongest_rssi = ?,
                        threat_score = ?,
                        threat_factors = ?,
                        updated_at = SYSDATETIME()
                WHEN NOT MATCHED THEN
                    INSERT (mac_addr, vendor, device_type, device_family, is_randomized,
                            fingerprint_hash, probed_ssids, connected_bssids, channels_seen,
                            first_seen, last_seen, total_frames, avg_rssi, strongest_rssi,
                            threat_score, threat_factors)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                # USING clause
                profile.mac_address,
                # UPDATE SET values
                profile.vendor,
                profile.device_type or self.infer_device_type(profile),
                profile.device_family,
                1 if profile.is_randomized_mac else 0,
                profile.fingerprint.ie_hash if profile.fingerprint else None,
                json.dumps(list(profile.probed_ssids)),
                json.dumps(list(profile.connected_bssids)),
                json.dumps(list(profile.channels_seen)),
                profile.first_seen,
                profile.last_seen,
                profile.total_frames,
                profile.avg_rssi,
                profile.strongest_rssi,
                profile.threat_score,
                json.dumps(profile.threat_factors),
                # INSERT values
                profile.mac_address,
                profile.vendor,
                profile.device_type or self.infer_device_type(profile),
                profile.device_family,
                1 if profile.is_randomized_mac else 0,
                profile.fingerprint.ie_hash if profile.fingerprint else None,
                json.dumps(list(profile.probed_ssids)),
                json.dumps(list(profile.connected_bssids)),
                json.dumps(list(profile.channels_seen)),
                profile.first_seen,
                profile.last_seen,
                profile.total_frames,
                profile.avg_rssi,
                profile.strongest_rssi,
                profile.threat_score,
                json.dumps(profile.threat_factors),
            ))
            conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save profile {profile.mac_address}: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()

    def save_all_profiles(self) -> int:
        """Save all profiles to database. Returns count saved."""
        saved = 0
        for profile in self._profiles.values():
            if self.save_profile(profile):
                saved += 1
        return saved

    def get_stats(self) -> dict:
        """Get fingerprinter statistics."""
        profiles = list(self._profiles.values())
        randomized = sum(1 for p in profiles if p.is_randomized_mac)
        high_threat = sum(1 for p in profiles if p.threat_score >= 30)

        # Device type breakdown
        types = defaultdict(int)
        for p in profiles:
            dtype = p.device_type or self.infer_device_type(p)
            types[dtype] += 1

        return {
            'total_clients': len(profiles),
            'randomized_macs': randomized,
            'high_threat': high_threat,
            'by_device_type': dict(types),
            'unique_vendors': len({p.vendor for p in profiles if p.vendor}),
        }


def main() -> None:
    """CLI entry point."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    parser = argparse.ArgumentParser(description='NEXUS Device Fingerprinter')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # lookup command
    lookup_parser = subparsers.add_parser('lookup', help='Look up MAC vendor')
    lookup_parser.add_argument('mac', help='MAC address')

    # check command
    check_parser = subparsers.add_parser('check', help='Check if MAC is randomized')
    check_parser.add_argument('mac', help='MAC address')

    # stats command
    subparsers.add_parser('stats', help='Show profiler statistics')

    args = parser.parse_args()

    config = get_nexus_config()
    fingerprinter = DeviceFingerprinter(config)

    try:
        if args.command == 'lookup':
            vendor = fingerprinter.lookup_vendor(args.mac)
            randomized = fingerprinter.is_randomized_mac(args.mac)
            print(f"MAC: {args.mac}")
            print(f"Vendor: {vendor or 'Unknown'}")
            print(f"Randomized: {'Yes' if randomized else 'No'}")

        elif args.command == 'check':
            randomized = fingerprinter.is_randomized_mac(args.mac)
            print(f"{'✅ Randomized MAC' if randomized else '❌ Not randomized'}")

        elif args.command == 'stats':
            stats = fingerprinter.get_stats()
            print("\n📊 Device Fingerprinter Statistics")
            print(f"   Total clients: {stats['total_clients']}")
            print(f"   Randomized MACs: {stats['randomized_macs']}")
            print(f"   High threat: {stats['high_threat']}")
            print(f"   Unique vendors: {stats['unique_vendors']}")
            if stats['by_device_type']:
                print("\n   By Device Type:")
                for dtype, count in stats['by_device_type'].items():
                    print(f"     {dtype}: {count}")

        else:
            parser.print_help()

    finally:
        fingerprinter.close()


if __name__ == '__main__':
    main()
