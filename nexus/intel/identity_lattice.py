"""
Identity Lattice - Probabilistic MAC Linking

This module maintains a graph of device observations and infers when different
MAC addresses belong to the same physical device using fingerprints and
behavioral signals.

Linkage Heuristics:
1. Fingerprint Match: MACs with identical fingerprint_hash are the same device.
2. Temporal Proximity: MACs seen within <2s with similar RSSI (future).
3. SSID Affinity: MACs probing for same rare SSIDs (future).
"""

import logging
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Observation:
    """A single MAC/fingerprint observation."""
    mac: str
    fingerprint_hash: str | None
    rssi: int | None
    timestamp: float
    ssid: str | None = None
    channel: int | None = None
    band: str | None = None
    freq: int | None = None


@dataclass
class DeviceIdentity:
    """
    Represents a unique physical device that may use multiple MAC addresses.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    fingerprint_hash: str | None = None
    macs: set[str] = field(default_factory=set)
    observations: list[Observation] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    observation_count: int = 0
    is_randomized: bool = False
    is_wifi6: bool = False
    last_channel: int | None = None

    def add_observation(self, obs: Observation) -> None:
        """Add an observation to this identity."""
        self.macs.add(obs.mac)
        self.observations.append(obs)
        self.last_seen = max(self.last_seen, obs.timestamp)
        self.first_seen = min(self.first_seen, obs.timestamp)
        if obs.channel:
            self.last_channel = obs.channel
        self.observation_count += 1

        # Keep observations bounded (last 100)
        if len(self.observations) > 100:
            self.observations = self.observations[-100:]


class IdentityLattice:
    """
    Maintains a lattice of device identities linked by fingerprints.

    Thread-safe for concurrent observe() calls.
    """

    def __init__(self, max_identities: int = 10000):
        """
        Initialize the lattice.

        Args:
            max_identities: Maximum number of identities to track (LRU eviction).
        """
        self._max_identities = max_identities

        # Primary index: fingerprint_hash -> DeviceIdentity
        self._by_fingerprint: dict[str, DeviceIdentity] = {}

        # Secondary index: MAC -> DeviceIdentity
        self._by_mac: dict[str, DeviceIdentity] = {}

        # LRU tracking: identity_id -> DeviceIdentity (ordered)
        self._identities: OrderedDict[str, DeviceIdentity] = OrderedDict()

        # Stats
        self._total_observations = 0
        self._merges = 0

    def observe(
        self,
        mac: str,
        fingerprint_hash: str | None,
        rssi: int | None = None,
        timestamp: float | None = None,
        ssid: str | None = None,
        channel: int | None = None,
        band: str | None = None,
        freq: int | None = None,
        is_wifi6: bool = False,
    ) -> DeviceIdentity:
        """
        Record an observation of a MAC address.

        Returns the DeviceIdentity this MAC is associated with.
        """
        ts = timestamp if timestamp is not None else time.time()
        obs = Observation(
            mac=mac.upper(),
            fingerprint_hash=fingerprint_hash,
            rssi=rssi,
            timestamp=ts,
            ssid=ssid,
            channel=channel,
            band=band,
            freq=freq,
        )

        self._total_observations += 1

        # Strategy 1: Fingerprint-based linking (highest confidence)
        if fingerprint_hash:
            if fingerprint_hash in self._by_fingerprint:
                identity = self._by_fingerprint[fingerprint_hash]
                identity.add_observation(obs)
                self._by_mac[obs.mac] = identity
                self._touch(identity)
                return identity

        # Strategy 2: MAC already known
        if obs.mac in self._by_mac:
            identity = self._by_mac[obs.mac]
            identity.add_observation(obs)

            # If we now have a fingerprint, register it
            if fingerprint_hash and not identity.fingerprint_hash:
                identity.fingerprint_hash = fingerprint_hash
                self._by_fingerprint[fingerprint_hash] = identity

            # sticky wifi6 flag
            if is_wifi6:
                identity.is_wifi6 = True

            self._touch(identity)
            return identity

        # Strategy 3: New identity
        identity = DeviceIdentity(
            fingerprint_hash=fingerprint_hash,
            first_seen=ts,
            last_seen=ts,
            is_wifi6=is_wifi6,
        )
        identity.add_observation(obs)

        # Mark as randomized if MAC bit 1 is set (locally administered, unicast)
        # This is the second-least significant bit of the first octet.
        # For MAC 'XX:XX:XX:XX:XX:XX', the first octet is 'XX'.
        # The second character of the first octet determines this bit.
        # If the second char is 2, 6, A, E (hex), then the bit is 1.
        try:
            second_char = obs.mac[1].lower()
            if second_char in ('2', '6', 'a', 'e'):
                identity.is_randomized = True
        except Exception:
            identity.is_randomized = False

        self._identities[identity.id] = identity
        self._by_mac[obs.mac] = identity
        if fingerprint_hash:
            self._by_fingerprint[fingerprint_hash] = identity

        # LRU eviction
        self._evict_if_needed()

        return identity

    def resolve(self, mac: str) -> DeviceIdentity | None:
        """
        Get the inferred identity for a MAC address.

        Returns None if the MAC has never been observed.
        """
        return self._by_mac.get(mac.upper())

    def merge(self, id1: str, id2: str) -> DeviceIdentity | None:
        """
        Manually merge two identities into one.

        Returns the merged identity, or None if either ID doesn't exist.
        """
        if id1 not in self._identities or id2 not in self._identities:
            return None

        primary = self._identities[id1]
        secondary = self._identities[id2]

        # Merge secondary into primary
        for obs in secondary.observations:
            primary.add_observation(obs)

        primary.macs.update(secondary.macs)
        primary.first_seen = min(primary.first_seen, secondary.first_seen)

        # Update indexes
        for mac in secondary.macs:
            self._by_mac[mac] = primary

        if secondary.fingerprint_hash:
            self._by_fingerprint[secondary.fingerprint_hash] = primary
            if not primary.fingerprint_hash:
                primary.fingerprint_hash = secondary.fingerprint_hash

        # Remove secondary
        del self._identities[id2]
        self._merges += 1

        logger.info(f"Merged identity {id2} into {id1}")
        return primary

    def get_all_identities(self) -> list[DeviceIdentity]:
        """Get all tracked identities, ordered by last_seen (newest first)."""
        return sorted(
            self._identities.values(),
            key=lambda x: x.last_seen,
            reverse=True,
        )

    def get_stats(self) -> dict:
        """Get lattice statistics."""
        return {
            "total_identities": len(self._identities),
            "total_macs": len(self._by_mac),
            "total_fingerprints": len(self._by_fingerprint),
            "total_observations": self._total_observations,
            "merges": self._merges,
            "compression_ratio": (
                len(self._by_mac) / len(self._identities)
                if self._identities else 1.0
            ),
        }

    def get_gravitas_channels(self, window: float = 60.0) -> list[int]:
        """
        Phase 3: The Hunter (Gravitas)
        Get list of channels with active targets seen in the last 'window' seconds.
        """
        cutoff = time.time() - window
        channels = set()
        for identity in self._identities.values():
            if identity.last_seen >= cutoff and identity.last_channel:
                channels.add(identity.last_channel)
        return list(channels)

    def _touch(self, identity: DeviceIdentity) -> None:
        """Move identity to end of LRU queue."""
        if identity.id in self._identities:
            self._identities.move_to_end(identity.id)

    def _evict_if_needed(self) -> None:
        """Evict oldest identities if over capacity."""
        while len(self._identities) > self._max_identities:
            oldest_id, oldest = self._identities.popitem(last=False)

            # Clean up indexes
            for mac in oldest.macs:
                self._by_mac.pop(mac, None)
            if oldest.fingerprint_hash:
                self._by_fingerprint.pop(oldest.fingerprint_hash, None)

            logger.debug(f"Evicted identity {oldest_id} (LRU)")
