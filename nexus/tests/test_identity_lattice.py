"""
Unit tests for Identity Lattice.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


import pytest

from nexus.intel.identity_lattice import DeviceIdentity, IdentityLattice, Observation


@pytest.fixture
def lattice():
    """Create a fresh lattice for each test."""
    return IdentityLattice(max_identities=100)


class TestObservation:
    """Test the Observation dataclass."""

    def test_basic_observation(self):
        obs = Observation(
            mac="AA:BB:CC:DD:EE:FF",
            fingerprint_hash="abc123",
            rssi=-50,
            timestamp=1000.0,
        )
        assert obs.mac == "AA:BB:CC:DD:EE:FF"
        assert obs.fingerprint_hash == "abc123"
        assert obs.rssi == -50


class TestDeviceIdentity:
    """Test the DeviceIdentity dataclass."""

    def test_add_observation(self):
        identity = DeviceIdentity()
        obs = Observation(
            mac="AA:BB:CC:DD:EE:FF",
            fingerprint_hash="abc123",
            rssi=-50,
            timestamp=1000.0,
        )
        identity.add_observation(obs)

        assert "AA:BB:CC:DD:EE:FF" in identity.macs
        assert identity.observation_count == 1
        assert len(identity.observations) == 1

    def test_observation_limit(self):
        """Observations should be bounded to 100."""
        identity = DeviceIdentity()
        for i in range(150):
            obs = Observation(
                mac=f"AA:BB:CC:DD:EE:{i:02X}",
                fingerprint_hash="abc123",
                rssi=-50,
                timestamp=float(i),
            )
            identity.add_observation(obs)

        assert identity.observation_count == 150
        assert len(identity.observations) == 100  # Bounded


class TestIdentityLattice:
    """Test the IdentityLattice class."""

    def test_new_observation_creates_identity(self, lattice):
        """First observation of a MAC creates a new identity."""
        identity = lattice.observe(
            mac="AA:BB:CC:DD:EE:FF",
            fingerprint_hash="fp1",
            rssi=-50,
        )

        assert identity is not None
        assert "AA:BB:CC:DD:EE:FF" in identity.macs
        assert identity.fingerprint_hash == "fp1"

        stats = lattice.get_stats()
        assert stats["total_identities"] == 1
        assert stats["total_macs"] == 1

    def test_fingerprint_links_macs(self, lattice):
        """MACs with same fingerprint should be linked to same identity."""
        id1 = lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash="fp1")
        id2 = lattice.observe(mac="AA:BB:CC:DD:EE:02", fingerprint_hash="fp1")
        id3 = lattice.observe(mac="AA:BB:CC:DD:EE:03", fingerprint_hash="fp1")

        # All should be the same identity
        assert id1.id == id2.id == id3.id
        assert len(id1.macs) == 3

        stats = lattice.get_stats()
        assert stats["total_identities"] == 1
        assert stats["total_macs"] == 3
        assert stats["compression_ratio"] == 3.0

    def test_different_fingerprints_separate_identities(self, lattice):
        """MACs with different fingerprints should be separate identities."""
        id1 = lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash="fp1")
        id2 = lattice.observe(mac="AA:BB:CC:DD:EE:02", fingerprint_hash="fp2")

        assert id1.id != id2.id

        stats = lattice.get_stats()
        assert stats["total_identities"] == 2

    def test_resolve_known_mac(self, lattice):
        """resolve() should return identity for known MAC."""
        lattice.observe(mac="AA:BB:CC:DD:EE:FF", fingerprint_hash="fp1")

        identity = lattice.resolve("AA:BB:CC:DD:EE:FF")
        assert identity is not None
        assert identity.fingerprint_hash == "fp1"

    def test_resolve_unknown_mac(self, lattice):
        """resolve() should return None for unknown MAC."""
        identity = lattice.resolve("AA:BB:CC:DD:EE:FF")
        assert identity is None

    def test_mac_case_insensitive(self, lattice):
        """MAC addresses should be normalized to uppercase."""
        id1 = lattice.observe(mac="aa:bb:cc:dd:ee:ff", fingerprint_hash="fp1")
        id2 = lattice.observe(mac="AA:BB:CC:DD:EE:FF", fingerprint_hash="fp1")

        assert id1.id == id2.id
        assert "AA:BB:CC:DD:EE:FF" in id1.macs

    def test_manual_merge(self, lattice):
        """merge() should combine two identities."""
        id1 = lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash="fp1")
        id2 = lattice.observe(mac="AA:BB:CC:DD:EE:02", fingerprint_hash="fp2")

        # Before merge: 2 identities
        assert lattice.get_stats()["total_identities"] == 2

        merged = lattice.merge(id1.id, id2.id)

        # After merge: 1 identity with 2 MACs
        assert merged is not None
        assert len(merged.macs) == 2
        assert lattice.get_stats()["total_identities"] == 1

        # Both MACs should resolve to the merged identity
        assert lattice.resolve("AA:BB:CC:DD:EE:01").id == merged.id
        assert lattice.resolve("AA:BB:CC:DD:EE:02").id == merged.id

    def test_lru_eviction(self):
        """LRU eviction should work when over capacity."""
        lattice = IdentityLattice(max_identities=5)

        # Add 10 identities (each with unique fingerprint)
        for i in range(10):
            lattice.observe(
                mac=f"AA:BB:CC:DD:EE:{i:02X}",
                fingerprint_hash=f"fp{i}",
            )

        stats = lattice.get_stats()
        assert stats["total_identities"] == 5  # Bounded

        # First 5 should be evicted, last 5 should remain
        assert lattice.resolve("AA:BB:CC:DD:EE:00") is None  # Evicted
        assert lattice.resolve("AA:BB:CC:DD:EE:09") is not None  # Kept

    def test_get_all_identities_ordered(self, lattice):
        """get_all_identities() should return newest first."""
        lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash="fp1", timestamp=100.0)
        lattice.observe(mac="AA:BB:CC:DD:EE:02", fingerprint_hash="fp2", timestamp=200.0)
        lattice.observe(mac="AA:BB:CC:DD:EE:03", fingerprint_hash="fp3", timestamp=150.0)

        identities = lattice.get_all_identities()

        assert len(identities) == 3
        assert identities[0].last_seen == 200.0
        assert identities[1].last_seen == 150.0
        assert identities[2].last_seen == 100.0

    def test_observation_without_fingerprint(self, lattice):
        """MACs without fingerprints should create separate identities."""
        id1 = lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash=None)
        id2 = lattice.observe(mac="AA:BB:CC:DD:EE:02", fingerprint_hash=None)

        # Without fingerprints, each MAC is a separate identity
        assert id1.id != id2.id

        # Subsequent observation of same MAC should use existing identity
        id3 = lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash=None)
        assert id3.id == id1.id

    def test_fingerprint_added_later(self, lattice):
        """If a fingerprint is added later, it should be registered."""
        id1 = lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash=None)
        assert id1.fingerprint_hash is None

        # Later observation with fingerprint
        id2 = lattice.observe(mac="AA:BB:CC:DD:EE:01", fingerprint_hash="fp1")
        assert id2.id == id1.id
        assert id2.fingerprint_hash == "fp1"

        # Now another MAC with same fingerprint should link
        id3 = lattice.observe(mac="AA:BB:CC:DD:EE:02", fingerprint_hash="fp1")
        assert id3.id == id1.id
