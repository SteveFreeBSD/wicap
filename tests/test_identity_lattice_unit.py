"""Unit tests for Identity Lattice."""
import time

import pytest

from nexus.intel.identity_lattice import IdentityLattice


class TestIdentityLattice:
    """Tests for the IdentityLattice class."""

    def test_new_mac_creates_identity(self):
        """First observation of a MAC creates a new identity."""
        lattice = IdentityLattice()
        identity = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None)

        assert identity is not None
        assert "00:11:22:33:44:55" in identity.macs

    def test_same_mac_returns_same_identity(self):
        """Subsequent observations of same MAC return same identity."""
        lattice = IdentityLattice()

        id1 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None)
        id2 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None)

        assert id1.id == id2.id
        assert id1.observation_count == 2

    def test_same_fingerprint_links_macs(self):
        """MACs with same fingerprint share identity."""
        lattice = IdentityLattice()

        id1 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash="abc123")
        id2 = lattice.observe(mac="66:77:88:99:aa:bb", fingerprint_hash="abc123")

        assert id1.id == id2.id
        assert len(id1.macs) == 2
        assert "00:11:22:33:44:55" in id1.macs
        assert "66:77:88:99:AA:BB" in id1.macs  # Note: lattice uppercases MACs

    def test_different_fingerprints_separate_identities(self):
        """Different fingerprints create separate identities."""
        lattice = IdentityLattice()

        id1 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash="hash1")
        id2 = lattice.observe(mac="66:77:88:99:aa:bb", fingerprint_hash="hash2")

        assert id1.id != id2.id

    def test_fingerprint_added_later(self):
        """Fingerprint added to existing MAC-only identity."""
        lattice = IdentityLattice()

        # First observation without fingerprint
        id1 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None)
        assert id1.fingerprint_hash is None

        # Second observation with fingerprint
        id2 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash="newfp")
        assert id2.fingerprint_hash == "newfp"
        assert id1.id == id2.id


class TestLRUEviction:
    """Tests for LRU eviction behavior."""

    def test_lru_eviction_at_capacity(self):
        """Oldest identities evicted when over capacity."""
        lattice = IdentityLattice(max_identities=3)

        # Create 5 identities
        for i in range(5):
            lattice.observe(mac=f"00:00:00:00:00:{i:02x}", fingerprint_hash=None)

        stats = lattice.get_stats()
        assert stats["total_identities"] <= 3

    def test_accessed_identities_not_evicted(self):
        """Recently accessed identities survive eviction."""
        lattice = IdentityLattice(max_identities=3)

        # Create initial identity
        lattice.observe(mac="00:00:00:00:00:01", fingerprint_hash=None)

        # Create 2 more
        lattice.observe(mac="00:00:00:00:00:02", fingerprint_hash=None)
        lattice.observe(mac="00:00:00:00:00:03", fingerprint_hash=None)

        # Access the first one again (makes it "recent")
        lattice.observe(mac="00:00:00:00:00:01", fingerprint_hash=None)

        # Create one more (should evict 02, not 01)
        lattice.observe(mac="00:00:00:00:00:04", fingerprint_hash=None)

        # Check 01 still exists
        identity = lattice.resolve("00:00:00:00:00:01")
        assert identity is not None


class TestResolve:
    """Tests for resolve() method."""

    def test_resolve_known_mac(self):
        """resolve() returns identity for known MAC."""
        lattice = IdentityLattice()
        original = lattice.observe(mac="AA:BB:CC:DD:EE:FF", fingerprint_hash="fp1")

        resolved = lattice.resolve("AA:BB:CC:DD:EE:FF")
        assert resolved is not None
        assert resolved.id == original.id

    def test_resolve_unknown_mac(self):
        """resolve() returns None for unknown MAC."""
        lattice = IdentityLattice()
        resolved = lattice.resolve("00:00:00:00:00:00")
        assert resolved is None

    def test_resolve_case_insensitive(self):
        """resolve() handles case differences in MAC."""
        lattice = IdentityLattice()
        lattice.observe(mac="aa:bb:cc:dd:ee:ff", fingerprint_hash=None)

        # Resolve with uppercase
        resolved = lattice.resolve("AA:BB:CC:DD:EE:FF")
        assert resolved is not None


class TestMerge:
    """Tests for manual identity merging."""

    def test_merge_combines_macs(self):
        """merge() combines MACs from both identities."""
        lattice = IdentityLattice()

        id1 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None)
        id2 = lattice.observe(mac="66:77:88:99:aa:bb", fingerprint_hash=None)

        merged = lattice.merge(id1.id, id2.id)

        assert merged is not None
        assert "00:11:22:33:44:55" in merged.macs
        assert "66:77:88:99:AA:BB" in merged.macs  # Note: lattice uppercases MACs

    def test_merge_nonexistent_returns_none(self):
        """merge() returns None if either ID doesn't exist."""
        lattice = IdentityLattice()
        id1 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None)

        result = lattice.merge(id1.id, "nonexistent")
        assert result is None


class TestStats:
    """Tests for get_stats() method."""

    def test_stats_structure(self):
        """get_stats() returns expected keys."""
        lattice = IdentityLattice()
        stats = lattice.get_stats()

        expected_keys = [
            "total_identities", "total_macs", "total_fingerprints",
            "total_observations", "merges", "compression_ratio"
        ]
        for key in expected_keys:
            assert key in stats

    def test_stats_after_observations(self):
        """Stats accurately reflect observations."""
        lattice = IdentityLattice()

        lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash="fp1")
        lattice.observe(mac="66:77:88:99:aa:bb", fingerprint_hash="fp2")

        stats = lattice.get_stats()
        assert stats["total_identities"] == 2
        assert stats["total_macs"] == 2
        assert stats["total_fingerprints"] == 2
        assert stats["total_observations"] == 2


class TestRandomizedMACDetection:
    """Tests for randomized MAC detection."""

    @pytest.mark.parametrize("mac,expected_randomized", [
        ("02:11:22:33:44:55", True),   # Locally administered
        ("06:11:22:33:44:55", True),   # Locally administered
        ("0A:11:22:33:44:55", True),   # Locally administered
        ("0E:11:22:33:44:55", True),   # Locally administered
        ("00:11:22:33:44:55", False),  # Global (OUI)
        ("04:11:22:33:44:55", False),  # Global (OUI)
    ])
    def test_randomized_mac_detection(self, mac, expected_randomized):
        """Locally administered MACs detected as randomized."""
        lattice = IdentityLattice()
        identity = lattice.observe(mac=mac, fingerprint_hash=None)
        assert identity.is_randomized == expected_randomized


class TestWifi6Flag:
    """Tests for WiFi 6 sticky flag."""

    def test_wifi6_flag_sticky(self):
        """is_wifi6 flag is sticky once set."""
        lattice = IdentityLattice()

        # First observation without WiFi 6
        id1 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None, is_wifi6=False)
        assert id1.is_wifi6 is False

        # Second observation with WiFi 6
        id2 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None, is_wifi6=True)
        assert id2.is_wifi6 is True

        # Third observation without WiFi 6 (flag should remain True)
        id3 = lattice.observe(mac="00:11:22:33:44:55", fingerprint_hash=None, is_wifi6=False)
        assert id3.is_wifi6 is True


class TestGravitasChannels:
    """Tests for get_gravitas_channels() method."""

    def test_returns_recent_channels(self):
        """Returns channels seen within window."""
        lattice = IdentityLattice()

        # Observe on channel 6
        lattice.observe(
            mac="00:11:22:33:44:55",
            fingerprint_hash=None,
            channel=6,
            timestamp=time.time(),
        )

        channels = lattice.get_gravitas_channels(window=60.0)
        assert 6 in channels

    def test_excludes_old_channels(self):
        """Excludes channels seen outside window."""
        lattice = IdentityLattice()

        # Observe on channel 6, 120 seconds ago
        old_ts = time.time() - 120
        lattice.observe(
            mac="00:11:22:33:44:55",
            fingerprint_hash=None,
            channel=6,
            timestamp=old_ts,
        )

        channels = lattice.get_gravitas_channels(window=60.0)
        assert 6 not in channels
