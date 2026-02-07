"""Unit tests for Ghost Hunter (no SQL required)."""
import pytest

from nexus.intel.ghost_hunter import FEATURE_NAMES, FeatureWindow, _is_valid_mac, _seq_delta


class TestFeatureWindow:
    """Tests for FeatureWindow dataclass."""

    def test_vector_order_matches_feature_names(self):
        """Feature vector respects FEATURE_NAMES order."""
        features = {name: float(i) for i, name in enumerate(FEATURE_NAMES)}
        fw = FeatureWindow(
            bssid="00:11:22:33:44:55",
            window_start=0.0,
            window_end=300.0,
            ssid="TestNetwork",
            event_count=100,
            features=features,
        )
        vec = fw.vector(FEATURE_NAMES)
        assert vec == list(range(len(FEATURE_NAMES)))

    def test_vector_missing_features_default_zero(self):
        """Missing features in vector default to 0.0."""
        fw = FeatureWindow(
            bssid="00:11:22:33:44:55",
            window_start=0.0,
            window_end=300.0,
            ssid=None,
            event_count=10,
            features={"event_count": 10.0},  # Only one feature
        )
        vec = fw.vector(FEATURE_NAMES)
        assert vec[0] == 10.0  # event_count
        assert all(v == 0.0 for v in vec[1:])  # Rest are zero

    def test_empty_evidence_event_ids(self):
        """Evidence event IDs default to empty list."""
        fw = FeatureWindow(
            bssid="aa:bb:cc:dd:ee:ff",
            window_start=100.0,
            window_end=200.0,
            ssid=None,
            event_count=5,
            features={},
        )
        assert fw.evidence_event_ids == []


class TestSeqDelta:
    """Tests for sequence number delta calculation."""

    @pytest.mark.parametrize("prev,next_,expected", [
        (100, 101, 1),      # Normal increment
        (100, 102, 2),      # Skip one
        (4095, 0, 1),       # Wrap-around at 4096
        (4094, 0, 2),       # Wrap-around with gap
        (100, 100, 0),      # No change
        (50, 49, 1),        # Small backward (noise)
        (0, 4095, 1),       # Large backward (wrap)
    ])
    def test_seq_delta_calculation(self, prev, next_, expected):
        """Sequence delta handles wrap-around correctly."""
        assert _seq_delta(prev, next_) == expected

    def test_seq_delta_none_values(self):
        """None values result in zero delta."""
        assert _seq_delta(None, 100) == 0
        assert _seq_delta(100, None) == 0
        assert _seq_delta(None, None) == 0


class TestIsValidMac:
    """Tests for MAC address validation."""

    @pytest.mark.parametrize("mac,expected", [
        ("00:11:22:33:44:55", True),      # Valid unicast
        ("AA:BB:CC:DD:EE:FF", True),      # Valid uppercase
        ("ff:ff:ff:ff:ff:ff", False),     # Broadcast
        ("FF:FF:FF:FF:FF:FF", False),     # Broadcast uppercase
        ("00:00:00:00:00:00", False),     # Null MAC
        (None, False),                     # None
        ("", False),                       # Empty string
    ])
    def test_is_valid_mac(self, mac, expected):
        """MAC validation rejects broadcast, null, and None."""
        assert _is_valid_mac(mac) == expected


class TestFeatureNames:
    """Tests for feature name constants."""

    def test_feature_names_count(self):
        """Expected number of features."""
        assert len(FEATURE_NAMES) == 10

    def test_feature_names_unique(self):
        """All feature names are unique."""
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
