"""
Unit tests for Pattern-of-Life (POL) Analyzer.

Tests K-Means clustering for device behavior patterns.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np
import pytest

from nexus.intel.pol_analyzer import (
    FEATURE_NAMES,
    DevicePOL,
    POLAnalyzer,
    _check_sklearn,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Mock Profile for Testing
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class MockClientProfile:
    """Mock client profile for testing."""
    mac: str
    timestamp_history: list[datetime] = field(default_factory=list)
    probed_ssids: dict[str, datetime] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


def create_test_profiles(n_devices=20, seed=42):
    """
    Create synthetic test profiles with distinct behavioral patterns.

    Patterns:
    - Commuters: Active 9am-5pm weekdays
    - Residents: Active throughout day, long sessions
    - Visitors: Brief appearances, few probes
    - Night Owls: Active 10pm-4am
    """
    np.random.seed(seed)
    profiles = {}
    base = datetime(2025, 6, 1, 0, 0, 0)  # Start on a Sunday

    # Commuters (5 devices)
    for i in range(5):
        mac = f"aa:bb:cc:00:00:{i:02x}"
        timestamps = []
        # Weekday 9am-5pm activity
        for day in range(14):
            date = base + timedelta(days=day)
            if date.weekday() < 5:  # Weekday
                for hour in range(9, 18):
                    if np.random.random() > 0.3:
                        ts = date.replace(hour=hour, minute=np.random.randint(0, 60))
                        timestamps.append(ts)

        profiles[mac] = MockClientProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"Work_{i}": base, "Corporate-WiFi": base},
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        )

    # Residents (5 devices)
    for i in range(5):
        mac = f"aa:bb:cc:11:11:{i:02x}"
        timestamps = []
        # Spread throughout day, many days
        for day in range(14):
            date = base + timedelta(days=day)
            for hour in [7, 8, 12, 13, 18, 19, 20, 21, 22]:
                if np.random.random() > 0.2:
                    ts = date.replace(hour=hour, minute=np.random.randint(0, 60))
                    timestamps.append(ts)

        profiles[mac] = MockClientProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"Home_{i}": base, "HomeWiFi": base, "Guest": base, "IoT-Net": base},
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        )

    # Visitors (5 devices)
    for i in range(5):
        mac = f"aa:bb:cc:22:22:{i:02x}"
        # Brief appearance, 1-2 days
        day = np.random.randint(0, 14)
        date = base + timedelta(days=day)
        timestamps = [
            date.replace(hour=np.random.randint(10, 16), minute=np.random.randint(0, 60))
            for _ in range(3, 6)
        ]

        profiles[mac] = MockClientProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"Visitor_{i}": base},
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        )

    # Night Owls (5 devices)
    for i in range(5):
        mac = f"aa:bb:cc:33:33:{i:02x}"
        timestamps = []
        # Late night activity
        for day in range(14):
            date = base + timedelta(days=day)
            for hour in [22, 23, 0, 1, 2, 3]:
                if np.random.random() > 0.4:
                    actual_date = date if hour >= 22 else date + timedelta(days=1)
                    ts = actual_date.replace(hour=hour, minute=np.random.randint(0, 60))
                    timestamps.append(ts)

        profiles[mac] = MockClientProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"Night_{i}": base, "24hr-Diner": base},
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        )

    return profiles


# ═══════════════════════════════════════════════════════════════════════════════
# Feature Extraction Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestFeatureExtraction:
    """Test feature extraction from timestamps."""

    def test_empty_timestamps(self):
        """Empty timestamps should return zero features."""
        features, feature_dict = POLAnalyzer.extract_features([])

        assert features.shape == (len(FEATURE_NAMES),)
        assert all(v == 0.0 for v in feature_dict.values())

    def test_morning_activity(self):
        """Morning timestamps should have high morning_activity."""
        base = datetime(2025, 6, 2, 9, 0)  # 9am
        timestamps = [base + timedelta(hours=i) for i in range(3)]

        _, features = POLAnalyzer.extract_features(timestamps)

        assert features['morning_activity'] > 0.5
        assert features['night_activity'] == 0.0

    def test_night_activity(self):
        """Night timestamps should have high night_activity."""
        base = datetime(2025, 6, 2, 2, 0)  # 2am
        timestamps = [base + timedelta(hours=i) for i in range(3)]

        _, features = POLAnalyzer.extract_features(timestamps)

        assert features['night_activity'] > 0.5
        assert features['afternoon_activity'] == 0.0

    def test_weekday_ratio(self):
        """Weekday-only activity should have high weekday_ratio."""
        # June 2, 2025 is Monday
        base = datetime(2025, 6, 2, 12, 0)
        timestamps = [base + timedelta(days=i) for i in range(5)]  # Mon-Fri

        _, features = POLAnalyzer.extract_features(timestamps)

        assert features['weekday_ratio'] == 1.0

    def test_session_duration(self):
        """Session spanning a week should have high session_hours."""
        base = datetime(2025, 6, 1, 12, 0)
        timestamps = [base, base + timedelta(days=7)]

        _, features = POLAnalyzer.extract_features(timestamps)

        assert features['session_hours'] == 1.0  # Capped at 1 week

    def test_pnl_diversity(self):
        """More SSIDs should increase pnl_diversity."""
        base = datetime.now()
        timestamps = [base]

        # Few SSIDs
        ssids_few = {"Home": base}
        _, feat_few = POLAnalyzer.extract_features(timestamps, ssids_few)

        # Many SSIDs
        ssids_many = {f"SSID_{i}": base for i in range(15)}
        _, feat_many = POLAnalyzer.extract_features(timestamps, ssids_many)

        assert feat_many['pnl_diversity'] > feat_few['pnl_diversity']

    def test_feature_vector_shape(self):
        """Feature vector should have correct shape."""
        base = datetime.now()
        timestamps = [base + timedelta(hours=i) for i in range(10)]

        features, feature_dict = POLAnalyzer.extract_features(timestamps)

        assert features.shape == (len(FEATURE_NAMES),)
        assert len(feature_dict) == len(FEATURE_NAMES)


# ═══════════════════════════════════════════════════════════════════════════════
# Clustering Tests
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _check_sklearn(), reason="scikit-learn not installed")
class TestClustering:
    """Test K-Means clustering functionality."""

    def test_fit_with_profiles(self):
        """Fitting should succeed with valid profiles."""
        profiles = create_test_profiles()
        analyzer = POLAnalyzer(n_clusters=4)

        stats = analyzer.fit(profiles)

        assert analyzer.is_fitted
        assert stats['n_profiles'] > 0
        assert stats['n_clusters'] == 4
        assert stats['silhouette_score'] is not None

    def test_cluster_assignment(self):
        """All profiles should be assigned to clusters."""
        profiles = create_test_profiles()
        analyzer = POLAnalyzer(n_clusters=4)
        analyzer.fit(profiles)

        for _mac, profile in analyzer.get_all_profiles().items():
            assert profile.cluster is not None
            assert profile.cluster_id is not None
            assert 0 <= profile.confidence <= 1

    def test_silhouette_score_reasonable(self):
        """Silhouette score should be reasonable (> 0.3)."""
        profiles = create_test_profiles()
        analyzer = POLAnalyzer(n_clusters=4)
        analyzer.fit(profiles)

        score = analyzer.get_silhouette_score()

        # With distinct patterns, should get decent separation
        assert score is not None
        assert score > 0.2  # Reasonable threshold for synthetic data

    def test_cluster_centers_accessible(self):
        """Cluster centers should be accessible after fitting."""
        profiles = create_test_profiles()
        analyzer = POLAnalyzer(n_clusters=4)
        analyzer.fit(profiles)

        centers = analyzer.get_cluster_centers()

        assert centers is not None
        # May have fewer unique labels if clusters get same semantic label
        assert len(centers) >= 1
        for _label, center in centers.items():
            assert len(center) == len(FEATURE_NAMES)

    def test_insufficient_data_handled(self):
        """Fitting with too few profiles should return error."""
        profiles = {"aa:bb:cc:00:00:00": MockClientProfile(
            mac="aa:bb:cc:00:00:00",
            timestamp_history=[datetime.now()],
        )}

        analyzer = POLAnalyzer(n_clusters=4)
        result = analyzer.fit(profiles)

        assert 'error' in result

    def test_predict_new_device(self):
        """Prediction should work for new devices."""
        profiles = create_test_profiles()
        analyzer = POLAnalyzer(n_clusters=4)
        analyzer.fit(profiles)

        # Create "commuter" pattern
        base = datetime(2025, 6, 2, 9, 0)  # Monday 9am
        timestamps = [base + timedelta(hours=i) for i in range(8)]

        prediction = analyzer.predict(timestamps, {"Work": base})

        assert prediction.cluster is not None
        assert 0 <= prediction.confidence <= 1

    def test_cluster_summary(self):
        """Cluster summary should show distribution."""
        profiles = create_test_profiles()
        analyzer = POLAnalyzer(n_clusters=4)
        analyzer.fit(profiles)

        summary = analyzer.get_cluster_summary()

        assert len(summary) > 0
        total = sum(s['count'] for s in summary.values())
        assert total == len(profiles)


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_device_pol_to_dict(self):
        """DevicePOL should serialize correctly."""
        pol = DevicePOL(
            mac="aa:bb:cc:dd:ee:ff",
            cluster="commuter",
            cluster_id=0,
            features={'morning_activity': 0.8},
            confidence=0.95,
        )

        result = pol.to_dict()

        assert result['mac'] == "aa:bb:cc:dd:ee:ff"
        assert result['cluster'] == "commuter"
        assert result['confidence'] == 0.95

    @pytest.mark.skipif(not _check_sklearn(), reason="scikit-learn not installed")
    def test_predict_without_fit_raises(self):
        """Prediction without fitting should raise error."""
        analyzer = POLAnalyzer()

        with pytest.raises(RuntimeError, match="must be fitted"):
            analyzer.predict([datetime.now()])

    def test_get_profile_not_found(self):
        """Getting unknown profile should return None."""
        analyzer = POLAnalyzer()

        assert analyzer.get_profile("unknown:mac") is None
