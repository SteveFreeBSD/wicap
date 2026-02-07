"""
Unit tests for Correlation Classifier.

Tests the Decision Tree classifier for MAC address correlation,
including feature extraction, training, prediction, and edge cases.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pytest

from nexus.intel.correlation_classifier import (
    FEATURE_NAMES,
    CorrelationClassifier,
    CorrelationPrediction,
    _check_sklearn,
    generate_training_data_from_lattice,
)
from nexus.scavenger.correlator import TargetDossier

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def empty_dossier():
    """Create an empty dossier."""
    return TargetDossier(mac="aa:bb:cc:dd:ee:01")


@pytest.fixture
def dossier_with_pnl():
    """Create a dossier with PNL data."""
    dossier = TargetDossier(mac="aa:bb:cc:dd:ee:02")
    dossier.probed_ssids = {
        "HomeWiFi": datetime.now(),
        "CoffeeShop": datetime.now() - timedelta(hours=1),
        "WorkNetwork": datetime.now() - timedelta(days=1),
    }
    dossier.rssi_samples = [-50, -52, -48, -51]
    dossier.channels_active = {1, 6, 11}
    dossier.first_seen = datetime.now() - timedelta(days=1)
    dossier.last_seen = datetime.now()
    dossier.is_randomized_mac = True
    return dossier


@pytest.fixture
def similar_dossier():
    """Create a dossier similar to dossier_with_pnl (same device candidate)."""
    dossier = TargetDossier(mac="aa:bb:cc:dd:ee:03")
    dossier.probed_ssids = {
        "HomeWiFi": datetime.now(),  # Overlap
        "CoffeeShop": datetime.now(),  # Overlap
        "GymNetwork": datetime.now(),  # Different
    }
    dossier.rssi_samples = [-51, -49, -50]  # Similar RSSI
    dossier.channels_active = {1, 6}  # Partial overlap
    dossier.first_seen = datetime.now() - timedelta(hours=12)
    dossier.last_seen = datetime.now()
    dossier.is_randomized_mac = True
    return dossier


@pytest.fixture
def different_dossier():
    """Create a dossier clearly different from others."""
    dossier = TargetDossier(mac="aa:bb:cc:dd:ee:04")
    dossier.probed_ssids = {
        "OtherNetwork": datetime.now(),
        "DifferentPlace": datetime.now(),
    }
    dossier.rssi_samples = [-80, -82, -85]  # Much weaker signal
    dossier.channels_active = {36, 40, 44}  # 5GHz channels, no overlap
    dossier.first_seen = datetime.now() - timedelta(days=30)
    dossier.last_seen = datetime.now() - timedelta(days=29)  # Old, different time
    dossier.is_randomized_mac = False
    return dossier


@pytest.fixture
def classifier():
    """Create a fresh classifier."""
    return CorrelationClassifier()


@pytest.fixture
def sample_dossiers():
    """Create a set of dossiers for training tests."""
    dossiers = {}
    base_time = datetime.now()

    # Group 1: Same device (fingerprint fp1)
    for i in range(4):
        mac = f"aa:bb:cc:00:00:{i:02x}"
        d = TargetDossier(mac=mac)
        d.probed_ssids = {"SharedSSID1": base_time, "SharedSSID2": base_time}
        d.rssi_samples = [-50 + i, -51 + i]
        d.channels_active = {1, 6}
        d.first_seen = base_time - timedelta(hours=i)
        d.last_seen = base_time
        d.metadata = {'fingerprint_hash': 'fp1'}
        dossiers[mac] = d

    # Group 2: Same device (fingerprint fp2)
    for i in range(3):
        mac = f"aa:bb:cc:11:11:{i:02x}"
        d = TargetDossier(mac=mac)
        d.probed_ssids = {"OtherSSID1": base_time, "OtherSSID2": base_time}
        d.rssi_samples = [-70 + i, -71 + i]
        d.channels_active = {36, 40}
        d.first_seen = base_time - timedelta(days=i)
        d.last_seen = base_time
        d.metadata = {'fingerprint_hash': 'fp2'}
        dossiers[mac] = d

    # Group 3: Individual devices (no fingerprint)
    for i in range(5):
        mac = f"aa:bb:cc:22:22:{i:02x}"
        d = TargetDossier(mac=mac)
        d.probed_ssids = {f"UniqueSSID{i}": base_time}
        d.rssi_samples = [-60 - i * 5]
        d.channels_active = {i * 2 + 1}
        d.first_seen = base_time - timedelta(days=i * 7)
        d.last_seen = base_time - timedelta(days=i * 7) + timedelta(hours=1)
        dossiers[mac] = d

    return dossiers


# ═══════════════════════════════════════════════════════════════════════════════
# Feature Extraction Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestFeatureExtraction:
    """Test feature extraction from dossier pairs."""

    def test_pnl_jaccard_full_overlap(self, dossier_with_pnl):
        """PNL Jaccard should be 1.0 for identical PNLs."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, dossier_with_pnl
        )
        assert feature_dict['pnl_jaccard'] == 1.0

    def test_pnl_jaccard_no_overlap(self, dossier_with_pnl, different_dossier):
        """PNL Jaccard should be 0.0 for completely different PNLs."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, different_dossier
        )
        assert feature_dict['pnl_jaccard'] == 0.0

    def test_pnl_jaccard_partial_overlap(self, dossier_with_pnl, similar_dossier):
        """PNL Jaccard should be between 0 and 1 for partial overlap."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, similar_dossier
        )
        # 2 shared (HomeWiFi, CoffeeShop) out of 4 unique (+ WorkNetwork, GymNetwork)
        assert 0 < feature_dict['pnl_jaccard'] < 1
        assert feature_dict['pnl_jaccard'] == 0.5  # 2/4

    def test_pnl_jaccard_empty(self, empty_dossier):
        """PNL Jaccard should be 0.0 for empty PNLs."""
        features, feature_dict = CorrelationClassifier.extract_features(
            empty_dossier, empty_dossier
        )
        assert feature_dict['pnl_jaccard'] == 0.0

    def test_rssi_similarity_close(self, dossier_with_pnl, similar_dossier):
        """RSSI similarity should be high for similar signal strengths."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, similar_dossier
        )
        # Both around -50dB, should be very similar
        assert feature_dict['rssi_similarity'] > 0.9

    def test_rssi_similarity_far(self, dossier_with_pnl, different_dossier):
        """RSSI similarity should be lower for different signal strengths."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, different_dossier
        )
        # -50 vs -80, ~30dB difference
        assert feature_dict['rssi_similarity'] < 0.7

    def test_rssi_similarity_no_samples(self, empty_dossier):
        """RSSI similarity should be neutral (0.5) with no samples."""
        features, feature_dict = CorrelationClassifier.extract_features(
            empty_dossier, empty_dossier
        )
        assert feature_dict['rssi_similarity'] == 0.5

    def test_temporal_overlap_same_window(self, dossier_with_pnl, similar_dossier):
        """Temporal overlap should be high for overlapping time windows."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, similar_dossier
        )
        # Both active until "now", should have high overlap
        assert feature_dict['temporal_overlap'] > 0.4

    def test_temporal_overlap_no_overlap(self):
        """Temporal overlap should be 0 for non-overlapping windows."""
        d1 = TargetDossier(mac="aa:bb:cc:dd:ee:01")
        d1.first_seen = datetime(2025, 1, 1)
        d1.last_seen = datetime(2025, 1, 2)

        d2 = TargetDossier(mac="aa:bb:cc:dd:ee:02")
        d2.first_seen = datetime(2025, 6, 1)
        d2.last_seen = datetime(2025, 6, 2)

        features, feature_dict = CorrelationClassifier.extract_features(d1, d2)
        assert feature_dict['temporal_overlap'] == 0.0

    def test_channel_overlap(self, dossier_with_pnl, similar_dossier):
        """Channel overlap should reflect shared channels."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, similar_dossier
        )
        # {1, 6, 11} vs {1, 6} = 2 shared, 3 total = 0.667
        assert 0.6 <= feature_dict['channel_overlap'] <= 0.7

    def test_both_randomized_true(self, dossier_with_pnl, similar_dossier):
        """both_randomized should be 1.0 when both have randomized MACs."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, similar_dossier
        )
        assert feature_dict['both_randomized'] == 1.0

    def test_both_randomized_false(self, dossier_with_pnl, different_dossier):
        """both_randomized should be 0.0 when not both randomized."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, different_dossier
        )
        assert feature_dict['both_randomized'] == 0.0

    def test_feature_vector_shape(self, dossier_with_pnl, similar_dossier):
        """Feature vector should have correct shape and order."""
        features, feature_dict = CorrelationClassifier.extract_features(
            dossier_with_pnl, similar_dossier
        )
        assert features.shape == (6,)
        assert len(feature_dict) == 6
        assert list(feature_dict.keys()) == FEATURE_NAMES


# ═══════════════════════════════════════════════════════════════════════════════
# Classifier Training Tests
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _check_sklearn(), reason="scikit-learn not installed")
class TestClassifierTraining:
    """Test classifier training functionality."""

    def test_train_with_labeled_pairs(self, classifier, sample_dossiers):
        """Training should succeed with valid labeled pairs."""
        fingerprint_groups = {
            'fp1': ['aa:bb:cc:00:00:00', 'aa:bb:cc:00:00:01',
                    'aa:bb:cc:00:00:02', 'aa:bb:cc:00:00:03'],
            'fp2': ['aa:bb:cc:11:11:00', 'aa:bb:cc:11:11:01',
                    'aa:bb:cc:11:11:02'],
        }

        labeled_pairs = generate_training_data_from_lattice(
            sample_dossiers, fingerprint_groups
        )

        stats = classifier.train(labeled_pairs, sample_dossiers)

        assert classifier.is_trained
        assert stats['n_samples'] > 0
        assert stats['n_positive'] > 0
        assert stats['n_negative'] > 0
        assert 'feature_importance' in stats

    def test_train_with_insufficient_data(self, classifier, sample_dossiers):
        """Training should fail with insufficient data."""
        # Only 2 pairs, below minimum
        labeled_pairs = [
            ('aa:bb:cc:00:00:00', 'aa:bb:cc:00:00:01', True),
        ]

        with pytest.raises(ValueError, match="Insufficient training data"):
            classifier.train(labeled_pairs, sample_dossiers)

    def test_feature_importance_populated(self, classifier, sample_dossiers):
        """Feature importance should be populated after training."""
        fingerprint_groups = {
            'fp1': ['aa:bb:cc:00:00:00', 'aa:bb:cc:00:00:01',
                    'aa:bb:cc:00:00:02', 'aa:bb:cc:00:00:03'],
            'fp2': ['aa:bb:cc:11:11:00', 'aa:bb:cc:11:11:01',
                    'aa:bb:cc:11:11:02'],
        }

        labeled_pairs = generate_training_data_from_lattice(
            sample_dossiers, fingerprint_groups
        )
        classifier.train(labeled_pairs, sample_dossiers)

        importance = classifier.get_feature_importance()

        assert len(importance) == 6
        assert all(name in importance for name in FEATURE_NAMES)
        assert all(0 <= v <= 1 for v in importance.values())
        # Total importance should sum to 1.0
        assert abs(sum(importance.values()) - 1.0) < 0.01

    def test_model_persistence(self, classifier, sample_dossiers):
        """Model should save and load correctly."""
        fingerprint_groups = {
            'fp1': ['aa:bb:cc:00:00:00', 'aa:bb:cc:00:00:01',
                    'aa:bb:cc:00:00:02', 'aa:bb:cc:00:00:03'],
            'fp2': ['aa:bb:cc:11:11:00', 'aa:bb:cc:11:11:01',
                    'aa:bb:cc:11:11:02'],
        }

        labeled_pairs = generate_training_data_from_lattice(
            sample_dossiers, fingerprint_groups
        )
        classifier.train(labeled_pairs, sample_dossiers)

        with tempfile.NamedTemporaryFile(suffix='.joblib', delete=False) as f:
            model_path = Path(f.name)

        try:
            classifier.save_model(model_path)

            # Load into new classifier
            new_classifier = CorrelationClassifier()
            new_classifier.load_model(model_path)

            assert new_classifier.is_trained
            assert new_classifier.get_feature_importance() == classifier.get_feature_importance()
        finally:
            model_path.unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Prediction Tests
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _check_sklearn(), reason="scikit-learn not installed")
class TestPrediction:
    """Test prediction functionality."""

    @pytest.fixture
    def trained_classifier(self, classifier, sample_dossiers):
        """Create and train a classifier."""
        fingerprint_groups = {
            'fp1': ['aa:bb:cc:00:00:00', 'aa:bb:cc:00:00:01',
                    'aa:bb:cc:00:00:02', 'aa:bb:cc:00:00:03'],
            'fp2': ['aa:bb:cc:11:11:00', 'aa:bb:cc:11:11:01',
                    'aa:bb:cc:11:11:02'],
        }

        labeled_pairs = generate_training_data_from_lattice(
            sample_dossiers, fingerprint_groups
        )
        classifier.train(labeled_pairs, sample_dossiers)
        return classifier, sample_dossiers

    def test_predict_returns_prediction(self, trained_classifier):
        """Prediction should return CorrelationPrediction object."""
        classifier, dossiers = trained_classifier

        d1 = dossiers['aa:bb:cc:00:00:00']
        d2 = dossiers['aa:bb:cc:00:00:01']

        prediction = classifier.predict(d1, d2)

        assert isinstance(prediction, CorrelationPrediction)
        assert isinstance(prediction.is_same_device, bool)
        assert 0 <= prediction.confidence <= 1
        assert len(prediction.features) == 6

    def test_predict_same_device_positive(self, trained_classifier):
        """Prediction for same-device pair should be positive."""
        classifier, dossiers = trained_classifier

        # Same fingerprint group
        d1 = dossiers['aa:bb:cc:00:00:00']
        d2 = dossiers['aa:bb:cc:00:00:01']

        prediction = classifier.predict(d1, d2)

        # Should predict same device with reasonable confidence
        assert prediction.is_same_device is True
        assert prediction.confidence > 0.5

    def test_predict_different_devices(self, trained_classifier):
        """Prediction for different-device pair should be negative."""
        classifier, dossiers = trained_classifier

        # Different groups
        d1 = dossiers['aa:bb:cc:00:00:00']
        d2 = dossiers['aa:bb:cc:22:22:00']

        prediction = classifier.predict(d1, d2)

        # Should predict different devices
        assert prediction.is_same_device is False

    def test_confidence_scores_valid(self, trained_classifier):
        """Confidence scores should be probabilities."""
        classifier, dossiers = trained_classifier

        d1 = dossiers['aa:bb:cc:00:00:00']
        d2 = dossiers['aa:bb:cc:00:00:01']

        prediction = classifier.predict(d1, d2)

        assert 0.5 <= prediction.confidence <= 1.0  # Max of binary probs

    def test_decision_path_readable(self, trained_classifier):
        """Decision path should contain readable decision rules."""
        classifier, dossiers = trained_classifier

        d1 = dossiers['aa:bb:cc:00:00:00']
        d2 = dossiers['aa:bb:cc:00:00:01']

        prediction = classifier.predict(d1, d2)

        assert isinstance(prediction.decision_path, list)
        # Path should have at least one decision
        if prediction.decision_path:
            for step in prediction.decision_path:
                assert isinstance(step, str)
                # Should contain a feature name
                assert any(name in step for name in FEATURE_NAMES)

    def test_predict_without_training_raises(self, classifier, dossier_with_pnl, similar_dossier):
        """Prediction without training should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="must be trained"):
            classifier.predict(dossier_with_pnl, similar_dossier)


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Cases Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_dossiers_feature_extraction(self, empty_dossier):
        """Feature extraction should work with empty dossiers."""
        features, feature_dict = CorrelationClassifier.extract_features(
            empty_dossier, empty_dossier
        )

        assert features.shape == (6,)
        # All features should have default values
        assert not np.any(np.isnan(features))

    def test_single_mac_dossiers(self):
        """Dossiers with minimal data should extract features."""
        d = TargetDossier(mac="aa:bb:cc:dd:ee:ff")
        d.first_seen = datetime.now()
        d.last_seen = datetime.now()

        features, feature_dict = CorrelationClassifier.extract_features(d, d)

        assert features.shape == (6,)
        assert not np.any(np.isnan(features))

    def test_prediction_to_dict(self):
        """CorrelationPrediction.to_dict should serialize correctly."""
        pred = CorrelationPrediction(
            is_same_device=True,
            confidence=0.95,
            features={'pnl_jaccard': 0.8, 'rssi_similarity': 0.9},
            decision_path=["pnl_jaccard > 0.5"]
        )

        result = pred.to_dict()

        assert result['is_same_device'] is True
        assert result['confidence'] == 0.95
        assert 'pnl_jaccard' in result['features']
        assert result['decision_path'] == ["pnl_jaccard > 0.5"]

    def test_generate_training_data_empty_groups(self, sample_dossiers):
        """Training data generation with empty groups should work."""
        # No fingerprint groups = only negative samples if any
        pairs = generate_training_data_from_lattice(sample_dossiers, {})

        # All pairs should be negative
        for _, _, is_same in pairs:
            assert is_same is False

    def test_save_untrained_model_raises(self, classifier):
        """Saving untrained model should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="Cannot save untrained"):
            classifier.save_model(Path("/tmp/test.joblib"))


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _check_sklearn(), reason="scikit-learn not installed")
class TestIntegration:
    """Integration tests for the full correlation workflow."""

    def test_full_workflow(self, sample_dossiers):
        """Test complete workflow: train -> predict -> explain."""
        from nexus.scavenger.correlator import IdentityFusion

        # Create fusion engine
        fusion = IdentityFusion()
        fusion.dossiers = sample_dossiers

        # Build fingerprint groups from metadata
        fingerprint_groups = {}
        for mac, dossier in sample_dossiers.items():
            fp_hash = dossier.metadata.get('fingerprint_hash')
            if fp_hash:
                fingerprint_groups.setdefault(fp_hash, []).append(mac)

        # Train
        stats = fusion.train_classifier(fingerprint_groups)
        assert 'n_samples' in stats

        # Get correlations
        correlations = fusion.suggest_correlations_ml(min_confidence=0.5)
        assert isinstance(correlations, list)

        # Get explanation for a pair
        if len(list(sample_dossiers.keys())) >= 2:
            macs = list(sample_dossiers.keys())
            explanation = fusion.get_correlation_explanation(macs[0], macs[1])
            # May be None if classifier predicts different devices
            if explanation:
                assert 'is_same_device' in explanation
                assert 'confidence' in explanation
