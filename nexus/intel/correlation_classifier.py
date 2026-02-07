"""
Decision Tree Correlation Classifier

Machine learning-powered MAC address correlation using scikit-learn Decision Trees.
Replaces heuristic-based correlation with a multi-feature classifier that provides
interpretable predictions with confidence scores.

Features extracted from dossier pairs:
1. PNL Jaccard Similarity - Overlap in probed SSIDs
2. RSSI Similarity - Signal strength pattern matching
3. Temporal Overlap - Time window intersection
4. Channel Overlap - Active channel intersection
5. Both Randomized - MAC randomization flag match
6. Activity Ratio - Observation count similarity
"""

import importlib.util
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

# Lazy import for sklearn to allow graceful degradation
_sklearn_available = None

def _check_sklearn():
    """Check if scikit-learn is available."""
    global _sklearn_available
    if _sklearn_available is None:
        _sklearn_available = importlib.util.find_spec("sklearn") is not None
    return _sklearn_available

if TYPE_CHECKING:
    from .correlator import TargetDossier

logger = logging.getLogger('nexus.intel.correlation_classifier')


# Feature indices for readability
FEATURE_NAMES = [
    'pnl_jaccard',
    'rssi_similarity',
    'temporal_overlap',
    'channel_overlap',
    'both_randomized',
    'activity_ratio',
]


@dataclass
class CorrelationPrediction:
    """Result of a correlation prediction."""
    is_same_device: bool
    confidence: float
    features: dict[str, float]
    decision_path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'is_same_device': self.is_same_device,
            'confidence': round(self.confidence, 4),
            'features': {k: round(v, 4) for k, v in self.features.items()},
            'decision_path': self.decision_path,
        }


class CorrelationClassifier:
    """
    Decision Tree classifier for MAC address correlation.

    Uses scikit-learn's DecisionTreeClassifier to predict whether two
    MAC addresses belong to the same physical device based on behavioral
    and signal features extracted from their dossiers.

    Example:
        classifier = CorrelationClassifier()
        classifier.train(labeled_pairs, dossiers)
        prediction = classifier.predict(dossier1, dossier2)
        print(f"Same device: {prediction.is_same_device} ({prediction.confidence:.1%})")
    """

    # Decision Tree hyperparameters (tuned for interpretability)
    MAX_DEPTH = 5
    MIN_SAMPLES_SPLIT = 5
    MIN_SAMPLES_LEAF = 2

    def __init__(self):
        """Initialize the classifier."""
        self._model = None
        self._is_trained = False
        self._feature_importance: dict[str, float] = {}
        self._training_stats: dict[str, Any] = {}

    @property
    def is_trained(self) -> bool:
        """Check if model has been trained."""
        return self._is_trained

    @staticmethod
    def extract_features(
        dossier1: 'TargetDossier',
        dossier2: 'TargetDossier',
    ) -> tuple[np.ndarray, dict[str, float]]:
        """
        Extract feature vector from a pair of dossiers.

        Args:
            dossier1: First target dossier
            dossier2: Second target dossier

        Returns:
            Tuple of (feature_array, feature_dict) for model input and debugging
        """
        features = {}

        # 1. PNL Jaccard Similarity (probed SSIDs overlap)
        pnl1 = set(dossier1.probed_ssids.keys()) if dossier1.probed_ssids else set()
        pnl2 = set(dossier2.probed_ssids.keys()) if dossier2.probed_ssids else set()

        if pnl1 or pnl2:
            intersection = len(pnl1 & pnl2)
            union = len(pnl1 | pnl2)
            features['pnl_jaccard'] = intersection / union if union > 0 else 0.0
        else:
            features['pnl_jaccard'] = 0.0

        # 2. RSSI Similarity (signal strength pattern)
        rssi1 = dossier1.rssi_samples if dossier1.rssi_samples else []
        rssi2 = dossier2.rssi_samples if dossier2.rssi_samples else []

        if rssi1 and rssi2:
            avg1 = sum(rssi1) / len(rssi1)
            avg2 = sum(rssi2) / len(rssi2)
            # RSSI typically ranges from -100 to -30, normalize difference
            rssi_diff = abs(avg1 - avg2)
            # Max expected difference is ~70dB, normalize to 0-1 similarity
            features['rssi_similarity'] = max(0.0, 1.0 - (rssi_diff / 70.0))
        else:
            features['rssi_similarity'] = 0.5  # Neutral when no data

        # 3. Temporal Overlap (time window intersection)
        if (dossier1.first_seen and dossier1.last_seen and
            dossier2.first_seen and dossier2.last_seen):
            # Convert to timestamps if datetime
            t1_start = dossier1.first_seen.timestamp() if hasattr(dossier1.first_seen, 'timestamp') else float(dossier1.first_seen)
            t1_end = dossier1.last_seen.timestamp() if hasattr(dossier1.last_seen, 'timestamp') else float(dossier1.last_seen)
            t2_start = dossier2.first_seen.timestamp() if hasattr(dossier2.first_seen, 'timestamp') else float(dossier2.first_seen)
            t2_end = dossier2.last_seen.timestamp() if hasattr(dossier2.last_seen, 'timestamp') else float(dossier2.last_seen)

            # Calculate overlap
            overlap_start = max(t1_start, t2_start)
            overlap_end = min(t1_end, t2_end)
            overlap = max(0, overlap_end - overlap_start)

            # Normalize by smaller window
            window1 = max(1, t1_end - t1_start)
            window2 = max(1, t2_end - t2_start)
            min_window = min(window1, window2)

            features['temporal_overlap'] = min(1.0, overlap / min_window) if min_window > 0 else 0.0
        else:
            features['temporal_overlap'] = 0.5  # Neutral when no data

        # 4. Channel Overlap (active channels intersection)
        ch1 = dossier1.channels_active if dossier1.channels_active else set()
        ch2 = dossier2.channels_active if dossier2.channels_active else set()

        if ch1 or ch2:
            intersection = len(ch1 & ch2)
            union = len(ch1 | ch2)
            features['channel_overlap'] = intersection / union if union > 0 else 0.0
        else:
            features['channel_overlap'] = 0.5  # Neutral when no data

        # 5. Both Randomized (MAC randomization flags)
        features['both_randomized'] = 1.0 if (
            dossier1.is_randomized_mac and dossier2.is_randomized_mac
        ) else 0.0

        # 6. Activity Ratio (observation count similarity)
        act1 = dossier1.activity_count if hasattr(dossier1, 'activity_count') else 1
        act2 = dossier2.activity_count if hasattr(dossier2, 'activity_count') else 1

        if act1 > 0 and act2 > 0:
            features['activity_ratio'] = min(act1, act2) / max(act1, act2)
        else:
            features['activity_ratio'] = 0.5  # Neutral when no data

        # Build feature array in consistent order
        feature_array = np.array([features[name] for name in FEATURE_NAMES])

        return feature_array, features

    def train(
        self,
        labeled_pairs: list[tuple[str, str, bool]],
        dossiers: dict[str, 'TargetDossier'],
        random_state: int = 42,
    ) -> dict[str, Any]:
        """
        Train the classifier on labeled MAC pairs.

        Args:
            labeled_pairs: List of (mac1, mac2, is_same_device) tuples
            dossiers: Dictionary of MAC -> TargetDossier
            random_state: Random seed for reproducibility

        Returns:
            Training statistics dictionary

        Raises:
            RuntimeError: If scikit-learn is not available
            ValueError: If insufficient training data
        """
        if not _check_sklearn():
            raise RuntimeError(
                "scikit-learn is required for training. "
                "Install with: pip install scikit-learn>=1.4.0"
            )

        from sklearn.tree import DecisionTreeClassifier

        # Extract features for all pairs
        X = []
        y = []
        skipped = 0

        for mac1, mac2, is_same in labeled_pairs:
            mac1_lower = mac1.lower()
            mac2_lower = mac2.lower()

            if mac1_lower not in dossiers or mac2_lower not in dossiers:
                skipped += 1
                continue

            features, _ = self.extract_features(
                dossiers[mac1_lower],
                dossiers[mac2_lower],
            )
            X.append(features)
            y.append(1 if is_same else 0)

        if len(X) < self.MIN_SAMPLES_SPLIT * 2:
            raise ValueError(
                f"Insufficient training data: {len(X)} pairs. "
                f"Need at least {self.MIN_SAMPLES_SPLIT * 2}."
            )

        X = np.array(X)
        y = np.array(y)

        # Train the model
        self._model = DecisionTreeClassifier(
            max_depth=self.MAX_DEPTH,
            min_samples_split=self.MIN_SAMPLES_SPLIT,
            min_samples_leaf=self.MIN_SAMPLES_LEAF,
            random_state=random_state,
        )
        self._model.fit(X, y)
        self._is_trained = True

        # Calculate feature importance
        importances = self._model.feature_importances_
        self._feature_importance = {
            name: float(imp) for name, imp in zip(FEATURE_NAMES, importances, strict=False)
        }

        # Record training stats
        self._training_stats = {
            'n_samples': len(X),
            'n_positive': int(sum(y)),
            'n_negative': int(len(y) - sum(y)),
            'n_skipped': skipped,
            'tree_depth': self._model.get_depth(),
            'n_leaves': self._model.get_n_leaves(),
            'feature_importance': self._feature_importance,
        }

        logger.info(
            f"Trained correlation classifier: {len(X)} samples, "
            f"depth={self._model.get_depth()}, leaves={self._model.get_n_leaves()}"
        )

        return self._training_stats

    def predict(
        self,
        dossier1: 'TargetDossier',
        dossier2: 'TargetDossier',
    ) -> CorrelationPrediction:
        """
        Predict if two dossiers represent the same device.

        Args:
            dossier1: First target dossier
            dossier2: Second target dossier

        Returns:
            CorrelationPrediction with result, confidence, and decision path

        Raises:
            RuntimeError: If model is not trained
        """
        if not self._is_trained:
            raise RuntimeError("Classifier must be trained before prediction")

        features, feature_dict = self.extract_features(dossier1, dossier2)

        # Get prediction and probabilities
        prediction = self._model.predict([features])[0]
        probabilities = self._model.predict_proba([features])[0]
        confidence = float(max(probabilities))

        # Generate decision path
        decision_path = self._get_decision_path(features)

        return CorrelationPrediction(
            is_same_device=bool(prediction),
            confidence=confidence,
            features=feature_dict,
            decision_path=decision_path,
        )

    def _get_decision_path(self, features: np.ndarray) -> list[str]:
        """
        Extract human-readable decision path for a prediction.

        Args:
            features: Feature array

        Returns:
            List of decision rule strings
        """
        if not self._is_trained:
            return []

        tree = self._model.tree_
        node_indicator = self._model.decision_path([features])
        node_indices = node_indicator.indices

        path = []
        for node_id in node_indices:
            if tree.feature[node_id] != -2:  # Not a leaf
                feature_name = FEATURE_NAMES[tree.feature[node_id]]
                threshold = tree.threshold[node_id]
                feature_value = features[tree.feature[node_id]]

                if feature_value <= threshold:
                    path.append(f"{feature_name} ≤ {threshold:.3f} (actual: {feature_value:.3f})")
                else:
                    path.append(f"{feature_name} > {threshold:.3f} (actual: {feature_value:.3f})")

        return path

    def get_feature_importance(self) -> dict[str, float]:
        """
        Get feature importance scores from trained model.

        Returns:
            Dictionary of feature_name -> importance (0-1)
        """
        return self._feature_importance.copy()

    def get_training_stats(self) -> dict[str, Any]:
        """Get statistics from last training run."""
        return self._training_stats.copy()

    def save_model(self, path: Path) -> None:
        """
        Save trained model to disk.

        Args:
            path: Path to save model (uses joblib)
        """
        if not self._is_trained:
            raise RuntimeError("Cannot save untrained model")

        if not _check_sklearn():
            raise RuntimeError("scikit-learn required for model persistence")

        import joblib

        model_data = {
            'model': self._model,
            'feature_importance': self._feature_importance,
            'training_stats': self._training_stats,
        }

        joblib.dump(model_data, path)
        logger.info(f"Saved correlation classifier to {path}")

    def load_model(self, path: Path) -> None:
        """
        Load trained model from disk.

        Args:
            path: Path to load model from
        """
        if not _check_sklearn():
            raise RuntimeError("scikit-learn required for model loading")

        import joblib

        model_data = joblib.load(path)
        self._model = model_data['model']
        self._feature_importance = model_data['feature_importance']
        self._training_stats = model_data['training_stats']
        self._is_trained = True

        logger.info(f"Loaded correlation classifier from {path}")


def generate_training_data_from_lattice(
    dossiers: dict[str, 'TargetDossier'],
    fingerprint_groups: dict[str, list[str]],
    negative_sample_ratio: float = 1.0,
    random_state: int = 42,
) -> list[tuple[str, str, bool]]:
    """
    Generate labeled training data from Identity Lattice fingerprint matches.

    MACs that share a fingerprint hash are known to be the same device.
    Random pairs with different fingerprints are negative samples.

    Args:
        dossiers: Dictionary of MAC -> TargetDossier
        fingerprint_groups: Dict of fingerprint_hash -> list of MACs
        negative_sample_ratio: Ratio of negative to positive samples
        random_state: Random seed for reproducibility

    Returns:
        List of (mac1, mac2, is_same_device) tuples
    """
    np.random.seed(random_state)

    labeled_pairs = []

    # Positive samples: pairs within same fingerprint group
    for _fp_hash, macs in fingerprint_groups.items():
        if len(macs) >= 2:
            # Generate all pairs within group
            for i, mac1 in enumerate(macs):
                for mac2 in macs[i+1:]:
                    labeled_pairs.append((mac1, mac2, True))

    n_positive = len(labeled_pairs)

    # Negative samples: pairs from different fingerprint groups
    all_macs = list(dossiers.keys())
    n_negative_target = int(n_positive * negative_sample_ratio)

    # Build fingerprint lookup for quick checking
    mac_to_fp = {}
    for fp_hash, macs in fingerprint_groups.items():
        for mac in macs:
            mac_to_fp[mac] = fp_hash

    negative_count = 0
    attempts = 0
    max_attempts = n_negative_target * 10

    while negative_count < n_negative_target and attempts < max_attempts:
        attempts += 1
        idx1, idx2 = np.random.choice(len(all_macs), 2, replace=False)
        mac1, mac2 = all_macs[idx1], all_macs[idx2]

        # Only use as negative if different fingerprints (or no fingerprint)
        fp1 = mac_to_fp.get(mac1)
        fp2 = mac_to_fp.get(mac2)

        if fp1 is None or fp2 is None or fp1 != fp2:
            labeled_pairs.append((mac1, mac2, False))
            negative_count += 1

    logger.info(
        f"Generated training data: {n_positive} positive, "
        f"{negative_count} negative samples"
    )

    return labeled_pairs
