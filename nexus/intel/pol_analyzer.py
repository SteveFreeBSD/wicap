"""
Pattern-of-Life (POL) Analyzer

K-Means clustering for device behavior pattern analysis.
Categorizes devices into behavioral groups based on temporal activity patterns.

Cluster Types:
- Commuters: Regular 9-5 weekday activity
- Residents: Always-on, consistent presence
- Visitors: Brief, one-time appearances
- Night Owls: Late night / early morning activity
"""

import importlib.util
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np

# Lazy import for sklearn
_sklearn_available = None

def _check_sklearn():
    """Check if scikit-learn is available."""
    global _sklearn_available
    if _sklearn_available is None:
        _sklearn_available = importlib.util.find_spec("sklearn") is not None
    return _sklearn_available

logger = logging.getLogger('nexus.intel.pol_analyzer')


# Cluster labels
CLUSTER_LABELS = {
    0: 'commuter',
    1: 'resident',
    2: 'visitor',
    3: 'night_owl',
}

# Feature names for interpretability
FEATURE_NAMES = [
    'morning_activity',    # 6am-12pm
    'afternoon_activity',  # 12pm-6pm
    'evening_activity',    # 6pm-12am
    'night_activity',      # 12am-6am
    'weekday_ratio',       # Weekday vs weekend
    'session_hours',       # Duration from first to last seen
    'probe_frequency',     # Probes per hour
    'pnl_diversity',       # Unique SSIDs probed
]


@dataclass
class DevicePOL:
    """Pattern-of-Life profile for a device."""
    mac: str
    cluster: str | None = None
    cluster_id: int | None = None
    features: dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0

    # Temporal stats
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_observations: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'mac': self.mac,
            'cluster': self.cluster,
            'cluster_id': self.cluster_id,
            'features': {k: round(v, 4) for k, v in self.features.items()},
            'confidence': round(self.confidence, 4),
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'total_observations': self.total_observations,
        }


class POLAnalyzer:
    """
    Pattern-of-Life analyzer using K-Means clustering.

    Clusters devices into behavioral groups based on when they're active,
    how long they stay, and what networks they probe for.

    Example:
        analyzer = POLAnalyzer()
        analyzer.fit(client_profiles)

        for mac, profile in analyzer.get_all_profiles().items():
            print(f"{mac}: {profile.cluster} ({profile.confidence:.1%})")
    """

    DEFAULT_N_CLUSTERS = 4

    def __init__(self, n_clusters: int = DEFAULT_N_CLUSTERS):
        """
        Initialize the POL analyzer.

        Args:
            n_clusters: Number of behavior clusters (default 4)
        """
        self.n_clusters = n_clusters
        self._model = None
        self._profiles: dict[str, DevicePOL] = {}
        self._cluster_centers = None
        self._silhouette_score: float | None = None
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        """Check if model has been fitted."""
        return self._is_fitted

    @staticmethod
    def extract_features(
        timestamps: list[datetime],
        probed_ssids: dict[str, datetime] | None = None,
    ) -> tuple[np.ndarray, dict[str, float]]:
        """
        Extract temporal features from a device's activity history.

        Args:
            timestamps: List of observation timestamps
            probed_ssids: Optional dict of SSID -> last_seen timestamp

        Returns:
            Tuple of (feature_array, feature_dict)
        """
        features = {}

        if not timestamps:
            # Return neutral features for empty data
            return np.zeros(len(FEATURE_NAMES)), dict.fromkeys(FEATURE_NAMES, 0.0)

        # Convert to datetime if needed
        ts_list = []
        for ts in timestamps:
            if isinstance(ts, datetime):
                ts_list.append(ts)
            elif isinstance(ts, (int, float)):
                ts_list.append(datetime.fromtimestamp(ts))

        if not ts_list:
            return np.zeros(len(FEATURE_NAMES)), dict.fromkeys(FEATURE_NAMES, 0.0)

        # 1-4: Time-of-day distribution (4 buckets)
        hours = [ts.hour for ts in ts_list]
        total = len(hours) or 1

        morning = sum(1 for h in hours if 6 <= h < 12) / total
        afternoon = sum(1 for h in hours if 12 <= h < 18) / total
        evening = sum(1 for h in hours if 18 <= h < 24) / total
        night = sum(1 for h in hours if 0 <= h < 6) / total

        features['morning_activity'] = morning
        features['afternoon_activity'] = afternoon
        features['evening_activity'] = evening
        features['night_activity'] = night

        # 5: Weekday ratio (0 = all weekend, 1 = all weekday)
        weekdays = [ts.weekday() for ts in ts_list]
        weekday_count = sum(1 for w in weekdays if w < 5)
        features['weekday_ratio'] = weekday_count / total

        # 6: Session duration (hours from first to last seen)
        first_seen = min(ts_list)
        last_seen = max(ts_list)
        session_hours = (last_seen - first_seen).total_seconds() / 3600
        # Normalize to 0-1 (cap at 168 hours = 1 week)
        features['session_hours'] = min(session_hours / 168, 1.0)

        # 7: Probe frequency (probes per hour)
        if session_hours > 0:
            probe_freq = len(ts_list) / session_hours
            # Normalize (cap at 60 probes/hour)
            features['probe_frequency'] = min(probe_freq / 60, 1.0)
        else:
            features['probe_frequency'] = 0.0

        # 8: PNL diversity (unique SSIDs)
        pnl_count = len(probed_ssids) if probed_ssids else 0
        # Normalize (cap at 20 SSIDs)
        features['pnl_diversity'] = min(pnl_count / 20, 1.0)

        # Build feature array
        feature_array = np.array([features[name] for name in FEATURE_NAMES])

        return feature_array, features

    def fit(
        self,
        client_profiles: dict[str, Any],
        min_observations: int = 3,
    ) -> dict[str, Any]:
        """
        Fit K-Means clustering on client profiles.

        Args:
            client_profiles: Dict of MAC -> ClientPNL or similar profile object
            min_observations: Minimum observations required for clustering

        Returns:
            Fitting statistics
        """
        if not _check_sklearn():
            raise RuntimeError(
                "scikit-learn is required for POL analysis. "
                "Install with: pip install scikit-learn>=1.4.0"
            )

        from sklearn.cluster import KMeans
        from sklearn.metrics import silhouette_score

        # Extract features for all profiles
        X = []
        macs = []

        for mac, profile in client_profiles.items():
            # Get timestamps from profile
            timestamps = []

            # Handle different profile types
            if hasattr(profile, 'timestamp_history') and profile.timestamp_history:
                timestamps = profile.timestamp_history
            elif hasattr(profile, 'probed_ssids') and profile.probed_ssids:
                # Fall back to SSID timestamps if no history
                timestamps = list(profile.probed_ssids.values())
            elif hasattr(profile, 'first_seen') and hasattr(profile, 'last_seen'):
                # Minimal: just first/last seen
                if profile.first_seen and profile.last_seen:
                    timestamps = [profile.first_seen, profile.last_seen]

            if len(timestamps) < min_observations:
                continue

            # Get PNL if available
            probed_ssids = getattr(profile, 'probed_ssids', {})

            features, feature_dict = self.extract_features(timestamps, probed_ssids)
            X.append(features)
            macs.append(mac)

            # Create POL profile
            self._profiles[mac] = DevicePOL(
                mac=mac,
                features=feature_dict,
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
                total_observations=len(timestamps),
            )

        if len(X) < self.n_clusters:
            logger.warning(f"Not enough profiles ({len(X)}) for {self.n_clusters} clusters")
            return {'error': 'Insufficient data', 'n_profiles': len(X)}

        X = np.array(X)

        # Fit K-Means
        self._model = KMeans(
            n_clusters=self.n_clusters,
            random_state=42,
            n_init=10,
        )
        labels = self._model.fit_predict(X)
        self._cluster_centers = self._model.cluster_centers_

        # Calculate silhouette score
        if len(X) > self.n_clusters:
            self._silhouette_score = float(silhouette_score(X, labels))
        else:
            self._silhouette_score = 0.0

        # Assign clusters to profiles
        for i, mac in enumerate(macs):
            cluster_id = int(labels[i])
            self._profiles[mac].cluster_id = cluster_id
            self._profiles[mac].cluster = self._label_cluster(cluster_id)

            # Calculate confidence (distance to cluster center)
            center = self._cluster_centers[cluster_id]
            distance = np.linalg.norm(X[i] - center)
            # Convert distance to confidence (closer = higher)
            max_dist = np.max([np.linalg.norm(X[i] - c) for c in self._cluster_centers])
            self._profiles[mac].confidence = 1 - (distance / max_dist) if max_dist > 0 else 1.0

        self._is_fitted = True

        logger.info(
            f"POL clustering complete: {len(macs)} devices, "
            f"{self.n_clusters} clusters, silhouette={self._silhouette_score:.3f}"
        )

        return {
            'n_profiles': len(macs),
            'n_clusters': self.n_clusters,
            'silhouette_score': self._silhouette_score,
            'cluster_sizes': {
                self._label_cluster(i): int(np.sum(labels == i))
                for i in range(self.n_clusters)
            },
        }

    def _label_cluster(self, cluster_id: int) -> str:
        """
        Assign semantic label to cluster based on center characteristics.
        """
        if self._cluster_centers is None:
            return CLUSTER_LABELS.get(cluster_id, f'cluster_{cluster_id}')

        center = self._cluster_centers[cluster_id]

        # Analyze center to assign label
        morning = center[0]
        afternoon = center[1]
        center[2]
        night = center[3]
        weekday_ratio = center[4]

        # Night owl: high night activity
        if night > 0.3:
            return 'night_owl'

        # Commuter: high weekday + morning/afternoon
        if weekday_ratio > 0.7 and (morning + afternoon) > 0.5:
            return 'commuter'

        # Resident: long session, spread activity
        session_hours = center[5]
        if session_hours > 0.5:
            return 'resident'

        # Visitor: brief appearance
        return 'visitor'

    def predict(self, timestamps: list[datetime], probed_ssids: dict | None = None) -> DevicePOL:
        """
        Predict cluster for a new device.

        Args:
            timestamps: Activity timestamps
            probed_ssids: Optional PNL data

        Returns:
            DevicePOL with cluster assignment
        """
        if not self._is_fitted:
            raise RuntimeError("Analyzer must be fitted before prediction")

        features, feature_dict = self.extract_features(timestamps, probed_ssids)

        cluster_id = int(self._model.predict([features])[0])

        # Calculate confidence
        center = self._cluster_centers[cluster_id]
        distance = np.linalg.norm(features - center)
        max_dist = np.max([np.linalg.norm(features - c) for c in self._cluster_centers])
        confidence = 1 - (distance / max_dist) if max_dist > 0 else 1.0

        return DevicePOL(
            mac='unknown',
            cluster=self._label_cluster(cluster_id),
            cluster_id=cluster_id,
            features=feature_dict,
            confidence=confidence,
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
            total_observations=len(timestamps),
        )

    def get_profile(self, mac: str) -> DevicePOL | None:
        """Get POL profile for a MAC address."""
        return self._profiles.get(mac.lower())

    def get_all_profiles(self) -> dict[str, DevicePOL]:
        """Get all POL profiles."""
        return self._profiles.copy()

    def get_cluster_summary(self) -> dict[str, dict[str, Any]]:
        """
        Get summary statistics for each cluster.

        Returns:
            Dict of cluster_label -> stats
        """
        summary = defaultdict(lambda: {'count': 0, 'macs': [], 'avg_confidence': 0})

        for mac, profile in self._profiles.items():
            if profile.cluster:
                summary[profile.cluster]['count'] += 1
                summary[profile.cluster]['macs'].append(mac)
                summary[profile.cluster]['avg_confidence'] += profile.confidence

        # Calculate averages
        for cluster in summary:
            count = summary[cluster]['count']
            if count > 0:
                summary[cluster]['avg_confidence'] /= count
            summary[cluster]['avg_confidence'] = round(summary[cluster]['avg_confidence'], 3)

        return dict(summary)

    def get_silhouette_score(self) -> float | None:
        """Get the silhouette score (cluster quality metric)."""
        return self._silhouette_score

    def get_cluster_centers(self) -> dict[str, dict[str, float]] | None:
        """
        Get cluster centers with feature names.

        Returns:
            Dict of cluster_label -> feature_values
        """
        if self._cluster_centers is None:
            return None

        centers = {}
        for i, center in enumerate(self._cluster_centers):
            label = self._label_cluster(i)
            centers[label] = {
                name: round(float(val), 4)
                for name, val in zip(FEATURE_NAMES, center, strict=False)
            }

        return centers
