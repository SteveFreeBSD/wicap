"""
Scavenger Correlation Engine ("The Nexus")
Connects dots between disconnected intelligence points.

Implements identity fusion to correlate potentially randomized MACs
and generates comprehensive dossiers for targets.

Enhanced with ML-powered correlation using Decision Tree classifier.
"""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

logger = logging.getLogger('nexus.scavenger.correlator')

# Lazy import for classifier to avoid circular imports
if TYPE_CHECKING:
    from nexus.intel.correlation_classifier import CorrelationClassifier


@dataclass
class TargetDossier:
    """
    Comprehensive dossier for a target device.

    Aggregates all known intelligence about a specific MAC address.
    """
    mac: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # PNL data
    probed_ssids: dict[str, datetime] = field(default_factory=dict)

    # Network associations
    associated_bssids: set[str] = field(default_factory=set)

    # EAPOL/handshake activity
    handshake_activity: list[dict[str, Any]] = field(default_factory=list)

    # Device characteristics
    is_randomized_mac: bool = False
    channels_active: set[int] = field(default_factory=set)
    rssi_samples: list[int] = field(default_factory=list)

    # Correlated identities (other MACs suspected to be same device)
    correlated_macs: set[str] = field(default_factory=set)

    # Metadata extracted
    metadata: dict[str, Any] = field(default_factory=dict)

    # Device Identification
    vendor: str = "Unknown"
    device_type: str | None = None


    @property
    def activity_count(self) -> int:
        """Total number of recorded activities."""
        return len(self.probed_ssids) + len(self.handshake_activity)

    @property
    def pnl_count(self) -> int:
        """Number of unique SSIDs in PNL."""
        return len(self.probed_ssids)

    @property
    def avg_rssi(self) -> float | None:
        """Average RSSI if samples available."""
        if not self.rssi_samples:
            return None
        return sum(self.rssi_samples) / len(self.rssi_samples)

    def merge(self, other: 'TargetDossier') -> None:
        """
        Merge another dossier into this one.
        Used when correlating multiple MACs as same device.
        """
        # Update timestamps
        if other.first_seen:
            if self.first_seen is None or other.first_seen < self.first_seen:
                self.first_seen = other.first_seen
        if other.last_seen:
            if self.last_seen is None or other.last_seen > self.last_seen:
                self.last_seen = other.last_seen

        # Merge PNL
        for ssid, ts in other.probed_ssids.items():
            if ssid not in self.probed_ssids or ts > self.probed_ssids[ssid]:
                self.probed_ssids[ssid] = ts

        # Merge associations
        self.associated_bssids.update(other.associated_bssids)

        # Merge handshake activity
        self.handshake_activity.extend(other.handshake_activity)

        # Merge characteristics
        self.channels_active.update(other.channels_active)
        self.rssi_samples.extend(other.rssi_samples)

        # Track correlation
        self.correlated_macs.add(other.mac)
        self.correlated_macs.update(other.correlated_macs)

        # Merge metadata
        self.metadata.update(other.metadata)

        # Merge identification (take specific over generic)
        if self.vendor == "Unknown" and other.vendor != "Unknown":
            self.vendor = other.vendor
            self.device_type = other.device_type


    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            'mac': self.mac,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'probed_ssids': {
                ssid: ts.isoformat() if ts else None
                for ssid, ts in self.probed_ssids.items()
            },
            'associated_bssids': sorted(self.associated_bssids),
            'handshake_activity': self.handshake_activity,
            'is_randomized_mac': self.is_randomized_mac,
            'channels_active': sorted(self.channels_active),
            'avg_rssi': self.avg_rssi,
            'correlated_macs': sorted(self.correlated_macs),
            'metadata': self.metadata,
            'activity_count': self.activity_count,
            'pnl_count': self.pnl_count,
            'vendor': self.vendor,
            'device_type': self.device_type,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class IdentityFusion:
    """
    Correlation engine that merges records from multiple sources.

    Key features:
    - Aggregates intelligence from AgentShadow and AgentCrypt
    - Detects potential MAC address correlations
    - Generates comprehensive target dossiers
    """

    def __init__(self, fingerprinter=None, classifier: Optional['CorrelationClassifier'] = None, enable_ml: bool = False):
        """
        Initialize the correlation engine.

        Args:
            fingerprinter: Optional DeviceFingerprinter for enhanced correlation
            classifier: Optional CorrelationClassifier for ML-powered correlation
            enable_ml: Whether to enable ML features (default: False)
        """
        self.dossiers: dict[str, TargetDossier] = {}
        self.fingerprinter = fingerprinter
        self.enable_ml = enable_ml
        self.classifier = classifier if enable_ml else None

        # Track SSIDs to find common probers
        self._ssid_to_macs: dict[str, set[str]] = defaultdict(set)

        # Track potential correlations (mac1, mac2) -> confidence
        self._correlations: dict[tuple[str, str], float] = {}

        self._stats = {
            'intelligence_items': 0,
            'dossiers_created': 0,
            'correlations_suggested': 0,
            'ml_correlations_suggested': 0,
        }

    def _get_or_create_dossier(self, mac: str) -> TargetDossier:
        """Get existing dossier or create new one."""
        mac = mac.lower()
        if mac not in self.dossiers:
            self.dossiers[mac] = TargetDossier(mac=mac)
            self._stats['dossiers_created'] += 1

            # Attempt to resolve vendor immediately
            if self.fingerprinter:
                vendor = self.fingerprinter.lookup_vendor(mac)
                if vendor:
                    self.dossiers[mac].vendor = vendor
                    # We could also infer device type if we had profile info,
                    # but pure MAC lookup is a good start.

        return self.dossiers[mac]

    def fuse(self, intelligence_stream: list[dict[str, Any]]) -> None:
        """
        Ingest a stream of intelligence dicts and merge them into dossiers.

        Each intelligence item should have at least:
        - 'type': 'probe_request' or 'eapol'
        - 'src_mac': source MAC address

        Additional fields depending on type:
        - probe_request: ssid, channel, rssi, timestamp, is_randomized_mac
        - eapol: bssid, message_number, pmkid, timestamp
        """
        for item in intelligence_stream:
            self._stats['intelligence_items'] += 1

            item_type = item.get('type')
            src_mac = item.get('src_mac')

            if not src_mac:
                continue

            src_mac = src_mac.lower()
            dossier = self._get_or_create_dossier(src_mac)

            # Update timestamps
            timestamp = item.get('timestamp')
            if timestamp:
                if isinstance(timestamp, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp)
                if dossier.first_seen is None or timestamp < dossier.first_seen:
                    dossier.first_seen = timestamp
                if dossier.last_seen is None or timestamp > dossier.last_seen:
                    dossier.last_seen = timestamp

            if item_type == 'probe_request':
                self._process_probe(dossier, item)
            elif item_type == 'eapol':
                self._process_eapol(dossier, item)

    def _process_probe(self, dossier: TargetDossier, item: dict[str, Any]) -> None:
        """Process probe request intelligence."""
        ssid = item.get('ssid')
        if ssid:
            timestamp = item.get('timestamp')
            if timestamp and (ssid not in dossier.probed_ssids or
                            timestamp > dossier.probed_ssids.get(ssid)):
                dossier.probed_ssids[ssid] = timestamp

            # Track for correlation
            self._ssid_to_macs[ssid].add(dossier.mac)

        # Update characteristics
        channel = item.get('channel')
        if channel is not None:
            dossier.channels_active.add(channel)

        rssi = item.get('rssi')
        if rssi is not None:
            dossier.rssi_samples.append(rssi)
            # Keep last 100 samples
            if len(dossier.rssi_samples) > 100:
                dossier.rssi_samples = dossier.rssi_samples[-100:]

        if item.get('is_randomized_mac'):
            dossier.is_randomized_mac = True

    def _process_eapol(self, dossier: TargetDossier, item: dict[str, Any]) -> None:
        """Process EAPOL/handshake intelligence."""
        bssid = item.get('bssid')
        if bssid:
            dossier.associated_bssids.add(bssid.lower())

        # Record handshake activity
        activity = {
            'bssid': bssid,
            'message_number': item.get('message_number'),
            'timestamp': item.get('timestamp').isoformat() if item.get('timestamp') else None,
            'pmkid': item.get('pmkid'),
        }
        dossier.handshake_activity.append(activity)

    def generate_dossier(self, target_mac: str) -> dict[str, Any] | None:
        """
        Return the aggregated known info for a target.

        Args:
            target_mac: MAC address to look up

        Returns:
            Dict representation of dossier, or None if not found
        """
        target_mac = target_mac.lower()
        dossier = self.dossiers.get(target_mac)
        if dossier:
            return dossier.to_dict()
        return None

    def get_dossier(self, target_mac: str) -> TargetDossier | None:
        """Get raw TargetDossier object."""
        return self.dossiers.get(target_mac.lower())

    def get_all_dossiers(self) -> dict[str, TargetDossier]:
        """Get all dossiers."""
        return self.dossiers.copy()

    def suggest_correlations(self, min_confidence: float = 0.5) -> list[tuple[str, str, float]]:
        """
        Suggest MAC address pairs that may be the same physical device.

        Correlation heuristics:
        1. PNL Overlap: Devices probing for >70% same SSIDs
        2. Temporal Proximity: Randomized MACs with sequential timestamps
        3. RSSI Similarity: Similar signal strength patterns

        Args:
            min_confidence: Minimum confidence score (0-1) to include

        Returns:
            List of (mac1, mac2, confidence) tuples
        """
        correlations = []

        # Find MACs with significant PNL overlap
        macs = list(self.dossiers.keys())

        for i, mac1 in enumerate(macs):
            dossier1 = self.dossiers[mac1]
            pnl1 = set(dossier1.probed_ssids.keys())

            if not pnl1:
                continue

            for mac2 in macs[i+1:]:
                dossier2 = self.dossiers[mac2]
                pnl2 = set(dossier2.probed_ssids.keys())

                if not pnl2:
                    continue

                # Calculate Jaccard similarity
                intersection = len(pnl1 & pnl2)
                union = len(pnl1 | pnl2)

                if union > 0:
                    similarity = intersection / union

                    # Boost score if both are randomized MACs
                    if dossier1.is_randomized_mac and dossier2.is_randomized_mac:
                        similarity *= 1.2  # 20% boost

                    # Cap at 1.0
                    similarity = min(similarity, 1.0)

                    if similarity >= min_confidence:
                        correlations.append((mac1, mac2, round(similarity, 3)))

        self._stats['correlations_suggested'] = len(correlations)

        # Sort by confidence descending
        return sorted(correlations, key=lambda x: -x[2])

    def suggest_correlations_ml(
        self,
        min_confidence: float = 0.7,
    ) -> list[tuple[str, str, float, dict[str, Any]]]:
        """
        ML-powered correlation suggestions using Decision Tree classifier.

        Uses trained classifier to predict MAC address correlations based on
        multiple features: PNL overlap, RSSI similarity, temporal overlap,
        channel overlap, randomization flags, and activity ratios.

        Args:
            min_confidence: Minimum confidence score (0-1) to include

        Returns:
            List of (mac1, mac2, confidence, explanation) tuples

        Raises:
            RuntimeError: If classifier is not trained
        """
        if not self.enable_ml:
            # logger.warning("ML correlation requested but ML is disabled.")
            return []

        if self.classifier is None:
            from nexus.intel.correlation_classifier import CorrelationClassifier
            self.classifier = CorrelationClassifier()

        if not self.classifier.is_trained:
            raise RuntimeError(
                "Classifier must be trained before ML correlation. "
                "Call train_classifier() first."
            )

        correlations = []
        macs = list(self.dossiers.keys())

        for i, mac1 in enumerate(macs):
            dossier1 = self.dossiers[mac1]

            for mac2 in macs[i+1:]:
                dossier2 = self.dossiers[mac2]

                prediction = self.classifier.predict(dossier1, dossier2)

                if prediction.is_same_device and prediction.confidence >= min_confidence:
                    correlations.append((
                        mac1,
                        mac2,
                        prediction.confidence,
                        prediction.to_dict(),
                    ))

        self._stats['ml_correlations_suggested'] = len(correlations)

        # Sort by confidence descending
        return sorted(correlations, key=lambda x: -x[2])

    def train_classifier(
        self,
        fingerprint_groups: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """
        Train the correlation classifier using fingerprint-based ground truth.

        Uses fingerprint hash matches as positive labels (if two MACs share
        a fingerprint, they're the same device). Generates negative samples
        from pairs with different fingerprints.

        Args:
            fingerprint_groups: Dict of fingerprint_hash -> list of MACs.
                               If None, builds from dossier metadata.

        Returns:
            Training statistics dictionary
        """
        if self.classifier is None:
            from nexus.intel.correlation_classifier import CorrelationClassifier
            self.classifier = CorrelationClassifier()

        from nexus.intel.correlation_classifier import generate_training_data_from_lattice

        # Build fingerprint groups if not provided
        if fingerprint_groups is None:
            fingerprint_groups = defaultdict(list)
            for mac, dossier in self.dossiers.items():
                fp_hash = dossier.metadata.get('fingerprint_hash')
                if fp_hash:
                    fingerprint_groups[fp_hash].append(mac)
            fingerprint_groups = dict(fingerprint_groups)

        # Generate training data
        labeled_pairs = generate_training_data_from_lattice(
            self.dossiers,
            fingerprint_groups,
        )

        if not labeled_pairs:
            logger.warning("No training data generated - need fingerprint matches")
            return {'error': 'No training data available'}

        # Train
        stats = self.classifier.train(labeled_pairs, self.dossiers)
        logger.info(f"Trained classifier: {stats}")

        return stats

    def get_correlation_explanation(
        self,
        mac1: str,
        mac2: str,
    ) -> dict[str, Any] | None:
        """
        Get detailed explanation of correlation prediction between two MACs.

        Useful for visualization and debugging.

        Args:
            mac1: First MAC address
            mac2: Second MAC address

        Returns:
            Dict with prediction, confidence, features, and decision path
        """
        mac1 = mac1.lower()
        mac2 = mac2.lower()

        if mac1 not in self.dossiers or mac2 not in self.dossiers:
            return None

        if self.classifier is None or not self.classifier.is_trained:
            return None

        prediction = self.classifier.predict(
            self.dossiers[mac1],
            self.dossiers[mac2],
        )

        return prediction.to_dict()

    def merge_identities(self, primary_mac: str, secondary_mac: str) -> bool:
        """
        Merge two MAC addresses into a single identity.

        The secondary dossier is merged into the primary and removed.

        Args:
            primary_mac: MAC to keep as primary identity
            secondary_mac: MAC to merge into primary

        Returns:
            True if merge successful, False if either MAC not found
        """
        primary_mac = primary_mac.lower()
        secondary_mac = secondary_mac.lower()

        if primary_mac not in self.dossiers or secondary_mac not in self.dossiers:
            return False

        if primary_mac == secondary_mac:
            return True  # Same MAC, nothing to merge

        primary = self.dossiers[primary_mac]
        secondary = self.dossiers[secondary_mac]

        primary.merge(secondary)
        del self.dossiers[secondary_mac]

        return True

    def export_all(self, filepath: str) -> int:
        """
        Export all dossiers to JSON file.

        Args:
            filepath: Path to output file

        Returns:
            Number of dossiers exported
        """
        output = {
            mac: dossier.to_dict()
            for mac, dossier in self.dossiers.items()
        }

        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)

        return len(output)

    def get_stats(self) -> dict[str, Any]:
        """Return processing statistics."""
        return {
            **self._stats,
            'total_dossiers': len(self.dossiers),
        }

    def reset(self) -> None:
        """Reset all state."""
        self.dossiers.clear()
        self._ssid_to_macs.clear()
        self._correlations.clear()
        self._stats = {
            'intelligence_items': 0,
            'dossiers_created': 0,
            'correlations_suggested': 0,
        }
