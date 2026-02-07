#!/usr/bin/env python3
"""
Correlation Method Comparison Script

Compares the heuristic-based correlation method vs ML-powered Decision Tree
to demonstrate how many additional correlations the ML version catches.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
from collections import defaultdict
from datetime import datetime, timedelta

from nexus.scavenger.correlator import IdentityFusion, TargetDossier


def create_synthetic_dataset(n_devices=20, n_macs_per_device=3):
    """
    Create a realistic dataset with known ground truth.

    Each "device" has multiple randomized MACs that should correlate.
    """
    dossiers = {}
    ground_truth = {}  # device_id -> list of MACs
    base_time = datetime.now()

    # Common SSIDs pool
    common_ssids = [
        "HomeWiFi", "Starbucks", "ATT-5G", "xfinitywifi",
        "NETGEAR", "linksys", "Guest", "Corporate-Secure",
        "AndroidAP", "iPhone", "Galaxy", "Pixel"
    ]

    for device_id in range(n_devices):
        device_macs = []

        # Device characteristics (consistent across its MACs)
        device_pnl = random.sample(common_ssids, random.randint(2, 5))
        device_rssi_base = random.randint(-70, -40)
        device_channels = set(random.sample([1, 6, 11, 36, 40, 44], random.randint(2, 4)))
        device_start = base_time - timedelta(days=random.randint(0, 7))

        for mac_idx in range(n_macs_per_device):
            mac = f"aa:bb:cc:{device_id:02x}:{mac_idx:02x}:ff"
            device_macs.append(mac)

            d = TargetDossier(mac=mac)

            # PNL: mostly shared but with some variation
            pnl_subset = random.sample(device_pnl, max(1, len(device_pnl) - 1))
            # Add 0-1 unique SSIDs per MAC
            if random.random() > 0.5:
                pnl_subset.append(f"UniqueTo{mac[:8]}")

            d.probed_ssids = dict.fromkeys(pnl_subset, base_time)

            # RSSI: similar with small variance
            d.rssi_samples = [device_rssi_base + random.randint(-3, 3) for _ in range(5)]

            # Channels: mostly same
            d.channels_active = device_channels.copy()
            if random.random() > 0.7:
                d.channels_active.add(random.choice([1, 6, 11, 36]))

            # Timing: overlapping windows
            d.first_seen = device_start + timedelta(hours=random.randint(0, 2))
            d.last_seen = base_time - timedelta(hours=random.randint(0, 2))

            # Randomization: high for same device
            d.is_randomized_mac = True

            # Ground truth fingerprint
            d.metadata = {'fingerprint_hash': f'fp_device_{device_id}'}

            dossiers[mac] = d

        ground_truth[device_id] = device_macs

    # Add some noise devices (single MAC, different behavior)
    for i in range(5):
        mac = f"bb:cc:dd:ee:{i:02x}:00"
        d = TargetDossier(mac=mac)
        d.probed_ssids = {f"RandomSSID{i}": base_time}
        d.rssi_samples = [-85 + random.randint(-5, 5)]
        d.channels_active = {random.choice([1, 6, 11])}
        d.first_seen = base_time - timedelta(days=30)
        d.last_seen = base_time - timedelta(days=29)
        d.is_randomized_mac = False
        dossiers[mac] = d

    return dossiers, ground_truth


def run_comparison():
    """Run comparison between heuristic and ML methods."""
    print("=" * 60)
    print("CORRELATION METHOD COMPARISON")
    print("=" * 60)
    print()

    # Create dataset
    print("📊 Generating synthetic dataset with known ground truth...")
    dossiers, ground_truth = create_synthetic_dataset(n_devices=15, n_macs_per_device=3)

    n_devices = len(ground_truth)
    n_macs = len(dossiers)
    n_true_pairs = sum(len(macs) * (len(macs) - 1) // 2 for macs in ground_truth.values())

    print(f"   • {n_devices} physical devices")
    print(f"   • {n_macs} MAC addresses total")
    print(f"   • {n_true_pairs} true same-device pairs")
    print()

    # Build fingerprint groups for training
    fingerprint_groups = defaultdict(list)
    for mac, dossier in dossiers.items():
        fp = dossier.metadata.get('fingerprint_hash')
        if fp:
            fingerprint_groups[fp].append(mac)

    # Create fusion engine
    fusion = IdentityFusion()
    fusion.dossiers = dossiers

    # === HEURISTIC METHOD ===
    print("🔍 Running HEURISTIC method (PNL Jaccard only)...")
    heuristic_results = fusion.suggest_correlations(min_confidence=0.3)

    heuristic_pairs = set()
    for mac1, mac2, _conf in heuristic_results:
        pair = tuple(sorted([mac1, mac2]))
        heuristic_pairs.add(pair)

    # === ML METHOD ===
    print("🤖 Training ML classifier...")
    try:
        stats = fusion.train_classifier(dict(fingerprint_groups))
        print(f"   • Trained on {stats.get('n_samples', 0)} samples")
        print(f"   • Tree depth: {stats.get('tree_depth', 'N/A')}")

        print("🤖 Running ML method (6-feature Decision Tree)...")
        ml_results = fusion.suggest_correlations_ml(min_confidence=0.5)

        ml_pairs = set()
        for mac1, mac2, _conf, _explanation in ml_results:
            pair = tuple(sorted([mac1, mac2]))
            ml_pairs.add(pair)
    except Exception as e:
        print(f"   ❌ ML method failed: {e}")
        ml_pairs = set()

    # === BUILD GROUND TRUTH SET ===
    true_pairs = set()
    for _device_id, macs in ground_truth.items():
        for i, mac1 in enumerate(macs):
            for mac2 in macs[i+1:]:
                pair = tuple(sorted([mac1, mac2]))
                true_pairs.add(pair)

    # === ANALYSIS ===
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print()

    # Heuristic stats
    heuristic_tp = len(heuristic_pairs & true_pairs)
    heuristic_fp = len(heuristic_pairs - true_pairs)
    heuristic_fn = len(true_pairs - heuristic_pairs)
    heuristic_precision = heuristic_tp / len(heuristic_pairs) if heuristic_pairs else 0
    heuristic_recall = heuristic_tp / len(true_pairs) if true_pairs else 0

    print("📈 HEURISTIC (PNL Jaccard + randomization boost):")
    print(f"   • Correlations found: {len(heuristic_pairs)}")
    print(f"   • True positives:     {heuristic_tp}")
    print(f"   • False positives:    {heuristic_fp}")
    print(f"   • Missed (FN):        {heuristic_fn}")
    print(f"   • Precision:          {heuristic_precision:.1%}")
    print(f"   • Recall:             {heuristic_recall:.1%}")
    print()

    # ML stats
    if ml_pairs:
        ml_tp = len(ml_pairs & true_pairs)
        ml_fp = len(ml_pairs - true_pairs)
        ml_fn = len(true_pairs - ml_pairs)
        ml_precision = ml_tp / len(ml_pairs) if ml_pairs else 0
        ml_recall = ml_tp / len(true_pairs) if true_pairs else 0

        print("📈 ML (6-feature Decision Tree):")
        print(f"   • Correlations found: {len(ml_pairs)}")
        print(f"   • True positives:     {ml_tp}")
        print(f"   • False positives:    {ml_fp}")
        print(f"   • Missed (FN):        {ml_fn}")
        print(f"   • Precision:          {ml_precision:.1%}")
        print(f"   • Recall:             {ml_recall:.1%}")
        print()

        # Comparison
        print("=" * 60)
        print("COMPARISON")
        print("=" * 60)
        print()

        only_ml = ml_pairs - heuristic_pairs
        only_heuristic = heuristic_pairs - ml_pairs
        both = ml_pairs & heuristic_pairs

        print(f"✅ Found by BOTH methods:     {len(both)}")
        print(f"🆕 Found ONLY by ML:          {len(only_ml)}")
        print(f"⚠️  Found ONLY by Heuristic:  {len(only_heuristic)}")
        print()

        # Improvement
        recall_improvement = (ml_recall - heuristic_recall) / heuristic_recall * 100 if heuristic_recall > 0 else 0
        additional_catches = len(only_ml & true_pairs)

        print("=" * 60)
        print("OPTIMIZATION IMPACT")
        print("=" * 60)
        print()
        print(f"🎯 Additional TRUE correlations caught by ML: {additional_catches}")
        print(f"📊 Recall improvement: {recall_improvement:+.1f}%")

        if additional_catches > 0:
            print()
            print("✅ ML method CATCHES correlations the heuristic MISSES")
            print("   by combining RSSI, timing, and channel signals!")

        # Feature importance
        if fusion.classifier:
            importance = fusion.classifier.get_feature_importance()
            print()
            print("🔬 Feature Importance (what the model learned):")
            for feat, imp in sorted(importance.items(), key=lambda x: -x[1]):
                bar = "█" * int(imp * 30)
                print(f"   {feat:18s} {bar} {imp:.1%}")


if __name__ == "__main__":
    run_comparison()
