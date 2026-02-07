#!/usr/bin/env python3
"""
POL Analysis Demo

Demonstrates Pattern-of-Life K-Means clustering for device behavior analysis.
Shows before/after comparison: raw timestamps vs behavioral clusters.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta

import numpy as np

from nexus.intel.pol_analyzer import POLAnalyzer


def create_demo_profiles():
    """Create synthetic profiles with distinct behavioral patterns."""
    from dataclasses import dataclass, field

    @dataclass
    class DemoProfile:
        mac: str
        timestamp_history: list[datetime] = field(default_factory=list)
        probed_ssids: dict[str, datetime] = field(default_factory=dict)
        first_seen: datetime | None = None
        last_seen: datetime | None = None

    np.random.seed(42)
    profiles = {}
    base = datetime(2025, 6, 2, 0, 0, 0)  # Monday

    # === COMMUTERS (work 9-5 weekdays) ===
    for i in range(6):
        mac = f"commuter_{i}"
        timestamps = []
        for day in range(14):
            date = base + timedelta(days=day)
            if date.weekday() < 5:  # Weekday
                for hour in range(8 + i % 2, 17 + i % 2):
                    if np.random.random() > 0.3:
                        ts = date.replace(hour=hour, minute=np.random.randint(0, 60))
                        timestamps.append(ts)

        profiles[mac] = DemoProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"Corporate_{i}": base, "Office-5G": base},
            first_seen=min(timestamps),
            last_seen=max(timestamps),
        )

    # === RESIDENTS (home all day, evening peaks) ===
    for i in range(6):
        mac = f"resident_{i}"
        timestamps = []
        for day in range(14):
            date = base + timedelta(days=day)
            for hour in [7, 8, 12, 18, 19, 20, 21, 22]:
                if np.random.random() > 0.2:
                    ts = date.replace(hour=hour, minute=np.random.randint(0, 60))
                    timestamps.append(ts)

        profiles[mac] = DemoProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"Home_{i}": base, "HomeWiFi": base, "Guest": base, "SmartTV": base},
            first_seen=min(timestamps),
            last_seen=max(timestamps),
        )

    # === VISITORS (brief, one-time) ===
    for i in range(6):
        mac = f"visitor_{i}"
        day = np.random.randint(0, 14)
        date = base + timedelta(days=day)
        timestamps = [
            date.replace(hour=np.random.randint(10, 16), minute=np.random.randint(0, 60))
            for _ in range(4)
        ]

        profiles[mac] = DemoProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"Visitor_{i}": base},
            first_seen=min(timestamps),
            last_seen=max(timestamps),
        )

    # === NIGHT OWLS (active 10pm-4am) ===
    for i in range(6):
        mac = f"night_owl_{i}"
        timestamps = []
        for day in range(14):
            date = base + timedelta(days=day)
            for hour in [22, 23, 0, 1, 2, 3]:
                if np.random.random() > 0.4:
                    actual_date = date if hour >= 22 else date + timedelta(days=1)
                    ts = actual_date.replace(hour=hour, minute=np.random.randint(0, 60))
                    timestamps.append(ts)

        profiles[mac] = DemoProfile(
            mac=mac,
            timestamp_history=timestamps,
            probed_ssids={f"NightClub_{i}": base, "24hr-Diner": base},
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        )

    return profiles


def run_demo():
    """Run the POL analysis demo."""
    print("=" * 70)
    print("PATTERN-OF-LIFE ANALYSIS DEMO")
    print("K-Means Clustering for Device Behavior")
    print("=" * 70)
    print()

    # Create profiles
    print("📊 Creating synthetic device profiles...")
    profiles = create_demo_profiles()
    print(f"   • {len(profiles)} devices with distinct behavioral patterns")
    print()

    # === BEFORE: Raw timestamps only ===
    print("-" * 70)
    print("BEFORE: Raw Timestamp Data (No Analysis)")
    print("-" * 70)
    print()
    for mac, profile in list(profiles.items())[:4]:
        n_ts = len(profile.timestamp_history)
        print(f"  {mac}: {n_ts} observations")
        print(f"    First: {profile.first_seen}")
        print(f"    Last:  {profile.last_seen}")
        print("    ❓ Behavior: UNKNOWN")
        print()
    print("  ... (no pattern analysis possible)")
    print()

    # === AFTER: K-Means clustering ===
    print("-" * 70)
    print("AFTER: K-Means Clustering (POL Analysis)")
    print("-" * 70)
    print()

    # Fit analyzer
    analyzer = POLAnalyzer(n_clusters=4)
    stats = analyzer.fit(profiles)

    print("🤖 Clustering complete:")
    print(f"   • Devices analyzed: {stats['n_profiles']}")
    print(f"   • Clusters found: {stats['n_clusters']}")
    print(f"   • Silhouette score: {stats['silhouette_score']:.3f} (>0.5 is good)")
    print()

    # Show cluster distribution
    print("📈 Cluster Distribution:")
    for cluster, count in stats['cluster_sizes'].items():
        bar = "█" * count
        print(f"   {cluster:12s} {bar} ({count})")
    print()

    # Show sample results
    print("🔍 Sample Results:")
    for mac in ['commuter_0', 'resident_0', 'visitor_0', 'night_owl_0']:
        profile = analyzer.get_profile(mac)
        if profile:
            print(f"  {mac}:")
            print(f"    📌 Cluster: {profile.cluster.upper()}")
            print(f"    💯 Confidence: {profile.confidence:.1%}")
            top_feature = max(profile.features.items(), key=lambda x: x[1])
            print(f"    🔝 Top feature: {top_feature[0]} = {top_feature[1]:.2f}")
            print()

    # Feature importance from cluster centers
    print("-" * 70)
    print("CLUSTER CHARACTERISTICS")
    print("-" * 70)
    print()

    centers = analyzer.get_cluster_centers()
    for cluster, features in centers.items():
        print(f"  {cluster.upper()}:")
        # Show top 3 features
        sorted_features = sorted(features.items(), key=lambda x: -x[1])[:3]
        for feat, val in sorted_features:
            bar = "█" * int(val * 20)
            print(f"    {feat:20s} {bar} ({val:.2f})")
        print()

    # === OPTIMIZATION IMPACT ===
    print("=" * 70)
    print("OPTIMIZATION IMPACT")
    print("=" * 70)
    print()
    print("  ✅ Before: Only raw timestamps, no behavioral insight")
    print("  ✅ After:  Automatic behavioral clustering")
    print()
    print("  📊 New capabilities:")
    print("     • Identify 'commuter' devices (9-5 activity)")
    print("     • Detect 'resident' devices (always present)")
    print("     • Flag 'visitor' devices (brief appearances)")
    print("     • Track 'night_owl' devices (unusual hours)")
    print()
    print(f"  📈 Silhouette score: {stats['silhouette_score']:.3f}")
    if stats['silhouette_score'] > 0.5:
        print("     ✅ Good cluster separation - patterns are distinct!")
    elif stats['silhouette_score'] > 0.25:
        print("     ⚠️  Moderate separation - some overlap in patterns")
    else:
        print("     ❌ Weak separation - may need more features")


if __name__ == "__main__":
    run_demo()
