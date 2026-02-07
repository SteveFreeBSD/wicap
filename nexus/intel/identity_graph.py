"""
Identity Graph - Cross-MAC Correlation

Builds identity clusters by linking MAC addresses that appear to belong to the
same physical device using fingerprints and behavioral similarity signals.

Primary signals:
1) Fingerprint match (high confidence)
2) PNL overlap (probe SSIDs Jaccard)
3) RSSI similarity
4) Temporal overlap
5) Channel overlap

This module is protocol-aware (wifi/bt) and can optionally link across
protocols when a strong fingerprint match exists.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass
class IdentityProfile:
    """Normalized device profile used for identity graph correlation."""
    identifier: str
    protocol: str  # "wifi" | "bt"
    fingerprint_hash: str | None = None
    probed_ssids: set[str] = field(default_factory=set)
    channels: set[int] = field(default_factory=set)
    avg_rssi: float | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    is_randomized: bool = False
    vendor: str | None = None
    device_type: str | None = None
    local_name: str | None = None
    services: set[str] = field(default_factory=set)


@dataclass
class IdentityEdge:
    """Graph edge between two profiles with confidence and signals."""
    a: str
    b: str
    confidence: float
    reasons: dict[str, float]


@dataclass
class IdentityCluster:
    """Cluster of identifiers inferred to be same device."""
    cluster_id: str
    members: list[str]
    confidence: float
    signals: dict[str, float] = field(default_factory=dict)


@dataclass
class IdentityGraph:
    """Identity graph output."""
    clusters: list[IdentityCluster]
    edges: list[IdentityEdge]
    profile_map: dict[str, IdentityProfile]

    def cluster_for(self, identifier: str) -> IdentityCluster | None:
        """Return cluster for a given identifier (MAC or BLE addr)."""
        for cluster in self.clusters:
            if identifier in cluster.members:
                return cluster
        return None

    def to_dict(self, include_profiles: bool = False) -> dict:
        """Serialize graph for API responses."""
        payload = {
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "members": c.members,
                    "confidence": round(c.confidence, 3),
                    "signals": {k: round(v, 3) for k, v in c.signals.items()},
                }
                for c in self.clusters
            ],
            "edges": [
                {
                    "a": e.a,
                    "b": e.b,
                    "confidence": round(e.confidence, 3),
                    "reasons": {k: round(v, 3) for k, v in e.reasons.items()},
                }
                for e in self.edges
            ],
        }
        if include_profiles:
            payload["profiles"] = [
                {
                    "id": p.identifier,
                    "protocol": p.protocol,
                    "fingerprint_hash": p.fingerprint_hash,
                    "vendor": p.vendor,
                    "device_type": p.device_type,
                    "local_name": p.local_name,
                    "is_randomized": p.is_randomized,
                    "first_seen": p.first_seen.isoformat() if hasattr(p.first_seen, "isoformat") else p.first_seen,
                    "last_seen": p.last_seen.isoformat() if hasattr(p.last_seen, "isoformat") else p.last_seen,
                }
                for p in self.profile_map.values()
            ]
        return payload

    def compact_profiles(self) -> None:
        """Drop heavy, build-time-only fields to reduce cached memory."""
        for profile in self.profile_map.values():
            profile.probed_ssids = set()
            profile.channels = set()
            profile.services = set()


class _UnionFind:
    def __init__(self, items: Iterable[str]):
        self._parent = {item: item for item in items}
        self._rank = dict.fromkeys(items, 0)

    def find(self, item: str) -> str:
        parent = self._parent[item]
        if parent != item:
            self._parent[item] = self.find(parent)
        return self._parent[item]

    def union(self, a: str, b: str) -> None:
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a == root_b:
            return
        rank_a = self._rank[root_a]
        rank_b = self._rank[root_b]
        if rank_a < rank_b:
            self._parent[root_a] = root_b
        elif rank_a > rank_b:
            self._parent[root_b] = root_a
        else:
            self._parent[root_b] = root_a
            self._rank[root_a] += 1


def _to_epoch(value: float | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    # datetime-like
    return float(value.timestamp())


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _rssi_similarity(a: float | None, b: float | None) -> float:
    if a is None or b is None:
        return 0.5
    diff = abs(a - b)
    # Normalize to 0-1 similarity (20dB = weak similarity)
    return max(0.0, 1.0 - (diff / 20.0))


def _temporal_overlap(a_start: float | None, a_end: float | None,
                      b_start: float | None, b_end: float | None) -> float:
    if a_start is None or a_end is None or b_start is None or b_end is None:
        return 0.5
    overlap_start = max(a_start, b_start)
    overlap_end = min(a_end, b_end)
    overlap = max(0.0, overlap_end - overlap_start)
    window_a = max(1.0, a_end - a_start)
    window_b = max(1.0, b_end - b_start)
    min_window = min(window_a, window_b)
    return min(1.0, overlap / min_window) if min_window > 0 else 0.0


def _channel_overlap(a: set[int], b: set[int]) -> float:
    if not a and not b:
        return 0.5
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _similarity(profile_a: IdentityProfile, profile_b: IdentityProfile) -> tuple[float, dict[str, float]]:
    """Compute similarity score and signal breakdown."""
    pnl = _jaccard(profile_a.probed_ssids, profile_b.probed_ssids)
    rssi = _rssi_similarity(profile_a.avg_rssi, profile_b.avg_rssi)
    temporal = _temporal_overlap(
        _to_epoch(profile_a.first_seen),
        _to_epoch(profile_a.last_seen),
        _to_epoch(profile_b.first_seen),
        _to_epoch(profile_b.last_seen),
    )
    channel = _channel_overlap(profile_a.channels, profile_b.channels)
    both_randomized = 1.0 if (profile_a.is_randomized and profile_b.is_randomized) else 0.0

    weights = {
        "pnl": 0.35,
        "rssi": 0.2,
        "temporal": 0.2,
        "channel": 0.15,
        "randomized": 0.1,
    }
    score = (
        pnl * weights["pnl"]
        + rssi * weights["rssi"]
        + temporal * weights["temporal"]
        + channel * weights["channel"]
        + both_randomized * weights["randomized"]
    )
    reasons = {
        "pnl_jaccard": pnl,
        "rssi_similarity": rssi,
        "temporal_overlap": temporal,
        "channel_overlap": channel,
        "both_randomized": both_randomized,
    }
    return score, reasons


def build_identity_graph(
    profiles: list[IdentityProfile],
    *,
    min_score: float = 0.85,
    max_time_gap_sec: float = 12 * 3600,
    allow_cross_protocol: bool = False,
) -> IdentityGraph:
    """
    Build identity graph clusters from profiles.

    Args:
        profiles: List of IdentityProfile entries.
        min_score: Minimum similarity score required to link.
        max_time_gap_sec: Limit pair comparisons to devices active within this window.
        allow_cross_protocol: Allow linking across wifi/bt when fingerprint matches.
    """
    profile_map = {p.identifier: p for p in profiles}
    uf = _UnionFind(profile_map.keys())
    edges: list[IdentityEdge] = []

    # 1) Fingerprint-based linking (always strong)
    fingerprint_groups: dict[str, list[IdentityProfile]] = {}
    for p in profiles:
        if p.fingerprint_hash:
            fingerprint_groups.setdefault(p.fingerprint_hash, []).append(p)
    for _fp, group in fingerprint_groups.items():
        if len(group) < 2:
            continue
        # Union all with fingerprint match
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a = group[i]
                b = group[j]
                if not allow_cross_protocol and a.protocol != b.protocol:
                    continue
                uf.union(a.identifier, b.identifier)
                edges.append(
                    IdentityEdge(
                        a=a.identifier,
                        b=b.identifier,
                        confidence=1.0,
                        reasons={"fingerprint_match": 1.0},
                    )
                )

    # 2) Behavioral similarity (randomized MACs)
    # Sort by last_seen to reduce comparisons
    sortable = []
    now = time.time()
    for p in profiles:
        last_seen = _to_epoch(p.last_seen) or now
        sortable.append((last_seen, p))
    sortable.sort(key=lambda x: x[0])

    for idx, (ts, p) in enumerate(sortable):
        j = idx + 1
        while j < len(sortable):
            ts2, q = sortable[j]
            if ts2 - ts > max_time_gap_sec:
                break
            j += 1

            if p.identifier == q.identifier:
                continue
            if not allow_cross_protocol and p.protocol != q.protocol:
                continue
            # Avoid linking stable (non-randomized) MACs without fingerprint
            if not (p.is_randomized and q.is_randomized):
                continue
            # Skip if already linked by fingerprint
            if p.fingerprint_hash and q.fingerprint_hash and p.fingerprint_hash == q.fingerprint_hash:
                continue

            score, reasons = _similarity(p, q)
            # Require at least some strong signal
            if score >= min_score and (reasons["pnl_jaccard"] >= 0.5 or reasons["rssi_similarity"] >= 0.85):
                uf.union(p.identifier, q.identifier)
                edges.append(
                    IdentityEdge(
                        a=p.identifier,
                        b=q.identifier,
                        confidence=score,
                        reasons=reasons,
                    )
                )

    # 3) Build clusters
    clusters_map: dict[str, list[str]] = {}
    for ident in profile_map.keys():
        root = uf.find(ident)
        clusters_map.setdefault(root, []).append(ident)

    clusters: list[IdentityCluster] = []
    for _root, members in clusters_map.items():
        members_sorted = sorted(members)
        cluster_id = hashlib.sha256(",".join(members_sorted).encode()).hexdigest()[:12]
        # Aggregate confidence from edges in cluster
        cluster_edges = [e for e in edges if e.a in members and e.b in members]
        confidence = (
            sum(e.confidence for e in cluster_edges) / len(cluster_edges)
            if cluster_edges
            else 1.0
        )
        signals: dict[str, float] = {}
        if cluster_edges:
            for e in cluster_edges:
                for k, v in e.reasons.items():
                    signals[k] = max(signals.get(k, 0.0), v)
        clusters.append(
            IdentityCluster(
                cluster_id=cluster_id,
                members=members_sorted,
                confidence=confidence,
                signals=signals,
            )
        )

    return IdentityGraph(clusters=clusters, edges=edges, profile_map=profile_map)
