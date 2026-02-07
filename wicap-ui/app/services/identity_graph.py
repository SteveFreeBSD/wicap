import os
import time
from dataclasses import dataclass, field

from nexus.intel.identity_graph import IdentityGraph
from nexus.intel.identity_graph_store import IdentityGraphStoreConfig, build_graph_from_db


@dataclass
class IdentityGraphConfig:
    ttl_sec: int = int(os.getenv("WICAP_IDENTITY_GRAPH_TTL_SEC", "300"))
    store: IdentityGraphStoreConfig = field(default_factory=IdentityGraphStoreConfig)


_CONFIG = IdentityGraphConfig()
_CACHE: dict[str, object] = {"graph": None, "ts": 0.0}


def get_identity_graph(conn) -> IdentityGraph:
    now = time.time()
    cached = _CACHE.get("graph")
    if cached and now - float(_CACHE.get("ts", 0.0)) < _CONFIG.ttl_sec:
        return cached

    graph = build_graph_from_db(conn, _CONFIG.store)
    _CACHE["graph"] = graph
    _CACHE["ts"] = now
    return graph


def get_identity_graph_cached() -> IdentityGraph | None:
    cached = _CACHE.get("graph")
    return cached if isinstance(cached, IdentityGraph) else None


def get_identity_graph_summary(conn, allow_build: bool = False) -> dict[str, object]:
    now = time.time()
    cached = _CACHE.get("graph")
    ts = float(_CACHE.get("ts", 0.0))
    if cached:
        return {
            "cached": True,
            "age_sec": round(now - ts, 2),
            "cluster_count": len(cached.clusters),
            "edge_count": len(cached.edges),
        }
    if allow_build:
        graph = get_identity_graph(conn)
        return {
            "cached": False,
            "age_sec": 0,
            "cluster_count": len(graph.clusters),
            "edge_count": len(graph.edges),
        }
    return {
        "cached": False,
        "age_sec": None,
        "cluster_count": 0,
        "edge_count": 0,
    }


def get_cluster_for_identifier(conn, identifier: str) -> dict | None:
    graph = get_identity_graph(conn)
    cluster = graph.cluster_for(identifier)
    if not cluster:
        return None
    members_detail = []
    for member in cluster.members:
        profile = graph.profile_map.get(member)
        members_detail.append(
            {
                "id": member,
                "protocol": profile.protocol if profile else None,
                "vendor": profile.vendor if profile else None,
                "device_type": profile.device_type if profile else None,
                "local_name": profile.local_name if profile else None,
            }
        )
    return {
        "cluster_id": cluster.cluster_id,
        "members": cluster.members,
        "members_detail": members_detail,
        "confidence": cluster.confidence,
        "signals": cluster.signals,
    }
