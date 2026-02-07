"""
Identity Graph Store

Loads profile data from SQL, builds the identity graph, and optionally
persists cluster results for investigations and reporting.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:
    import pyodbc
except ImportError:  # pragma: no cover - optional dependency
    pyodbc = None

from nexus.utils import json_compat

from .identity_graph import IdentityGraph, IdentityProfile, build_identity_graph


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class IdentityGraphStoreConfig:
    lookback_days: int = int(os.getenv("WICAP_IDENTITY_GRAPH_LOOKBACK_DAYS", "7"))
    min_score: float = float(os.getenv("WICAP_IDENTITY_GRAPH_MIN_SCORE", "0.85"))
    max_time_gap_sec: float = float(os.getenv("WICAP_IDENTITY_GRAPH_TIME_GAP_SEC", str(12 * 3600)))
    allow_cross_protocol: bool = _parse_bool(os.getenv("WICAP_IDENTITY_GRAPH_ALLOW_CROSS_PROTOCOL"))
    compact_profiles: bool = _parse_bool(os.getenv("WICAP_IDENTITY_GRAPH_COMPACT_PROFILES", "1"))


def _safe_json_set(value) -> set[str]:
    if not value:
        return set()
    try:
        decoded = json_compat.loads(value)
        return set(decoded) if isinstance(decoded, list) else set()
    except Exception:
        return set()


def load_profiles(conn, lookback_days: int | None = None) -> list[IdentityProfile]:
    """Load Wi-Fi and BLE profiles from SQL for graph build."""
    cursor = conn.cursor()
    profiles: list[IdentityProfile] = []

    lookback_days = max(1, int(lookback_days or IdentityGraphStoreConfig().lookback_days))

    cursor.execute(
        """
        SELECT mac_addr,
               ie_fingerprint,
               probe_fingerprint,
               probed_ssids,
               channels_active,
               first_seen,
               last_seen,
               rssi_avg,
               is_randomized,
               vendor,
               device_type
        FROM client_profiles
        WHERE last_seen > DATEADD(day, ?, GETDATE())
        """,
        (-lookback_days,),
    )
    for row in cursor.fetchall():
        profiles.append(
            IdentityProfile(
                identifier=row[0],
                protocol="wifi",
                fingerprint_hash=row[1] or row[2],
                probed_ssids=_safe_json_set(row[3]),
                channels=_safe_json_set(row[4]),
                first_seen=row[5],
                last_seen=row[6],
                avg_rssi=row[7],
                is_randomized=bool(row[8]) if row[8] is not None else False,
                vendor=row[9],
                device_type=row[10],
            )
        )

    # Bluetooth profiles (optional)
    try:
        cursor.execute(
            """
            SELECT addr,
                   manufacturer_data_hash,
                   services,
                   local_name,
                   first_seen,
                   last_seen,
                   rssi_avg,
                   addr_type,
                   vendor
            FROM bt_devices
            WHERE last_seen > DATEADD(day, ?, GETDATE())
            """,
            (-lookback_days,),
        )
        for row in cursor.fetchall():
            addr_type = (row[7] or "").lower()
            profiles.append(
                IdentityProfile(
                    identifier=row[0],
                    protocol="bt",
                    fingerprint_hash=row[1],
                    services=_safe_json_set(row[2]),
                    local_name=row[3],
                    first_seen=row[4],
                    last_seen=row[5],
                    avg_rssi=row[6],
                    is_randomized=(addr_type == "random"),
                    vendor=row[8],
                )
            )
    except Exception:
        pass

    return profiles


def build_graph_from_db(conn, config: IdentityGraphStoreConfig | None = None) -> IdentityGraph:
    """Build identity graph from SQL profile data."""
    config = config or IdentityGraphStoreConfig()
    profiles = load_profiles(conn, config.lookback_days)
    graph = build_identity_graph(
        profiles,
        min_score=config.min_score,
        max_time_gap_sec=config.max_time_gap_sec,
        allow_cross_protocol=config.allow_cross_protocol,
    )
    if config.compact_profiles:
        graph.compact_profiles()
    return graph


def ensure_identity_graph_tables(cursor) -> None:
    """Create identity graph tables if they don't exist."""
    cursor.execute(
        """
        IF NOT EXISTS (SELECT * FROM sys.objects WHERE name='device_identity_clusters' AND type='U')
        CREATE TABLE device_identity_clusters (
            cluster_id CHAR(12) NOT NULL PRIMARY KEY,
            member_count INT NOT NULL,
            confidence FLOAT NOT NULL,
            signals NVARCHAR(MAX),
            updated_at DATETIME2 DEFAULT SYSDATETIME()
        )
        """
    )
    cursor.execute(
        """
        IF NOT EXISTS (SELECT * FROM sys.objects WHERE name='device_identity_members' AND type='U')
        CREATE TABLE device_identity_members (
            cluster_id CHAR(12) NOT NULL,
            identifier NVARCHAR(64) NOT NULL,
            protocol VARCHAR(8),
            vendor NVARCHAR(100),
            device_type VARCHAR(32),
            local_name NVARCHAR(128),
            first_seen DATETIME2,
            last_seen DATETIME2,
            CONSTRAINT PK_device_identity_members PRIMARY KEY (cluster_id, identifier)
        )
        """
    )
    cursor.execute(
        """
        IF NOT EXISTS (
            SELECT 1 FROM sys.indexes
            WHERE name = 'IX_identity_members_identifier' AND object_id = OBJECT_ID('device_identity_members')
        )
        CREATE INDEX IX_identity_members_identifier ON device_identity_members(identifier);
        """
    )


def persist_graph(conn, graph: IdentityGraph, *, full_refresh: bool = True) -> None:
    """Persist graph clusters and members to SQL."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is required to persist identity graph")

    cursor = conn.cursor()
    ensure_identity_graph_tables(cursor)

    cluster_rows = []
    member_rows = []

    for cluster in graph.clusters:
        cluster_rows.append(
            (
                cluster.cluster_id,
                len(cluster.members),
                float(cluster.confidence),
                json_compat.dumps(cluster.signals, sort_keys=True),
            )
        )
        for member in cluster.members:
            profile = graph.profile_map.get(member)
            member_rows.append(
                (
                    cluster.cluster_id,
                    member,
                    profile.protocol if profile else None,
                    profile.vendor if profile else None,
                    profile.device_type if profile else None,
                    profile.local_name if profile else None,
                    profile.first_seen,
                    profile.last_seen,
                )
            )

    cursor.execute(
        """
        IF OBJECT_ID('tempdb..#IdentityClusterStaging') IS NULL
            CREATE TABLE #IdentityClusterStaging (
                cluster_id CHAR(12) PRIMARY KEY,
                member_count INT,
                confidence FLOAT,
                signals NVARCHAR(MAX)
            )
        ELSE
            TRUNCATE TABLE #IdentityClusterStaging
        """
    )
    cursor.execute(
        """
        IF OBJECT_ID('tempdb..#IdentityMemberStaging') IS NULL
            CREATE TABLE #IdentityMemberStaging (
                cluster_id CHAR(12),
                identifier NVARCHAR(64),
                protocol VARCHAR(8),
                vendor NVARCHAR(100),
                device_type VARCHAR(32),
                local_name NVARCHAR(128),
                first_seen DATETIME2,
                last_seen DATETIME2
            )
        ELSE
            TRUNCATE TABLE #IdentityMemberStaging
        """
    )

    cursor.fast_executemany = True
    cursor.executemany(
        "INSERT INTO #IdentityClusterStaging VALUES (?,?,?,?)",
        cluster_rows,
    )
    cursor.executemany(
        "INSERT INTO #IdentityMemberStaging VALUES (?,?,?,?,?,?,?,?)",
        member_rows,
    )

    cursor.execute(
        """
        MERGE device_identity_clusters AS target
        USING #IdentityClusterStaging AS source
        ON target.cluster_id = source.cluster_id
        WHEN MATCHED THEN
            UPDATE SET
                member_count = source.member_count,
                confidence = source.confidence,
                signals = source.signals,
                updated_at = SYSDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (cluster_id, member_count, confidence, signals)
            VALUES (source.cluster_id, source.member_count, source.confidence, source.signals)
        """
        + ("WHEN NOT MATCHED BY SOURCE THEN DELETE" if full_refresh else "")
    )

    cursor.execute(
        """
        MERGE device_identity_members AS target
        USING #IdentityMemberStaging AS source
        ON target.cluster_id = source.cluster_id AND target.identifier = source.identifier
        WHEN MATCHED THEN
            UPDATE SET
                protocol = source.protocol,
                vendor = source.vendor,
                device_type = source.device_type,
                local_name = source.local_name,
                first_seen = source.first_seen,
                last_seen = source.last_seen
        WHEN NOT MATCHED THEN
            INSERT (
                cluster_id, identifier, protocol, vendor, device_type,
                local_name, first_seen, last_seen
            )
            VALUES (
                source.cluster_id, source.identifier, source.protocol, source.vendor,
                source.device_type, source.local_name, source.first_seen, source.last_seen
            )
        """
        + ("WHEN NOT MATCHED BY SOURCE THEN DELETE" if full_refresh else "")
    )

    conn.commit()
