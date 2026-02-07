"""
Scavenger Persistence Layer - SQL DAO

Handles persistence of Scavenger intelligence (Clients, PNLs, Handshakes)
to the Nexus SQL database.
"""

import json as _json
import logging
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

import pyodbc

from nexus.config import NexusConfig
from nexus.utils import json_compat

from .agents import HandshakeState
from .correlator import TargetDossier

logger = logging.getLogger('nexus.scavenger.persistence')


def _merge_rssi_stats(
    existing_avg: int | None,
    existing_max: int | None,
    existing_last: int | None,
    existing_count: int | None,
    existing_last_seen: datetime | None,
    new_samples: list[int],
    new_last_seen: datetime | None,
) -> tuple[int | None, int | None, int | None, int, datetime | None]:
    """Merge RSSI aggregates with new samples."""
    if not new_samples:
        return (
            existing_avg,
            existing_max,
            existing_last,
            existing_count or 0,
            existing_last_seen,
        )

    sample_count = len(new_samples)
    sample_sum = sum(new_samples)
    sample_avg = int(round(sample_sum / sample_count))
    sample_max = max(new_samples)
    sample_last = new_samples[-1]

    base_count = existing_count or 0
    total_count = base_count + sample_count

    if base_count <= 0 or existing_avg is None:
        merged_avg = sample_avg
    else:
        merged_avg = int(round((existing_avg * base_count + sample_sum) / total_count))

    merged_max = sample_max if existing_max is None else max(existing_max, sample_max)
    merged_last = sample_last

    if existing_last_seen and new_last_seen:
        merged_last_seen = max(existing_last_seen, new_last_seen)
    else:
        merged_last_seen = new_last_seen or existing_last_seen

    return (merged_avg, merged_max, merged_last, total_count, merged_last_seen)


def _is_randomized_mac(mac: str | None) -> bool:
    if not mac or mac == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _chunked(items: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    """Yield items in fixed-size chunks for IN clause batching."""
    if size <= 0:
        raise ValueError("chunk size must be positive")
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _build_association_updates(
    cursor: pyodbc.Cursor,
    associations: Sequence[dict[str, object]],
) -> tuple[list[tuple[str, datetime, datetime, int]], dict[str, str]]:
    if not associations:
        return [], {}

    mac_to_bssids: dict[str, set] = {}
    mac_first_last: dict[str, tuple[datetime, datetime]] = {}

    for assoc in associations:
        client = assoc.get("client_mac")
        bssid = assoc.get("bssid")
        if not client or not bssid:
            continue
        client = str(client).lower()
        bssid = str(bssid).lower()

        mac_to_bssids.setdefault(client, set()).add(bssid)
        first_seen = assoc.get("first_seen")
        last_seen = assoc.get("last_seen")
        existing = mac_first_last.get(client)
        if existing is None:
            mac_first_last[client] = (first_seen, last_seen)
        else:
            mac_first_last[client] = (
                min(existing[0], first_seen),
                max(existing[1], last_seen),
            )

    macs = list(mac_to_bssids.keys())
    existing: dict[str, list[str]] = {}
    if macs:
        for chunk in _chunked(macs, 900):
            placeholders = ",".join("?" for _ in chunk)
            cursor.execute(
                f"SELECT mac_addr, associated_bssids FROM client_profiles WHERE mac_addr IN ({placeholders})",
                chunk,
            )
            for row in cursor.fetchall():
                existing[row[0].lower()] = json_compat.loads(row[1]) if row[1] else []

    updated_json: dict[str, str] = {}
    for mac, bssids in mac_to_bssids.items():
        merged = set(existing.get(mac, []))
        merged.update(bssids)
        final = list(merged)[:1000]
        updated_json[mac] = json_compat.dumps(final)

    ensure_rows = []
    for mac, (first_seen, last_seen) in mac_first_last.items():
        ensure_rows.append((mac, first_seen, last_seen, 1 if _is_randomized_mac(mac) else 0))

    return ensure_rows, updated_json

class ScavengerDAO:
    """Data Access Object for Scavenger findings."""

    def __init__(self, config: NexusConfig):
        self.config = config
        self.conn_str = config.get_sql_connection_string()
        self._ensure_schema()

    def _ensure_schema(self):
        """Ensure schema updates are applied."""
        try:
            with pyodbc.connect(self.conn_str) as conn:
                cursor = conn.cursor()
                # Ensure client_profiles columns exist
                cursor.execute("""
                    IF COL_LENGTH('client_profiles', 'channels_active') IS NULL
                        ALTER TABLE client_profiles ADD channels_active NVARCHAR(MAX);
                    IF COL_LENGTH('client_profiles', 'rssi_avg') IS NULL
                        ALTER TABLE client_profiles ADD rssi_avg INT NULL;
                    IF COL_LENGTH('client_profiles', 'rssi_max') IS NULL
                        ALTER TABLE client_profiles ADD rssi_max INT NULL;
                    IF COL_LENGTH('client_profiles', 'rssi_last') IS NULL
                        ALTER TABLE client_profiles ADD rssi_last INT NULL;
                    IF COL_LENGTH('client_profiles', 'rssi_sample_count') IS NULL
                        ALTER TABLE client_profiles ADD rssi_sample_count INT NULL DEFAULT 0;
                    IF COL_LENGTH('client_profiles', 'rssi_last_seen') IS NULL
                        ALTER TABLE client_profiles ADD rssi_last_seen DATETIME2 NULL;
                """)

                # Ensure client_associations table exists
                cursor.execute("""
                    IF OBJECT_ID('client_associations', 'U') IS NULL
                    BEGIN
                        CREATE TABLE client_associations (
                            id BIGINT IDENTITY PRIMARY KEY,
                            client_mac CHAR(17) NOT NULL,
                            bssid CHAR(17) NOT NULL,
                            ssid NVARCHAR(64),
                            first_seen DATETIME2 NOT NULL,
                            last_seen DATETIME2 NOT NULL,
                            association_count INT NOT NULL DEFAULT 1,
                            last_assoc_type VARCHAR(16),
                            CONSTRAINT UQ_client_assoc UNIQUE (client_mac, bssid)
                        );
                    END
                """)

                # Ensure indexes for client_associations
                cursor.execute("""
                    IF NOT EXISTS (
                        SELECT 1 FROM sys.indexes
                        WHERE name = 'IX_client_assoc_client'
                          AND object_id = OBJECT_ID('client_associations')
                    )
                        CREATE INDEX IX_client_assoc_client ON client_associations(client_mac);
                    IF NOT EXISTS (
                        SELECT 1 FROM sys.indexes
                        WHERE name = 'IX_client_assoc_bssid'
                          AND object_id = OBJECT_ID('client_associations')
                    )
                        CREATE INDEX IX_client_assoc_bssid ON client_associations(bssid);
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Schema check failed: {e}")

    def _get_connection(
        self,
        conn: pyodbc.Connection | None,
    ) -> tuple[pyodbc.Connection, bool]:
        if conn is not None:
            return conn, False
        return pyodbc.connect(self.conn_str), True

    def merge_dossiers_batch(
        self,
        dossiers: Sequence[TargetDossier],
        conn: pyodbc.Connection | None = None,
        commit: bool = True,
    ) -> bool:
        """Merge multiple dossiers into client_profiles in one batch."""
        dossier_map: dict[str, TargetDossier] = {}
        for dossier in dossiers:
            if dossier and dossier.mac:
                dossier_map[dossier.mac.lower()] = dossier
        if not dossier_map:
            return False

        conn, should_close = self._get_connection(conn)
        try:
            cursor = conn.cursor()
            existing: dict[str, tuple] = {}
            macs = list(dossier_map.keys())
            for chunk in _chunked(macs, 900):
                placeholders = ",".join("?" for _ in chunk)
                cursor.execute(
                    f"""
                    SELECT
                        mac_addr,
                        probed_ssids,
                        associated_bssids,
                        first_seen,
                        last_seen,
                        probe_count,
                        threat_score,
                        vendor,
                        device_type,
                        channels_active
                    FROM client_profiles
                    WHERE mac_addr IN ({placeholders})
                    """,
                    chunk,
                )
                for row in cursor.fetchall():
                    existing[row[0].lower()] = row

            rows = []
            for mac_key, dossier in dossier_map.items():
                row = existing.get(mac_key)

                existing_probes: set[str] = set()
                existing_associations: set[str] = set()
                existing_channels: set[int] = set()

                first_seen = dossier.first_seen or datetime.now()
                last_seen = dossier.last_seen or datetime.now()
                threat_score = row[6] if row and row[6] is not None else 0

                vendor = dossier.vendor or "Unknown"
                device_type = dossier.device_type

                if row:
                    try:
                        if row[1]:
                            existing_probes = set(json_compat.loads(row[1]))
                        if row[2]:
                            existing_associations = set(json_compat.loads(row[2]))
                        if row[9]:
                            existing_channels = set(json_compat.loads(row[9]))
                    except _json.JSONDecodeError:
                        pass

                    db_first = row[3]
                    db_last = row[4]
                    if db_first and db_first < first_seen:
                        first_seen = db_first
                    if db_last and db_last > last_seen:
                        last_seen = db_last

                    db_vendor = row[7]
                    db_device = row[8]
                    if vendor == "Unknown" and db_vendor and db_vendor != "Unknown":
                        vendor = db_vendor
                        if not device_type:
                            device_type = db_device

                existing_probes.update(dossier.probed_ssids.keys())
                existing_associations.update(dossier.associated_bssids)
                existing_channels.update(dossier.channels_active)

                final_probes = list(existing_probes)[:1000]
                final_assoc = list(existing_associations)[:1000]
                final_channels = list(existing_channels)

                if dossier.is_randomized_mac:
                    threat_score = max(threat_score, 10)

                rows.append(
                    (
                        dossier.mac,
                        vendor,
                        device_type,
                        json_compat.dumps(final_probes),
                        json_compat.dumps(final_assoc),
                        first_seen,
                        last_seen,
                        len(final_probes),
                        1 if dossier.is_randomized_mac else 0,
                        threat_score,
                        json_compat.dumps(final_channels),
                    )
                )

            if not rows:
                return False

            # NOTE: fast_executemany defaults to 510-byte buffer for NVARCHAR.
            # Use setinputsizes() to override for JSON columns.
            cursor.fast_executemany = True
            cursor.setinputsizes([
                (pyodbc.SQL_CHAR, 17, 0),       # mac_addr
                (pyodbc.SQL_VARCHAR, 100, 0),   # vendor
                (pyodbc.SQL_VARCHAR, 50, 0),    # device_type
                (pyodbc.SQL_WVARCHAR, 0, 0),    # probed_ssids NVARCHAR(MAX)
                (pyodbc.SQL_WVARCHAR, 0, 0),    # associated_bssids NVARCHAR(MAX)
                (pyodbc.SQL_TYPE_TIMESTAMP, 0, 0),  # first_seen
                (pyodbc.SQL_TYPE_TIMESTAMP, 0, 0),  # last_seen
                (pyodbc.SQL_INTEGER, 0, 0),     # probe_count
                (pyodbc.SQL_INTEGER, 0, 0),     # is_randomized
                (pyodbc.SQL_INTEGER, 0, 0),     # threat_score
                (pyodbc.SQL_WVARCHAR, 0, 0),    # channels_active NVARCHAR(MAX)
            ])
            cursor.executemany(
                """
                MERGE client_profiles AS target
                USING (
                    SELECT ? AS mac_addr, ? AS vendor, ? AS device_type, ? AS probed_ssids,
                           ? AS associated_bssids, ? AS first_seen, ? AS last_seen,
                           ? AS probe_count, ? AS is_randomized, ? AS threat_score, ? AS channels_active
                ) AS source
                ON target.mac_addr = source.mac_addr
                WHEN MATCHED THEN
                    UPDATE SET
                        vendor = source.vendor,
                        device_type = source.device_type,
                        probed_ssids = source.probed_ssids,
                        associated_bssids = source.associated_bssids,
                        first_seen = source.first_seen,
                        last_seen = source.last_seen,
                        probe_count = source.probe_count,
                        is_randomized = source.is_randomized,
                        threat_score = source.threat_score,
                        channels_active = source.channels_active,
                        updated_at = SYSDATETIME()
                WHEN NOT MATCHED THEN
                    INSERT (
                        mac_addr,
                        vendor,
                        device_type,
                        probed_ssids,
                        associated_bssids,
                        first_seen,
                        last_seen,
                        probe_count,
                        is_randomized,
                        threat_score,
                        channels_active
                    )
                    VALUES (
                        source.mac_addr,
                        source.vendor,
                        source.device_type,
                        source.probed_ssids,
                        source.associated_bssids,
                        source.first_seen,
                        source.last_seen,
                        source.probe_count,
                        source.is_randomized,
                        source.threat_score,
                        source.channels_active
                    );
                """,
                rows,
            )

            if commit:
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to merge dossiers batch: {e}")
            return False
        finally:
            if should_close:
                conn.close()

    def merge_dossier(
        self,
        dossier: TargetDossier,
        conn: pyodbc.Connection | None = None,
        commit: bool = True,
    ) -> bool:
        """
        Merge a TargetDossier into the persistent client_profiles table.
        """
        if not dossier or not dossier.mac:
            return False
        return self.merge_dossiers_batch([dossier], conn=conn, commit=commit)

    def save_handshake(
        self,
        hs: HandshakeState,
        conn: pyodbc.Connection | None = None,
        commit: bool = True,
    ) -> bool:
        """
        Save a HandshakeState to the handshakes table.
        Avoids duplicates based on BSSID + Client + Type + Capture Time (approx).
        """
        if not hs.bssid or not hs.client_mac:
            return False

        conn, should_close = self._get_connection(conn)
        try:
            cursor = conn.cursor()

            # Determine handshake type + flags
            hs_type = '4way_full' if hs.is_complete else '4way_partial'
            msg_flags = 0
            if hs.m1_frame:
                msg_flags |= 1
            if hs.m2_frame:
                msg_flags |= 2
            if hs.m3_frame:
                msg_flags |= 4
            if hs.m4_frame:
                msg_flags |= 8

            # Simple duplicate check
            cursor.execute("""
                SELECT id FROM handshakes
                WHERE bssid = ? AND client_mac = ? AND handshake_type = ?
                AND DATEDIFF(minute, capture_time, ?) < 5
            """, (hs.bssid, hs.client_mac, hs_type, hs.last_seen or datetime.now()))

            if cursor.fetchone():
                return False

            cursor.execute("""
                INSERT INTO handshakes
                (bssid, ssid, client_mac, handshake_type, capture_time, anonce, snonce, mic, pmkid, crack_status, msg_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
            """, (
                hs.bssid,
                'Unknown',
                hs.client_mac,
                hs_type,
                hs.last_seen or datetime.now(),
                bytes(hs.m1_frame.key_nonce) if hs.m1_frame and hs.m1_frame.key_nonce else None,
                bytes(hs.m2_frame.key_nonce) if hs.m2_frame and hs.m2_frame.key_nonce else None,
                bytes(hs.m2_frame.key_mic) if hs.m2_frame and hs.m2_frame.key_mic else None,
                hs.m1_frame.pmkid if (hs.m1_frame and hasattr(hs.m1_frame, 'pmkid') and hs.m1_frame.pmkid) else None,
                msg_flags
            ))

            if commit:
                conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save handshake {hs.bssid}: {e}")
            return False
        finally:
            if should_close:
                conn.close()

    def merge_associations_batch(
        self,
        associations: Sequence[dict[str, object]],
        conn: pyodbc.Connection | None = None,
        commit: bool = True,
    ) -> bool:
        """Merge association records and update JSON summaries."""
        if not associations:
            return False

        conn, should_close = self._get_connection(conn)
        try:
            cursor = conn.cursor()

            ensure_rows, updated_json = _build_association_updates(cursor, associations)
            if ensure_rows:
                cursor.fast_executemany = True
                cursor.executemany(
                    """
                    MERGE client_profiles AS target
                    USING (SELECT ? AS mac_addr, ? AS first_seen, ? AS last_seen, ? AS is_randomized) AS source
                    ON target.mac_addr = source.mac_addr
                    WHEN MATCHED THEN
                        UPDATE SET
                            first_seen = CASE
                                WHEN target.first_seen IS NULL OR source.first_seen < target.first_seen
                                    THEN source.first_seen
                                ELSE target.first_seen
                            END,
                            last_seen = CASE
                                WHEN target.last_seen IS NULL OR source.last_seen > target.last_seen
                                    THEN source.last_seen
                                ELSE target.last_seen
                            END,
                            updated_at = SYSDATETIME()
                    WHEN NOT MATCHED THEN
                        INSERT (mac_addr, vendor, device_type, first_seen, last_seen, probe_count, is_randomized, threat_score)
                        VALUES (source.mac_addr, 'Unknown', NULL, source.first_seen, source.last_seen, 0, source.is_randomized, 0);
                    """,
                    ensure_rows,
                )

            rows = []
            for assoc in associations:
                client_mac = assoc.get("client_mac")
                bssid = assoc.get("bssid")
                if not client_mac or not bssid:
                    continue
                rows.append(
                    (
                        str(client_mac).lower(),
                        str(bssid).lower(),
                        assoc.get("ssid"),
                        assoc.get("first_seen"),
                        assoc.get("last_seen"),
                        assoc.get("association_count", 1),
                        assoc.get("assoc_type"),
                    )
                )

            if rows:
                cursor.fast_executemany = True
                cursor.executemany(
                    """
                    MERGE client_associations AS target
                    USING (
                        SELECT ? AS client_mac, ? AS bssid, ? AS ssid, ? AS first_seen,
                               ? AS last_seen, ? AS association_count, ? AS assoc_type
                    ) AS source
                    ON target.client_mac = source.client_mac AND target.bssid = source.bssid
                    WHEN MATCHED THEN
                        UPDATE SET
                            ssid = COALESCE(target.ssid, source.ssid),
                            first_seen = CASE
                                WHEN target.first_seen IS NULL OR source.first_seen < target.first_seen
                                    THEN source.first_seen
                                ELSE target.first_seen
                            END,
                            last_seen = CASE
                                WHEN target.last_seen IS NULL OR source.last_seen > target.last_seen
                                    THEN source.last_seen
                                ELSE target.last_seen
                            END,
                            association_count = target.association_count + source.association_count,
                            last_assoc_type = source.assoc_type
                    WHEN NOT MATCHED THEN
                        INSERT (client_mac, bssid, ssid, first_seen, last_seen, association_count, last_assoc_type)
                        VALUES (source.client_mac, source.bssid, source.ssid, source.first_seen,
                                source.last_seen, source.association_count, source.assoc_type);
                    """,
                    rows,
                )

            if updated_json:
                updates = [(value, mac) for mac, value in updated_json.items()]
                # setinputsizes for NVARCHAR(MAX) associated_bssids column
                cursor.fast_executemany = True
                cursor.setinputsizes([
                    (pyodbc.SQL_WVARCHAR, 0, 0),  # associated_bssids NVARCHAR(MAX)
                    (pyodbc.SQL_CHAR, 17, 0),     # mac_addr
                ])
                cursor.executemany(
                    """
                    UPDATE client_profiles
                    SET associated_bssids = ?, updated_at = SYSDATETIME()
                    WHERE mac_addr = ?
                    """,
                    updates,
                )

            if commit:
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to merge associations batch: {e}")
            return False
        finally:
            if should_close:
                conn.close()

    def upsert_association(
        self,
        client_mac: str,
        bssid: str,
        ssid: str | None,
        first_seen: datetime,
        last_seen: datetime,
        assoc_type: str | None,
        conn: pyodbc.Connection | None = None,
        commit: bool = True,
    ) -> bool:
        """Insert or update a client_associations row."""
        if not client_mac or not bssid:
            return False

        conn, should_close = self._get_connection(conn)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, first_seen, last_seen, association_count, ssid
                FROM client_associations
                WHERE client_mac = ? AND bssid = ?
                """,
                (client_mac, bssid),
            )
            row = cursor.fetchone()

            if row:
                db_first = row[1] or first_seen
                db_last = row[2] or last_seen
                count = row[3] or 0
                db_ssid = row[4]

                if first_seen and db_first and first_seen < db_first:
                    db_first = first_seen
                if last_seen and db_last and last_seen > db_last:
                    db_last = last_seen

                cursor.execute(
                    """
                    UPDATE client_associations SET
                        ssid = COALESCE(?, ssid),
                        first_seen = ?,
                        last_seen = ?,
                        association_count = ?,
                        last_assoc_type = ?
                    WHERE id = ?
                    """,
                    (ssid if db_ssid is None else None, db_first, db_last, count + 1, assoc_type, row[0]),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO client_associations
                    (client_mac, bssid, ssid, first_seen, last_seen, association_count, last_assoc_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (client_mac, bssid, ssid, first_seen, last_seen, 1, assoc_type),
                )

            if commit:
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to upsert association {client_mac} -> {bssid}: {e}")
            return False
        finally:
            if should_close:
                conn.close()

    def merge_rssi_aggregates(
        self,
        samples: Sequence[tuple[str, list[int], datetime | None]],
        conn: pyodbc.Connection | None = None,
        commit: bool = True,
    ) -> bool:
        """Merge RSSI aggregates for multiple clients in one batch."""
        sample_map: dict[str, tuple[list[int], datetime | None]] = {}
        for mac, rssi_samples, last_seen in samples:
            if not mac or not rssi_samples:
                continue
            key = mac.lower()
            if key in sample_map:
                sample_map[key][0].extend(rssi_samples)
                existing_last_seen = sample_map[key][1]
                if last_seen and (existing_last_seen is None or last_seen > existing_last_seen):
                    sample_map[key] = (sample_map[key][0], last_seen)
            else:
                sample_map[key] = (list(rssi_samples), last_seen)

        if not sample_map:
            return False

        conn, should_close = self._get_connection(conn)
        try:
            cursor = conn.cursor()
            existing: dict[str, tuple[int | None, int | None, int | None, int | None, datetime | None]] = {}
            macs = list(sample_map.keys())
            for chunk in _chunked(macs, 900):
                placeholders = ",".join("?" for _ in chunk)
                cursor.execute(
                    f"""
                    SELECT mac_addr, rssi_avg, rssi_max, rssi_last, rssi_sample_count, rssi_last_seen
                    FROM client_profiles
                    WHERE mac_addr IN ({placeholders})
                    """,
                    chunk,
                )
                for row in cursor.fetchall():
                    existing[row[0].lower()] = (row[1], row[2], row[3], row[4], row[5])

            rows = []
            for mac, (rssi_samples, last_seen) in sample_map.items():
                row = existing.get(mac)
                if not row:
                    continue
                merged = _merge_rssi_stats(
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    rssi_samples,
                    last_seen,
                )
                rows.append((merged[0], merged[1], merged[2], merged[3], merged[4], mac))

            if not rows:
                return False

            cursor.fast_executemany = True
            cursor.executemany(
                """
                MERGE client_profiles AS target
                USING (
                    SELECT ? AS rssi_avg, ? AS rssi_max, ? AS rssi_last,
                           ? AS rssi_sample_count, ? AS rssi_last_seen, ? AS mac_addr
                ) AS source
                ON target.mac_addr = source.mac_addr
                WHEN MATCHED THEN
                    UPDATE SET
                        rssi_avg = source.rssi_avg,
                        rssi_max = source.rssi_max,
                        rssi_last = source.rssi_last,
                        rssi_sample_count = source.rssi_sample_count,
                        rssi_last_seen = source.rssi_last_seen,
                        updated_at = SYSDATETIME();
                """,
                rows,
            )
            if commit:
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to merge RSSI aggregates batch: {e}")
            return False
        finally:
            if should_close:
                conn.close()

    def merge_rssi_aggregate(
        self,
        mac: str,
        rssi_samples: list[int],
        last_seen: datetime | None,
        conn: pyodbc.Connection | None = None,
        commit: bool = True,
    ) -> bool:
        """Merge RSSI aggregates for a client."""
        if not mac or not rssi_samples:
            return False
        return self.merge_rssi_aggregates([(mac, rssi_samples, last_seen)], conn=conn, commit=commit)

    def get_all_clients(self) -> list[dict[str, Any]]:
        """Retrieve all client profiles for API/Correlation."""
        profiles = []
        try:
            with pyodbc.connect(self.conn_str) as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        SELECT
                            mac_addr,
                            vendor,
                            probed_ssids,
                            associated_bssids,
                            first_seen,
                            last_seen,
                            probe_count,
                            is_randomized,
                            channels_active,
                            rssi_avg,
                            rssi_max,
                            rssi_last,
                            rssi_sample_count,
                            rssi_last_seen
                        FROM client_profiles
                    """)
                except Exception:
                    cursor.execute("""
                        SELECT
                            mac_addr,
                            vendor,
                            probed_ssids,
                            associated_bssids,
                            first_seen,
                            last_seen,
                            probe_count,
                            is_randomized,
                            NULL as channels_active,
                            NULL as rssi_avg,
                            NULL as rssi_max,
                            NULL as rssi_last,
                            NULL as rssi_sample_count,
                            NULL as rssi_last_seen
                        FROM client_profiles
                    """)

                rows = cursor.fetchall()
                for row in rows:
                    probed = json_compat.loads(row[2]) if row[2] else []
                    associated = json_compat.loads(row[3]) if row[3] else []
                    channels = json_compat.loads(row[8]) if row[8] else []

                    profiles.append({
                        'mac': row[0],
                        'vendor': row[1],
                        'probed_ssids': probed,
                        'associated_bssids': associated,
                        'first_seen': row[4],
                        'last_seen': row[5],
                        'probe_count': row[6],
                        'is_randomized_mac': bool(row[7]),
                        'pnl_count': len(probed),
                        'channels_seen': channels,
                        'rssi_avg': row[9],
                        'rssi_max': row[10],
                        'rssi_last': row[11],
                        'rssi_sample_count': row[12] or 0,
                        'rssi_last_seen': row[13],
                    })
        except Exception as e:
            logger.error(f"Failed to get clients: {e}")
        return profiles
