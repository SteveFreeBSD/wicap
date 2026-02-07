"""
NEXUS Security Posture Module

Aggregates network security configurations from captured events,
maintains the security_posture table, and calculates risk scores.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import pyodbc

from .config import NexusConfig, get_nexus_config
from .risk_scorer import RiskScorer

logger = logging.getLogger('nexus.security_posture')


@dataclass
class NetworkPosture:
    """Security posture for a single network."""
    bssid: str
    ssid: str | None

    # Security config
    is_open: bool = False
    has_wep: bool = False
    has_wpa: bool = False
    has_wpa2: bool = False
    has_wpa3: bool = False
    cipher_suite: str | None = None
    akm_suite: str | None = None
    has_pmf: bool = False

    # Metadata
    channel: int | None = None
    vendor: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    beacon_count: int = 0

    # Fingerprint
    ie_fingerprint: str | None = None

    # Risk assessment
    risk_score: int = 0
    risk_factors: list[str] = None

    def __post_init__(self):
        if self.risk_factors is None:
            self.risk_factors = []


class SecurityPostureManager:
    """
    Manages security posture data for all observed networks.

    Responsibilities:
    - Extract security info from curated events
    - Maintain security_posture table in SQL
    - Calculate and update risk scores
    - Provide queries for audit/reporting
    """

    def __init__(self, config: NexusConfig | None = None):
        self.config = config or get_nexus_config()
        self.scorer = RiskScorer()
        self._conn: pyodbc.Connection | None = None

    def _get_connection(self) -> pyodbc.Connection:
        """Get or create SQL connection."""
        # Check if connection is None or closed (handle pyodbc versions without .closed)
        needs_reconnect = self._conn is None
        if not needs_reconnect:
            try:
                needs_reconnect = getattr(self._conn, 'closed', False)
            except Exception:
                needs_reconnect = True

        if needs_reconnect:
            self._conn = pyodbc.connect(
                self.config.get_sql_connection_string(),
                autocommit=False
            )
        return self._conn

    def close(self) -> None:
        """Close SQL connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def update_from_event(self, event: dict[str, Any]) -> NetworkPosture | None:
        """
        Update security posture from a curated event.

        Extracts security information and updates the database.
        Also checks for captured handshakes to include in risk scoring.
        Returns the updated NetworkPosture or None if not applicable.
        """
        bssid = event.get('bssid')
        if not bssid:
            return None

        # Extract security info from event payload
        payload = event.get('payload', {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError, ValueError):
                payload = {}

        # Build posture from event
        posture = NetworkPosture(
            bssid=bssid,
            ssid=event.get('ssid') or payload.get('ssid'),
            channel=event.get('channel') or payload.get('ch'),
            vendor=payload.get('vendor'),
        )

        # Extract security fields
        security = payload.get('security', {})
        if security:
            posture.is_open = security.get('is_open', False)
            posture.has_wep = security.get('has_wep', False)
            posture.has_wpa = security.get('has_wpa', False)
            posture.has_wpa2 = security.get('has_wpa2', False)
            posture.has_wpa3 = security.get('has_wpa3', False)
            posture.cipher_suite = security.get('cipher')
            posture.akm_suite = security.get('akm')
            posture.has_pmf = security.get('has_pmf', False)

        # Get timestamp
        ts_epoch = event.get('ts_epoch') or payload.get('ts')
        if ts_epoch:
            posture.last_seen = datetime.fromtimestamp(float(ts_epoch))
        else:
            posture.last_seen = datetime.now()

        # Check if we have a captured handshake for this network
        handshake_captured = self._has_handshake(bssid)

        # Calculate risk score (including handshake status)
        assessment = self.scorer.assess_network(
            bssid=posture.bssid,
            ssid=posture.ssid,
            is_open=posture.is_open,
            has_wep=posture.has_wep,
            has_wpa=posture.has_wpa,
            has_wpa2=posture.has_wpa2,
            has_wpa3=posture.has_wpa3,
            cipher=posture.cipher_suite,
            akm=posture.akm_suite,
            has_pmf=posture.has_pmf,
            handshake_captured=handshake_captured,
        )
        posture.risk_score = assessment.total_score
        posture.risk_factors = assessment.factor_names

        # Upsert to database
        self._upsert_posture(posture)

        return posture

    def _upsert_posture(self, posture: NetworkPosture, event_count: int = 1) -> None:
        """
        Insert or update security posture in SQL.

        Args:
            posture: NetworkPosture to upsert
            event_count: Number of events to add to beacon_count (for batch updates)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Use MERGE for upsert
            cursor.execute("""
                MERGE INTO security_posture AS target
                USING (SELECT ? AS bssid) AS source
                ON target.bssid = source.bssid
                WHEN MATCHED THEN
                    UPDATE SET
                        ssid = COALESCE(?, target.ssid),
                        is_open = ?,
                        has_wep = ?,
                        has_wpa = ?,
                        has_wpa2 = ?,
                        has_wpa3 = ?,
                        cipher_suite = COALESCE(?, target.cipher_suite),
                        akm_suite = COALESCE(?, target.akm_suite),
                        has_pmf = ?,
                        risk_score = ?,
                        risk_factors = ?,
                        channel = COALESCE(?, target.channel),
                        vendor = COALESCE(?, target.vendor),
                        last_seen = ?,
                        beacon_count = target.beacon_count + ?,
                        updated_at = SYSDATETIME()
                WHEN NOT MATCHED THEN
                    INSERT (bssid, ssid, is_open, has_wep, has_wpa, has_wpa2, has_wpa3,
                            cipher_suite, akm_suite, has_pmf, risk_score, risk_factors,
                            channel, vendor, first_seen, last_seen, beacon_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                # USING clause
                posture.bssid,
                # UPDATE SET values
                posture.ssid,
                1 if posture.is_open else 0,
                1 if posture.has_wep else 0,
                1 if posture.has_wpa else 0,
                1 if posture.has_wpa2 else 0,
                1 if posture.has_wpa3 else 0,
                posture.cipher_suite,
                posture.akm_suite,
                1 if posture.has_pmf else 0,
                posture.risk_score,
                json.dumps(posture.risk_factors),
                posture.channel,
                posture.vendor,
                posture.last_seen,
                event_count,  # Add this many to beacon_count
                # INSERT values
                posture.bssid,
                posture.ssid,
                1 if posture.is_open else 0,
                1 if posture.has_wep else 0,
                1 if posture.has_wpa else 0,
                1 if posture.has_wpa2 else 0,
                1 if posture.has_wpa3 else 0,
                posture.cipher_suite,
                posture.akm_suite,
                1 if posture.has_pmf else 0,
                posture.risk_score,
                json.dumps(posture.risk_factors),
                posture.channel,
                posture.vendor,
                posture.last_seen,
                posture.last_seen,
                event_count,  # Initial beacon_count
            ))
            conn.commit()

        except Exception as e:
            logger.error(f"Failed to upsert security posture for {posture.bssid}: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()

    def get_posture(self, bssid: str) -> NetworkPosture | None:
        """Get security posture for a specific BSSID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT bssid, ssid, is_open, has_wep, has_wpa, has_wpa2, has_wpa3,
                       cipher_suite, akm_suite, has_pmf, risk_score, risk_factors,
                       channel, vendor, first_seen, last_seen, beacon_count
                FROM security_posture
                WHERE bssid = ?
            """, (bssid,))

            row = cursor.fetchone()
            if not row:
                return None

            return NetworkPosture(
                bssid=row.bssid,
                ssid=row.ssid,
                is_open=bool(row.is_open),
                has_wep=bool(row.has_wep),
                has_wpa=bool(row.has_wpa),
                has_wpa2=bool(row.has_wpa2),
                has_wpa3=bool(row.has_wpa3),
                cipher_suite=row.cipher_suite,
                akm_suite=row.akm_suite,
                has_pmf=bool(row.has_pmf),
                risk_score=row.risk_score,
                risk_factors=json.loads(row.risk_factors) if row.risk_factors else [],
                channel=row.channel,
                vendor=row.vendor,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                beacon_count=row.beacon_count,
            )

        finally:
            cursor.close()

    # Valid order_by options to prevent SQL injection
    VALID_ORDER_BY = {
        'risk_score DESC': 'risk_score DESC',
        'risk_score ASC': 'risk_score ASC',
        'last_seen DESC': 'last_seen DESC',
        'last_seen ASC': 'last_seen ASC',
        'ssid ASC': 'ssid ASC',
        'bssid ASC': 'bssid ASC',
        'event_count DESC': 'beacon_count DESC',
    }

    def get_all_postures(
        self,
        min_risk_score: int = 0,
        order_by: str = 'risk_score DESC',
        limit: int = 100
    ) -> list[NetworkPosture]:
        """Get all network postures, optionally filtered and sorted."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Validate order_by to prevent SQL injection
        safe_order_by = self.VALID_ORDER_BY.get(order_by, 'risk_score DESC')

        try:
            query = f"""
                SELECT TOP (?) bssid, ssid, is_open, has_wep, has_wpa, has_wpa2, has_wpa3,
                       cipher_suite, akm_suite, has_pmf, risk_score, risk_factors,
                       channel, vendor, first_seen, last_seen, beacon_count
                FROM security_posture
                WHERE risk_score >= ?
                ORDER BY {safe_order_by}
            """

            cursor.execute(query, (limit, min_risk_score))

            postures = []
            for row in cursor.fetchall():
                postures.append(NetworkPosture(
                    bssid=row.bssid,
                    ssid=row.ssid,
                    is_open=bool(row.is_open),
                    has_wep=bool(row.has_wep),
                    has_wpa=bool(row.has_wpa),
                    has_wpa2=bool(row.has_wpa2),
                    has_wpa3=bool(row.has_wpa3),
                    cipher_suite=row.cipher_suite,
                    akm_suite=row.akm_suite,
                    has_pmf=bool(row.has_pmf),
                    risk_score=row.risk_score,
                    risk_factors=json.loads(row.risk_factors) if row.risk_factors else [],
                    channel=row.channel,
                    vendor=row.vendor,
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    beacon_count=row.beacon_count,
                ))

            return postures

        finally:
            cursor.close()

    def get_risk_summary(self) -> dict[str, Any]:
        """Get summary statistics of security posture."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    COUNT(*) as total_networks,
                    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN risk_score >= 40 AND risk_score < 60 THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN risk_score >= 20 AND risk_score < 40 THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN risk_score < 20 THEN 1 ELSE 0 END) as info,
                    SUM(CASE WHEN is_open = 1 THEN 1 ELSE 0 END) as open_networks,
                    SUM(CASE WHEN has_wep = 1 THEN 1 ELSE 0 END) as wep_networks,
                    SUM(CASE WHEN has_wpa3 = 1 THEN 1 ELSE 0 END) as wpa3_networks,
                    AVG(risk_score) as avg_risk_score
                FROM security_posture
            """)

            row = cursor.fetchone()
            return {
                'total_networks': row.total_networks or 0,
                'by_risk_level': {
                    'critical': row.critical or 0,
                    'high': row.high or 0,
                    'medium': row.medium or 0,
                    'low': row.low or 0,
                    'info': row.info or 0,
                },
                'security_breakdown': {
                    'open': row.open_networks or 0,
                    'wep': row.wep_networks or 0,
                    'wpa3': row.wpa3_networks or 0,
                },
                'avg_risk_score': round(row.avg_risk_score or 0, 1),
            }

        finally:
            cursor.close()

    def recalculate_all_scores(self) -> int:
        """
        Recalculate risk scores for all networks.

        Useful after risk factor weights are updated.
        Returns count of updated networks.
        """
        postures = self.get_all_postures(min_risk_score=0, limit=10000)
        updated = 0

        for posture in postures:
            # Check if handshake captured for this network
            handshake_captured = self._has_handshake(posture.bssid)

            # Recalculate
            assessment = self.scorer.assess_network(
                bssid=posture.bssid,
                ssid=posture.ssid,
                is_open=posture.is_open,
                has_wep=posture.has_wep,
                has_wpa=posture.has_wpa,
                has_wpa2=posture.has_wpa2,
                has_wpa3=posture.has_wpa3,
                cipher=posture.cipher_suite,
                akm=posture.akm_suite,
                has_pmf=posture.has_pmf,
                handshake_captured=handshake_captured,
            )

            if assessment.total_score != posture.risk_score:
                posture.risk_score = assessment.total_score
                posture.risk_factors = assessment.factor_names
                self._upsert_posture(posture)
                updated += 1

        logger.info(f"Recalculated risk scores for {updated} networks")
        return updated

    def _has_handshake(self, bssid: str) -> bool:
        """Check if we have a captured handshake for this BSSID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT COUNT(*) FROM handshakes WHERE bssid = ?",
                (bssid,)
            )
            return cursor.fetchone()[0] > 0
        except Exception:
            return False
        finally:
            cursor.close()


def build_posture_from_events(
    config: NexusConfig | None = None,
    limit: int = 10000
) -> int:
    """
    Build security posture table from existing curated_events.

    Uses window function to get only the latest security config per BSSID,
    while aggregating total event counts across all events for that BSSID.

    Returns count of networks updated.
    """
    config = config or get_nexus_config()
    manager = SecurityPostureManager(config)

    conn = pyodbc.connect(config.get_sql_connection_string())
    cursor = conn.cursor()

    try:
        # Use CTE with ROW_NUMBER to get latest row per BSSID, plus aggregate counts
        # This ensures deterministic, single-row-per-BSSID results
        cursor.execute("""
            WITH ranked_events AS (
                SELECT
                    JSON_VALUE(payload, '$.bssid') as bssid,
                    JSON_VALUE(payload, '$.ssid') as ssid,
                    JSON_VALUE(payload, '$.security.is_open') as is_open,
                    JSON_VALUE(payload, '$.security.has_wep') as has_wep,
                    JSON_VALUE(payload, '$.security.has_wpa') as has_wpa,
                    JSON_VALUE(payload, '$.security.has_wpa2') as has_wpa2,
                    JSON_VALUE(payload, '$.security.has_wpa3') as has_wpa3,
                    JSON_VALUE(payload, '$.security.cipher') as cipher,
                    JSON_VALUE(payload, '$.security.akm') as akm,
                    JSON_VALUE(payload, '$.security.has_pmf') as has_pmf,
                    JSON_VALUE(payload, '$.vendor') as vendor,
                    channel,
                    ts_epoch,
                    ROW_NUMBER() OVER (
                        PARTITION BY JSON_VALUE(payload, '$.bssid')
                        ORDER BY ts_epoch DESC
                    ) as rn
                FROM curated_events
                WHERE JSON_VALUE(payload, '$.bssid') IS NOT NULL
            ),
            bssid_counts AS (
                SELECT
                    JSON_VALUE(payload, '$.bssid') as bssid,
                    COUNT(*) as event_count,
                    MIN(ts_epoch) as first_seen,
                    MAX(ts_epoch) as last_seen
                FROM curated_events
                WHERE JSON_VALUE(payload, '$.bssid') IS NOT NULL
                GROUP BY JSON_VALUE(payload, '$.bssid')
            )
            SELECT TOP (?)
                r.bssid,
                r.ssid,
                r.is_open,
                r.has_wep,
                r.has_wpa,
                r.has_wpa2,
                r.has_wpa3,
                r.cipher,
                r.akm,
                r.has_pmf,
                r.vendor,
                r.channel,
                c.first_seen,
                c.last_seen,
                c.event_count
            FROM ranked_events r
            JOIN bssid_counts c ON r.bssid = c.bssid
            WHERE r.rn = 1
            ORDER BY c.last_seen DESC
        """, (limit,))

        updated = 0
        for row in cursor.fetchall():
            if not row.bssid:
                continue

            # Build posture from latest security config
            posture = NetworkPosture(
                bssid=row.bssid,
                ssid=row.ssid,
                is_open=row.is_open == 'true',
                has_wep=row.has_wep == 'true',
                has_wpa=row.has_wpa == 'true',
                has_wpa2=row.has_wpa2 == 'true',
                has_wpa3=row.has_wpa3 == 'true',
                cipher_suite=row.cipher,
                akm_suite=row.akm,
                has_pmf=row.has_pmf == 'true',
                channel=row.channel,
                vendor=row.vendor,
                first_seen=datetime.fromtimestamp(float(row.first_seen)) if row.first_seen else None,
                last_seen=datetime.fromtimestamp(float(row.last_seen)) if row.last_seen else None,
                beacon_count=row.event_count,
            )

            # Calculate risk score
            assessment = manager.scorer.assess_network(
                bssid=posture.bssid,
                ssid=posture.ssid,
                is_open=posture.is_open,
                has_wep=posture.has_wep,
                has_wpa=posture.has_wpa,
                has_wpa2=posture.has_wpa2,
                has_wpa3=posture.has_wpa3,
                cipher=posture.cipher_suite,
                akm=posture.akm_suite,
                has_pmf=posture.has_pmf,
            )
            posture.risk_score = assessment.total_score
            posture.risk_factors = assessment.factor_names

            try:
                # Use event_count for beacon_count instead of incrementing by 1
                manager._upsert_posture(posture, event_count=row.event_count)
            except Exception as e:
                logger.warning(f"Failed to update posture for {row.bssid}: {e}")

        logger.info(f"Built security posture for {updated} networks from events")
        return updated

    finally:
        cursor.close()
        conn.close()
        manager.close()


if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    parser = argparse.ArgumentParser(description='NEXUS Security Posture Manager')
    parser.add_argument('command', choices=['build', 'recalc', 'summary', 'list'],
                        help='Command to run')
    parser.add_argument('--limit', type=int, default=10000, help='Max records to process')
    parser.add_argument('--min-risk', type=int, default=0, help='Minimum risk score filter')

    args = parser.parse_args()

    config = get_nexus_config()

    if args.command == 'build':
        count = build_posture_from_events(config, limit=args.limit)
        print(f"✅ Built posture for {count} networks")

    elif args.command == 'recalc':
        manager = SecurityPostureManager(config)
        count = manager.recalculate_all_scores()
        print(f"✅ Recalculated scores for {count} networks")
        manager.close()

    elif args.command == 'summary':
        manager = SecurityPostureManager(config)
        summary = manager.get_risk_summary()
        print("\n📊 Security Posture Summary")
        print(f"   Total Networks: {summary['total_networks']}")
        print(f"   Average Risk Score: {summary['avg_risk_score']}")
        print("\n   By Risk Level:")
        for level, count in summary['by_risk_level'].items():
            print(f"     {level.upper():10} {count}")
        print("\n   Security Breakdown:")
        print(f"     Open Networks: {summary['security_breakdown']['open']}")
        print(f"     WEP Networks:  {summary['security_breakdown']['wep']}")
        print(f"     WPA3 Networks: {summary['security_breakdown']['wpa3']}")
        manager.close()

    elif args.command == 'list':
        manager = SecurityPostureManager(config)
        postures = manager.get_all_postures(min_risk_score=args.min_risk, limit=50)

        print(f"\n{'BSSID':<18} {'SSID':<25} {'Risk':>5} {'Security':<15}")
        print("-" * 70)
        for p in postures:
            security = 'OPEN' if p.is_open else (
                'WEP' if p.has_wep else (
                    'WPA3' if p.has_wpa3 else (
                        'WPA2' if p.has_wpa2 else 'WPA'
                    )
                )
            )
            ssid_display = (p.ssid or '<hidden>')[:24]
            print(f"{p.bssid:<18} {ssid_display:<25} {p.risk_score:>5} {security:<15}")

        manager.close()
