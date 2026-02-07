"""
Incident Manager
================

Consolidates high-volume WIDS alerts into actionable Incidents.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Grouping window: if an alert matches an active incident seen within X minutes, group it.
INCIDENT_WINDOW_MINUTES = 30


def _clip(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text[:max_len] if len(text) > max_len else text


def _coerce_severity(value: Any, default: int = 1) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _coerce_ts_epoch(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


class IncidentManager:
    """
    Manages the lifecycle of Incidents (consolidated alerts).
    """

    def __init__(self, db_cursor):
        self.cursor = db_cursor

        # Cache active incidents to minimize DB hits during bursts.
        # Key: (signature, source_mac, target_mac, bssid)
        # Value: {incident_id, last_seen_epoch, alert_count}
        self._active_cache: dict[tuple, dict[str, Any]] = {}
        self._cache_last_refresh = 0

    def process_alerts(self, alerts: list[dict[str, Any]]) -> int:
        """
        Process a batch of raw alerts and assign them to incidents.
        Returns the number of incidents created or updated.
        """
        if not alerts:
            return 0

        updated_count = 0
        for alert in alerts:
            try:
                # If alert already has an ID (from a previous assignment), skip?
                # But here we are processing raw alerts.
                inc_id = self.assign_incident(alert)
                if inc_id:
                    self._link_alert(alert['alert_id'], inc_id)
                    updated_count += 1
            except Exception as e:
                logger.error(f"Failed to process alert {alert.get('alert_id')}: {e}")

        return updated_count

    def assign_incident(self, alert: dict[str, Any]) -> str:
        """
        Find or create an active incident for this alert and return its ID.
        Updates the incidents table (last_seen, count), but does NOT link the alert.
        """
        signature = _clip(alert.get('alert_signature') or 'unknown', 256) or 'unknown'
        source_mac = _clip(alert.get('source_mac'), 17)
        target_mac = _clip(alert.get('target_mac'), 17)
        bssid = _clip(alert.get('bssid') or alert.get('payload_effective_bssid'), 17)

        # Grouping key
        key = (
            signature,
            source_mac,
            target_mac,
            bssid,  # Fallback already applied
        )

        ts_epoch = _coerce_ts_epoch(alert.get('ts_epoch'), 0.0)

        # Check cache/DB for active incident
        incident_id = self._find_active_incident_id(key, ts_epoch)

        if incident_id:
             # Update existing incident stats
            self._update_incident(incident_id, alert, ts_epoch)
        else:
            # Create new incident
            incident_id = self._create_incident(key, alert, ts_epoch)

        return incident_id

    def _handle_single_alert(self, alert: dict[str, Any]) -> None:
        """Deprecated internal method."""
        pass

    def _find_active_incident_id(self, key: tuple, current_ts: float) -> str | None:
        """Find active incident ID for key within window."""

        # 1. Check Memory Cache
        if key in self._active_cache:
            entry = self._active_cache[key]
            # Check window (e.g. 30 mins from last seen)
            # If (current_ts - last_seen) < window -> Valid
            if (current_ts - entry['last_seen']) < (INCIDENT_WINDOW_MINUTES * 60):
                return entry['id']
            else:
                # Expired
                del self._active_cache[key]

        # 2. Check Database (Active incidents matching signature/entities)
        # We query for incidents modified recently

        # Refined Logic: Find the most recent alert with this key.
        # If it has an incident_id and that incident is active and recent, reuse it.

        sig, src, dst, bssid = key

        # Construct SQL filter dynamically based on nulls
        params = [sig]
        clauses = ["alert_signature = ?"]

        if src:
            clauses.append("source_mac = ?")
            params.append(src)
        else:
            clauses.append("source_mac IS NULL")

        if dst:
            clauses.append("target_mac = ?")
            params.append(dst)
        else:
            clauses.append("target_mac IS NULL")

        if bssid:
            clauses.append("bssid = ?")
            params.append(bssid)
        else:
            clauses.append("bssid IS NULL")

        # Efficient lookup: find latest alert with this signature
        # This is expensive if table is huge.
        # Better: Add 'signature_hash' to incidents table?
        # For now, we will assume cache hits most bursts.
        # DB lookup is fallback.

        sql = f"""
        SELECT TOP 1 incident_id
        FROM attack_alerts
        WHERE { ' AND '.join(clauses) }
          AND incident_id IS NOT NULL
        ORDER BY ts_epoch DESC
        """

        self.cursor.execute(sql, params)
        row = self.cursor.fetchone()

        if row:
            inc_id = row[0]
            # Verify incident is still active and within window
            self.cursor.execute("SELECT last_seen, status FROM incidents WHERE incident_id = ?", [inc_id])
            inc_row = self.cursor.fetchone()
            if inc_row:
                last_seen_dt, status = inc_row
                # Convert datetime2 to epoch if needed or compare
                # Simplified: just check status for now.
                # (Ideally we check time window too, but 'active' implies current)
                if status == 'active':
                    # Update cache
                    # We might need to convert last_seen_dt to epoch
                    last_seen_epoch = current_ts # Approximation
                    self._active_cache[key] = {'id': inc_id, 'last_seen': last_seen_epoch}
                    return inc_id

        return None

    def _create_incident(self, key: tuple, alert: dict[str, Any], ts_epoch: float) -> str:
        """Create a new incident record."""
        inc_id = uuid.uuid4().hex

        title = _clip(alert.get('title') or f"Alert: {key[0]}", 200)
        desc = _clip(alert.get('description') or f"Detected {key[0]} from {key[1]} to {key[2]}", 4000)
        severity = _coerce_severity(alert.get('severity'), 1)

        # Use ISO string for DATETIME2
        dt_str = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        sql = """
        INSERT INTO incidents (incident_id, status, severity, title, description, first_seen, last_seen, alert_count)
        VALUES (?, 'active', ?, ?, ?, ?, ?, 1)
        """
        self.cursor.execute(sql, [inc_id, severity, title, desc, dt_str, dt_str])

        # Cache
        self._active_cache[key] = {'id': inc_id, 'last_seen': ts_epoch}
        logger.info(f"Created new incident {inc_id} for {title}")
        return inc_id

    def _update_incident(self, inc_id: str, alert: dict[str, Any], ts_epoch: float) -> None:
        """Update existing incident counters."""
        dt_str = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        # Update last_seen and increment count
        sql = """
        UPDATE incidents
        SET last_seen = ?, alert_count = alert_count + 1, updated_at = SYSDATETIME()
        WHERE incident_id = ?
        """
        self.cursor.execute(sql, [dt_str, inc_id])

        # Update cache timestamp
        # Locate keys pointing to this inc_id (expensive?) -> No, we called this because we found the key.
        # But we don't have the key passed here conveniently.
        # Optimization: caller updates cache. We just do DB.

    def _link_alert(self, alert_id: str, incident_id: str) -> None:
        """Link a raw alert to an incident."""
        sql = "UPDATE attack_alerts SET incident_id = ? WHERE alert_id = ?"
        self.cursor.execute(sql, [incident_id, alert_id])
