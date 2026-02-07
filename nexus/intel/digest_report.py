"""
Daily Digest Report

Summarizes key operational metrics for a given time window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class DigestSnapshot:
    start_ts: float
    end_ts: float
    generated_at: float
    totals: dict[str, int] = field(default_factory=dict)
    top_alerts: list[dict[str, str]] = field(default_factory=list)
    incidents: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _row_to_dict(columns, row) -> dict[str, str]:
    return {columns[i]: row[i] for i in range(len(columns))}


def collect_digest(conn, start_ts: float, end_ts: float) -> DigestSnapshot:
    cursor = conn.cursor()

    totals: dict[str, int] = {}

    cursor.execute(
        "SELECT COUNT(*) FROM curated_events WHERE ts_epoch BETWEEN ? AND ?",
        (start_ts, end_ts),
    )
    totals["events"] = int(cursor.fetchone()[0])

    # New Wi-Fi devices (client_profiles first_seen)
    cursor.execute(
        "SELECT COUNT(*) FROM client_profiles WHERE first_seen BETWEEN ? AND ?",
        (datetime.fromtimestamp(start_ts), datetime.fromtimestamp(end_ts)),
    )
    totals["new_wifi_devices"] = int(cursor.fetchone()[0])

    # New BLE devices
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM bt_devices WHERE first_seen BETWEEN ? AND ?",
            (datetime.fromtimestamp(start_ts), datetime.fromtimestamp(end_ts)),
        )
        totals["new_bt_devices"] = int(cursor.fetchone()[0])
    except Exception:
        totals["new_bt_devices"] = 0

    # Alerts (WIDS / rule)
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM attack_alerts WHERE ts_epoch BETWEEN ? AND ?",
            (start_ts, end_ts),
        )
        totals["wids_alerts"] = int(cursor.fetchone()[0])
    except Exception:
        totals["wids_alerts"] = 0

    # Baseline drift subset
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM attack_alerts WHERE alert_type LIKE 'baseline_%' AND ts_epoch BETWEEN ? AND ?",
            (start_ts, end_ts),
        )
        totals["baseline_drift"] = int(cursor.fetchone()[0])
    except Exception:
        totals["baseline_drift"] = 0

    # ML anomalies
    try:
        cursor.execute(
            """
            SELECT COUNT(*) FROM attack_timeline
            WHERE start_time BETWEEN ? AND ?
            """,
            (datetime.fromtimestamp(start_ts), datetime.fromtimestamp(end_ts)),
        )
        totals["anomalies"] = int(cursor.fetchone()[0])
    except Exception:
        totals["anomalies"] = 0

    # Top alerts by type
    top_alerts: list[dict[str, str]] = []
    try:
        cursor.execute(
            """
            SELECT TOP 5 alert_type, COUNT(*) AS cnt
            FROM attack_alerts
            WHERE ts_epoch BETWEEN ? AND ?
            GROUP BY alert_type
            ORDER BY cnt DESC
            """,
            (start_ts, end_ts),
        )
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            top_alerts.append(_row_to_dict(columns, row))
    except Exception:
        top_alerts = []

    # Recent incidents
    incidents: list[dict[str, str]] = []
    try:
        cursor.execute(
            """
            SELECT TOP 5 incident_id, title, severity, alert_count, first_seen, last_seen
            FROM incidents
            WHERE last_seen BETWEEN ? AND ?
            ORDER BY last_seen DESC
            """,
            (datetime.fromtimestamp(start_ts), datetime.fromtimestamp(end_ts)),
        )
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            item = _row_to_dict(columns, row)
            if item.get("first_seen"):
                item["first_seen"] = item["first_seen"].isoformat()
            if item.get("last_seen"):
                item["last_seen"] = item["last_seen"].isoformat()
            incidents.append(item)
    except Exception:
        incidents = []

    return DigestSnapshot(
        start_ts=start_ts,
        end_ts=end_ts,
        generated_at=datetime.now(timezone.utc).timestamp(),
        totals=totals,
        top_alerts=top_alerts,
        incidents=incidents,
    )


def format_digest_markdown(snapshot: DigestSnapshot) -> str:
    start = datetime.fromtimestamp(snapshot.start_ts).isoformat()
    end = datetime.fromtimestamp(snapshot.end_ts).isoformat()
    generated = datetime.fromtimestamp(snapshot.generated_at).isoformat()

    totals = snapshot.totals
    lines = [
        "# WICAP Daily Digest",
        "",
        f"Window: {start} → {end}",
        f"Generated: {generated}",
        "",
        "## Summary",
        f"- Events: {totals.get('events', 0)}",
        f"- New Wi‑Fi devices: {totals.get('new_wifi_devices', 0)}",
        f"- New BLE devices: {totals.get('new_bt_devices', 0)}",
        f"- WIDS alerts: {totals.get('wids_alerts', 0)}",
        f"- Baseline drift alerts: {totals.get('baseline_drift', 0)}",
        f"- Anomalies (ML): {totals.get('anomalies', 0)}",
        "",
        "## Top Alert Types",
    ]

    if snapshot.top_alerts:
        for alert in snapshot.top_alerts:
            lines.append(f"- {alert.get('alert_type')}: {alert.get('cnt')}")
    else:
        lines.append("- None")

    lines.extend(["", "## Recent Incidents"])
    if snapshot.incidents:
        for inc in snapshot.incidents:
            lines.append(
                f"- {inc.get('incident_id')} | {inc.get('title')} | severity {inc.get('severity')} | alerts {inc.get('alert_count')}"
            )
    else:
        lines.append("- None")

    if snapshot.notes:
        lines.extend(["", "## Notes"])
        for note in snapshot.notes:
            lines.append(f"- {note}")

    return "\n".join(lines)
