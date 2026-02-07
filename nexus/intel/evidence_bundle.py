"""
Evidence Bundle Builder

Packages curated events, alerts, anomalies, and PCAP slices into a single zip
archive for investigations or SIEM export.
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexus.utils import json_compat


@dataclass
class EvidenceBundle:
    start_ts: float
    end_ts: float
    generated_at: float
    events: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    anomalies: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)
    pcap_path: str | None = None


def _row_to_dict(columns, row) -> dict[str, Any]:
    return {columns[i]: row[i] for i in range(len(columns))}


def _safe_json(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json_compat.loads(value)
    except Exception:
        return value


def collect_bundle_data(conn, start_ts: float, end_ts: float, *, max_events: int = 10000) -> EvidenceBundle:
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM curated_events WHERE ts_epoch BETWEEN ? AND ?",
        (start_ts, end_ts),
    )
    total_events = int(cursor.fetchone()[0])
    truncated = total_events > max_events

    cursor.execute(
        """
        SELECT TOP (?)
            event_id,
            ts_epoch,
            event_type,
            payload,
            payload_keys_sa,
            payload_keys_da,
            payload_effective_bssid,
            payload_effective_ssid
        FROM curated_events
        WHERE ts_epoch BETWEEN ? AND ?
        ORDER BY ts_epoch ASC
        """,
        (max_events, start_ts, end_ts),
    )
    columns = [col[0] for col in cursor.description]
    events = []
    for row in cursor.fetchall():
        item = _row_to_dict(columns, row)
        item["payload"] = _safe_json(item.get("payload"))
        events.append(item)

    # WIDS / rule alerts
    alerts = []
    try:
        cursor.execute(
            """
            SELECT alert_id, alert_type, severity, title, description, ts_epoch,
                   first_seen, last_seen, source_mac, target_mac, bssid, ssid, channel, incident_id
            FROM attack_alerts
            WHERE ts_epoch BETWEEN ? AND ?
            ORDER BY ts_epoch DESC
            """,
            (start_ts, end_ts),
        )
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            item = _row_to_dict(columns, row)
            if item.get("first_seen"):
                item["first_seen"] = item["first_seen"].isoformat()
            if item.get("last_seen"):
                item["last_seen"] = item["last_seen"].isoformat()
            alerts.append(item)
    except Exception:
        alerts = []

    # ML anomalies (attack_timeline)
    anomalies = []
    try:
        cursor.execute(
            """
            SELECT id, attack_type, severity, confidence, target_bssid, target_ssid,
                   target_client, attacker_mac, start_time, end_time, duration_sec,
                   event_count, evidence_events, evidence_pcaps, description, ioc_summary
            FROM attack_timeline
            WHERE start_time BETWEEN ? AND ?
            ORDER BY start_time DESC
            """,
            (datetime.fromtimestamp(start_ts), datetime.fromtimestamp(end_ts)),
        )
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            item = _row_to_dict(columns, row)
            if item.get("start_time"):
                item["start_time"] = item["start_time"].isoformat()
            if item.get("end_time"):
                item["end_time"] = item["end_time"].isoformat()
            item["evidence_events"] = _safe_json(item.get("evidence_events"))
            item["evidence_pcaps"] = _safe_json(item.get("evidence_pcaps"))
            anomalies.append(item)
    except Exception:
        anomalies = []

    metadata = {
        "event_count": total_events,
        "alert_count": len(alerts),
        "anomaly_count": len(anomalies),
        "truncated": truncated,
        "max_events": max_events,
    }
    return EvidenceBundle(
        start_ts=start_ts,
        end_ts=end_ts,
        generated_at=datetime.now(timezone.utc).timestamp(),
        events=events,
        alerts=alerts,
        anomalies=anomalies,
        metadata=metadata,
        pcap_path=None,
    )


def build_bundle_archive(bundle: EvidenceBundle, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    metadata = dict(bundle.metadata)
    metadata.update(
        {
            "start_ts": bundle.start_ts,
            "end_ts": bundle.end_ts,
            "generated_at": bundle.generated_at,
        }
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        (tmpdir / "metadata.json").write_text(json.dumps(metadata, indent=2))
        (tmpdir / "events.json").write_text(json.dumps(bundle.events, indent=2))
        (tmpdir / "alerts.json").write_text(json.dumps(bundle.alerts, indent=2))
        (tmpdir / "anomalies.json").write_text(json.dumps(bundle.anomalies, indent=2))

        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(tmpdir / "metadata.json", arcname="metadata.json")
            zf.write(tmpdir / "events.json", arcname="events.json")
            zf.write(tmpdir / "alerts.json", arcname="alerts.json")
            zf.write(tmpdir / "anomalies.json", arcname="anomalies.json")
            if bundle.pcap_path:
                pcap_path = Path(bundle.pcap_path)
                if pcap_path.exists():
                    zf.write(pcap_path, arcname=pcap_path.name)

    return output_path


def build_bundle(
    conn,
    evidence_collector,
    start_ts: float,
    end_ts: float,
    *,
    output_dir: Path,
    max_events: int = 10000,
) -> Path:
    bundle = collect_bundle_data(conn, start_ts, end_ts, max_events=max_events)
    pcap_path = evidence_collector.slice_pcap(start_ts, end_ts)
    bundle.pcap_path = pcap_path

    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"evidence_bundle_{int(start_ts)}_{int(end_ts)}.zip"
    output_path = output_dir / filename
    return build_bundle_archive(bundle, output_path)
