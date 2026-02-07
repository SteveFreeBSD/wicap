import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

import app.services.state as state
from app.schemas import AlertAcknowledge, AlertFeedback, MACAddress, RecentEventsQuery
from app.services.alert_consolidation import apply_alert_policy
from app.services.bluetooth_behavior import build_bt_behavior_insight
from app.services.bluetooth_insights import build_bt_device_insight
from app.services.bluetooth_rotation import annotate_rotation_clusters
from app.services.bluetooth_text import count_unknown_bt_services, format_bt_service_labels, sanitize_bt_name
from app.services.bluetooth_timeline import annotate_bt_recurrence
from app.services.identity_graph import (
    get_cluster_for_identifier,
    get_identity_graph,
    get_identity_graph_cached,
    get_identity_graph_summary,
)
from nexus.intel.evidence_bundle import build_bundle
from nexus.intel.feedback_calibration import compute_metrics, recommend_threshold
from nexus.intel.network_baseline import load_network_baseline
from nexus.utils import json_compat

router = APIRouter()
logger = logging.getLogger("wicap.ui")


# =============================================================================
# Identity Graph Export
# =============================================================================
@router.get("/api/identity/graph")
async def api_identity_graph(include_profiles: bool = True):
    """Return the cached identity graph (clusters + edges)."""
    def _query(conn):
        graph = get_identity_graph(conn)
        return graph.to_dict(include_profiles=include_profiles)

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc), "clusters": [], "edges": []}


@router.get("/api/identity/graph/summary")
async def api_identity_graph_summary(allow_build: bool = False):
    """Return cached identity graph metadata without forcing a rebuild."""
    def _query(conn):
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT OBJECT_ID('device_identity_clusters')")
            if cursor.fetchone()[0]:
                cursor.execute("SELECT COUNT(*) FROM device_identity_clusters")
                clusters = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM device_identity_members")
                members = cursor.fetchone()[0]
                return {
                    "cached": False,
                    "age_sec": None,
                    "cluster_count": clusters,
                    "edge_count": 0,
                    "member_count": members,
                }
        except Exception:
            pass
        return get_identity_graph_summary(conn, allow_build=allow_build)

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc), "cluster_count": 0, "edge_count": 0, "cached": False}


@router.get("/api/identity/graph/export")
async def api_identity_graph_export():
    """Export identity graph as a JSON download for investigations."""
    def _query(conn):
        graph = get_identity_graph(conn)
        return graph.to_dict(include_profiles=True)

    try:
        payload = await state.run_db(_query)
        filename = f"identity_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        return JSONResponse(
            content=payload,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/ops/siem")
async def api_ops_siem(since_hours: int = 24, limit: int = 200):
    """Export alert data with evidence pointers for SIEM/webhook use."""
    since_hours = max(1, min(since_hours, 720))
    limit = max(1, min(limit, 1000))
    start_ts = time.time() - (since_hours * 3600)

    def _query(conn):
        cursor = conn.cursor()
        payload = {"since_hours": since_hours, "alerts": []}

        # WIDS / rule alerts
        try:
            cursor.execute(
                """
                SELECT TOP (?)
                    alert_id, alert_type, severity, title, description,
                    ts_epoch, source_mac, target_mac, bssid, ssid, channel, incident_id
                FROM attack_alerts
                WHERE ts_epoch >= ?
                ORDER BY ts_epoch DESC
                """,
                (limit, start_ts),
            )
            columns = [col[0] for col in cursor.description]
            for row in cursor.fetchall():
                item = {columns[i]: row[i] for i in range(len(columns))}
                ts_epoch = float(item.get("ts_epoch") or start_ts)
                item["source"] = "attack_alerts"
                item["evidence"] = {
                    "slice_start": ts_epoch - 60,
                    "slice_end": ts_epoch + 60,
                    "slice_url": f"/api/evidence/slice?start_ts={ts_epoch - 60:.0f}&end_ts={ts_epoch + 60:.0f}",
                }
                payload["alerts"].append(item)
        except Exception:
            pass

        # ML anomalies
        try:
            cursor.execute(
                """
                SELECT TOP (?)
                    id, attack_type, severity, confidence, target_bssid, target_ssid,
                    target_client, attacker_mac, start_time, end_time, event_count,
                    evidence_events, evidence_pcaps, description
                FROM attack_timeline
                WHERE start_time >= ?
                ORDER BY start_time DESC
                """,
                (limit, datetime.fromtimestamp(start_ts)),
            )
            columns = [col[0] for col in cursor.description]
            for row in cursor.fetchall():
                item = {columns[i]: row[i] for i in range(len(columns))}
                item["source"] = "attack_timeline"
                item["evidence_events"] = json_compat.loads(item["evidence_events"]) if item.get("evidence_events") else []
                item["evidence_pcaps"] = json_compat.loads(item["evidence_pcaps"]) if item.get("evidence_pcaps") else []
                payload["alerts"].append(item)
        except Exception:
            pass

        return payload

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc), "alerts": []}


# =============================================================================
# Evidence Export
# =============================================================================
@router.get("/api/evidence/slice")
async def api_evidence_slice(start_ts: float, end_ts: float):
    """
    Export a PCAP slice for the given time range.
    """
    try:
        # Run blocking editcap operation in threadpool
        path = await run_in_threadpool(state.evidence_collector.slice_pcap, start_ts, end_ts)

        if not path or not os.path.exists(path):
            raise HTTPException(status_code=404, detail="No capture data found for this time range")

        filename = os.path.basename(path)
        return FileResponse(
            path=path,
            filename=filename,
            media_type="application/vnd.tcpdump.pcap",
        )
    except HTTPException:
        raise
    except Exception as exc:
        print(f"Error slicing PCAP: {exc}")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# =============================================================================
# API Endpoints
# =============================================================================
@router.get("/api/baseline/network")
async def api_network_baseline(include_maps: bool = False):
    """
    Return the current 30-day network baseline snapshot summary.
    """
    path = Path(os.getenv("WICAP_NETWORK_BASELINE_PATH", "captures/network_baselines/network_baseline_global.json"))
    snapshot = load_network_baseline(path)
    if not snapshot:
        return {
            "ready": False,
            "path": str(path),
            "message": "Baseline snapshot not found. Run: python -m nexus.intel.network_baseline refresh --since 30d",
        }

    summary = {
        "ready": True,
        "path": str(path),
        "scope": snapshot.scope,
        "horizon_days": snapshot.horizon_days,
        "updated_at": snapshot.updated_at,
        "total_ssids": snapshot.total_ssids,
        "total_bssids": snapshot.total_bssids,
    }
    if include_maps:
        summary["ssid_bssids"] = snapshot.ssid_bssids
        summary["bssid_security"] = snapshot.bssid_security
        summary["bssid_channel"] = snapshot.bssid_channel
    return summary


@router.get("/api/baseline/drift")
async def api_baseline_drift(limit: int = 100):
    """
    Return recent baseline drift alerts (wids_baseline_*).
    """

    def _query(conn):
        cursor = conn.cursor()
        limit_value = max(1, min(int(limit or 100), 500))
        cursor.execute(
            f"""
            SELECT TOP {limit_value}
                event_type,
                ts_epoch,
                payload_effective_bssid,
                payload_effective_ssid,
                payload_rssi_int,
                channel,
                payload
            FROM curated_events
            WHERE event_type LIKE 'wids_baseline_%'
            ORDER BY ts_epoch DESC
            """
        )
        rows = []
        for row in cursor.fetchall():
            rows.append(
                {
                    "event_type": row[0],
                    "ts_epoch": float(row[1]) if row[1] is not None else None,
                    "bssid": row[2],
                    "ssid": row[3],
                    "rssi": row[4],
                    "channel": row[5],
                    "payload": json_compat.loads(row[6]) if row[6] else None,
                }
            )
        return {"count": len(rows), "items": rows}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc), "count": 0, "items": []}


@router.get("/api/stats")
async def api_stats(source: str = "live"):
    # Get live statistics for HTMX polling.
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)

        cursor.execute(f"SELECT COUNT(*) FROM curated_events WHERE {where_clause}", params)
        total_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM handshakes")
        total_handshakes = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM handshakes WHERE crack_status = 'cracked'")
        cracked = cursor.fetchone()[0]

        # Approximate active clients (unique source MACs seen in last 5 mins)
        query_clients = (
            "SELECT COUNT(DISTINCT payload_keys_sa) "
            "FROM curated_events "
            "WHERE payload_keys_sa IS NOT NULL "
            "AND event_type <> 'telemetry_pulse' "
            "AND inserted_at > DATEADD(minute, -5, GETDATE()) "
            "AND (payload_keys_bssid IS NULL "
            "     OR payload_keys_sa <> payload_keys_bssid) "
            f"AND {where_clause}"
        )
        cursor.execute(query_clients, params)
        active_clients = cursor.fetchone()[0]

        # 5. Last Event
        cursor.execute(f"SELECT MAX(inserted_at) FROM curated_events WHERE {where_clause}", params)
        last_event_row = cursor.fetchone()
        last_event = "N/A"
        if last_event_row and last_event_row[0]:
            # Assuming datetime object from connector, or string. Format as HH:MM:SS
            le_val = last_event_row[0]
            if isinstance(le_val, str):
                try:
                    last_event = le_val.split("T")[1][:8] if "T" in le_val else str(le_val)
                except Exception:
                    last_event = str(le_val)
            elif hasattr(le_val, "strftime"):
                last_event = le_val.strftime("%H:%M:%S")
            else:
                last_event = str(le_val)

        return {
            "total_events": total_events,
            "total_handshakes": total_handshakes,
            "cracked": cracked,
            "active_clients": active_clients,
            "last_event": last_event,
            "timestamp": datetime.now().isoformat(),
        }

    try:
        return await state.run_db(_query)
    except Exception as exc:
        logger.error("API stats query failed: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable for stats endpoint.") from exc


@router.get("/api/evidence/bundles/{bundle_date}")
async def api_evidence_bundle(
    bundle_date: str,
    start_ts: float | None = None,
    end_ts: float | None = None,
    max_events: int = 10000,
):
    """Build and download a bundled evidence ZIP for a given date (YYYY-MM-DD or YYYYMMDD)."""

    def _parse_date_to_range(date_str: str) -> tuple[float, float]:
        if "-" in date_str:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
        else:
            dt = datetime.strptime(date_str, "%Y%m%d")
        start = dt.timestamp()
        end = (dt + timedelta(days=1)).timestamp()
        return start, end

    if start_ts is None or end_ts is None:
        start_ts, end_ts = _parse_date_to_range(bundle_date)

    def _build(conn):
        output_dir = Path(os.getenv("WICAP_EVIDENCE_BUNDLE_DIR", "captures/evidence/bundles"))
        return build_bundle(
            conn,
            state.evidence_collector,
            start_ts,
            end_ts,
            output_dir=output_dir,
            max_events=max_events,
        )

    try:
        path = await state.run_db(_build)
        if not path or not os.path.exists(path):
            raise HTTPException(status_code=404, detail="Evidence bundle not created")
        return FileResponse(path, filename=os.path.basename(path))
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/charts/activity")
async def api_chart_activity(source: str = "live"):
    # Get activity timeline (events per minute for last hour).
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)
        # Initial implementation: simple count bucketed by minute
        # Optimized for SQL Server
        query_chart = (
            "SELECT "
            "FORMAT(inserted_at, 'HH:mm') as time_bucket, "
            "COUNT(*) as count "
            "FROM curated_events "
            "WHERE inserted_at > DATEADD(hour, -1, GETDATE()) "
            "AND event_type NOT IN ('telemetry_pulse', 'summary') "
            f"AND {where_clause} "
            "GROUP BY FORMAT(inserted_at, 'HH:mm') "
            "ORDER BY MAX(inserted_at) ASC"
        )
        cursor.execute(query_chart, params)
        rows = cursor.fetchall()
        if not rows:
            fallback_query = (
                "SELECT "
                "FORMAT(inserted_at, 'HH:mm') as time_bucket, "
                "COUNT(*) as count "
                "FROM curated_events "
                "WHERE inserted_at > DATEADD(hour, -1, GETDATE()) "
                "AND event_type <> 'summary' "
                f"AND {where_clause} "
                "GROUP BY FORMAT(inserted_at, 'HH:mm') "
                "ORDER BY MAX(inserted_at) ASC"
            )
            cursor.execute(fallback_query, params)
            rows = cursor.fetchall()
        labels = [row[0] for row in rows]
        data = [row[1] for row in rows]
        return {"labels": labels, "data": data}

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc), "labels": [], "data": []}


@router.get("/api/charts/spectrum")
async def api_chart_spectrum(source: str = "live"):
    # Get channel usage distribution.
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        protocol_expr = (
            "payload_protocol"
            if _col_exists("payload_protocol")
            else "CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8))"
        )

        query_spectrum = (
            "SELECT channel, COUNT(*) as count "
            "FROM curated_events "
            "WHERE channel IS NOT NULL "
            "AND event_type NOT IN ('telemetry_pulse', 'summary') "
            f"AND ({protocol_expr} IS NULL OR {protocol_expr} <> 'bt') "
            "AND inserted_at > DATEADD(hour, -1, GETDATE()) "
            f"AND {where_clause} "
            "GROUP BY channel "
            "ORDER BY count DESC"
        )
        cursor.execute(query_spectrum, params)
        rows = cursor.fetchall()
        if not rows:
            fallback_query = (
                "SELECT channel, COUNT(*) as count "
                "FROM curated_events "
                "WHERE channel IS NOT NULL "
                "AND inserted_at > DATEADD(hour, -1, GETDATE()) "
                f"AND {where_clause} "
                "GROUP BY channel "
                "ORDER BY count DESC"
            )
            cursor.execute(fallback_query, params)
            rows = cursor.fetchall()
        rows = rows[:15]  # Top 15 channels
        labels = [str(row[0]) for row in rows]
        data = [row[1] for row in rows]
        return {"labels": labels, "data": data}

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc), "labels": [], "data": []}


@router.get("/api/charts/vendors")
async def api_chart_vendors(source: str = "live"):
    # Get top device vendors.
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        vendor_expr = (
            "payload_vendor"
            if _col_exists("payload_vendor")
            else "CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100))"
        )
        protocol_expr = (
            "payload_protocol"
            if _col_exists("payload_protocol")
            else "CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8))"
        )

        query_vendors = (
            f"SELECT COALESCE({vendor_expr}, 'Unknown') as vendor, COUNT(*) as count "
            "FROM curated_events "
            "WHERE inserted_at > DATEADD(hour, -24, GETDATE()) "
            "AND event_type NOT IN ('telemetry_pulse', 'summary') "
            f"AND ({protocol_expr} IS NULL OR {protocol_expr} <> 'bt') "
            f"AND {where_clause} "
            f"GROUP BY COALESCE({vendor_expr}, 'Unknown') "
            "ORDER BY count DESC"
        )
        cursor.execute(query_vendors, params)
        rows = cursor.fetchall()
        if not rows:
            fallback_query = (
                f"SELECT COALESCE({vendor_expr}, 'Unknown') as vendor, COUNT(*) as count "
                "FROM curated_events "
                "WHERE inserted_at > DATEADD(hour, -24, GETDATE()) "
                f"AND {where_clause} "
                f"GROUP BY COALESCE({vendor_expr}, 'Unknown') "
                "ORDER BY count DESC"
            )
            cursor.execute(fallback_query, params)
            rows = cursor.fetchall()
        # Clean up nulls
        clean_rows = [(row[0] or "Unknown", row[1]) for row in rows]
        # Top 5 + Others
        top_5 = clean_rows[:5]
        others_count = sum(r[1] for r in clean_rows[5:])

        labels = [r[0] for r in top_5]
        data = [r[1] for r in top_5]
        if others_count > 0:
            labels.append("Others")
            data.append(others_count)
        return {"labels": labels, "data": data}

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc), "labels": [], "data": []}


@router.get("/api/recent-events")
async def api_recent_events(query: Annotated[RecentEventsQuery, Depends()]):
    # Get recent events for live feed.
    source = state._normalize_source(query.source)
    limit = query.limit
    include_bt = bool(query.include_bt)
    include_pulse = bool(query.include_pulse)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        bssid_expr = (
            "payload_effective_bssid"
            if _col_exists("payload_effective_bssid")
            else "CAST(COALESCE(JSON_VALUE(payload, '$.keys.bssid'), JSON_VALUE(payload, '$.bssid')) AS NVARCHAR(17))"
        )
        ssid_expr = (
            "payload_effective_ssid"
            if _col_exists("payload_effective_ssid")
            else "CAST(COALESCE(JSON_VALUE(payload, '$.keys.ssid'), JSON_VALUE(payload, '$.ssid')) AS NVARCHAR(64))"
        )
        rssi_expr = (
            "payload_rssi_int"
            if _col_exists("payload_rssi_int")
            else "TRY_CAST(COALESCE(JSON_VALUE(payload, '$.keys.rssi_dbm'), JSON_VALUE(payload, '$.rssi')) AS INT)"
        )
        vendor_expr = (
            "payload_vendor"
            if _col_exists("payload_vendor")
            else "CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100))"
        )
        wifi6_expr = (
            "payload_wifi6"
            if _col_exists("payload_wifi6")
            else "CAST(JSON_VALUE(payload, '$.fingerprint.is_wifi6') AS BIT)"
        )
        protocol_expr = (
            "payload_protocol"
            if _col_exists("payload_protocol")
            else "CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8))"
        )
        filters = [where_clause]
        if not include_pulse:
            filters.append("event_type NOT IN ('telemetry_pulse', 'summary')")
        if not include_bt:
            filters.append(f"(({protocol_expr} IS NULL OR {protocol_expr} <> 'bt') AND event_type NOT LIKE 'bt_%')")
        final_where = " AND ".join(filters)

        # Use parameterized query for limit to prevent injection
        query_recent = (
            "SELECT TOP (?) "
            f"{ssid_expr} as ssid, "
            f"{bssid_expr} as bssid, "
            "event_type, "
            f"{rssi_expr} as rssi, "
            "channel, "
            f"{vendor_expr} as vendor, "
            f"{wifi6_expr} as is_wifi6, "
            "inserted_at as timestamp "
            "FROM curated_events "
            f"WHERE {final_where} "
            "ORDER BY inserted_at DESC"
        )
        cursor.execute(query_recent, (limit, *params))
        columns = [col[0] for col in cursor.description]
        return {"events": [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]}

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/telemetry/stats")
async def api_telemetry_stats(source: str = "live"):
    """Get aggregated telemetry stats for charts."""
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)

        # Helper to execute query and format for Chart.js
        def get_chart_data(query, params=(), label_col=0, data_col=1):
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return {"labels": [str(r[label_col]) for r in rows], "data": [r[data_col] for r in rows]}

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        rssi_expr = (
            "payload_rssi_int"
            if _col_exists("payload_rssi_int")
            else "TRY_CAST(COALESCE(JSON_VALUE(payload, '$.keys.rssi_dbm'), JSON_VALUE(payload, '$.rssi')) AS INT)"
        )
        event_type_expr = "event_type"
        channel_expr = "channel"
        vendor_expr = (
            "payload_vendor"
            if _col_exists("payload_vendor")
            else "CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100))"
        )
        ssid_expr = (
            "payload_effective_ssid"
            if _col_exists("payload_effective_ssid")
            else "CAST(COALESCE(JSON_VALUE(payload, '$.keys.ssid'), JSON_VALUE(payload, '$.ssid')) AS NVARCHAR(64))"
        )
        talker_expr = (
            "payload_keys_sa"
            if _col_exists("payload_keys_sa")
            else "CAST(JSON_VALUE(payload, '$.keys.sa') AS NVARCHAR(17))"
        )
        protocol_expr = (
            "payload_protocol"
            if _col_exists("payload_protocol")
            else "CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8))"
        )

        stats = {}
        time_window_sql = f"inserted_at > DATEADD(minute, -60, GETDATE()) AND {where_clause}"
        time_window_params = params
        protocol_filter = f"({protocol_expr} IS NULL OR {protocol_expr} <> 'bt')"

        # 1. RSSI Distribution (Buckets)
        cursor.execute(
            f"""
            SELECT
                CASE
                    WHEN {rssi_expr} > -50 THEN 'Strong (>-50)'
                    WHEN {rssi_expr} > -70 THEN 'Good (-50 to -70)'
                    WHEN {rssi_expr} > -85 THEN 'Weak (-70 to -85)'
                    ELSE 'Poor (<-85)'
                END as quality,
                COUNT(*) as count
            FROM curated_events
            WHERE {time_window_sql} AND {rssi_expr} IS NOT NULL AND {protocol_filter}
            GROUP BY
                CASE
                    WHEN {rssi_expr} > -50 THEN 'Strong (>-50)'
                    WHEN {rssi_expr} > -70 THEN 'Good (-50 to -70)'
                    WHEN {rssi_expr} > -85 THEN 'Weak (-70 to -85)'
                    ELSE 'Poor (<-85)'
                END
        """,
            time_window_params,
        )
        rssi_rows = cursor.fetchall()
        stats["rssi"] = {"labels": [r[0] for r in rssi_rows], "data": [r[1] for r in rssi_rows]}

        # 2. Event Types
        stats["types"] = get_chart_data(
            f"SELECT {event_type_expr}, COUNT(*) FROM curated_events WHERE {time_window_sql} AND event_type NOT IN ('telemetry_pulse', 'summary') GROUP BY {event_type_expr} ORDER BY COUNT(*) DESC",
            time_window_params,
        )

        # 3. Channels (for Waterfall/Spectrum)
        stats["channels"] = get_chart_data(
            f"SELECT {channel_expr}, COUNT(*) FROM curated_events WHERE {time_window_sql} AND {channel_expr} IS NOT NULL AND {protocol_filter} GROUP BY {channel_expr} ORDER BY CAST({channel_expr} as INT)",
            time_window_params,
        )

        # 4. Vendors
        stats["vendors"] = get_chart_data(
            f"SELECT TOP 8 COALESCE({vendor_expr}, 'Unknown'), COUNT(*) FROM curated_events WHERE {time_window_sql} AND {protocol_filter} GROUP BY COALESCE({vendor_expr}, 'Unknown') ORDER BY COUNT(*) DESC",
            time_window_params,
        )

        # 5. Top SSIDs
        stats["ssids"] = get_chart_data(
            f"SELECT TOP 8 "
            f"{ssid_expr} as ssid, "
            f"COUNT(*) FROM curated_events WHERE {time_window_sql} "
            f"AND {ssid_expr} IS NOT NULL "
            f"AND {ssid_expr} != 'None' "
            f"AND {protocol_filter} "
            f"GROUP BY {ssid_expr} "
            "ORDER BY COUNT(*) DESC",
            time_window_params,
        )

        # 6. Top Talkers (Source MAC)
        stats["talkers"] = get_chart_data(
            f"SELECT TOP 8 {talker_expr}, COUNT(*) FROM curated_events WHERE {time_window_sql} AND {talker_expr} IS NOT NULL AND {protocol_filter} GROUP BY {talker_expr} ORDER BY COUNT(*) DESC",
            time_window_params,
        )
        return stats

    try:
        return await state.run_db(_query, retries=1)
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/telemetry/feed")
async def api_telemetry_feed(
    limit: int = 50,
    source: str = "live",
    include_bt: bool = False,
    include_pulse: bool = False,
):
    """Get raw telemetry feed."""
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        rssi_expr = (
            "payload_rssi_int"
            if _col_exists("payload_rssi_int")
            else "TRY_CAST(COALESCE(JSON_VALUE(payload, '$.keys.rssi_dbm'), JSON_VALUE(payload, '$.rssi')) AS INT)"
        )
        source_expr = (
            "payload_keys_sa"
            if _col_exists("payload_keys_sa")
            else "CAST(JSON_VALUE(payload, '$.keys.sa') AS NVARCHAR(17))"
        )
        dest_expr = (
            "payload_keys_da"
            if _col_exists("payload_keys_da")
            else "CAST(JSON_VALUE(payload, '$.keys.da') AS NVARCHAR(17))"
        )
        vendor_expr = (
            "payload_vendor"
            if _col_exists("payload_vendor")
            else "CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100))"
        )
        ssid_expr = (
            "payload_effective_ssid"
            if _col_exists("payload_effective_ssid")
            else "CAST(COALESCE(JSON_VALUE(payload, '$.keys.ssid'), JSON_VALUE(payload, '$.ssid')) AS NVARCHAR(64))"
        )
        protocol_expr = (
            "payload_protocol"
            if _col_exists("payload_protocol")
            else "CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8))"
        )
        filters = [where_clause]
        if not include_pulse:
            filters.append("event_type NOT IN ('telemetry_pulse', 'summary')")
        if not include_bt:
            filters.append(f"(({protocol_expr} IS NULL OR {protocol_expr} <> 'bt') AND event_type NOT LIKE 'bt_%')")
        final_where = " AND ".join(filters)

        query = (
            "SELECT TOP (?) "
            "inserted_at as timestamp, "
            "event_type, "
            "channel, "
            f"{rssi_expr} as rssi, "
            f"COALESCE({source_expr}, payload_source) as source, "
            f"COALESCE({dest_expr}, payload_dest) as dest, "
            f"{vendor_expr} as vendor, "
            f"{ssid_expr} as ssid "
            "FROM curated_events "
            f"WHERE {final_where} "
            "ORDER BY inserted_at DESC"
        )
        cursor.execute(query, (limit, *params))
        columns = [col[0] for col in cursor.description]
        events = []
        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row, strict=False))
            row_dict["timestamp"] = row_dict["timestamp"].isoformat() if row_dict["timestamp"] else None
            events.append(row_dict)
        return {"events": events}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/device/{mac}")
async def api_device_dossier(mac: str):
    """Get comprehensive dossier for a device."""
    # Validate MAC address
    try:
        validated_mac = MACAddress.validate(mac)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid MAC address: {exc}") from exc

    def _query(conn):
        cursor = conn.cursor()

        # 1. Basic Info (from latest event)
        cursor.execute(
            "SELECT TOP 1 payload, inserted_at FROM curated_events "
            "WHERE payload_keys_sa = ? OR payload_keys_bssid = ? "
            "ORDER BY inserted_at DESC",
            (validated_mac, validated_mac),
        )
        row = cursor.fetchone()

        info = {"mac": mac, "seen": False}
        if row:
            info["seen"] = True
            info["last_seen"] = row[1].isoformat()
            payload = json_compat.loads(row[0])
            info["vendor"] = payload.get("vendor", "Unknown")
            info["type"] = "AP" if payload.get("keys", {}).get("bssid") == validated_mac else "Client"

        # 2. Activity Stats
        cursor.execute(
            "SELECT COUNT(*), MIN(inserted_at), MAX(inserted_at) FROM curated_events "
            "WHERE payload_keys_sa = ? OR payload_keys_bssid = ?",
            (validated_mac, validated_mac),
        )
        stats = cursor.fetchone()
        info["total_packets"] = stats[0]
        info["first_seen"] = stats[1].isoformat() if stats[1] else None

        # 3. Known SSIDs (Probes)
        cursor.execute(
            "SELECT DISTINCT payload_effective_ssid as ssid "
            "FROM curated_events "
            "WHERE (payload_keys_sa = ?) "
            "AND payload_effective_ssid IS NOT NULL",
            (validated_mac,),
        )
        info["ssids"] = [r[0] for r in cursor.fetchall() if r[0] != "None"]

        # 4. RSSI aggregates (client_profiles)
        info["rssi"] = {
            "avg": None,
            "max": None,
            "last": None,
            "sample_count": 0,
            "last_seen": None,
        }
        try:
            cursor.execute(
                "SELECT rssi_avg, rssi_max, rssi_last, rssi_sample_count, rssi_last_seen "
                "FROM client_profiles WHERE mac_addr = ?",
                (validated_mac,),
            )
            row = cursor.fetchone()
            if row:
                info["rssi"]["avg"] = row[0]
                info["rssi"]["max"] = row[1]
                info["rssi"]["last"] = row[2]
                info["rssi"]["sample_count"] = row[3] or 0
                info["rssi"]["last_seen"] = row[4].isoformat() if row[4] else None
        except Exception:
            pass

        # 5. Associations (client_associations)
        info["associations"] = []
        try:
            cursor.execute(
                "SELECT bssid, ssid, first_seen, last_seen, association_count "
                "FROM client_associations WHERE client_mac = ? "
                "ORDER BY last_seen DESC",
                (validated_mac,),
            )
            columns = [col[0] for col in cursor.description]
            associations = []
            for row in cursor.fetchall():
                row_dict = dict(zip(columns, row, strict=False))
                if row_dict.get("first_seen"):
                    row_dict["first_seen"] = row_dict["first_seen"].isoformat()
                if row_dict.get("last_seen"):
                    row_dict["last_seen"] = row_dict["last_seen"].isoformat()
                associations.append(row_dict)
            info["associations"] = associations
        except Exception:
            pass

        # 6. Identity cluster (graph correlation)
        info["identity_cluster"] = None
        try:
            info["identity_cluster"] = get_cluster_for_identifier(conn, validated_mac)
        except Exception:
            info["identity_cluster"] = None
        return info

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc)}


# =============================================================================
# Identity Intelligence: Device Identities
# =============================================================================
@router.get("/api/devices")
async def api_list_device_identities(source: str = "live"):
    """
    List all device identities tracked by the Identity Lattice.
    Refactored to optimize performance (3 queries instead of 1+2N).
    """
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)

        # 1. Get identity statistics (Limited to Top 100 recent)
        cursor.execute(
            f"""
            SELECT TOP 100
                device_identity_id,
                COUNT(DISTINCT payload_keys_sa) as mac_count,
                MAX(ts_epoch) as last_seen,
                MIN(ts_epoch) as first_seen,
                COUNT(*) as observation_count
            FROM curated_events
            WHERE device_identity_id IS NOT NULL AND {where_clause}
            GROUP BY device_identity_id
            ORDER BY last_seen DESC
        """,
            params,
        )
        raw_identities = cursor.fetchall()

        # 2. Bulk fetch MAC assignments
        cursor.execute(
            f"""
            SELECT device_identity_id, payload_keys_sa
            FROM curated_events
            WHERE device_identity_id IS NOT NULL AND payload_keys_sa IS NOT NULL AND {where_clause}
            GROUP BY device_identity_id, payload_keys_sa
        """,
            params,
        )
        mac_rows = cursor.fetchall()
        from collections import defaultdict

        mac_map = defaultdict(list)
        for rid, mac in mac_rows:
            mac_map[rid].append(mac)

        # 3. Bulk fetch latest fingerprints
        # Get one fingerprint per identity (latest non-null)
        cursor.execute(
            f"""
            SELECT device_identity_id,
                   MAX(JSON_VALUE(payload, '$.fingerprint.hash')),
                   MAX(CAST(payload_wifi6 AS INT))
            FROM curated_events
            WHERE device_identity_id IS NOT NULL AND JSON_VALUE(payload, '$.fingerprint.hash') IS NOT NULL AND {where_clause}
            GROUP BY device_identity_id
        """,
            params,
        )
        fp_rows = cursor.fetchall()
        # Create maps for hash and wifi6 status
        fp_map = {row[0]: row[1] for row in fp_rows}
        wifi6_map = {row[0]: bool(row[2]) for row in fp_rows}

        # 4. Helper for randomized MAC detection
        def _is_randomized(macs):
            for mac in macs:
                if not mac or len(mac) < 2:
                    continue
                # Locally administered bit (2nd nibble: 2, 6, A, E)
                try:
                    second_char = mac.split(":")[0][1].lower()
                    if second_char in ("2", "6", "a", "e"):
                        return True
                except Exception:
                    continue
            return False

        # 5. Assemble results
        identities = []
        total_macs = len(mac_rows)

        for row in raw_identities:
            rid = row[0]
            macs = mac_map.get(rid, [])

            identities.append(
                {
                    "id": rid,
                    "macs": macs,
                    "mac_count": row[1],
                    "last_seen": row[2],
                    "first_seen": row[3],
                    "observation_count": row[4],
                    "fingerprint_hash": fp_map.get(rid),
                    "is_randomized": _is_randomized(macs),
                    "is_wifi6": wifi6_map.get(rid, False),
                    "confidence_score": 100 if fp_map.get(rid) else min(100, row[4] * 10),
                }
            )

        return {
            "identities": identities,
            "total": len(identities),
            "total_macs": total_macs,
            "total_fingerprints": len(fp_map),
            "compression_ratio": (total_macs / len(identities) if identities else 1.0),
        }

    try:
        return await state.run_db(_query)
    except Exception as exc:
        logger.error(f"API Devices error: {exc}")
        return {"error": str(exc), "identities": [], "total": 0}


# =============================================================================
# Bluetooth Data
# =============================================================================
@router.get("/api/devices/bluetooth")
async def api_list_bt_devices(limit: int = 100):
    """
    List Bluetooth devices and summary statistics.
    """
    limit = min(max(limit, 1), 500)

    def _query(conn):
        cursor = conn.cursor()

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        def _bt_fallback():
            protocol_expr = (
                "payload_protocol"
                if _col_exists("payload_protocol")
                else "CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8))"
            )
            bt_addr_expr = (
                "payload_bt_addr"
                if _col_exists("payload_bt_addr")
                else "CAST(JSON_VALUE(payload, '$.bt.addr') AS NVARCHAR(17))"
            )
            bt_rssi_expr = (
                "payload_bt_rssi"
                if _col_exists("payload_bt_rssi")
                else "TRY_CAST(JSON_VALUE(payload, '$.bt.rssi') AS INT)"
            )
            bt_name_expr = (
                "payload_bt_local_name"
                if _col_exists("payload_bt_local_name")
                else "CAST(JSON_VALUE(payload, '$.bt.local_name') AS NVARCHAR(128))"
            )
            vendor_expr = (
                "payload_vendor"
                if _col_exists("payload_vendor")
                else "CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100))"
            )

            bt_filter = f"{protocol_expr} = 'bt'"

            cursor.execute(
                f"SELECT COUNT(DISTINCT {bt_addr_expr}) FROM curated_events WHERE {bt_filter} AND {bt_addr_expr} IS NOT NULL"
            )
            total_devices = cursor.fetchone()[0]

            cursor.execute(
                f"SELECT COUNT(*) FROM curated_events WHERE {bt_filter}"
            )
            total_observations = cursor.fetchone()[0]

            cursor.execute(
                f"""
                SELECT COUNT(DISTINCT {bt_addr_expr})
                FROM curated_events
                WHERE {bt_filter}
                  AND inserted_at > DATEADD(minute, -5, GETDATE())
                  AND {bt_addr_expr} IS NOT NULL
                """
            )
            active_5m = cursor.fetchone()[0]

            cursor.execute(
                f"""
                SELECT COUNT(DISTINCT COALESCE({vendor_expr}, 'Unknown'))
                FROM curated_events
                WHERE {bt_filter}
                """
            )
            unique_vendors = cursor.fetchone()[0]

            cursor.execute(
                f"""
                SELECT TOP 10 COALESCE({vendor_expr}, 'Unknown') AS vendor, COUNT(*) AS cnt
                FROM curated_events
                WHERE {bt_filter}
                GROUP BY COALESCE({vendor_expr}, 'Unknown')
                ORDER BY cnt DESC
                """
            )
            top_vendors = [
                {"vendor": row[0], "count": row[1]}
                for row in cursor.fetchall()
            ]

            cursor.execute(
                f"""
                SELECT TOP {limit}
                    {bt_addr_expr} as addr,
                    MAX({vendor_expr}) as vendor,
                    MAX({bt_name_expr}) as local_name,
                    MAX({bt_rssi_expr}) as rssi_last,
                    COUNT(*) as observation_count,
                    MIN(inserted_at) as first_seen,
                    MAX(inserted_at) as last_seen
                FROM curated_events
                WHERE {bt_filter} AND {bt_addr_expr} IS NOT NULL
                GROUP BY {bt_addr_expr}
                ORDER BY MAX(inserted_at) DESC
                """
            )
            columns = [col[0] for col in cursor.description]
            devices = []
            for row in cursor.fetchall():
                d = dict(zip(columns, row, strict=False))
                if d.get("last_seen"):
                    d["last_seen"] = d["last_seen"].isoformat()
                if d.get("first_seen"):
                    d["first_seen"] = d["first_seen"].isoformat()
                sanitized_name = sanitize_bt_name(d.get("local_name"))
                insight = build_bt_device_insight(
                    vendor=d.get("vendor"),
                    local_name=sanitized_name,
                    addr_type=None,
                    observation_count=d.get("observation_count"),
                    known_service_count=0,
                    unknown_service_count=0,
                    has_manufacturer_hash=False,
                )
                behavior = build_bt_behavior_insight(
                    first_seen=row[5],
                    last_seen=row[6],
                    observation_count=d.get("observation_count"),
                    is_randomized=insight["is_randomized"],
                    timestamps=None,
                )
                devices.append(
                    {
                        "addr": d.get("addr"),
                        "vendor": d.get("vendor"),
                        "type": "BLE",
                        "name": sanitized_name,
                        "rssi_last": d.get("rssi_last") or -100,
                        "services": [],
                        "service_unknown_count": 0,
                        "last_seen": d.get("last_seen"),
                        "confidence_score": insight["score"],
                        "confidence_tier": insight["tier"],
                        "why_matters": insight["summary"],
                        "is_randomized": insight["is_randomized"],
                        "behavior_label": behavior["behavior_label"],
                        "behavior_summary": behavior["behavior_summary"],
                        "dwell_minutes": behavior["dwell_minutes"],
                        "observation_rate_per_hour": behavior["observation_rate_per_hour"],
                        "rotation_risk_score": behavior["rotation_risk_score"],
                        "interval_median_sec": behavior["interval_median_sec"],
                        "interval_jitter_sec": behavior["interval_jitter_sec"],
                        "manufacturer_data_hash": None,
                    }
                )

            annotate_rotation_clusters(devices)
            annotate_bt_recurrence(devices)
            for device in devices:
                device.pop("manufacturer_data_hash", None)

            return {
                "stats": {
                    "total_devices": total_devices,
                    "total_observations": total_observations,
                    "active_5m": active_5m,
                    "unique_vendors": unique_vendors,
                    "top_vendors": top_vendors,
                },
                "devices": devices,
            }

        # 1. Summary Stats
        stats = {}
        cursor.execute("SELECT CASE WHEN OBJECT_ID('bt_devices', 'U') IS NULL THEN 0 ELSE 1 END")
        if cursor.fetchone()[0] == 0:
            return _bt_fallback()

        cursor.execute("SELECT COUNT(*) FROM bt_devices")
        stats["total_devices"] = cursor.fetchone()[0]

        try:
            cursor.execute("SELECT COUNT(*) FROM bt_observations")
            stats["total_observations"] = cursor.fetchone()[0]
        except Exception:
            stats["total_observations"] = 0

        cursor.execute(
            "SELECT COUNT(*) FROM bt_devices WHERE last_seen > DATEADD(minute, -5, GETDATE())"
        )
        stats["active_5m"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT vendor) FROM bt_devices")
        stats["unique_vendors"] = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT TOP 10 COALESCE(vendor, 'Unknown') AS vendor, COUNT(*) AS cnt
            FROM bt_devices
            GROUP BY COALESCE(vendor, 'Unknown')
            ORDER BY cnt DESC
            """
        )
        stats["top_vendors"] = [
            {"vendor": row[0], "count": row[1]}
            for row in cursor.fetchall()
        ]

        # 2. Devices List
        query = (
            f"SELECT TOP {limit} "
            "addr, vendor, device_type, addr_type, first_seen, last_seen, "
            "rssi_avg, rssi_max, rssi_last, rssi_sample_count, services, local_name, manufacturer_data_hash "
            "FROM bt_devices "
            "ORDER BY last_seen DESC"
        )
        cursor.execute(query)
        columns = [col[0] for col in cursor.description]
        devices = []
        for row in cursor.fetchall():
            d = dict(zip(columns, row, strict=False))
            # Normalize timestamps
            if d.get("last_seen"):
                d["last_seen"] = d["last_seen"].isoformat()
            if d.get("first_seen"):
                d["first_seen"] = d["first_seen"].isoformat()
            # Normalize services (stored as JSON string)
            raw_services = []
            if d.get("services"):
                try:
                    parsed_services = json_compat.loads(d["services"])
                    raw_services = parsed_services if isinstance(parsed_services, list) else []
                except Exception:
                    raw_services = []

            known_services = format_bt_service_labels(raw_services)
            unknown_service_count = count_unknown_bt_services(raw_services)
            sanitized_name = sanitize_bt_name(d["local_name"])
            insight = build_bt_device_insight(
                vendor=d.get("vendor"),
                local_name=sanitized_name,
                addr_type=d.get("addr_type"),
                observation_count=d.get("rssi_sample_count"),
                known_service_count=len(known_services),
                unknown_service_count=unknown_service_count,
                has_manufacturer_hash=bool(d.get("manufacturer_data_hash")),
            )
            behavior = build_bt_behavior_insight(
                first_seen=row[4],
                last_seen=row[5],
                observation_count=d.get("rssi_sample_count"),
                is_randomized=insight["is_randomized"],
                timestamps=None,
            )
            devices.append({
                "addr": d["addr"],
                "vendor": d["vendor"],
                "type": d["device_type"],
                "name": sanitized_name,
                "rssi_last": d["rssi_last"] or -100,
                "services": known_services,
                "service_unknown_count": unknown_service_count,
                "last_seen": d["last_seen"],
                "confidence_score": insight["score"],
                "confidence_tier": insight["tier"],
                "why_matters": insight["summary"],
                "is_randomized": insight["is_randomized"],
                "behavior_label": behavior["behavior_label"],
                "behavior_summary": behavior["behavior_summary"],
                "dwell_minutes": behavior["dwell_minutes"],
                "observation_rate_per_hour": behavior["observation_rate_per_hour"],
                "rotation_risk_score": behavior["rotation_risk_score"],
                "interval_median_sec": behavior["interval_median_sec"],
                "interval_jitter_sec": behavior["interval_jitter_sec"],
                "manufacturer_data_hash": d.get("manufacturer_data_hash"),
            })
        annotate_rotation_clusters(devices)
        annotate_bt_recurrence(devices)
        for device in devices:
            device.pop("manufacturer_data_hash", None)
        if stats.get("total_devices", 0) == 0:
            return _bt_fallback()

        return {"stats": stats, "devices": devices}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        logger.error("Bluetooth device listing failed: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable for Bluetooth endpoint.") from exc


@router.get("/api/bluetooth/locations")
async def api_bt_locations(limit: int = 200):
    """
    Return BLE location estimates (triangulated) when available.
    """
    limit = min(max(limit, 1), 1000)

    def _query(conn):
        cursor = conn.cursor()
        cursor.execute("SELECT CASE WHEN OBJECT_ID('rf_location_estimates', 'U') IS NULL THEN 0 ELSE 1 END")
        if cursor.fetchone()[0] == 0:
            return {"locations": [], "total": 0}

        cursor.execute(
            """
            SELECT TOP (?) target_id, lat, lon, accuracy_m, sensor_count, sample_count,
                   window_start, window_end, algorithm, updated_at
            FROM rf_location_estimates
            WHERE protocol = 'bt'
            ORDER BY updated_at DESC
            """,
            (limit,),
        )

        locations = []
        for row in cursor.fetchall():
            window_start = row[6]
            window_end = row[7]
            updated_at = row[9]
            locations.append(
                {
                    "addr": row[0],
                    "lat": float(row[1]) if row[1] is not None else None,
                    "lon": float(row[2]) if row[2] is not None else None,
                    "accuracy_m": row[3],
                    "sensor_count": row[4],
                    "sample_count": row[5],
                    "window_start": window_start.timestamp() if window_start else None,
                    "window_end": window_end.timestamp() if window_end else None,
                    "algorithm": row[8],
                    "updated_at": updated_at.timestamp() if updated_at else None,
                }
            )

        return {"locations": locations, "total": len(locations)}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        logger.error(f"Bluetooth locations API error: {exc}")
        return {"error": str(exc), "locations": [], "total": 0}
# =============================================================================
# ML Insights: Pattern-of-Life & Correlations
# =============================================================================
_pol_cache = {"data": None, "expiry": 0}


@router.get("/api/insights/pol")
async def api_pol_insights():
    """
    Get Pattern-of-Life clustering insights for devices.
    Optimized to use SQL-side filtering and 5-minute caching.
    """
    now_ts = time.time()

    if _pol_cache["data"] and _pol_cache["expiry"] > now_ts:
        return _pol_cache["data"]

    def _query(conn):
        cursor = conn.cursor()

        # Get behavior data only for MACs with enough history (>=3 events)
        cursor.execute(
            """
            SELECT
                payload_keys_sa as mac,
                ts_epoch
            FROM curated_events
            WHERE payload_keys_sa IN (
                SELECT payload_keys_sa
                FROM curated_events
                WHERE event_type NOT IN ('telemetry_pulse', 'summary')
                GROUP BY payload_keys_sa
                HAVING COUNT(*) >= 3
            )
            AND event_type NOT IN ('telemetry_pulse', 'summary')
            AND ts_epoch IS NOT NULL
            ORDER BY payload_keys_sa, ts_epoch
        """
        )

        from collections import defaultdict
        from datetime import datetime

        mac_timestamps = defaultdict(list)
        for row in cursor.fetchall():
            mac, ts_epoch = row[0], row[1]
            if ts_epoch:
                try:
                    mac_timestamps[mac].append(datetime.fromtimestamp(float(ts_epoch)))
                except Exception:
                    pass

        if len(mac_timestamps) < 4:
            return {
                "clusters": {},
                "summary": {"message": "Insufficient active devices (need 4+)"},
                "silhouette_score": None,
            }

        try:
            from dataclasses import dataclass, field

            from nexus.intel.pol_analyzer import POLAnalyzer

            @dataclass
            class MockProfile:
                mac: str
                timestamp_history: list[datetime] = field(default_factory=list)
                probed_ssids: dict = field(default_factory=dict)

            profiles = {
                mac: MockProfile(mac=mac, timestamp_history=ts_list)
                for mac, ts_list in mac_timestamps.items()
            }

            analyzer = POLAnalyzer(n_clusters=min(4, len(profiles)))
            analyzer.fit(profiles)

            clusters = {}
            for mac, profile in analyzer.get_all_profiles().items():
                clusters[mac] = {"cluster": profile.cluster, "confidence": round(profile.confidence, 3)}

            result = {
                "clusters": clusters,
                "total_analyzed": len(profiles),
                "timestamp": now_ts,
            }
            return result
        except Exception as exc:
            logger.error(f"POL analysis failed: {exc}")
            return {"clusters": {}, "error": str(exc)}

    try:
        data = await state.run_db(_query)
        _pol_cache["data"] = data
        _pol_cache["expiry"] = now_ts + 300  # Cache for 5 minutes
        return data
    except Exception as exc:
        return {"error": str(exc), "clusters": {}}


@router.get("/api/insights/correlations")
async def api_correlation_insights(min_confidence: float = 0.6):
    """
    Get ML-powered correlation predictions for MAC address pairs.

    Uses a Decision Tree classifier to identify MAC addresses that likely
    belong to the same physical device based on behavioral signals.
    """
    # Correlations require Scavenger data which may not always be available
    # Return demo/empty data structure for now
    return {
        "correlations": [],
        "model_info": {
            "type": "decision_tree",
            "min_confidence": min_confidence,
            "message": "Run Scavenger analysis to populate correlations",
        },
    }


# =============================================================================
# WIDS: Security Alerts
# =============================================================================
@router.get("/api/alerts")
async def api_list_wids_alerts(
    include_acknowledged: bool = False,
    source: str = "all",
    limit: int = 100,
):
    """
    List WIDS (Wireless Intrusion Detection System) alerts.

    Returns security alerts from the attack_alerts table (or curated_events fallback).
    """

    def _query(conn):
        cursor = conn.cursor()
        alerts = []
        source_filter = (source or "all").lower()
        limit_value = max(1, min(int(limit or 100), 500))

        # Attack timeline (anomalies + offline detections)
        feedback_exists = False
        if source_filter in ("all", "anomaly", "ml"):
            try:
                cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_timeline'")
                if cursor.fetchone():
                    cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_feedback'")
                    feedback_exists = cursor.fetchone() is not None

                    if feedback_exists:
                        cursor.execute(
                            f"""
                            SELECT TOP {limit_value}
                                a.id,
                                a.attack_type,
                                a.severity,
                                a.confidence,
                                a.target_bssid,
                                a.target_ssid,
                                a.event_count,
                                a.description,
                                a.attacker_mac,
                                a.target_client,
                                DATEDIFF_BIG(MILLISECOND, '1970-01-01', a.start_time) / 1000.0 AS first_seen_epoch,
                                DATEDIFF_BIG(MILLISECOND, '1970-01-01', COALESCE(a.end_time, a.start_time)) / 1000.0 AS last_seen_epoch,
                                fb.label
                            FROM attack_timeline a
                            OUTER APPLY (
                                SELECT TOP 1 label
                                FROM attack_feedback
                                WHERE attack_id = a.id
                                ORDER BY inserted_at DESC
                            ) fb
                            ORDER BY a.start_time DESC
                            """
                        )
                    else:
                        cursor.execute(
                            f"""
                            SELECT TOP {limit_value}
                                id,
                                attack_type,
                                severity,
                                confidence,
                                target_bssid,
                                target_ssid,
                                event_count,
                                description,
                                attacker_mac,
                                target_client,
                                DATEDIFF_BIG(MILLISECOND, '1970-01-01', start_time) / 1000.0 AS first_seen_epoch,
                                DATEDIFF_BIG(MILLISECOND, '1970-01-01', COALESCE(end_time, start_time)) / 1000.0 AS last_seen_epoch
                            FROM attack_timeline
                            ORDER BY start_time DESC
                            """
                        )

                    for row in cursor.fetchall():
                        confidence = int(row[3]) if row[3] is not None else None
                        attack_type = row[1] or "anomaly"
                        title = attack_type.replace("_", " ").title()
                        if confidence is not None:
                            title = f"{title} ({confidence}%)"
                        first_seen = float(row[10]) if row[10] else None
                        last_seen = float(row[11]) if row[11] else None
                        alerts.append(
                            {
                                "id": f"atk-{row[0]}",
                                "alert_type": attack_type,
                                "severity": row[2],
                                "title": title,
                                "description": row[7],
                                "timestamp": last_seen,
                                "first_seen": first_seen,
                                "last_seen": last_seen,
                                "bssid": row[4],
                                "ssid": row[5],
                                "event_count": row[6],
                                "confidence": confidence,
                                "source_mac": row[8],
                                "target_mac": row[9],
                                "feedback_label": row[12] if feedback_exists else None,
                                "source": "attack_timeline",
                            }
                        )
            except Exception:
                pass

        # WIDS alerts from attack_alerts (preferred when present)
        wids_loaded = False
        if source_filter in ("all", "wids", "rules"):
            try:
                cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_alerts'")
                if cursor.fetchone():
                    ack_clause = "" if include_acknowledged else "WHERE acknowledged = 0"
                    cursor.execute(
                        f"""
                        SELECT TOP {limit_value}
                            alert_id,
                            alert_type,
                            severity,
                            title,
                            description,
                            ts_epoch,
                            first_seen,
                            last_seen,
                            source_mac,
                            target_mac,
                            bssid,
                            ssid,
                            channel,
                            event_count,
                            acknowledged,
                            acknowledged_at
                        FROM attack_alerts
                        {ack_clause}
                        ORDER BY ts_epoch DESC
                        """
                    )

                    for row in cursor.fetchall():
                        first_seen = row[6]
                        last_seen = row[7]
                        alerts.append(
                            {
                                "id": row[0],
                                "alert_type": row[1],
                                "severity": row[2],
                                "title": row[3],
                                "description": row[4],
                                "timestamp": float(row[5]) if row[5] else None,
                                "first_seen": first_seen.timestamp() if first_seen else None,
                                "last_seen": last_seen.timestamp() if last_seen else None,
                                "source_mac": row[8],
                                "target_mac": row[9],
                                "bssid": row[10],
                                "ssid": row[11],
                                "channel": row[12],
                                "event_count": row[13],
                                "acknowledged": bool(row[14]) if row[14] is not None else False,
                                "acknowledged_at": row[15].timestamp() if row[15] else None,
                                "source": "attack_alerts",
                            }
                        )
                    wids_loaded = True
            except Exception:
                wids_loaded = False

        # Fallback: WIDS events from curated_events
        if not wids_loaded and source_filter in ("all", "wids", "rules"):
            cursor.execute(
                f"""
                SELECT TOP {limit_value}
                    event_id,
                    event_type,
                    ts_epoch,
                    score,
                    payload_effective_bssid as bssid,
                    payload_effective_ssid as ssid,
                    payload_keys_sa as source_mac,
                    payload_keys_da as target_mac,
                    JSON_VALUE(payload, '$.channel') as channel
                FROM curated_events
                WHERE event_type LIKE 'wids_%'
                ORDER BY ts_epoch DESC
                """
            )

            for row in cursor.fetchall():
                event_type = row[1]
                alert_type = event_type.replace("wids_", "") if event_type else "unknown"
                alerts.append(
                    {
                        "id": row[0][:8] if row[0] else None,
                        "alert_type": alert_type,
                        "severity": row[3] // 10 if row[3] else 1,
                        "timestamp": row[2],
                        "bssid": row[4],
                        "ssid": row[5],
                        "source_mac": row[6],
                        "target_mac": row[7],
                        "channel": row[8],
                        "source": "curated_events",
                    }
                )

        alerts = apply_alert_policy(alerts)
        alerts.sort(key=lambda a: a.get("timestamp") or 0.0, reverse=True)
        alerts = alerts[:limit_value]
        return {"alerts": alerts, "total": len(alerts), "source": "mixed"}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc), "alerts": [], "total": 0}


@router.post("/api/alerts/ack", dependencies=[Depends(state._require_admin)])
async def api_acknowledge_alert(payload: AlertAcknowledge):
    """Acknowledge or reopen WIDS alerts."""

    def _query(conn):
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_alerts'")
        if not cursor.fetchone():
            raise RuntimeError("attack_alerts table is missing")

        acknowledged = 1 if payload.acknowledged else 0
        cursor.execute(
            """
            UPDATE attack_alerts
            SET acknowledged = ?,
                acknowledged_at = CASE WHEN ? = 1 THEN SYSDATETIME() ELSE NULL END
            WHERE alert_id = ?
            """,
            (acknowledged, acknowledged, payload.alert_id),
        )
        if cursor.rowcount == 0:
            raise RuntimeError("Alert not found")
        conn.commit()
        return {"status": "ok", "alert_id": payload.alert_id, "acknowledged": payload.acknowledged}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc), "status": "error"}


@router.post("/api/alerts/feedback", dependencies=[Depends(state._require_admin)])
async def api_alert_feedback(payload: AlertFeedback):
    """
    Persist operator feedback for attack_timeline alerts.
    """

    def _query(conn):
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_timeline'")
        if not cursor.fetchone():
            raise RuntimeError("attack_timeline table is missing")

        cursor.execute(
            """
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='attack_feedback' AND xtype='U')
            CREATE TABLE attack_feedback (
                id BIGINT IDENTITY PRIMARY KEY,
                attack_id BIGINT NOT NULL,
                label VARCHAR(16) NOT NULL,
                note NVARCHAR(256),
                analyst NVARCHAR(64),
                inserted_at DATETIME2 DEFAULT SYSDATETIME(),
                CONSTRAINT FK_attack_feedback_attack
                    FOREIGN KEY (attack_id) REFERENCES attack_timeline(id)
            )
            """
        )

        alert_id = payload.alert_id
        if not alert_id.startswith("atk-"):
            raise ValueError("Feedback is only supported for attack_timeline alerts")
        try:
            attack_id = int(alert_id.split("-", 1)[1])
        except ValueError as exc:
            raise ValueError("Invalid alert_id format") from exc

        cursor.execute(
            """
            INSERT INTO attack_feedback (attack_id, label, note)
            VALUES (?, ?, ?)
            """,
            (attack_id, payload.label, payload.note),
        )
        conn.commit()
        return {"status": "ok"}

    try:
        return await state.run_db(_query)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/alerts/metrics")
async def api_alert_metrics(since_hours: int = 24, attack_type: str = "anomaly_%", bssid: str = ""):
    """
    Return feedback metrics and calibration suggestions for anomaly alerts.
    """

    def _query(conn):
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_timeline'")
        if not cursor.fetchone():
            return {
                "attack_type": attack_type,
                "since_hours": since_hours,
                "total_anomalies": 0,
                "feedback": {"confirmed": 0, "benign": 0, "noisy": 0},
                "metrics": {},
            }

        attack_filter = "a.attack_type = ?"
        if "%" in attack_type:
            attack_filter = "a.attack_type LIKE ?"
        params = [attack_type]
        bssid_filter = ""
        if bssid:
            bssid_filter = " AND a.target_bssid = ?"
            params.append(bssid.lower())

        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM attack_timeline a
            WHERE {attack_filter}
            {bssid_filter}
            AND a.start_time >= DATEADD(hour, -?, SYSDATETIME())
            """,
            params + [since_hours],
        )
        total_anomalies = int(cursor.fetchone()[0] or 0)

        feedback_counts = {"confirmed": 0, "benign": 0, "noisy": 0}
        cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_feedback'")
        if cursor.fetchone():
            cursor.execute(
                f"""
                SELECT f.label, COUNT(*)
                FROM attack_feedback f
                JOIN attack_timeline a ON f.attack_id = a.id
                WHERE {attack_filter}
                {bssid_filter}
                AND a.start_time >= DATEADD(hour, -?, SYSDATETIME())
                GROUP BY f.label
                """,
                params + [since_hours],
            )
            for label, count in cursor.fetchall():
                if label:
                    feedback_counts[str(label).lower()] = int(count or 0)

        metrics = compute_metrics(total_anomalies, feedback_counts)
        current_threshold = float(os.getenv("WICAP_ANOMALY_SCORE_THRESHOLD", "70"))
        min_feedback = int(os.getenv("WICAP_ANOMALY_CALIBRATION_MIN_FEEDBACK", "10"))
        recommended, delta, reason = recommend_threshold(
            current_threshold,
            metrics,
            min_feedback=min_feedback,
        )

        return {
            "attack_type": attack_type,
            "bssid": bssid.lower() if bssid else None,
            "since_hours": since_hours,
            "total_anomalies": metrics.total_anomalies,
            "feedback": {
                "confirmed": metrics.confirmed,
                "benign": metrics.benign,
                "noisy": metrics.noisy,
                "total": metrics.feedback_total,
            },
            "metrics": {
                "precision": metrics.precision,
                "recall_proxy": metrics.recall_proxy,
                "coverage": metrics.coverage,
            },
            "calibration": {
                "current_threshold": current_threshold,
                "recommended_threshold": recommended,
                "threshold_delta": delta,
                "reason": reason,
                "min_feedback": min_feedback,
            },
        }

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/sensors")
async def api_list_sensors():
    """List distributed sensors from the registry."""

    def _query(conn):
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'sensor_registry'")
        if not cursor.fetchone():
            return {"sensors": [], "total": 0, "now_ts": time.time()}

        cursor.execute(
            """
            SELECT COUNT(*) FROM sys.columns
            WHERE object_id = OBJECT_ID('sensor_registry') AND name = 'events_received'
            """
        )
        has_events = cursor.fetchone()[0] > 0
        cursor.execute(
            """
            SELECT COUNT(*) FROM sys.columns
            WHERE object_id = OBJECT_ID('sensor_registry') AND name = 'last_event_at'
            """
        )
        has_last_event = cursor.fetchone()[0] > 0
        cursor.execute(
            """
            SELECT COUNT(*) FROM sys.columns
            WHERE object_id = OBJECT_ID('sensor_registry')
              AND name IN ('location_lat', 'location_lon')
            """
        )
        has_geo = cursor.fetchone()[0] == 2

        columns = [
            "sensor_id",
            "name",
            "interface",
            "location",
            "status",
            "connected_at",
            "last_heartbeat",
            "frames_received",
            "alerts_received",
            "frames_sent",
            "alerts_sent",
        ]
        if has_events:
            columns.append("events_received")
        if has_last_event:
            columns.append("last_event_at")
        if has_geo:
            columns.extend(["location_lat", "location_lon"])

        cursor.execute(
            f"""
            SELECT {', '.join(columns)}
            FROM sensor_registry
            ORDER BY last_heartbeat DESC
            """
        )
        sensors = []
        for row in cursor.fetchall():
            row_data = dict(zip(columns, row, strict=False))
            connected_at = row_data.get("connected_at")
            last_heartbeat = row_data.get("last_heartbeat")
            last_event_at = row_data.get("last_event_at")
            location_lat = row_data.get("location_lat")
            location_lon = row_data.get("location_lon")
            sensors.append(
                {
                    "sensor_id": row_data.get("sensor_id"),
                    "name": row_data.get("name"),
                    "interface": row_data.get("interface"),
                    "location": row_data.get("location"),
                    "status": row_data.get("status"),
                    "connected_at": connected_at.timestamp() if connected_at else None,
                    "last_heartbeat": last_heartbeat.timestamp() if last_heartbeat else None,
                    "frames_received": row_data.get("frames_received"),
                    "alerts_received": row_data.get("alerts_received"),
                    "frames_sent": row_data.get("frames_sent"),
                    "alerts_sent": row_data.get("alerts_sent"),
                    "events_received": int(row_data.get("events_received") or 0),
                    "last_event_at": last_event_at.timestamp() if last_event_at else None,
                    "location_lat": float(location_lat) if location_lat is not None else None,
                    "location_lon": float(location_lon) if location_lon is not None else None,
                }
            )
        return {"sensors": sensors, "total": len(sensors), "now_ts": time.time()}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc), "sensors": [], "total": 0, "now_ts": time.time()}


# =============================================================================
# Investigation Workflow
# =============================================================================
@router.get("/api/investigations")
async def api_list_investigations():
    """
    List all investigations.

    Investigations are created from WIDS alerts and contain:
    - Timeline of events
    - Related evidence (PCAPs)
    - Investigator notes
    """

    def _query(conn):
        cursor = conn.cursor()

        # Get WIDS alerts grouped by type to show investigation candidates
        cursor.execute(
            """
            SELECT
                event_type,
                COUNT(*) as alert_count,
                MAX(ts_epoch) as last_seen,
                MIN(ts_epoch) as first_seen
            FROM curated_events
            WHERE event_type LIKE 'wids_%'
            GROUP BY event_type
            ORDER BY last_seen DESC
        """
        )

        alert_summaries = []
        for row in cursor.fetchall():
            event_type = row[0]
            alert_type = event_type.replace("wids_", "") if event_type else "unknown"

            alert_summaries.append(
                {
                    "alert_type": alert_type,
                    "count": row[1],
                    "last_seen": row[2],
                    "first_seen": row[3],
                }
            )

        return {
            "investigations": [],  # Placeholder - full investigation state stored in memory
            "alert_summaries": alert_summaries,
            "total_alerts": sum(a["count"] for a in alert_summaries),
        }

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc), "investigations": [], "alert_summaries": []}


@router.post("/api/investigations")
async def api_create_investigation(request: Request):
    """Create a new investigation from an alert."""
    try:
        data = await request.json()
        return {
            "status": "ok",
            "message": "Investigation created",
            "investigation_id": data.get("alert_id", "new")[:8],
        }
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/action/export")
async def action_export_data(limit: int = 10000, offset: int = 0):
    # Export curated events as JSON download (paged to avoid OOM).
    max_limit = int(os.getenv("WICAP_EXPORT_MAX_ROWS", "100000"))
    limit = max(1, min(limit or 1, max_limit))
    offset = max(0, int(offset or 0))

    def _query(conn):
        cursor = conn.cursor()

        # Fetch all events, ordered by time
        query_export = (
            "SELECT "
            "event_id, "
            "inserted_at, "
            "event_type, "
            "channel, "
            "payload "
            "FROM curated_events "
            "ORDER BY inserted_at DESC "
            "OFFSET ? ROWS FETCH NEXT ? ROWS ONLY"
        )
        cursor.execute(query_export, (offset, limit))

        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()

        # Convert to list of dicts
        # We need to manually parse fields because payload is a JSON string
        export_data = []
        for row in rows:
            item = dict(zip(columns, row, strict=False))
            try:
                item["payload"] = json_compat.loads(item["payload"])
            except Exception:
                pass
            item["inserted_at"] = item["inserted_at"].isoformat() if item["inserted_at"] else None
            export_data.append(item)
        return export_data

    try:
        export_data = await state.run_db(_query)
        return JSONResponse(
            content=export_data,
            headers={
                "Content-Disposition": f"attachment; filename=wicap_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            },
        )
    except Exception as exc:
        return {"error": str(exc)}


# RSSI Distance Path Loss Model
# d = d0 * 10 ^ ((RSS(d0) - RSS) / 10n)
# n=2.5-3.0 for office/home with obstacles
def estimate_distance(rssi: int, n: float = 3.0, tx_calibrated: int = -40) -> float | None:
    if not rssi:
        return None
    try:
        # Clamp reasonable RSSI
        rssi = max(-100, min(-20, rssi))
        dist = 1.0 * (10 ** ((tx_calibrated - rssi) / (10 * n)))
        return round(dist, 1)
    except Exception:
        return None

@router.get("/api/map/topology")
async def api_map_topology(
    include_scavenger: bool = False,
    source: str = "live",
    build_identity_graph: bool = False,
):
    """Get network topology for visualization with optional Scavenger ghost nodes."""
    source = state._normalize_source(source)


    def _query(conn):
        cursor = conn.cursor()
        source_filter, params = state._source_filter_sql(source)

        nodes = {}
        edges = []
        live_macs = set()
        identity_cluster_map = {}
        identity_cluster_size = {}
        try:
            graph = None
            if build_identity_graph:
                graph = get_identity_graph(conn)
            else:
                graph = get_identity_graph_cached()
            if graph:
                for cluster in graph.clusters:
                    for member in cluster.members:
                        identity_cluster_map[member.lower()] = cluster.cluster_id
                        identity_cluster_size[member.lower()] = len(cluster.members)
        except Exception:
            pass

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        bssid_expr = (
            "payload_effective_bssid"
            if _col_exists("payload_effective_bssid")
            else "CAST(COALESCE(JSON_VALUE(payload, '$.keys.bssid'), JSON_VALUE(payload, '$.bssid')) AS NVARCHAR(17))"
        )
        ssid_expr = (
            "payload_effective_ssid"
            if _col_exists("payload_effective_ssid")
            else "CAST(COALESCE(JSON_VALUE(payload, '$.keys.ssid'), JSON_VALUE(payload, '$.ssid')) AS NVARCHAR(64))"
        )
        vendor_expr = (
            "payload_vendor"
            if _col_exists("payload_vendor")
            else "CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100))"
        )
        rssi_expr = (
            "payload_rssi_int"
            if _col_exists("payload_rssi_int")
            else "TRY_CAST(COALESCE(JSON_VALUE(payload, '$.keys.rssi_dbm'), JSON_VALUE(payload, '$.rssi')) AS INT)"
        )
        protocol_expr = (
            "payload_protocol"
            if _col_exists("payload_protocol")
            else "CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8))"
        )
        sa_expr = (
            "payload_keys_sa"
            if _col_exists("payload_keys_sa")
            else "CAST(JSON_VALUE(payload, '$.keys.sa') AS NVARCHAR(17))"
        )
        da_expr = (
            "payload_keys_da"
            if _col_exists("payload_keys_da")
            else "CAST(JSON_VALUE(payload, '$.keys.da') AS NVARCHAR(17))"
        )

        # Helper: Clean SSID
        def clean_ssid(value):
            if not value or value == "None" or value == "":
                return "Hidden"
            return value

        # 1. Get APs & Build SSID Map
        ssid_map = {}

        # 1. Get APs & Build SSID Map
        ssid_map = {}

        # 1. Get APs & Build SSID Map
        ssid_map = {}

        # R1: Use security_posture for authoritative security info
        # M7: Get connected client counts (approximate from recent events)
        query_map = f"""
            WITH ConnectedCounts AS (
                SELECT bssid, COUNT(DISTINCT client_mac) as client_count
                FROM client_associations
                WHERE last_seen > DATEADD(hour, -24, GETDATE())
                GROUP BY bssid
            )
            SELECT DISTINCT
                {bssid_expr} as mac,
                {ssid_expr} as ssid,
                {vendor_expr} as vendor,
                ce.channel,
                {rssi_expr} as rssi,
                sp.is_open,
                sp.has_wpa3,
                sp.has_wpa2,
                sp.has_wpa,
                COALESCE(cc.client_count, 0) as client_count
            FROM curated_events ce
            LEFT JOIN security_posture sp ON {bssid_expr} = sp.bssid
            LEFT JOIN ConnectedCounts cc ON {bssid_expr} = cc.bssid
            WHERE ce.event_type IN ('new_bssid', 'open_network', 'strong_rssi', 'new_ssid', 'hidden_ssid')
              AND ce.inserted_at > DATEADD(mi, -60, GETDATE())
              AND ({protocol_expr} IS NULL OR {protocol_expr} <> 'bt')
              AND {source_filter.replace('event_type', 'ce.event_type')}
        """

        cursor.execute(query_map, params)
        for row in cursor.fetchall():
            mac = row[0]
            if not mac:
                continue
            if mac.lower() == "ff:ff:ff:ff:ff:ff":
                continue
            if mac in nodes:
                continue
            live_macs.add(mac.lower())

            ssid = clean_ssid(row[1])
            vendor = row[2] or ""
            is_open = row[5]  # From bit/bool column
            has_wpa3 = row[6]
            has_wpa2 = row[7]
            client_count = row[9]

            security_label = "WPA/WEP"  # Default fallback
            security_color = "#d29922"  # Orange

            if is_open:
                security_label = "Open"
                security_color = "#da3633"  # Red
            elif has_wpa3:
                security_label = "WPA3"
                security_color = "#3fb950"  # Green
            elif has_wpa2:
                security_label = "WPA2"
                security_color = "#58a6ff"  # Blue

            if ssid != "Hidden":
                ssid_map.setdefault(ssid, []).append(mac)

            nodes[mac] = {
                "id": mac,
                "label": ssid if ssid != "Hidden" else mac[-5:],
                "group": "ap",
                "vendor": vendor,
                "channel": row[3],
                "rssi": row[4],
                "distance": estimate_distance(row[4]),
                "security": security_label,
                "security_color": security_color,
                "client_count": client_count,
                "identity_cluster_id": identity_cluster_map.get(mac.lower()),
                "identity_cluster_size": identity_cluster_size.get(mac.lower(), 1),
                "title": f"BSSID: {mac}\nSSID: {ssid}\nVendor: {vendor}\nCh: {row[3]}\nRSSI: {row[4]}\nSecurity: {security_label}\nClients: {client_count}",
                "value": 25 + (min(client_count, 20) * 2),  # Grow node with more clients
                "mass": 3,
                "borderWidth": 4,
                "color": {
                    "border": security_color,
                    "background": "#ffffff" # Map background is dark, white text/icon contrast
                }
            }

        # 2. Get Edges (Active Associations + Probes + Deauths)

        # R2: Confirmed associations from client_associations
        # Still get probes/deauths from events stream
        query = (
            "SELECT "
            f"{sa_expr} as sa, "
            f"{da_expr} as da, "
            f"{bssid_expr} as bssid, "
            f"{ssid_expr} as target_ssid, "
            f"{vendor_expr} as vendor, "
            "ce.event_type, "
            f"{rssi_expr} as rssi, "
            "cp.device_type "
            "FROM curated_events ce "
            f"LEFT JOIN client_profiles cp ON {sa_expr} = cp.mac_addr "
            "WHERE ce.event_type IN ('probe_directed', 'deauth', 'deauth_spike') "
            f"AND {sa_expr} IS NOT NULL "
            "AND ce.inserted_at > DATEADD(minute, -60, GETDATE()) "
            f"AND ({protocol_expr} IS NULL OR {protocol_expr} <> 'bt') "
            f"AND {source_filter.replace('event_type', 'ce.event_type')} "
            "UNION ALL "
            "SELECT "
            "ca.client_mac as sa, "
            "ca.bssid as da, "
            "ca.bssid as bssid, "
            "ca.ssid as target_ssid, "
            "cp.vendor, "
            "'association' as event_type, "
            "cp.rssi_last as rssi, "
            "cp.device_type "
            "FROM client_associations ca "
            "LEFT JOIN client_profiles cp ON ca.client_mac = cp.mac_addr "
            "WHERE ca.last_seen > DATEADD(hour, -1, GETDATE())"
        )

        cursor.execute(query, params)
        processed_edges = set()

        for row in cursor.fetchall():
            client = row[0]
            dst = row[1]
            bssid = row[2]
            target_ssid = clean_ssid(row[3])
            vendor = row[4] or ""
            etype = row[5]
            rssi = row[6]
            device_type = row[7]

            if not client:
                continue
            if client.lower() == "ff:ff:ff:ff:ff:ff":
                continue

            live_macs.add(client.lower())

            if client not in nodes:
                group = "client"
                label = client[-5:]
                title_parts = [f"MAC: {client}", f"Vendor: {vendor}", f"RSSI: {rssi}"]
                if device_type:
                    title_parts.insert(1, f"Type: {device_type}")
                title = "\n".join(title_parts)

                if bssid and client == bssid:
                    group = "ap"
                    label = client[-5:]
                    title = f"BSSID: {client}\nVendor: {vendor}\nRSSI: {rssi}"
                nodes[client] = {
                    "id": client,
                    "label": label,
                    "group": group,
                    "vendor": vendor,
                    "device_type": device_type,
                    "rssi": rssi,
                    "distance": estimate_distance(rssi),
                    "identity_cluster_id": identity_cluster_map.get(client.lower()),
                    "identity_cluster_size": identity_cluster_size.get(client.lower(), 1),
                    "title": title,
                    "value": 10 if group == "client" else 20,
                    "mass": 1 if group == "client" else 3,
                }

            final_target_id = None
            is_probe = etype == "probe_directed"
            is_deauth = etype in ("deauth", "deauth_spike")
            is_association = etype == "association"

            target_mac = None
            if is_deauth:
                if dst and dst.lower() != "ff:ff:ff:ff:ff:ff":
                    target_mac = dst
                elif bssid and bssid.lower() != "ff:ff:ff:ff:ff:ff":
                    target_mac = bssid
            else:
                if bssid and bssid.lower() != "ff:ff:ff:ff:ff:ff":
                    target_mac = bssid
                elif dst and dst.lower() != "ff:ff:ff:ff:ff:ff":
                    target_mac = dst

            if target_mac:
                if target_mac in nodes:
                    final_target_id = target_mac
                else:
                    target_group = "client"
                    if bssid and target_mac == bssid:
                        target_group = "ap"
                    nodes[target_mac] = {
                        "id": target_mac,
                        "label": target_mac[-5:],
                        "group": target_group,
                        "vendor": "",
                        "title": f"MAC: {target_mac}",
                        "value": 10 if target_group == "client" else 20,
                        "mass": 1 if target_group == "client" else 3,
                    }
                    final_target_id = target_mac
            elif is_probe and target_ssid and target_ssid != "Hidden":
                if target_ssid in ssid_map:
                    final_target_id = ssid_map[target_ssid][0]
                else:
                    synth_id = f"ssid|{target_ssid}"
                    if synth_id not in nodes:
                        nodes[synth_id] = {
                            "id": synth_id,
                            "label": target_ssid,
                            "group": "ap",
                            "vendor": "",
                            "title": f"SSID: {target_ssid}\n(Observed probe)",
                            "value": 18,
                            "mass": 2,
                        }
                    final_target_id = synth_id

            if final_target_id and final_target_id != client:
                edge_key = f"{client}|{final_target_id}|{etype}"
                if edge_key in processed_edges:
                    continue
                processed_edges.add(edge_key)

                # Edge styling based on event type
                edge_color = "#3fb950"  # Default: green (association)
                edge_width = 2
                edge_dashes = False

                if is_deauth:
                    edge_color = "#da3633"  # Red for attacks
                    edge_width = 3 if etype == "deauth_spike" else 2
                elif is_probe:
                    edge_color = "#d29922"  # Yellow for probes
                    edge_dashes = True
                    edge_width = 1
                elif is_association:
                    # Solid green for active confirmed associations
                    edge_color = "#3fb950"
                    edge_dashes = False
                    # Width based on RSSI strength
                    if rssi:
                        if rssi > -50:
                            edge_width = 4  # Strong signal
                        elif rssi > -70:
                            edge_width = 2  # Medium signal
                        else:
                            edge_width = 1  # Weak signal

                edges.append(
                    {
                        "from": client,
                        "to": final_target_id,
                        "arrows": "to",
                        "color": {"color": edge_color},
                        "width": edge_width,
                        "dashes": edge_dashes,
                        "title": f"{etype}" + (f" ({rssi} dBm)" if rssi and is_association else ""),
                    }
                )

        # 2.5 BLE Overlay (Optional if BLE data exists)
        try:
            cursor.execute("SELECT CASE WHEN OBJECT_ID('bt_devices', 'U') IS NULL THEN 0 ELSE 1 END")
            bt_tables_present = cursor.fetchone()[0] == 1
        except Exception:
            bt_tables_present = False

        try:
            if bt_tables_present:
                cursor.execute(
                    """
                    SELECT TOP 200
                        addr,
                        vendor,
                        local_name,
                        rssi_last,
                        last_seen
                    FROM bt_devices
                    WHERE last_seen > DATEADD(minute, -60, GETDATE())
                    ORDER BY last_seen DESC
                    """
                )
                bt_rows = cursor.fetchall()
            else:
                bt_addr_expr = (
                    "payload_bt_addr"
                    if _col_exists("payload_bt_addr")
                    else "CAST(JSON_VALUE(payload, '$.bt.addr') AS NVARCHAR(17))"
                )
                bt_rssi_expr = (
                    "payload_bt_rssi"
                    if _col_exists("payload_bt_rssi")
                    else "TRY_CAST(JSON_VALUE(payload, '$.bt.rssi') AS INT)"
                )
                bt_name_expr = (
                    "payload_bt_local_name"
                    if _col_exists("payload_bt_local_name")
                    else "CAST(JSON_VALUE(payload, '$.bt.local_name') AS NVARCHAR(128))"
                )
                cursor.execute(
                    f"""
                    SELECT TOP 200
                        {bt_addr_expr} as addr,
                        MAX({vendor_expr}) as vendor,
                        MAX({bt_name_expr}) as local_name,
                        MAX({bt_rssi_expr}) as rssi_last,
                        MAX(inserted_at) as last_seen
                    FROM curated_events
                    WHERE {protocol_expr} = 'bt'
                      AND {bt_addr_expr} IS NOT NULL
                      AND inserted_at > DATEADD(minute, -60, GETDATE())
                    GROUP BY {bt_addr_expr}
                    ORDER BY MAX(inserted_at) DESC
                    """
                )
                bt_rows = cursor.fetchall()

            for row in bt_rows:
                addr = row[0]
                if not addr:
                    continue
                node_id = f"bt|{addr}"
                if node_id in nodes:
                    continue
                vendor = row[1] or ""
                local_name = sanitize_bt_name(row[2]) or ""
                rssi = row[3]
                label = local_name if local_name else addr[-5:]
                title = f"BLE: {addr}"
                if local_name:
                    title += f"\nName: {local_name}"
                if vendor:
                    title += f"\nVendor: {vendor}"
                if rssi is not None:
                    title += f"\nRSSI: {rssi}"

                nodes[node_id] = {
                    "id": node_id,
                    "mac": addr,
                    "label": label,
                    "group": "ble",
                    "vendor": vendor,
                    "device_type": "ble",
                    "rssi": rssi,
                    "distance": estimate_distance(rssi) if rssi is not None else None,
                    "title": title,
                    "value": 10,
                    "mass": 1,
                }
        except Exception:
            pass

        # 3. Scavenger Ghosts (Optional)
        if include_scavenger:
            try:
                cursor.execute(
                    """
                    SELECT mac_addr, vendor, probed_ssids, last_seen
                    FROM client_profiles
                    WHERE last_seen > DATEADD(day, -7, GETDATE())
                """
                )
                for row in cursor.fetchall():
                    mac = row[0]
                    if not mac or mac.lower() in live_macs:
                        continue
                    if mac in nodes:
                        continue

                    vendor = row[1] or ""

                    nodes[mac] = {
                        "id": mac,
                        "label": f"👻 {mac[-5:]}",
                        "group": "ghost",
                        "vendor": vendor,
                        "title": f"MAC: {mac}\nVendor: {vendor}\n(Historical)",
                        "value": 8,
                        "ghost": True,
                    }
            except Exception:
                pass

        return {"nodes": list(nodes.values()), "edges": edges}

    try:
        return await state.run_db(_query)
    except Exception as exc:
        return {"error": str(exc), "nodes": [], "edges": []}


@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    # WebSocket for live event streaming.
    denial_reason = state._validate_websocket_access(websocket)
    if denial_reason:
        await websocket.close(code=1008, reason=denial_reason)
        return
    await state.manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        state.manager.disconnect(websocket)
