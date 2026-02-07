from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

import app.services.scavenger as scavenger_service
import app.services.state as state
from app.schemas import MACAddress, RecentEventsQuery
from app.services.bluetooth_behavior import build_bt_behavior_insight
from app.services.bluetooth_insights import build_bt_device_insight
from app.services.bluetooth_rotation import annotate_rotation_clusters
from app.services.bluetooth_text import count_unknown_bt_services, format_bt_service_labels, sanitize_bt_name
from app.services.bluetooth_timeline import build_bt_timeline_overlay
from nexus.utils import json_compat

router = APIRouter()


@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(state.STATIC_DIR / "favicon.ico")


async def _render_dashboard(request: Request, source: str) -> HTMLResponse:
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        stats = {}
        where_clause, params = state._source_filter_sql(source)

        # Get summary stats
        cursor.execute(f"SELECT COUNT(*) FROM curated_events WHERE {where_clause}", params)
        stats["total_events"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM handshakes WHERE hashcat_hash IS NOT NULL")
        stats["total_handshakes"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM handshakes WHERE crack_status = 'cracked'")
        stats["cracked"] = cursor.fetchone()[0]

        cursor.execute(
            f"SELECT TOP 1 inserted_at FROM curated_events WHERE {where_clause} ORDER BY inserted_at DESC",
            params,
        )
        row = cursor.fetchone()
        stats["last_event"] = row[0] if row else None
        return stats

    try:
        stats = await state.run_db(_query)
    except Exception as exc:
        stats = {"error": str(exc)}

    return state.templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "stats": stats,
            "now": datetime.now(),
            "data_source": source,
        },
    )


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Main dashboard page (live data).
    return await _render_dashboard(request, source="live")


@router.get("/replay", response_class=HTMLResponse)
async def replay_dashboard(request: Request):
    # Replay-only dashboard.
    return await _render_dashboard(request, source="replay")


@router.get("/styleguide", response_class=HTMLResponse)
async def page_styleguide(request: Request):
    return state.templates.TemplateResponse("style_guide.html", {"request": request})


@router.get("/telemetry", response_class=HTMLResponse)
async def page_telemetry(request: Request):
    return state.templates.TemplateResponse("telemetry.html", {"request": request})


@router.get("/handshakes", response_class=HTMLResponse)
async def handshakes(request: Request):
    # Handshakes page.
    def _query(conn):
        cursor = conn.cursor()
        query_handshakes = (
            "SELECT TOP 50 id, ssid, bssid, client_mac, handshake_type, "
            "crack_status, priority_score, capture_time "
            "FROM handshakes "
            "ORDER BY capture_time DESC"
        )
        cursor.execute(query_handshakes)
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]

    try:
        handshakes = await state.run_db(_query)
    except Exception:
        handshakes = []

    return state.templates.TemplateResponse(
        "handshakes.html",
        {
            "request": request,
            "handshakes": handshakes,
        },
    )


@router.get("/networks", response_class=HTMLResponse)
async def networks(request: Request, source: str = "live"):
    # Discovered networks page.
    source = state._normalize_source(source)

    def _query(conn):
        cursor = conn.cursor()
        where_clause, params = state._source_filter_sql(source)
        query_networks = (
            "SELECT TOP 100 "
            "payload_effective_ssid as ssid, "
            "payload_effective_bssid as bssid, "
            "channel, "
            "payload_rssi_int as rssi, "
            "payload_vendor as vendor, "
            "payload_encryption as security_info, "
            "MAX(inserted_at) as last_seen "
            "FROM curated_events "
            f"WHERE {where_clause} AND ("
            "event_type IN ('new_bssid', 'open_network', 'strong_rssi', 'new_ssid', 'hidden_ssid')"
            ") "
            "GROUP BY "
            "payload_effective_ssid, "
            "payload_effective_bssid, "
            "channel, "
            "payload_rssi_int, "
            "payload_vendor, "
            "payload_encryption "
            "HAVING payload_effective_bssid IS NOT NULL "
            "ORDER BY MAX(inserted_at) DESC"
        )
        cursor.execute(query_networks, params)
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]

    try:
        networks = await state.run_db(_query)
    except Exception:
        networks = []

    return state.templates.TemplateResponse(
        "networks.html",
        {
            "request": request,
            "networks": networks,
            "data_source": source,
        },
    )


@router.get("/map", response_class=HTMLResponse)
async def map_view(request: Request):
    # Network topology map.
    return state.templates.TemplateResponse(
        "map.html",
        {
            "request": request,
        },
    )


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Security alerts page - WIDS intrusion detection alerts."""
    return state.templates.TemplateResponse(
        "alerts.html",
        {
            "request": request,
        },
    )


@router.get("/sensors", response_class=HTMLResponse)
async def sensors_page(request: Request):
    """Distributed sensor status page."""
    return state.templates.TemplateResponse(
        "sensors.html",
        {
            "request": request,
        },
    )


@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request):
    """Identity Intelligence - Device fingerprints and MAC groupings."""
    return state.templates.TemplateResponse(
        "devices.html",
        {
            "request": request,
        },
    )


@router.get("/bluetooth", response_class=HTMLResponse)
async def bluetooth_page(request: Request):
    """Bluetooth Intelligence page."""
    return state.templates.TemplateResponse(
        "bluetooth.html",
        {
            "request": request,
        },
    )


@router.get("/bluetooth/{addr}", response_class=HTMLResponse)
async def bluetooth_device_detail(request: Request, addr: str):
    """Bluetooth device dossier."""
    # Validate BLE address (MAC format)
    try:
        validated_addr = MACAddress.validate(addr)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid BLE address: {exc}") from exc

    def _query(conn):
        cursor = conn.cursor()

        def _col_exists(name: str) -> bool:
            cursor.execute("SELECT COL_LENGTH('curated_events', ?)", (name,))
            return cursor.fetchone()[0] is not None

        # Determine if BT tables exist
        try:
            cursor.execute("SELECT CASE WHEN OBJECT_ID('bt_devices', 'U') IS NULL THEN 0 ELSE 1 END")
            has_bt_tables = cursor.fetchone()[0] == 1
        except Exception:
            has_bt_tables = False

        metadata = {
            "addr": validated_addr,
            "vendor": "Unknown",
            "local_name": None,
            "addr_type": None,
            "first_seen": None,
            "last_seen": None,
            "total_observations": 0,
            "rssi_avg": None,
            "rssi_max": None,
            "rssi_last": None,
            "rssi_sample_count": 0,
            "rssi_last_seen": None,
            "services": [],
            "service_unknown_count": 0,
            "manufacturer_data_hash": None,
            "confidence_score": 0,
            "confidence_tier": "low",
            "why_matters": "Low confidence: waiting for enough BLE data to classify this device.",
            "is_randomized": False,
            "confidence_highlights": [],
            "behavior_label": "sparse",
            "behavior_summary": "Not enough BLE activity yet to characterize device behavior.",
            "dwell_minutes": 0.0,
            "observation_rate_per_hour": 0.0,
            "rotation_risk_score": 0,
            "interval_median_sec": None,
            "interval_jitter_sec": None,
            "rotation_cluster_size": 1,
            "rotation_peer_count": 0,
            "rotation_suspected": False,
            "rotation_correlation_score": 0,
            "rotation_summary": "No correlated alternate BLE addresses detected in the current analysis window.",
            "rotation_related": [],
            "recurrence_label": "sparse",
            "recurrence_score": 0,
            "recurrence_summary": "Not enough cadence data for recurrence analysis yet.",
            "recurrence_handoff_count": 0,
            "recurrence_peer_presence_ratio": 0.0,
            "timeline_bucket_minutes": 15,
            "timeline_window_minutes": 180,
            "timeline_buckets": [],
            "timeline_anomalies": [],
        }

        observations = []
        connections = []
        alerts = []

        if has_bt_tables:
            cursor.execute(
                """
                SELECT TOP 1
                    addr,
                    vendor,
                    addr_type,
                    local_name,
                    first_seen,
                    last_seen,
                    rssi_avg,
                    rssi_max,
                    rssi_last,
                    rssi_sample_count,
                    rssi_last_seen,
                    services,
                    manufacturer_data_hash
                FROM bt_devices
                WHERE addr = ?
                """,
                (validated_addr,),
            )
            row = cursor.fetchone()
            if row:
                metadata.update(
                    {
                        "addr": row[0],
                        "vendor": row[1] or "Unknown",
                        "addr_type": row[2],
                        "local_name": sanitize_bt_name(row[3]),
                        "first_seen": row[4],
                        "last_seen": row[5],
                        "rssi_avg": row[6],
                        "rssi_max": row[7],
                        "rssi_last": row[8],
                        "rssi_sample_count": row[9] or 0,
                        "rssi_last_seen": row[10],
                        "manufacturer_data_hash": row[12],
                    }
                )
                if row[11]:
                    try:
                        parsed_services = json_compat.loads(row[11])
                        parsed_services = parsed_services if isinstance(parsed_services, list) else []
                        metadata["services"] = format_bt_service_labels(parsed_services)
                        metadata["service_unknown_count"] = count_unknown_bt_services(parsed_services)
                    except Exception:
                        metadata["services"] = []
                        metadata["service_unknown_count"] = 0

            cursor.execute(
                """
                SELECT TOP 200
                    ts_epoch,
                    rssi,
                    channel,
                    adv_type,
                    local_name
                FROM bt_observations
                WHERE addr = ?
                ORDER BY ts_epoch DESC
                """,
                (validated_addr,),
            )
            for ts_epoch, rssi, channel, adv_type, local_name in cursor.fetchall():
                ts_dt = None
                try:
                    ts_dt = datetime.fromtimestamp(float(ts_epoch))
                except Exception:
                    ts_dt = None
                observations.append(
                    {
                        "timestamp": ts_dt,
                        "rssi": rssi,
                        "channel": channel,
                        "adv_type": adv_type,
                        "local_name": sanitize_bt_name(local_name),
                    }
                )

            cursor.execute(
                """
                SELECT TOP 50 peer_addr, access_address, first_seen, last_seen
                FROM bt_connections
                WHERE addr = ?
                ORDER BY last_seen DESC
                """,
                (validated_addr,),
            )
            connections = [
                dict(zip([c[0] for c in cursor.description], row, strict=False))
                for row in cursor.fetchall()
            ]
            if not metadata["total_observations"]:
                metadata["total_observations"] = len(observations)

            cursor.execute(
                """
                SELECT TOP 25 alert_type, severity, title, description, ts_epoch, first_seen, last_seen
                FROM attack_alerts
                WHERE source_mac = ? AND alert_type LIKE 'ble_%'
                ORDER BY last_seen DESC
                """,
                (validated_addr,),
            )
            alerts = [
                dict(zip([c[0] for c in cursor.description], row, strict=False))
                for row in cursor.fetchall()
            ]
        else:
            # Fallback to curated_events when BT tables are missing
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

            cursor.execute(
                f"""
                SELECT
                    MIN(inserted_at),
                    MAX(inserted_at),
                    COUNT(*),
                    AVG(CAST({bt_rssi_expr} AS FLOAT)),
                    MAX({bt_rssi_expr})
                FROM curated_events
                WHERE {protocol_expr} = 'bt' AND {bt_addr_expr} = ?
                """,
                (validated_addr,),
            )
            row = cursor.fetchone()
            if row:
                metadata["first_seen"] = row[0]
                metadata["last_seen"] = row[1]
                metadata["total_observations"] = row[2] or 0
                metadata["rssi_avg"] = int(row[3]) if row[3] is not None else None
                metadata["rssi_max"] = row[4]

            cursor.execute(
                f"""
                SELECT TOP 1
                    {vendor_expr} as vendor,
                    {bt_name_expr} as local_name,
                    {bt_rssi_expr} as rssi_last,
                    inserted_at
                FROM curated_events
                WHERE {protocol_expr} = 'bt' AND {bt_addr_expr} = ?
                ORDER BY inserted_at DESC
                """,
                (validated_addr,),
            )
            last_row = cursor.fetchone()
            if last_row:
                metadata["vendor"] = last_row[0] or metadata["vendor"]
                metadata["local_name"] = sanitize_bt_name(last_row[1]) or metadata["local_name"]
                metadata["rssi_last"] = last_row[2]
                metadata["rssi_last_seen"] = last_row[3]

            cursor.execute(
                f"""
                SELECT TOP 200
                    inserted_at,
                    event_type,
                    channel,
                    {bt_rssi_expr} as rssi,
                    payload
                FROM curated_events
                WHERE {protocol_expr} = 'bt' AND {bt_addr_expr} = ?
                ORDER BY inserted_at DESC
                """,
                (validated_addr,),
            )
            services = set()
            for inserted_at, event_type, channel, rssi, payload in cursor.fetchall():
                bt = {}
                try:
                    parsed = json_compat.loads(payload) if payload else {}
                    bt = parsed.get("bt", {}) if isinstance(parsed, dict) else {}
                except Exception:
                    bt = {}
                adv_type = bt.get("adv_type") or event_type
                local_name = bt.get("local_name")
                if not metadata.get("manufacturer_data_hash"):
                    metadata["manufacturer_data_hash"] = bt.get("manufacturer_data_hash")
                for svc in bt.get("service_uuids") or []:
                    services.add(svc)
                observations.append(
                    {
                        "timestamp": inserted_at,
                        "rssi": rssi,
                        "channel": channel,
                        "adv_type": adv_type,
                        "local_name": sanitize_bt_name(local_name),
                    }
                )
            sorted_services = sorted(services)
            metadata["services"] = format_bt_service_labels(sorted_services)
            metadata["service_unknown_count"] = count_unknown_bt_services(sorted_services)
            metadata["rssi_sample_count"] = len([o for o in observations if o.get("rssi") is not None])

        insight = build_bt_device_insight(
            vendor=metadata.get("vendor"),
            local_name=metadata.get("local_name"),
            addr_type=metadata.get("addr_type"),
            observation_count=metadata.get("total_observations") or metadata.get("rssi_sample_count"),
            known_service_count=len(metadata.get("services") or []),
            unknown_service_count=metadata.get("service_unknown_count") or 0,
            has_manufacturer_hash=bool(metadata.get("manufacturer_data_hash")),
        )
        metadata["confidence_score"] = insight["score"]
        metadata["confidence_tier"] = insight["tier"]
        metadata["why_matters"] = insight["summary"]
        metadata["is_randomized"] = insight["is_randomized"]
        metadata["confidence_highlights"] = insight["highlights"]

        behavior = build_bt_behavior_insight(
            first_seen=metadata.get("first_seen"),
            last_seen=metadata.get("last_seen"),
            observation_count=metadata.get("total_observations") or metadata.get("rssi_sample_count"),
            is_randomized=insight["is_randomized"],
            timestamps=[o.get("timestamp") for o in observations if o.get("timestamp")],
        )
        metadata["behavior_label"] = behavior["behavior_label"]
        metadata["behavior_summary"] = behavior["behavior_summary"]
        metadata["dwell_minutes"] = behavior["dwell_minutes"]
        metadata["observation_rate_per_hour"] = behavior["observation_rate_per_hour"]
        metadata["rotation_risk_score"] = behavior["rotation_risk_score"]
        metadata["interval_median_sec"] = behavior["interval_median_sec"]
        metadata["interval_jitter_sec"] = behavior["interval_jitter_sec"]

        rotation_related: list[dict[str, object]] = []
        related_seen: set[str] = set()
        if has_bt_tables:
            if metadata.get("manufacturer_data_hash"):
                cursor.execute(
                    """
                    SELECT TOP 12
                        addr,
                        vendor,
                        addr_type,
                        local_name,
                        last_seen,
                        rssi_last,
                        services,
                        manufacturer_data_hash
                    FROM bt_devices
                    WHERE addr <> ?
                      AND manufacturer_data_hash = ?
                    ORDER BY last_seen DESC
                    """,
                    (validated_addr, metadata["manufacturer_data_hash"]),
                )
                for row in cursor.fetchall():
                    addr = row[0]
                    if not addr or addr in related_seen:
                        continue
                    related_seen.add(addr)
                    services = []
                    if row[6]:
                        try:
                            parsed_services = json_compat.loads(row[6])
                            parsed_services = parsed_services if isinstance(parsed_services, list) else []
                            services = format_bt_service_labels(parsed_services)
                        except Exception:
                            services = []
                    rotation_related.append(
                        {
                            "addr": addr,
                            "vendor": row[1] or "Unknown",
                            "addr_type": row[2],
                            "name": sanitize_bt_name(row[3]),
                            "last_seen": row[4],
                            "rssi_last": row[5],
                            "services": services,
                            "manufacturer_data_hash": row[7],
                        }
                    )

            if len(rotation_related) < 12 and metadata.get("vendor") and metadata.get("local_name"):
                cursor.execute(
                    """
                    SELECT TOP 12
                        addr,
                        vendor,
                        addr_type,
                        local_name,
                        last_seen,
                        rssi_last,
                        services,
                        manufacturer_data_hash
                    FROM bt_devices
                    WHERE addr <> ?
                      AND COALESCE(vendor, 'Unknown') = COALESCE(?, 'Unknown')
                      AND local_name = ?
                    ORDER BY last_seen DESC
                    """,
                    (validated_addr, metadata.get("vendor"), metadata.get("local_name")),
                )
                for row in cursor.fetchall():
                    addr = row[0]
                    if not addr or addr in related_seen:
                        continue
                    related_seen.add(addr)
                    services = []
                    if row[6]:
                        try:
                            parsed_services = json_compat.loads(row[6])
                            parsed_services = parsed_services if isinstance(parsed_services, list) else []
                            services = format_bt_service_labels(parsed_services)
                        except Exception:
                            services = []
                    rotation_related.append(
                        {
                            "addr": addr,
                            "vendor": row[1] or "Unknown",
                            "addr_type": row[2],
                            "name": sanitize_bt_name(row[3]),
                            "last_seen": row[4],
                            "rssi_last": row[5],
                            "services": services,
                            "manufacturer_data_hash": row[7],
                        }
                    )
        elif metadata.get("vendor") and metadata.get("local_name"):
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
            cursor.execute(
                f"""
                SELECT TOP 8
                    {bt_addr_expr} as addr,
                    MAX({vendor_expr}) as vendor,
                    MAX({bt_name_expr}) as local_name,
                    MAX(inserted_at) as last_seen,
                    MAX(CAST({bt_rssi_expr} AS INT)) as rssi_last
                FROM curated_events
                WHERE {protocol_expr} = 'bt'
                  AND {bt_addr_expr} IS NOT NULL
                  AND {bt_addr_expr} <> ?
                  AND COALESCE({vendor_expr}, 'Unknown') = COALESCE(?, 'Unknown')
                  AND {bt_name_expr} = ?
                GROUP BY {bt_addr_expr}
                ORDER BY MAX(inserted_at) DESC
                """,
                (validated_addr, metadata.get("vendor"), metadata.get("local_name")),
            )
            for addr, vendor, local_name, last_seen, rssi_last in cursor.fetchall():
                if not addr or addr in related_seen:
                    continue
                related_seen.add(addr)
                rotation_related.append(
                    {
                        "addr": addr,
                        "vendor": vendor or "Unknown",
                        "addr_type": None,
                        "name": sanitize_bt_name(local_name),
                        "last_seen": last_seen,
                        "rssi_last": rssi_last,
                        "services": [],
                        "manufacturer_data_hash": None,
                    }
                )

        candidates = [
            {
                "addr": metadata.get("addr"),
                "vendor": metadata.get("vendor"),
                "name": metadata.get("local_name"),
                "services": metadata.get("services"),
                "manufacturer_data_hash": metadata.get("manufacturer_data_hash"),
                "is_randomized": metadata.get("is_randomized"),
                "confidence_score": metadata.get("confidence_score"),
            }
        ]
        candidates.extend(
            {
                "addr": related.get("addr"),
                "vendor": related.get("vendor"),
                "name": related.get("name"),
                "services": related.get("services"),
                "manufacturer_data_hash": related.get("manufacturer_data_hash"),
                "is_randomized": bool(related.get("addr_type") and "random" in str(related.get("addr_type")).lower()),
                "confidence_score": metadata.get("confidence_score"),
            }
            for related in rotation_related
        )
        annotate_rotation_clusters(candidates)
        current_rotation = next((item for item in candidates if item.get("addr") == metadata.get("addr")), None)
        if current_rotation:
            metadata["rotation_cluster_size"] = current_rotation.get("rotation_cluster_size", 1)
            metadata["rotation_peer_count"] = current_rotation.get("rotation_peer_count", 0)
            metadata["rotation_suspected"] = bool(current_rotation.get("rotation_suspected"))
            metadata["rotation_correlation_score"] = current_rotation.get("rotation_correlation_score", 0)
            metadata["rotation_summary"] = current_rotation.get("rotation_summary")

        candidate_map = {item.get("addr"): item for item in candidates if item.get("addr")}
        for related in rotation_related:
            annotated = candidate_map.get(related.get("addr")) or {}
            related["rotation_suspected"] = bool(annotated.get("rotation_suspected"))
            related["rotation_correlation_score"] = annotated.get("rotation_correlation_score", 0)
            related["manufacturer_data_hash"] = None
        metadata["rotation_related"] = rotation_related

        primary_timestamps = [
            ts
            for ts in (obs.get("timestamp") for obs in observations)
            if isinstance(ts, datetime)
        ]
        peer_timestamps: dict[str, list[datetime]] = {}
        if has_bt_tables and rotation_related:
            related_addrs = [
                str(item.get("addr"))
                for item in rotation_related
                if item.get("addr")
            ][:12]
            if related_addrs:
                placeholders = ", ".join("?" for _ in related_addrs)
                cursor.execute(
                    f"""
                    SELECT TOP 1500 addr, ts_epoch
                    FROM bt_observations
                    WHERE addr IN ({placeholders})
                      AND ts_epoch IS NOT NULL
                    ORDER BY ts_epoch DESC
                    """,
                    tuple(related_addrs),
                )
                for related_addr, ts_epoch in cursor.fetchall():
                    try:
                        ts_dt = datetime.fromtimestamp(float(ts_epoch))
                    except Exception:
                        ts_dt = None
                    if not ts_dt:
                        continue
                    peer_timestamps.setdefault(related_addr, []).append(ts_dt)

        timeline = build_bt_timeline_overlay(
            primary_addr=validated_addr,
            primary_timestamps=primary_timestamps,
            peer_timestamps=peer_timestamps,
            window_minutes=180,
            bucket_minutes=15,
        )
        metadata["timeline_bucket_minutes"] = timeline["bucket_minutes"]
        metadata["timeline_window_minutes"] = timeline["window_minutes"]
        metadata["timeline_buckets"] = timeline["timeline_buckets"]
        metadata["timeline_anomalies"] = timeline["timeline_anomalies"]
        metadata["recurrence_label"] = timeline["recurrence_label"]
        metadata["recurrence_score"] = timeline["recurrence_score"]
        metadata["recurrence_summary"] = timeline["recurrence_summary"]
        metadata["recurrence_handoff_count"] = timeline["recurrence_handoff_count"]
        metadata["recurrence_peer_presence_ratio"] = timeline["recurrence_peer_presence_ratio"]

        if not alerts:
            try:
                cursor.execute(
                    """
                    SELECT TOP 25 alert_type, severity, title, description, ts_epoch, first_seen, last_seen
                    FROM attack_alerts
                    WHERE source_mac = ? AND alert_type LIKE 'ble_%'
                    ORDER BY last_seen DESC
                    """,
                    (validated_addr,),
                )
                alerts = [
                    dict(zip([c[0] for c in cursor.description], row, strict=False))
                    for row in cursor.fetchall()
                ]
            except Exception:
                alerts = []

        return metadata, observations, connections, alerts

    try:
        metadata, observations, connections, alerts = await state.run_db(_query)
        return state.templates.TemplateResponse(
            "bluetooth_device.html",
            {
                "request": request,
                "device": metadata,
                "observations": observations,
                "connections": connections,
                "alerts": alerts,
            },
        )
    except Exception as exc:
        fallback = {
            "addr": validated_addr,
            "vendor": "Unknown",
            "local_name": None,
            "addr_type": None,
            "first_seen": None,
            "last_seen": None,
            "total_observations": 0,
            "rssi_avg": None,
            "rssi_max": None,
            "rssi_last": None,
            "rssi_sample_count": 0,
            "rssi_last_seen": None,
            "services": [],
            "service_unknown_count": 0,
            "manufacturer_data_hash": None,
            "confidence_score": 0,
            "confidence_tier": "low",
            "why_matters": "Low confidence: waiting for enough BLE data to classify this device.",
            "is_randomized": False,
            "confidence_highlights": [],
            "behavior_label": "sparse",
            "behavior_summary": "Not enough BLE activity yet to characterize device behavior.",
            "dwell_minutes": 0.0,
            "observation_rate_per_hour": 0.0,
            "rotation_risk_score": 0,
            "interval_median_sec": None,
            "interval_jitter_sec": None,
            "rotation_cluster_size": 1,
            "rotation_peer_count": 0,
            "rotation_suspected": False,
            "rotation_correlation_score": 0,
            "rotation_summary": "No correlated alternate BLE addresses detected in the current analysis window.",
            "rotation_related": [],
            "recurrence_label": "sparse",
            "recurrence_score": 0,
            "recurrence_summary": "Not enough cadence data for recurrence analysis yet.",
            "recurrence_handoff_count": 0,
            "recurrence_peer_presence_ratio": 0.0,
            "timeline_bucket_minutes": 15,
            "timeline_window_minutes": 180,
            "timeline_buckets": [],
            "timeline_anomalies": [],
        }
        return state.templates.TemplateResponse(
            "bluetooth_device.html",
            {
                "request": request,
                "device": fallback,
                "observations": [],
                "connections": [],
                "alerts": [],
                "error": str(exc),
            },
        )


@router.get("/device/{mac}", response_class=HTMLResponse)
async def device_detail(request: Request, mac: str):
    # Device deep dive page.
    # Validate MAC address
    try:
        validated_mac = MACAddress.validate(mac)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid MAC address: {exc}") from exc

    def _query(conn):
        cursor = conn.cursor()

        # 1. Device Metadata (Vendor, First/Last Seen)
        query_meta = (
            "SELECT TOP 1 "
            "payload_vendor as vendor, "
            "MIN(inserted_at) as first_seen, "
            "MAX(inserted_at) as last_seen, "
            "COUNT(*) as total_events "
            "FROM curated_events "
            "WHERE payload_keys_sa = ? OR payload_keys_da = ? "
            "GROUP BY payload_vendor"
        )
        cursor.execute(query_meta, (validated_mac, validated_mac))
        row = cursor.fetchone()

        metadata = {
            "mac": mac,
            "vendor": row[0] if row else "Unknown",
            "first_seen": row[1] if row else None,
            "last_seen": row[2] if row else None,
            "total_events": row[3] if row else 0,
            "rssi_avg": None,
            "rssi_max": None,
            "rssi_last": None,
            "rssi_sample_count": 0,
            "rssi_last_seen": None,
        }

        # 1b. RSSI aggregates (from client_profiles)
        try:
            cursor.execute(
                "SELECT rssi_avg, rssi_max, rssi_last, rssi_sample_count, rssi_last_seen "
                "FROM client_profiles WHERE mac_addr = ?",
                (validated_mac,),
            )
            rssi_row = cursor.fetchone()
            if rssi_row:
                metadata["rssi_avg"] = rssi_row[0]
                metadata["rssi_max"] = rssi_row[1]
                metadata["rssi_last"] = rssi_row[2]
                metadata["rssi_sample_count"] = rssi_row[3] or 0
                metadata["rssi_last_seen"] = rssi_row[4]
        except Exception:
            pass

        # 2. Probe Requests (Networks this device is looking for)
        query_probes = (
            "SELECT DISTINCT payload_keys_ssid as ssid "
            "FROM curated_events "
            "WHERE payload_keys_sa = ? "
            "AND event_type = 'probe_directed' "
            "AND payload_keys_ssid IS NOT NULL"
        )
        cursor.execute(query_probes, (mac,))
        probes = [r[0] for r in cursor.fetchall()]

        # 3. Observed Targets (BSSIDs seen in recent frames)
        query_targets = (
            "SELECT DISTINCT "
            "COALESCE(payload_keys_bssid, payload_keys_da) as bssid "
            "FROM curated_events "
            "WHERE payload_keys_sa = ? "
            "AND COALESCE(payload_keys_bssid, payload_keys_da) IS NOT NULL "
            "AND COALESCE(payload_keys_bssid, payload_keys_da) != 'ff:ff:ff:ff:ff:ff' "
            "AND event_type != 'telemetry_pulse'"
        )
        cursor.execute(query_targets, (validated_mac,))
        targets = [r[0] for r in cursor.fetchall()]

        # 4. Association History (client_associations)
        associations = []
        try:
            query_assoc = (
                "SELECT bssid, ssid, first_seen, last_seen, association_count "
                "FROM client_associations WHERE client_mac = ? "
                "ORDER BY last_seen DESC"
            )
            cursor.execute(query_assoc, (validated_mac,))
            columns = [col[0] for col in cursor.description]
            associations = [dict(zip(columns, r, strict=False)) for r in cursor.fetchall()]
        except Exception:
            associations = []

        # 5. Recent Activity (for sparkline/log)
        query_activity = (
            "SELECT TOP 50 inserted_at, event_type, channel, "
            "payload_rssi_int as rssi "
            "FROM curated_events "
            "WHERE payload_keys_sa = ? OR payload_keys_da = ? "
            "ORDER BY inserted_at DESC"
        )
        cursor.execute(query_activity, (validated_mac, validated_mac))
        activity = [dict(zip([c[0] for c in cursor.description], r, strict=False)) for r in cursor.fetchall()]

        return metadata, probes, targets, associations, activity

    try:
        metadata, probes, targets, associations, activity = await state.run_db(_query)
        return state.templates.TemplateResponse(
            "device.html",
            {
                "request": request,
                "device": metadata,
                "probes": probes,
                "targets": targets,
                "associations": associations,
                "activity": activity,
            },
        )
    except Exception as exc:
        return state.templates.TemplateResponse("error.html", {"request": request, "error": str(exc)})


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return state.templates.TemplateResponse("admin.html", {"request": request})


@router.get("/scavenger", response_class=HTMLResponse)
async def scavenger_page(request: Request):
    """Scavenger forensic intelligence page."""
    # Get capture stats
    capture_count = 0
    capture_size = "0 MB"
    clients_found = 0

    capture_dir = Path("/app/captures")
    if capture_dir.exists():
        files = list(capture_dir.glob("*.pcap*")) + list(capture_dir.glob("*.cap"))
        capture_count = len(files)
        total_bytes = sum(f.stat().st_size for f in files if f.is_file())
        if total_bytes > 1024 * 1024 * 1024:
            capture_size = f"{total_bytes / (1024**3):.1f} GB"
        else:
            capture_size = f"{total_bytes / (1024**2):.1f} MB"

    # Get client count from last run
    if scavenger_service.scavenger_state.results and "findings" in scavenger_service.scavenger_state.results:
        clients_found = scavenger_service.scavenger_state.results["findings"].get("unique_clients", 0)

    return state.templates.TemplateResponse(
        "scavenger.html",
        {
            "request": request,
            "capture_count": capture_count,
            "capture_size": capture_size,
            "clients_found": clients_found,
        },
    )


# =============================================================================
# HTMX Partials
# =============================================================================
@router.get("/partials/stats", response_class=HTMLResponse)
async def partial_stats(request: Request, source: str = "live"):
    # HTMX partial for stats update.
    from app.routes import api as api_routes

    stats = await api_routes.api_stats(source=source)
    return state.templates.TemplateResponse(
        "partials/stats.html",
        {
            "request": request,
            "stats": stats,
        },
    )


@router.get("/partials/events", response_class=HTMLResponse)
async def partial_events(request: Request, source: str = "live"):
    # HTMX partial for live event feed.
    from app.routes import api as api_routes

    result = await api_routes.api_recent_events(RecentEventsQuery(limit=10, source=source))
    return state.templates.TemplateResponse(
        "partials/events.html",
        {
            "request": request,
            "events": result.get("events", []),
        },
    )
