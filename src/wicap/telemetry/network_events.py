"""WiCAP event contract normalization and compatibility exports."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

EVENT_CONTRACT_VERSION = "wicap.event.v1"
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _first_non_empty_str(*values: object) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _to_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_iso_utc(ts: object, ts_epoch: object) -> str:
    text = _first_non_empty_str(ts)
    if text:
        normalized = text.replace(" ", "T")
        if normalized.endswith("Z"):
            return normalized
        if "+" in normalized or normalized.endswith("00:00"):
            return normalized
        return normalized + "Z"

    epoch = _to_float(ts_epoch)
    if epoch is not None:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _severity_from_event(event: Mapping[str, Any]) -> str:
    explicit = _first_non_empty_str(event.get("severity"))
    if explicit:
        lowered = explicit.lower()
        if lowered in _ALLOWED_SEVERITIES:
            return lowered

    score = _to_float(event.get("score"))
    if score is None:
        score = 0.0
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def _infer_source(event: Mapping[str, Any]) -> str:
    explicit = _first_non_empty_str(event.get("source"))
    if explicit:
        lowered = explicit.lower()
        if lowered in {"wifi", "ble", "service", "runtime", "network"}:
            return lowered

    protocol = _first_non_empty_str(event.get("protocol"), event.get("proto"))
    lowered_protocol = (protocol or "").lower()
    if lowered_protocol in {"bt", "ble", "bluetooth"}:
        return "ble"
    if lowered_protocol in {"wifi", "802.11", "wlan"}:
        return "wifi"
    return "runtime"


def _infer_category(event: Mapping[str, Any]) -> str:
    category = _first_non_empty_str(event.get("interest_category"), event.get("category"))
    if category:
        return category.lower()
    anomaly_flags = event.get("anomaly_flags")
    if isinstance(anomaly_flags, list) and anomaly_flags:
        return "network_anomaly"
    event_type = _first_non_empty_str(event.get("event_type"))
    if event_type:
        return event_type.lower()
    return "runtime_event"


def _build_signature(event: Mapping[str, Any]) -> str:
    keys = event.get("keys")
    payload = event.get("payload")
    keys_map = keys if isinstance(keys, dict) else {}
    payload_map = payload if isinstance(payload, dict) else {}
    parts = [
        _first_non_empty_str(event.get("event_type")),
        _first_non_empty_str(keys_map.get("bssid"), payload_map.get("effective_bssid")),
        _first_non_empty_str(keys_map.get("ssid"), payload_map.get("effective_ssid")),
        _first_non_empty_str(keys_map.get("sa"), payload_map.get("keys_sa")),
        _first_non_empty_str(keys_map.get("da"), payload_map.get("keys_da")),
    ]
    normalized = [part for part in parts if part]
    if not normalized:
        return "wicap-event"
    return "|".join(normalized)[:240]


def _derive_community_id(
    *,
    src_ip: str,
    src_port: int | None,
    dest_ip: str,
    dest_port: int | None,
    proto: str,
) -> str:
    # Canonicalize endpoints so both flow directions map to one key.
    left = (str(src_ip), int(src_port or 0))
    right = (str(dest_ip), int(dest_port or 0))
    ordered = sorted((left, right), key=lambda item: (item[0], item[1]))
    key = f"{ordered[0][0]}:{ordered[0][1]}|{ordered[1][0]}:{ordered[1][1]}|{proto.lower()}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:20]
    return f"wicap:{digest}"


def _extract_flow(event: Mapping[str, Any]) -> dict[str, Any] | None:
    keys = event.get("keys")
    payload = event.get("payload")
    keys_map = keys if isinstance(keys, dict) else {}
    payload_map = payload if isinstance(payload, dict) else {}

    src_ip = _first_non_empty_str(
        event.get("src_ip"),
        payload_map.get("src_ip"),
        payload_map.get("source_ip"),
        keys_map.get("sa_ip"),
    )
    dest_ip = _first_non_empty_str(
        event.get("dest_ip"),
        payload_map.get("dest_ip"),
        payload_map.get("destination_ip"),
        keys_map.get("da_ip"),
    )
    proto = _first_non_empty_str(
        event.get("proto"),
        event.get("protocol"),
        payload_map.get("proto"),
        payload_map.get("protocol"),
    )
    if not (src_ip and dest_ip and proto):
        return None

    src_port = _to_int(_first_non_empty_str(event.get("src_port"), payload_map.get("src_port")))
    dest_port = _to_int(_first_non_empty_str(event.get("dest_port"), payload_map.get("dest_port")))
    duration_seconds = _to_float(
        _first_non_empty_str(event.get("duration_seconds"), event.get("duration"), payload_map.get("duration"))
    )
    bytes_total = _to_int(_first_non_empty_str(event.get("bytes"), payload_map.get("bytes")))
    packets_total = _to_int(_first_non_empty_str(event.get("packets"), payload_map.get("packets")))
    service = _first_non_empty_str(event.get("service"), payload_map.get("service"), event.get("event_type"))
    community_id = _first_non_empty_str(
        event.get("community_id"),
        payload_map.get("community_id"),
    ) or _derive_community_id(
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        proto=proto,
    )

    flow: dict[str, Any] = {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "proto": proto.lower(),
        "community_id": community_id,
    }
    if src_port is not None:
        flow["src_port"] = src_port
    if dest_port is not None:
        flow["dest_port"] = dest_port
    if duration_seconds is not None:
        flow["duration_seconds"] = duration_seconds
    if bytes_total is not None:
        flow["bytes"] = bytes_total
    if packets_total is not None:
        flow["packets"] = packets_total
    if service:
        flow["service"] = service
    return flow


def normalize_wicap_event(
    event: Mapping[str, Any],
    *,
    sensor_id: str = "wicap-local",
    evidence_path: str | None = None,
    evidence_offset: int | None = None,
) -> dict[str, Any]:
    """Normalize one WiCAP event into the `wicap.event.v1` envelope."""
    payload = dict(event)
    normalized: dict[str, Any] = {
        "event_contract_version": EVENT_CONTRACT_VERSION,
        "ts": _to_iso_utc(payload.get("ts"), payload.get("ts_epoch")),
        "source": _infer_source(payload),
        "category": _infer_category(payload),
        "signature": _build_signature(payload),
        "severity": _severity_from_event(payload),
        "sensor_id": _first_non_empty_str(payload.get("sensor_id"), sensor_id) or "wicap-local",
        "evidence_ref": {
            "kind": "curated_events_jsonl",
            "path": _first_non_empty_str(payload.get("dwell_file"), evidence_path) or "",
        },
    }
    if evidence_offset is not None:
        normalized["evidence_ref"]["offset"] = int(evidence_offset)

    flow = _extract_flow(payload)
    if flow is not None:
        normalized["flow"] = flow
    return normalized


def to_zeek_conn_record(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """Convert normalized event into a Zeek conn-compatible JSON object."""
    flow = event.get("flow")
    if not isinstance(flow, dict):
        return None

    src_ip = _first_non_empty_str(flow.get("src_ip"))
    dest_ip = _first_non_empty_str(flow.get("dest_ip"))
    proto = _first_non_empty_str(flow.get("proto"))
    if not (src_ip and dest_ip and proto):
        return None

    src_port = _to_int(flow.get("src_port")) or 0
    dest_port = _to_int(flow.get("dest_port")) or 0
    ts_text = _first_non_empty_str(event.get("ts")) or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ts_epoch = datetime.fromisoformat(ts_text.replace("Z", "+00:00")).timestamp()
    community_id = _first_non_empty_str(flow.get("community_id")) or _derive_community_id(
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        proto=proto,
    )
    uid = hashlib.sha1(community_id.encode("utf-8")).hexdigest()[:18]

    return {
        "ts": ts_epoch,
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": src_port,
        "id.resp_h": dest_ip,
        "id.resp_p": dest_port,
        "proto": proto,
        "service": _first_non_empty_str(flow.get("service")) or "-",
        "duration": _to_float(flow.get("duration_seconds")),
        "orig_bytes": _to_int(flow.get("bytes")),
        "resp_bytes": None,
        "orig_pkts": _to_int(flow.get("packets")),
        "resp_pkts": None,
        "community_id": community_id,
    }


def to_suricata_eve_record(event: Mapping[str, Any]) -> dict[str, Any]:
    """Convert normalized event into a Suricata EVE-like JSON object."""
    flow = event.get("flow")
    flow_map = flow if isinstance(flow, dict) else {}
    severity = _first_non_empty_str(event.get("severity")) or "info"
    severity_map = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    category = _first_non_empty_str(event.get("category")) or "runtime_event"
    event_type = "flow"
    if "anomaly" in category or severity in {"high", "critical"}:
        event_type = "alert"

    payload: dict[str, Any] = {
        "timestamp": _first_non_empty_str(event.get("ts"))
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_type": event_type,
    }

    src_ip = _first_non_empty_str(flow_map.get("src_ip"))
    dest_ip = _first_non_empty_str(flow_map.get("dest_ip"))
    proto = _first_non_empty_str(flow_map.get("proto"))
    if src_ip:
        payload["src_ip"] = src_ip
    if dest_ip:
        payload["dest_ip"] = dest_ip
    if proto:
        payload["proto"] = proto
    src_port = _to_int(flow_map.get("src_port"))
    dest_port = _to_int(flow_map.get("dest_port"))
    if src_port is not None:
        payload["src_port"] = src_port
    if dest_port is not None:
        payload["dest_port"] = dest_port

    if event_type == "alert":
        payload["alert"] = {
            "signature": _first_non_empty_str(event.get("signature")) or "wicap-alert",
            "severity": int(severity_map.get(severity, 1)),
            "category": category,
        }

    if flow_map:
        payload["flow"] = {
            "bytes_toclient": _to_int(flow_map.get("bytes")),
            "pkts_toclient": _to_int(flow_map.get("packets")),
            "start": _first_non_empty_str(event.get("ts")),
        }
    return payload


def export_network_events(
    input_path: Path,
    output_path: Path,
    *,
    sensor_id: str = "wicap-local",
    conn_output_path: Path | None = None,
    eve_output_path: Path | None = None,
) -> dict[str, int]:
    """Export normalized WiCAP events (and optional conn/EVE views) from JSONL input."""
    input_file = Path(input_path)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    if conn_output_path is not None:
        conn_output_path.parent.mkdir(parents=True, exist_ok=True)
    if eve_output_path is not None:
        eve_output_path.parent.mkdir(parents=True, exist_ok=True)

    processed = 0
    exported = 0
    skipped = 0
    conn_rows = 0
    eve_rows = 0

    with input_file.open("r", encoding="utf-8", errors="replace") as source, output_file.open(
        "w",
        encoding="utf-8",
    ) as out_handle:
        conn_handle = (
            conn_output_path.open("w", encoding="utf-8")
            if conn_output_path is not None
            else None
        )
        eve_handle = (
            eve_output_path.open("w", encoding="utf-8")
            if eve_output_path is not None
            else None
        )
        try:
            for line_number, raw_line in enumerate(source, start=1):
                text = raw_line.strip()
                if not text:
                    continue
                processed += 1
                try:
                    raw_event = json.loads(text)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                if not isinstance(raw_event, dict):
                    skipped += 1
                    continue

                normalized = normalize_wicap_event(
                    raw_event,
                    sensor_id=sensor_id,
                    evidence_path=str(input_file),
                    evidence_offset=line_number,
                )
                out_handle.write(json.dumps(normalized, sort_keys=True) + "\n")
                exported += 1

                if conn_handle is not None:
                    conn_record = to_zeek_conn_record(normalized)
                    if conn_record is not None:
                        conn_handle.write(json.dumps(conn_record, sort_keys=True) + "\n")
                        conn_rows += 1

                if eve_handle is not None:
                    eve_record = to_suricata_eve_record(normalized)
                    eve_handle.write(json.dumps(eve_record, sort_keys=True) + "\n")
                    eve_rows += 1
        finally:
            if conn_handle is not None:
                conn_handle.close()
            if eve_handle is not None:
                eve_handle.close()

    return {
        "processed": int(processed),
        "exported": int(exported),
        "skipped": int(skipped),
        "conn_rows": int(conn_rows),
        "eve_rows": int(eve_rows),
    }
