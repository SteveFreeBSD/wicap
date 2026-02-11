from __future__ import annotations

import json
from pathlib import Path

from src.wicap.telemetry.network_events import (
    EVENT_CONTRACT_VERSION,
    export_network_events,
    normalize_wicap_event,
    to_suricata_eve_record,
    to_zeek_conn_record,
)


def _sample_event(
    *,
    src_ip: str = "10.0.0.10",
    dest_ip: str = "10.0.0.20",
    src_port: int = 5353,
    dest_port: int = 53,
) -> dict[str, object]:
    return {
        "ts_epoch": 1768800000.0,
        "event_type": "deauth",
        "protocol": "wifi",
        "interest_category": "wids_alert",
        "score": 82,
        "keys": {
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "lab-net",
            "sa": "11:22:33:44:55:66",
            "da": "77:88:99:aa:bb:cc",
            "sa_ip": src_ip,
            "da_ip": dest_ip,
        },
        "payload": {
            "src_port": src_port,
            "dest_port": dest_port,
            "bytes": 2400,
            "packets": 11,
            "service": "dns",
        },
    }


def test_normalize_wicap_event_emits_required_contract_fields() -> None:
    normalized = normalize_wicap_event(
        _sample_event(),
        sensor_id="sensor-a",
        evidence_path="/tmp/curated.jsonl",
        evidence_offset=7,
    )
    required = {
        "event_contract_version",
        "ts",
        "source",
        "category",
        "signature",
        "severity",
        "sensor_id",
        "evidence_ref",
    }
    assert required.issubset(set(normalized.keys()))
    assert normalized["event_contract_version"] == EVENT_CONTRACT_VERSION
    assert normalized["sensor_id"] == "sensor-a"
    assert normalized["evidence_ref"]["path"] == "/tmp/curated.jsonl"
    assert int(normalized["evidence_ref"]["offset"]) == 7
    flow = normalized["flow"]
    assert flow["src_ip"] == "10.0.0.10"
    assert flow["dest_ip"] == "10.0.0.20"
    assert flow["proto"] == "wifi"
    assert str(flow["community_id"]).startswith("wicap:")


def test_community_id_is_stable_for_bidirectional_flow() -> None:
    forward = normalize_wicap_event(
        _sample_event(src_ip="192.168.1.10", dest_ip="192.168.1.20", src_port=5353, dest_port=53)
    )
    reverse = normalize_wicap_event(
        _sample_event(src_ip="192.168.1.20", dest_ip="192.168.1.10", src_port=53, dest_port=5353)
    )
    assert forward["flow"]["community_id"] == reverse["flow"]["community_id"]


def test_export_network_events_writes_contract_conn_and_eve_outputs(tmp_path: Path) -> None:
    input_path = tmp_path / "curated_events.jsonl"
    output_path = tmp_path / "wicap_network_events.jsonl"
    conn_path = tmp_path / "zeek_conn_compat.jsonl"
    eve_path = tmp_path / "suricata_eve_compat.jsonl"
    input_path.write_text(
        "\n".join(
            [
                json.dumps(_sample_event()),
                json.dumps({"ts_epoch": 1768800002.0, "event_type": "telemetry_pulse", "protocol": "runtime"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    summary = export_network_events(
        input_path=input_path,
        output_path=output_path,
        sensor_id="sensor-z",
        conn_output_path=conn_path,
        eve_output_path=eve_path,
    )
    assert int(summary["processed"]) == 2
    assert int(summary["exported"]) == 2
    assert output_path.exists()
    assert conn_path.exists()
    assert eve_path.exists()

    first_normalized = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert first_normalized["event_contract_version"] == EVENT_CONTRACT_VERSION
    assert first_normalized["sensor_id"] == "sensor-z"

    conn_row = json.loads(conn_path.read_text(encoding="utf-8").splitlines()[0])
    assert conn_row["id.orig_h"] == "10.0.0.10"
    assert conn_row["id.resp_h"] == "10.0.0.20"
    assert conn_row["community_id"].startswith("wicap:")

    eve_rows = [json.loads(line) for line in eve_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert eve_rows
    assert eve_rows[0]["event_type"] in {"alert", "flow"}

    conn_record = to_zeek_conn_record(first_normalized)
    eve_record = to_suricata_eve_record(first_normalized)
    assert conn_record is not None
    assert eve_record["timestamp"] == first_normalized["ts"]
