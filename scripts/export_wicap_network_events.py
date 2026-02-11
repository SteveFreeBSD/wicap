#!/usr/bin/env python3
"""Export WiCAP curated events into contract-normalized network event streams."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.wicap.telemetry.network_events import export_network_events


def main() -> int:
    parser = argparse.ArgumentParser(description="Export WiCAP network event contract artifacts")
    parser.add_argument(
        "--input",
        default=str(REPO_ROOT / "captures" / "curated_events.jsonl"),
        help="Input curated events JSONL path",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "captures" / "wicap_network_events.jsonl"),
        help="Output contract event JSONL path",
    )
    parser.add_argument(
        "--conn-output",
        default=str(REPO_ROOT / "captures" / "zeek_conn_compat.jsonl"),
        help="Output Zeek conn-compatible JSONL path",
    )
    parser.add_argument(
        "--eve-output",
        default=str(REPO_ROOT / "captures" / "suricata_eve_compat.jsonl"),
        help="Output Suricata EVE-compatible JSONL path",
    )
    parser.add_argument(
        "--sensor-id",
        default="wicap-local",
        help="Sensor identifier embedded in normalized events",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(json.dumps({"status": "error", "message": f"input file missing: {input_path}"}))
        return 2

    summary = export_network_events(
        input_path=input_path,
        output_path=Path(args.output),
        sensor_id=str(args.sensor_id),
        conn_output_path=Path(args.conn_output) if args.conn_output else None,
        eve_output_path=Path(args.eve_output) if args.eve_output else None,
    )
    payload = {
        "status": "ok",
        "input": str(input_path),
        "output": str(args.output),
        "conn_output": str(args.conn_output) if args.conn_output else None,
        "eve_output": str(args.eve_output) if args.eve_output else None,
        **summary,
    }
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
