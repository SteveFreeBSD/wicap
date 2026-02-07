#!/usr/bin/env python3
import argparse
from pathlib import Path

import pyodbc

from nexus.config import NexusConfig
from nexus.intel.evidence import EvidenceCollector
from nexus.intel.evidence_bundle import build_bundle


def parse_args():
    parser = argparse.ArgumentParser(description="Generate evidence bundle zip.")
    parser.add_argument("--start-ts", type=float, required=True, help="Start timestamp (epoch)")
    parser.add_argument("--end-ts", type=float, required=True, help="End timestamp (epoch)")
    parser.add_argument("--output-dir", type=Path, default=Path("captures/evidence/bundles"))
    parser.add_argument("--max-events", type=int, default=10000)
    return parser.parse_args()


def main():
    args = parse_args()
    config = NexusConfig.from_env()
    conn = pyodbc.connect(config.get_sql_connection_string())
    evidence = EvidenceCollector()
    try:
        output = build_bundle(
            conn,
            evidence,
            args.start_ts,
            args.end_ts,
            output_dir=args.output_dir,
            max_events=args.max_events,
        )
    finally:
        conn.close()
    print(f"Wrote bundle: {output}")


if __name__ == "__main__":
    main()
