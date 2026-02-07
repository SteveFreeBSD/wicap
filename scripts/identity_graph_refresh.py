#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import pyodbc

from nexus.config import NexusConfig
from nexus.intel.identity_graph_store import IdentityGraphStoreConfig, build_graph_from_db, persist_graph


def parse_args():
    parser = argparse.ArgumentParser(description="Build and persist the identity graph.")
    parser.add_argument("--lookback-days", type=int, default=None, help="Profile lookback window (days)")
    parser.add_argument("--min-score", type=float, default=None, help="Minimum similarity score to link")
    parser.add_argument("--time-gap-sec", type=float, default=None, help="Max time gap for comparisons (seconds)")
    parser.add_argument("--allow-cross-protocol", action="store_true", help="Allow Wi-Fi ↔ BLE links")
    parser.add_argument("--no-persist", action="store_true", help="Skip SQL persistence")
    parser.add_argument("--no-full-refresh", action="store_true", help="Do not delete old clusters on persist")
    parser.add_argument("--export", type=Path, default=None, help="Write graph JSON to path")
    return parser.parse_args()


def main():
    args = parse_args()
    config = IdentityGraphStoreConfig()
    if args.lookback_days is not None:
        config.lookback_days = args.lookback_days
    if args.min_score is not None:
        config.min_score = args.min_score
    if args.time_gap_sec is not None:
        config.max_time_gap_sec = args.time_gap_sec
    if args.allow_cross_protocol:
        config.allow_cross_protocol = True

    sql_config = NexusConfig.from_env()
    conn = pyodbc.connect(sql_config.get_sql_connection_string())
    try:
        graph = build_graph_from_db(conn, config)
        if not args.no_persist:
            persist_graph(conn, graph, full_refresh=not args.no_full_refresh)
        if args.export:
            payload = graph.to_dict(include_profiles=True)
            args.export.parent.mkdir(parents=True, exist_ok=True)
            args.export.write_text(json.dumps(payload, indent=2))
            print(f"Wrote {args.export}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
