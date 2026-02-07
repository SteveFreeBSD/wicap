#!/usr/bin/env python3
import argparse
from datetime import datetime, timedelta
from pathlib import Path

import pyodbc

from nexus.config import NexusConfig
from nexus.intel.digest_report import collect_digest, format_digest_markdown


def parse_args():
    parser = argparse.ArgumentParser(description="Generate WICAP daily digest.")
    parser.add_argument("--since-hours", type=int, default=24, help="Lookback window in hours")
    parser.add_argument("--output", type=Path, default=None, help="Output markdown path")
    return parser.parse_args()


def main():
    args = parse_args()
    end_ts = datetime.utcnow().timestamp()
    start_ts = (datetime.utcnow() - timedelta(hours=args.since_hours)).timestamp()

    config = NexusConfig.from_env()
    conn = pyodbc.connect(config.get_sql_connection_string())
    try:
        snapshot = collect_digest(conn, start_ts, end_ts)
        content = format_digest_markdown(snapshot)
    finally:
        conn.close()

    output = args.output
    if output is None:
        date_str = datetime.utcnow().strftime("%Y%m%d")
        output = Path("docs/reports/soak") / f"digest_{date_str}.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content)
    print(f"Wrote digest: {output}")


if __name__ == "__main__":
    main()
