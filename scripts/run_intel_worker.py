#!/usr/bin/env python3
"""Run WiCAP sidecar intel worker for anomaly v2 + prediction artifacts."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nexus.intel.intel_worker import run_intel_worker_loop  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="WiCAP sidecar intel worker")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Worker cycle interval seconds (default: env WICAP_INTEL_WORKER_INTERVAL_SECONDS or 10)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    interval = float(args.interval) if args.interval is not None else float(
        os.getenv("WICAP_INTEL_WORKER_INTERVAL_SECONDS", "10")
    )
    return run_intel_worker_loop(
        once=bool(args.once),
        interval_seconds=max(0.5, float(interval)),
    )


if __name__ == "__main__":
    raise SystemExit(main())
