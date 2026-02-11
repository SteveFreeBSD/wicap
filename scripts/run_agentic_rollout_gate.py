#!/usr/bin/env python3
"""Run cross-repo rollout gates for live agentic testing readiness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.wicap.rollout_gate import (  # noqa: E402
    evaluate_agentic_rollout_gate,
    evaluate_shadow_validation_gate,
    load_assistant_rollout_report,
    run_assistant_rollout_command,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-repo rollout gate evaluation for live testing")
    parser.add_argument(
        "--captures-dir",
        default=str(REPO_ROOT / "captures"),
        help="WiCAP captures directory",
    )
    parser.add_argument(
        "--assistant-rollout-report",
        default=None,
        help="Optional precomputed assistant rollout-gates JSON report path",
    )
    parser.add_argument(
        "--assistant-repo-root",
        default=str((REPO_ROOT.parent / "wicap-assistant").resolve()),
        help="Path to wicap-assistant repo (used if report path not provided)",
    )
    parser.add_argument(
        "--assistant-db",
        default=None,
        help="Optional assistant DB path (defaults to <assistant-repo>/data/assistant.db)",
    )
    parser.add_argument(
        "--max-backlog-bytes",
        type=int,
        default=25_000_000,
        help="Maximum tolerated event queue backlog bytes for local runtime gate",
    )
    parser.add_argument(
        "--min-curated-events",
        type=int,
        default=1,
        help="Minimum curated events required for local runtime gate",
    )
    parser.add_argument(
        "--shadow-curated-input",
        default=None,
        help="Curated events input for shadow validation (defaults to <captures>/curated_events.jsonl)",
    )
    parser.add_argument(
        "--shadow-work-dir",
        default=str(REPO_ROOT / "captures" / "rollout_shadow"),
        help="Directory for generated shadow validation artifacts",
    )
    parser.add_argument("--min-shadow-exported", type=int, default=1)
    parser.add_argument("--min-conn-coverage", type=float, default=0.50)
    parser.add_argument("--min-eve-coverage", type=float, default=0.80)
    parser.add_argument(
        "--require-assistant",
        dest="require_assistant",
        action="store_true",
        help="Require assistant rollout gates to pass (default)",
    )
    parser.add_argument(
        "--no-require-assistant",
        dest="require_assistant",
        action="store_false",
        help="Do not require assistant rollout gate data for PASS",
    )
    parser.set_defaults(require_assistant=True)
    parser.add_argument(
        "--require-shadow-data",
        action="store_true",
        help="Require shadow validation data/coverage gate to pass",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero when rollout gate overall pass is false",
    )
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")
    args = parser.parse_args()

    captures_dir = Path(args.captures_dir)
    curated_input = (
        Path(args.shadow_curated_input)
        if args.shadow_curated_input is not None
        else captures_dir / "curated_events.jsonl"
    )
    assistant_report: dict | None = None
    assistant_error: str | None = None
    if args.assistant_rollout_report:
        try:
            assistant_report = load_assistant_rollout_report(Path(args.assistant_rollout_report))
        except Exception as exc:
            assistant_error = str(exc)
    else:
        try:
            assistant_report = run_assistant_rollout_command(
                assistant_repo_root=Path(args.assistant_repo_root),
                assistant_db=Path(args.assistant_db) if args.assistant_db else None,
            )
        except Exception as exc:
            assistant_error = str(exc)

    shadow_gate = evaluate_shadow_validation_gate(
        curated_input=Path(curated_input),
        work_dir=Path(args.shadow_work_dir),
        min_conn_coverage=float(args.min_conn_coverage),
        min_eve_coverage=float(args.min_eve_coverage),
        min_exported=max(1, int(args.min_shadow_exported)),
    )
    report = evaluate_agentic_rollout_gate(
        captures_dir=captures_dir,
        assistant_report=assistant_report,
        max_backlog_bytes=max(0, int(args.max_backlog_bytes)),
        min_curated_events=max(0, int(args.min_curated_events)),
        shadow_gate=shadow_gate,
        require_assistant=bool(args.require_assistant),
        require_shadow_data=bool(args.require_shadow_data),
    )
    if assistant_error:
        report["assistant_error"] = assistant_error

    if args.as_json:
        print(json.dumps(report, sort_keys=True))
    else:
        status = "PASS" if bool(report.get("overall_pass")) else "FAIL"
        print(f"Agentic rollout gate: {status}")
        gates = report.get("gates", {})
        if isinstance(gates, dict):
            for gate_name in sorted(gates.keys()):
                gate_payload = gates.get(gate_name, {})
                if not isinstance(gate_payload, dict):
                    continue
                print(f"- {gate_name}: {gate_payload.get('status')} (pass={bool(gate_payload.get('pass'))})")
        if assistant_error:
            print(f"- assistant_error: {assistant_error}")

    if bool(args.enforce) and not bool(report.get("overall_pass")):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
