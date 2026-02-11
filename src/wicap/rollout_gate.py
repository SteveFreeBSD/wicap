"""Cross-repo rollout gate evaluation for live agentic testing."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from src.wicap.telemetry.network_events import export_network_events


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_int(value: object, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _count_jsonl_rows(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.strip():
            count += 1
    return count


def collect_local_runtime_metrics(captures_dir: Path) -> dict[str, Any]:
    root = Path(captures_dir)
    queue_path = root / "event_queue.jsonl"
    curated_path = root / "curated_events.jsonl"
    state_path = root / "processor.state.json"

    queue_size = int(queue_path.stat().st_size) if queue_path.exists() else 0
    curated_rows = _count_jsonl_rows(curated_path)
    state_payload: dict[str, Any] = {}
    if state_path.exists():
        try:
            value = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            value = {}
        if isinstance(value, dict):
            state_payload = value
    byte_offset = _safe_int(state_payload.get("byte_offset", queue_size), default=queue_size)
    backlog = max(0, int(queue_size - byte_offset))
    return {
        "captures_dir": str(root),
        "queue_exists": bool(queue_path.exists()),
        "curated_exists": bool(curated_path.exists()),
        "queue_size_bytes": int(queue_size),
        "queue_backlog_bytes": int(backlog),
        "curated_row_count": int(curated_rows),
        "state_path": str(state_path),
    }


def evaluate_local_runtime_gate(
    metrics: dict[str, Any],
    *,
    max_backlog_bytes: int,
    min_curated_events: int,
) -> dict[str, Any]:
    curated_ok = bool(metrics.get("curated_exists")) and int(metrics.get("curated_row_count", 0)) >= int(
        min_curated_events
    )
    queue_ok = bool(metrics.get("queue_exists"))
    backlog_ok = int(metrics.get("queue_backlog_bytes", 0)) <= int(max_backlog_bytes)
    gate_pass = bool(curated_ok and queue_ok and backlog_ok)
    status = "pass" if gate_pass else "fail"
    return {
        "status": status,
        "pass": bool(gate_pass),
        "queue_exists": bool(queue_ok),
        "curated_exists": bool(metrics.get("curated_exists")),
        "curated_row_count": int(metrics.get("curated_row_count", 0)),
        "min_curated_events": int(min_curated_events),
        "queue_backlog_bytes": int(metrics.get("queue_backlog_bytes", 0)),
        "max_backlog_bytes": int(max_backlog_bytes),
    }


def load_assistant_rollout_report(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    raise ValueError("assistant rollout report must be a JSON object")


def run_assistant_rollout_command(
    *,
    assistant_repo_root: Path,
    assistant_db: Path | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    repo_root = Path(assistant_repo_root).resolve()
    db_path = assistant_db if assistant_db is not None else (repo_root / "data" / "assistant.db")
    env = dict(os.environ)
    existing_pythonpath = str(env.get("PYTHONPATH", "")).strip()
    assistant_pythonpath = str(repo_root / "src")
    if existing_pythonpath:
        env["PYTHONPATH"] = f"{assistant_pythonpath}:{existing_pythonpath}"
    else:
        env["PYTHONPATH"] = assistant_pythonpath
    command = [
        sys.executable,
        "-m",
        "wicap_assist.cli",
        "--db",
        str(db_path),
        "rollout-gates",
        "--json",
    ]
    result = subprocess.run(
        command,
        cwd=str(repo_root),
        check=False,
        capture_output=True,
        text=True,
        timeout=max(1.0, float(timeout_seconds)),
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"assistant rollout command failed rc={result.returncode}: {result.stderr.strip()}")
    payload = json.loads(result.stdout.strip() or "{}")
    if not isinstance(payload, dict):
        raise RuntimeError("assistant rollout command returned invalid JSON object")
    return payload


def evaluate_shadow_validation_gate(
    *,
    curated_input: Path,
    work_dir: Path,
    min_conn_coverage: float,
    min_eve_coverage: float,
    min_exported: int,
) -> dict[str, Any]:
    input_path = Path(curated_input)
    if not input_path.exists():
        return {
            "status": "insufficient_data",
            "pass": False,
            "reason": "curated input missing",
            "input": str(input_path),
        }
    if not input_path.read_text(encoding="utf-8", errors="replace").strip():
        return {
            "status": "insufficient_data",
            "pass": False,
            "reason": "curated input empty",
            "input": str(input_path),
        }

    output_dir = Path(work_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    event_output = output_dir / "wicap_network_events.shadow.jsonl"
    conn_output = output_dir / "zeek_conn.shadow.jsonl"
    eve_output = output_dir / "suricata_eve.shadow.jsonl"
    summary = export_network_events(
        input_path=input_path,
        output_path=event_output,
        conn_output_path=conn_output,
        eve_output_path=eve_output,
    )
    exported = int(summary.get("exported", 0))
    conn_rows = int(summary.get("conn_rows", 0))
    eve_rows = int(summary.get("eve_rows", 0))
    conn_coverage = float(conn_rows) / float(exported) if exported > 0 else 0.0
    eve_coverage = float(eve_rows) / float(exported) if exported > 0 else 0.0
    gate_pass = (
        exported >= int(min_exported)
        and conn_coverage >= float(min_conn_coverage)
        and eve_coverage >= float(min_eve_coverage)
    )
    status = "pass" if gate_pass else "fail"
    if exported < int(min_exported):
        status = "insufficient_data"
    return {
        "status": status,
        "pass": bool(gate_pass),
        "input": str(input_path),
        "exported": int(exported),
        "conn_rows": int(conn_rows),
        "eve_rows": int(eve_rows),
        "conn_coverage": round(float(conn_coverage), 4),
        "eve_coverage": round(float(eve_coverage), 4),
        "min_exported": int(min_exported),
        "min_conn_coverage": float(min_conn_coverage),
        "min_eve_coverage": float(min_eve_coverage),
        "event_output": str(event_output),
        "conn_output": str(conn_output),
        "eve_output": str(eve_output),
    }


def evaluate_agentic_rollout_gate(
    *,
    captures_dir: Path,
    assistant_report: dict[str, Any] | None,
    max_backlog_bytes: int,
    min_curated_events: int,
    shadow_gate: dict[str, Any],
    require_assistant: bool,
    require_shadow_data: bool,
) -> dict[str, Any]:
    local_metrics = collect_local_runtime_metrics(Path(captures_dir))
    local_gate = evaluate_local_runtime_gate(
        local_metrics,
        max_backlog_bytes=max_backlog_bytes,
        min_curated_events=min_curated_events,
    )

    if assistant_report is None:
        assistant_gate = {
            "status": "unavailable",
            "pass": False,
            "overall_pass": None,
        }
    else:
        assistant_gate = {
            "status": "pass" if bool(assistant_report.get("overall_pass")) else "fail",
            "pass": bool(assistant_report.get("overall_pass")),
            "overall_pass": bool(assistant_report.get("overall_pass")),
            "promotion": assistant_report.get("promotion"),
        }

    shadow_required_pass = bool(shadow_gate.get("pass", False))
    if not require_shadow_data and str(shadow_gate.get("status")) == "insufficient_data":
        shadow_required_pass = True

    overall_pass = bool(local_gate.get("pass"))
    if bool(require_assistant):
        overall_pass = overall_pass and bool(assistant_gate.get("pass"))
    if bool(require_shadow_data):
        overall_pass = overall_pass and bool(shadow_gate.get("pass"))
    else:
        overall_pass = overall_pass and bool(shadow_required_pass)

    return {
        "generated_ts": _now_iso(),
        "overall_pass": bool(overall_pass),
        "gates": {
            "local_runtime": local_gate,
            "assistant_rollout": assistant_gate,
            "shadow_validation": shadow_gate,
        },
        "requirements": {
            "require_assistant": bool(require_assistant),
            "require_shadow_data": bool(require_shadow_data),
        },
    }
