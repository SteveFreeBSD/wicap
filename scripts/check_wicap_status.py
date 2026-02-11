#!/usr/bin/env python3
"""
Local and SQL status checks for WiFiWizard.

Use --local-only or --sql-only to scope checks.
"""

import argparse
import json
import os
import sys
import time
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
UI_ROOT = REPO_ROOT / "wicap-ui"
if str(UI_ROOT) not in sys.path:
    sys.path.insert(0, str(UI_ROOT))

try:
    import pyodbc
except ImportError:  # pragma: no cover - optional dependency
    pyodbc = None

try:
    from app.services.control_intent import evaluate_control_intent, load_control_contract
except Exception:  # pragma: no cover - optional dependency
    evaluate_control_intent = None
    load_control_contract = None

from config import get_scout_config  # noqa: E402
from nexus.config import NexusConfig  # noqa: E402
from scout import PidFile  # noqa: E402


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat()


def _fmt_age(ts: float) -> str:
    age = max(0.0, time.time() - ts)
    if age < 60:
        return f"{age:.1f}s"
    if age < 3600:
        return f"{age/60:.1f}m"
    return f"{age/3600:.1f}h"


def _fmt_bytes(count: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(count)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"


def _read_tail_lines(path: Path, max_lines: int = 5, max_bytes: int = 16384) -> list[str]:
    if not path.exists():
        return []
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if end == 0:
            return []
        read_size = min(end, max_bytes)
        f.seek(end - read_size)
        data = f.read()
    text = data.decode(errors="replace")
    lines = text.splitlines()
    return lines[-max_lines:]


def _last_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    lines = _read_tail_lines(path, max_lines=10)
    if not lines:
        return None, "no lines"
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line), None
        except Exception:
            continue
    return None, "no valid json"


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text()), None
    except Exception as exc:
        return None, f"invalid json: {exc}"


def _print_section(title: str) -> None:
    print(f"\n== {title} ==")


def _print_kv(key: str, value: str) -> None:
    print(f"{key:>24}: {value}")


def _local_status_json(cfg) -> dict[str, Any]:
    captures_dir = cfg.captures_dir
    pidfile = cfg.pidfile
    pid_file = PidFile(pidfile)
    files = {
        "events.log": cfg.events_log,
        "event_queue.jsonl": captures_dir / "event_queue.jsonl",
        "curated_events.jsonl": captures_dir / "curated_events.jsonl",
        "summary_stats.jsonl": captures_dir / "summary_stats.jsonl",
        "processor.state.json": captures_dir / "processor.state.json",
        "dedup_cache.json": captures_dir / "dedup_cache.json",
    }

    file_payload: dict[str, dict[str, Any]] = {}
    for label, path in files.items():
        if not path.exists():
            file_payload[label] = {"exists": False}
            continue
        stat = path.stat()
        file_payload[label] = {
            "exists": True,
            "size_bytes": int(stat.st_size),
            "mtime_epoch": float(stat.st_mtime),
            "mtime_iso": _fmt_ts(stat.st_mtime),
            "age_seconds": max(0.0, time.time() - stat.st_mtime),
        }

    queue_path = captures_dir / "event_queue.jsonl"
    state, state_err = _load_json(captures_dir / "processor.state.json")
    dedup, dedup_err = _load_json(captures_dir / "dedup_cache.json")
    last_event, last_event_err = _last_json(cfg.events_log)
    last_queue, last_queue_err = _last_json(queue_path)
    last_curated, last_curated_err = _last_json(captures_dir / "curated_events.jsonl")
    last_summary, last_summary_err = _last_json(captures_dir / "summary_stats.jsonl")

    backlog = None
    if state and queue_path.exists():
        try:
            backlog = max(0, queue_path.stat().st_size - int(state.get("byte_offset", 0)))
        except Exception:
            backlog = None

    return {
        "captures_dir": str(captures_dir),
        "pidfile": str(pidfile),
        "pid": pid_file.get_pid(),
        "running": bool(pid_file.is_running()),
        "files": file_payload,
        "state": state,
        "state_error": state_err,
        "queue_backlog_bytes": backlog,
        "dedup_entries": len(dedup) if isinstance(dedup, dict) else None,
        "dedup_error": dedup_err,
        "last_event": last_event,
        "last_event_error": last_event_err,
        "last_queue": last_queue,
        "last_queue_error": last_queue_err,
        "last_curated": last_curated,
        "last_curated_error": last_curated_err,
        "last_summary": last_summary,
        "last_summary_error": last_summary_err,
    }


def _sql_status_json() -> dict[str, Any]:
    if pyodbc is None:
        return {
            "available": False,
            "connection_ok": False,
            "error": "pyodbc not installed",
            "queries": {},
        }

    config = NexusConfig.from_env()
    conn_str = config.get_sql_connection_string()
    payload: dict[str, Any] = {
        "available": True,
        "connection_ok": False,
        "error": None,
        "queries": {},
    }
    try:
        conn = pyodbc.connect(conn_str, timeout=5)
        cursor = conn.cursor()
        payload["connection_ok"] = True
    except Exception as exc:
        payload["error"] = str(exc)
        return payload

    query_map = {
        "curated_events_count": "SELECT COUNT(*) AS total FROM curated_events",
        "summary_stats_count": "SELECT COUNT(*) AS total FROM summary_stats",
    }
    for name, query in query_map.items():
        try:
            cursor.execute(query)
            row = cursor.fetchone()
            payload["queries"][name] = row[0] if row is not None else None
        except Exception as exc:
            payload["queries"][name] = f"error: {exc}"

    conn.close()
    return payload


def _control_intent_validation_json(
    intent_path: Path,
    *,
    contract_path: str | None = None,
) -> dict[str, Any]:
    output: dict[str, Any] = {
        "intent_path": str(intent_path),
        "accepted": False,
        "reasons": [],
        "plane_evaluation": None,
        "error": None,
    }

    if evaluate_control_intent is None or load_control_contract is None:
        output["error"] = "control intent module unavailable"
        return output

    if not intent_path.exists():
        output["error"] = "intent file missing"
        return output

    try:
        raw_payload = json.loads(intent_path.read_text(encoding="utf-8"))
    except Exception as exc:
        output["error"] = f"invalid control intent json: {exc}"
        return output

    intent = raw_payload
    if isinstance(raw_payload, dict) and isinstance(raw_payload.get("intent"), dict):
        intent = raw_payload.get("intent")

    if not isinstance(intent, dict):
        output["error"] = "intent payload must be a JSON object"
        return output

    contract = load_control_contract(contract_path)
    accepted, reasons, plane = evaluate_control_intent(intent, contract=contract)
    output["accepted"] = accepted
    output["reasons"] = reasons
    output["plane_evaluation"] = plane
    return output


def _local_status(cfg) -> None:
    captures_dir = cfg.captures_dir
    _print_section("Local Status")
    _print_kv("captures_dir", str(captures_dir))

    pidfile = cfg.pidfile
    pid = PidFile(pidfile).get_pid()
    running = PidFile(pidfile).is_running()
    _print_kv("pidfile", f"{pidfile} ({'running' if running else 'stopped'})")
    if pid:
        _print_kv("pid", str(pid))

    files = {
        "events.log": cfg.events_log,
        "event_queue.jsonl": captures_dir / "event_queue.jsonl",
        "curated_events.jsonl": captures_dir / "curated_events.jsonl",
        "summary_stats.jsonl": captures_dir / "summary_stats.jsonl",
        "processor.state.json": captures_dir / "processor.state.json",
        "dedup_cache.json": captures_dir / "dedup_cache.json",
    }

    for label, path in files.items():
        if not path.exists():
            _print_kv(label, "missing")
            continue
        stat = path.stat()
        _print_kv(label, f"{_fmt_bytes(stat.st_size)} (mtime { _fmt_age(stat.st_mtime) } ago)")

    state, state_err = _load_json(captures_dir / "processor.state.json")
    if state:
        _print_kv("state.offset", str(state.get("byte_offset")))
        _print_kv("state.processed", str(state.get("events_processed")))
        _print_kv("state.curated", str(state.get("events_curated")))
    elif state_err and state_err != "missing":
        _print_kv("state.error", state_err)

    queue_path = captures_dir / "event_queue.jsonl"
    if state and queue_path.exists():
        backlog = max(0, queue_path.stat().st_size - int(state.get("byte_offset", 0)))
        _print_kv("queue.backlog", _fmt_bytes(backlog))

    dedup, dedup_err = _load_json(captures_dir / "dedup_cache.json")
    if dedup:
        _print_kv("dedup.entries", str(len(dedup)))
    elif dedup_err and dedup_err != "missing":
        _print_kv("dedup.error", dedup_err)

    last_event, err = _last_json(cfg.events_log)
    if last_event:
        _print_kv("events.log.last", f"{last_event.get('type')} @ {last_event.get('ts')}")
    elif err and err != "missing":
        _print_kv("events.log.last", err)

    last_queue, err = _last_json(queue_path)
    if last_queue:
        _print_kv("queue.last", f"{last_queue.get('event_type')} @ {last_queue.get('ts_epoch')}")
    elif err and err != "missing":
        _print_kv("queue.last", err)

    curated_path = captures_dir / "curated_events.jsonl"
    last_curated, err = _last_json(curated_path)
    if last_curated:
        _print_kv("curated.last", f"{last_curated.get('event_type')} @ {last_curated.get('ts_epoch')}")
    elif err and err != "missing":
        _print_kv("curated.last", err)

    summary_path = captures_dir / "summary_stats.jsonl"
    last_summary, err = _last_json(summary_path)
    if last_summary:
        _print_kv(
            "summary.last",
            f"{last_summary.get('window_start')} -> {last_summary.get('window_end')} (events {last_summary.get('events_count')})",
        )
    elif err and err != "missing":
        _print_kv("summary.last", err)


def _sql_status() -> None:
    _print_section("SQL Status")
    if pyodbc is None:
        _print_kv("pyodbc", "not installed (skipping SQL checks)")
        return

    config = NexusConfig.from_env()
    conn_str = config.get_sql_connection_string()

    try:
        conn = pyodbc.connect(conn_str, timeout=5)
        cursor = conn.cursor()
        _print_kv("connection", "ok")
    except Exception as exc:
        _print_kv("connection", f"failed: {exc}")
        return

    def run_query(title: str, query: str, params: Iterable | None = None, limit: int = 5) -> None:
        print(f"\n-- {title} --")
        cursor.execute(query, params or [])
        if not cursor.description:
            print("(no result set)")
            return
        cols = [col[0] for col in cursor.description]
        rows = cursor.fetchmany(limit)
        print(" | ".join(cols))
        print("-" * (len(" | ".join(cols)) + 2))
        if not rows:
            print("(no rows)")
            return
        for row in rows:
            print(row)

    run_query(
        "curated_events.event_id schema",
        """
        SELECT t.name AS type_name, c.max_length
        FROM sys.columns c
        JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('curated_events') AND c.name = 'event_id'
        """,
    )

    run_query(
        "curated_events row count",
        "SELECT COUNT(*) AS total FROM curated_events",
    )

    run_query(
        "latest curated_events",
        """
        SELECT TOP 5 event_id, ts_epoch, event_type, channel, score, inserted_at
        FROM curated_events
        ORDER BY ts_epoch DESC
        """,
    )

    run_query(
        "summary_stats latest",
        """
        SELECT TOP 5 window_start, window_end, events_count, top_category, top_vendor, inserted_at
        FROM summary_stats
        ORDER BY window_start DESC
        """,
    )

    conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="WiFiWizard status checks")
    parser.add_argument("--local-only", action="store_true", help="Skip SQL checks")
    parser.add_argument("--sql-only", action="store_true", help="Skip local checks")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable JSON output")
    parser.add_argument("--captures-dir", help="Override captures directory")
    parser.add_argument(
        "--validate-control-intent-json",
        help="Validate a control-intent JSON payload against wicap.control.v1 policy gates",
    )
    parser.add_argument(
        "--control-intent-contract",
        help="Override control contract JSON path (default: ops/contracts/wicap.control.v1.json)",
    )
    parser.add_argument(
        "--enforce-control-intent",
        action="store_true",
        help="Exit non-zero when control intent validation fails",
    )
    args = parser.parse_args()

    cfg = get_scout_config()
    if args.captures_dir:
        cfg.captures_dir = Path(args.captures_dir)

    if args.as_json:
        payload: dict[str, Any] = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "local": None,
            "sql": None,
            "control_intent_validation": None,
        }
        if not args.sql_only:
            payload["local"] = _local_status_json(cfg)
        if not args.local_only:
            payload["sql"] = _sql_status_json()
        validation = None
        if args.validate_control_intent_json:
            validation = _control_intent_validation_json(
                Path(args.validate_control_intent_json),
                contract_path=args.control_intent_contract,
            )
            payload["control_intent_validation"] = validation
        print(json.dumps(payload, indent=2, sort_keys=True))
        if args.enforce_control_intent and validation and not validation.get("accepted", False):
            return 2
        return 0

    if not args.sql_only:
        _local_status(cfg)
    if not args.local_only:
        _sql_status()
    validation = None
    if args.validate_control_intent_json:
        validation = _control_intent_validation_json(
            Path(args.validate_control_intent_json),
            contract_path=args.control_intent_contract,
        )
        _print_section("Control Intent Validation")
        _print_kv("intent_path", validation["intent_path"])
        _print_kv("accepted", str(validation["accepted"]).lower())
        if validation.get("error"):
            _print_kv("error", str(validation["error"]))
        else:
            _print_kv("reasons", "; ".join(validation.get("reasons", [])) or "none")
            plane = validation.get("plane_evaluation") or {}
            _print_kv("plane.denied_by", str(plane.get("denied_by") or "none"))
            _print_kv(
                "plane.summary",
                f"runtime={plane.get('runtime_plane')} tool={plane.get('tool_policy_plane')} elevated={plane.get('elevated_plane')}",
            )

    if args.enforce_control_intent and validation and not validation.get("accepted", False):
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
