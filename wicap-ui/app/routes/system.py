import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

import app.services.control_intent as control_intent_service
import app.services.docker_client as docker_client
import app.services.scavenger as scavenger_service
import app.services.state as state
import docker
from app.services import memprof

router = APIRouter()

REPO_ROOT = Path(__file__).resolve().parents[3]
REDIS_QUEUE_KEY = os.getenv("WICAP_REDIS_QUEUE_KEY", "wicap:events")


def _get_capture_dir() -> Path:
    return Path(
        state._get_env("WICAP_CAPTURE_DIR", "WICAP_CAPTURES_DIR", default=str(REPO_ROOT / "captures"))
    )


def _read_tail_json(path: Path, max_bytes: int = 16384) -> dict | None:
    if not path.exists():
        return None
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            end = handle.tell()
            if end == 0:
                return None
            handle.seek(max(0, end - max_bytes))
            data = handle.read()
        lines = data.decode(errors="replace").splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except Exception:
                continue
    except Exception:
        return None
    return None


def _control_plane_state() -> dict[str, Any]:
    runtime_enabled = os.getenv("WICAP_CONTROL_RUNTIME_PLANE_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
        "disabled",
    }
    tool_enabled = os.getenv("WICAP_CONTROL_TOOL_POLICY_PLANE_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
        "disabled",
    }
    elevated_enabled = os.getenv("WICAP_CONTROL_ELEVATED_PLANE_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }
    return {
        "runtime_plane": bool(runtime_enabled),
        "tool_policy_plane": bool(tool_enabled),
        "elevated_plane": bool(elevated_enabled),
        "active_policy_profile": os.getenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1").strip() or "observe-v1",
        "profile_version": os.getenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE_VERSION", "1").strip() or "1",
        "cooldown_until": os.getenv("WICAP_CONTROL_ACTION_COOLDOWN_UNTIL", "").strip() or None,
    }


def _failover_state_path() -> Path:
    raw = os.getenv("WICAP_CONTROL_FAILOVER_STATE_PATH", "").strip()
    if raw:
        return Path(raw).expanduser()
    return REPO_ROOT / "captures" / "failover_state.json"


def _load_failover_state() -> dict[str, Any]:
    path = _failover_state_path()
    payload: dict[str, Any] = {
        "state_path": str(path),
        "auth_profile": os.getenv("WICAP_CONTROL_AUTH_PROFILE", "primary"),
        "attempt": 0,
        "cooldown_until": os.getenv("WICAP_CONTROL_ACTION_COOLDOWN_UNTIL", "").strip() or None,
        "failure_class": "none",
        "disabled_until": None,
        "updated_ts": None,
    }
    if not path.exists():
        return payload
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return payload
    if not isinstance(parsed, dict):
        return payload
    payload.update(
        {
            "auth_profile": str(parsed.get("auth_profile", payload["auth_profile"])).strip() or payload["auth_profile"],
            "attempt": int(parsed.get("attempt", 0) or 0),
            "cooldown_until": parsed.get("cooldown_until"),
            "failure_class": str(parsed.get("failure_class", "none")).strip() or "none",
            "disabled_until": parsed.get("disabled_until"),
            "updated_ts": parsed.get("updated_ts"),
        }
    )
    return payload


def _intent_with_v2_defaults(intent: dict[str, Any], *, plane: dict[str, Any]) -> dict[str, Any]:
    payload = dict(intent)
    payload.setdefault(
        "policy_trace",
        {
            "trace_id": str(payload.get("decision_id", "")).strip() or "trace-missing",
            "plane_decisions": {
                "runtime_plane": bool(plane.get("runtime_plane", False)),
                "tool_policy_plane": bool(plane.get("tool_policy_plane", False)),
                "elevated_plane": bool(plane.get("elevated_plane", False)),
            },
            "deny_reasons": [],
            "budget_state": {
                "action_budget_used": 0,
                "action_budget_max": None,
                "elevated_action_budget_used": 0,
                "elevated_action_budget_max": None,
            },
        },
    )
    payload.setdefault(
        "failover",
        {
            "auth_profile": "primary",
            "attempt": 0,
            "cooldown_until": None,
            "failure_class": "none",
        },
    )
    payload.setdefault(
        "mission",
        {
            "graph_id": "default-mission",
            "step_id": "observe",
            "step_type": "observe",
            "terminal_state": "running",
        },
    )
    return payload


def _read_redis_queue_depth(redis_url: str) -> int | None:
    if not redis_url:
        return None
    try:
        import redis  # type: ignore
    except Exception:
        return None
    try:
        client = redis.from_url(
            redis_url,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
            decode_responses=True,
        )
        return int(client.llen(REDIS_QUEUE_KEY))
    except Exception:
        return None


def _dispatch_control_intent_action(action: str) -> dict[str, Any]:
    normalized = str(action).strip()
    if not normalized:
        return {"executed": False, "status": "rejected", "detail": "missing recommended_action"}

    if normalized == "status_check":
        command = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "check_wicap_status.py"),
            "--local-only",
            "--json",
        ]
    elif normalized == "compose_up":
        command = ["docker", "compose", "up", "-d"]
    elif normalized == "shutdown":
        command = ["docker", "compose", "down"]
    elif normalized.startswith("restart_service:"):
        service = normalized.split(":", 1)[1].strip()
        command = ["docker", "compose", "restart", service]
    else:
        return {"executed": False, "status": "rejected", "detail": f"unsupported action: {normalized}"}

    result = subprocess.run(
        command,
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload: dict[str, Any] = {
        "executed": result.returncode == 0,
        "status": "ok" if result.returncode == 0 else "failed",
        "command": command,
        "returncode": int(result.returncode),
    }
    if result.stdout.strip():
        payload["stdout"] = result.stdout[-4000:]
    if result.stderr.strip():
        payload["stderr"] = result.stderr[-4000:]
    return payload


@router.get("/api/system/status")
async def api_system_status():
    # Get system health, EPS, and container status.
    status = {
        "service_status": "unknown",
        "db_status": "unknown",
        "eps": 0,  # Events Per Second
        "last_insert": None,
        "last_insert_age_sec": None,
        "uptime": "0s",
        "queue_mode": "file",
        "queue_bytes": None,
        "queue_backlog_bytes": None,
        "queue_depth_events": None,
        "queue_last_ts": None,
        "queue_last_event_age_sec": None,
        "control_plane": _control_plane_state(),
        "intel_worker": {
            "container_state": "unknown",
            "healthy": None,
            "latest_anomaly_v2_ts": None,
            "latest_prediction_ts": None,
            "latest_drift_state": None,
        },
    }

    # 1. Container Status
    client = docker_client.get_docker_client()
    if client:
        try:
            container = client.containers.get("wicap-scout")
            status["service_status"] = container.status  # 'running', 'exited', etc.
            status["uptime"] = container.attrs["State"]["StartedAt"]
        except docker.errors.NotFound:
            status["service_status"] = "not_found"
        except Exception:
            status["service_status"] = "error"

    # Fallback: Local Process Check
    # If Docker failed (local mode), check for scout.py process
    if status["service_status"] in ["not_found", "no_access", "error"]:
        try:
            res = subprocess.run(["pgrep", "-f", "scout.py"], stdout=subprocess.DEVNULL)
            if res.returncode == 0:
                status["service_status"] = "running"
            elif status["service_status"] == "not_found":
                status["service_status"] = "stopped"
        except Exception:
            pass

    # Optional intel sidecar health + latest anomaly/prediction signals.
    try:
        if client:
            intel = client.containers.get("wicap-intel-worker")
            intel_state = str(intel.attrs.get("State", {}).get("Status", "unknown"))
            intel_health = intel.attrs.get("State", {}).get("Health", {})
            status["intel_worker"]["container_state"] = intel_state
            status["intel_worker"]["healthy"] = (
                str(intel_health.get("Status", "")).lower() == "healthy"
                if isinstance(intel_health, dict) and intel_health
                else None
            )
        else:
            status["intel_worker"]["container_state"] = "unavailable"
    except Exception:
        status["intel_worker"]["container_state"] = "not_found"

    # 2. Database Metrics (EPS)
    def _query(conn):
        cursor = conn.cursor()
        # Calculate EPS (Avg over last 1 min)
        query_eps = "SELECT COUNT(*) FROM curated_events WHERE inserted_at > DATEADD(minute, -1, GETDATE())"
        cursor.execute(query_eps)
        events_last_min = cursor.fetchone()[0]
        result = {"eps": round(events_last_min / 60.0, 2)}

        # Last Insert
        where_clause, params = state._source_filter_sql("live")
        cursor.execute(
            f"SELECT TOP 1 inserted_at FROM curated_events WHERE {where_clause} ORDER BY inserted_at DESC",
            params,
        )
        row = cursor.fetchone()
        if row:
            result["last_insert"] = row[0].isoformat()
        return result

    try:
        status.update(await state.run_db(_query))
        status["db_status"] = "connected"
    except Exception:
        status["db_status"] = "disconnected"

    # 3. Event queue health (live pipeline)
    capture_dir = _get_capture_dir()
    queue_path = capture_dir / "event_queue.jsonl"
    state_path = capture_dir / "processor.state.json"
    redis_url = os.getenv("WICAP_REDIS_URL", "").strip()
    if redis_url:
        status["queue_mode"] = "redis"
        status["queue_depth_events"] = _read_redis_queue_depth(redis_url)
    else:
        status["queue_mode"] = "file"
        if queue_path.exists():
            try:
                status["queue_bytes"] = queue_path.stat().st_size
            except Exception:
                status["queue_bytes"] = None

        state_json = None
        if state_path.exists():
            try:
                state_json = json.loads(state_path.read_text())
            except Exception:
                state_json = None

        if status["queue_bytes"] is not None and state_json:
            try:
                offset = int(state_json.get("byte_offset", 0))
                status["queue_backlog_bytes"] = max(0, status["queue_bytes"] - offset)
            except Exception:
                status["queue_backlog_bytes"] = None

        last_queue_event = _read_tail_json(queue_path)
        if last_queue_event and "ts_epoch" in last_queue_event:
            try:
                ts = float(last_queue_event["ts_epoch"])
                status["queue_last_ts"] = ts
                status["queue_last_event_age_sec"] = round(time.time() - ts, 2)
            except Exception:
                pass

    if status.get("last_insert"):
        try:
            last_insert_ts = time.mktime(time.strptime(status["last_insert"][:19], "%Y-%m-%dT%H:%M:%S"))
            status["last_insert_age_sec"] = round(time.time() - last_insert_ts, 2)
        except Exception:
            status["last_insert_age_sec"] = None

    # If DB inserts are fresh but file queue activity is stale, mark file metrics inactive.
    if (
        status.get("queue_mode") == "file"
        and status.get("queue_last_event_age_sec") is not None
        and status.get("last_insert_age_sec") is not None
        and status["queue_last_event_age_sec"] > 600
        and status["last_insert_age_sec"] < 120
    ):
        status["queue_mode"] = "file_inactive"
        status["queue_backlog_bytes"] = None
        status["queue_last_ts"] = None
        status["queue_last_event_age_sec"] = None

    anomaly_v2 = _read_tail_json(capture_dir / "wicap_anomaly_events_v2.jsonl")
    if isinstance(anomaly_v2, dict):
        status["intel_worker"]["latest_anomaly_v2_ts"] = anomaly_v2.get("ts")
        drift_state = anomaly_v2.get("drift_state")
        if isinstance(drift_state, dict):
            status["intel_worker"]["latest_drift_state"] = drift_state
    prediction = _read_tail_json(capture_dir / "wicap_predictions.jsonl")
    if isinstance(prediction, dict):
        status["intel_worker"]["latest_prediction_ts"] = prediction.get("ts")

    status["ui_memory"] = memprof.summary()

    return status


@router.get("/api/system/memory")
async def api_system_memory(limit: int = 10):
    """Return UI memory diagnostics (requires WICAP_UI_MEMPROF=1 for tracemalloc)."""
    limit = max(1, min(limit, 50))
    memprof.try_start_deferred(reason="on-demand")
    return {
        "summary": memprof.summary(),
        "top_allocations": memprof.top_allocations(limit=limit),
    }


@router.post("/api/system/control")
async def api_system_control(action: str):
    """Start, stop, or restart wicap-core. Supports Docker and bare-metal modes."""
    if action not in ["start", "stop", "restart"]:
        return {"status": "error", "message": "Invalid action value"}

    # Try Docker first
    client = docker_client.get_docker_client()
    if client:
        try:
            container = client.containers.get("wicap-scout")
            if action == "start":
                container.start()
                return {"status": "success", "message": "Started wicap-core (Docker)"}
            if action == "stop":
                container.stop()
                return {"status": "success", "message": "Stopped wicap-core (Docker)"}
            if action == "restart":
                container.restart()
                return {"status": "success", "message": "Restarted wicap-core (Docker)"}
        except docker.errors.NotFound:
            pass  # Fall through to bare-metal
        except Exception as exc:
            return {"status": "error", "message": f"Docker error: {exc}"}

    # Bare-metal fallback using subprocess
    try:
        if action == "stop":
            subprocess.run(["pkill", "-f", "start_wicap.py"], check=False)
            subprocess.run(["pkill", "-f", "scout.py"], check=False)
            return {"status": "success", "message": "Stopped wicap-core (bare-metal)"}
        if action == "start":
            # Start in background - requires sudo, so just signal user
            return {"status": "info", "message": "Start requires: sudo python3 start_wicap.py"}
        if action == "restart":
            subprocess.run(["pkill", "-f", "start_wicap.py"], check=False)
            subprocess.run(["pkill", "-f", "scout.py"], check=False)
            return {"status": "info", "message": "Stopped. Restart requires: sudo python3 start_wicap.py"}
    except Exception as exc:
        return {"status": "error", "message": f"Bare-metal error: {exc}"}

    return {"status": "error", "message": "Unknown control action"}


@router.post("/api/system/control-intent")
async def api_system_control_intent(request: Request, payload: dict[str, Any], execute: bool = False):
    """Validate policy-gated control intents and optionally dispatch allowlisted action."""
    state._validate_internal_access(request)

    intent = payload.get("intent") if isinstance(payload.get("intent"), dict) else payload
    accepted, reasons, plane = control_intent_service.evaluate_control_intent(intent)

    action = str(intent.get("recommended_action", "")).strip() if isinstance(intent, dict) else ""
    response: dict[str, Any] = {
        "accepted": accepted,
        "decision_id": (intent.get("decision_id") if isinstance(intent, dict) else None),
        "recommended_action": action,
        "policy_profile": (intent.get("policy_profile") if isinstance(intent, dict) else None),
        "profile_version": (
            (intent.get("profile_version") or plane.get("profile_version"))
            if isinstance(intent, dict)
            else plane.get("profile_version")
        ),
        "reasons": reasons,
        "policy_eval": plane,
        "denied_by": plane.get("denied_by"),
        "cooldown_until": plane.get("cooldown_until"),
        "plane_evaluation": plane,
        "execute_requested": bool(execute),
        "dispatch": {"executed": False, "status": "skipped", "detail": "execute=false"},
    }

    if accepted and execute:
        response["dispatch"] = _dispatch_control_intent_action(action)

    audit_record = {
        "decision_id": response["decision_id"],
        "recommended_action": response["recommended_action"],
        "policy_profile": response["policy_profile"],
        "profile_version": response["profile_version"],
        "accepted": response["accepted"],
        "denied_by": response["denied_by"],
        "cooldown_until": response["cooldown_until"],
        "reasons": response["reasons"],
        "policy_eval": response["policy_eval"],
        "plane_evaluation": response["plane_evaluation"],
        "execute_requested": response["execute_requested"],
        "dispatch": response["dispatch"],
    }
    audit_path = control_intent_service.append_control_intent_audit(audit_record)
    response["audit_path"] = str(audit_path)
    return JSONResponse(status_code=200 if accepted else 403, content=response)


@router.post("/api/system/control-intent/v2")
async def api_system_control_intent_v2(request: Request, payload: dict[str, Any], execute: bool = False):
    """Validate v2 control intents with dual-read compatibility and optional dispatch."""
    state._validate_internal_access(request)

    intent = payload.get("intent") if isinstance(payload.get("intent"), dict) else payload
    if not isinstance(intent, dict):
        intent = {}
    requested_version = str(intent.get("control_intent_version", "wicap.control.v2")).strip().lower()
    if requested_version == "wicap.control.v1":
        contract = control_intent_service.load_control_contract(version="v1")
    else:
        contract = control_intent_service.load_control_contract(version="v2")
        intent = _intent_with_v2_defaults(intent, plane=_control_plane_state())

    accepted, reasons, plane = control_intent_service.evaluate_control_intent(intent, contract=contract)
    action = str(intent.get("recommended_action", "")).strip() if isinstance(intent, dict) else ""
    response: dict[str, Any] = {
        "accepted": accepted,
        "decision_id": intent.get("decision_id"),
        "recommended_action": action,
        "policy_profile": intent.get("policy_profile"),
        "profile_version": intent.get("profile_version") or plane.get("profile_version"),
        "reasons": reasons,
        "policy_eval": plane,
        "denied_by": plane.get("denied_by"),
        "cooldown_until": plane.get("cooldown_until"),
        "plane_evaluation": plane,
        "execute_requested": bool(execute),
        "dispatch": {"executed": False, "status": "skipped", "detail": "execute=false"},
        "policy_trace": intent.get("policy_trace"),
        "failover": intent.get("failover"),
        "mission": intent.get("mission"),
    }
    if accepted and execute:
        response["dispatch"] = _dispatch_control_intent_action(action)

    audit_record = {
        "decision_id": response["decision_id"],
        "recommended_action": response["recommended_action"],
        "policy_profile": response["policy_profile"],
        "profile_version": response["profile_version"],
        "accepted": response["accepted"],
        "denied_by": response["denied_by"],
        "cooldown_until": response["cooldown_until"],
        "reasons": response["reasons"],
        "policy_eval": response["policy_eval"],
        "policy_trace": response.get("policy_trace"),
        "failover": response.get("failover"),
        "mission": response.get("mission"),
        "execute_requested": response["execute_requested"],
        "dispatch": response["dispatch"],
        "endpoint": "control-intent/v2",
    }
    audit_path = control_intent_service.append_control_intent_audit(audit_record)
    response["audit_path"] = str(audit_path)
    return JSONResponse(status_code=200 if accepted else 403, content=response)


@router.get("/api/system/policy-explain")
async def api_system_policy_explain(request: Request):
    """Expose active control-plane policy snapshot for operator-grade explainability."""
    state._validate_internal_access(request)
    capture_dir = _get_capture_dir()
    anomaly_v2 = _read_tail_json(capture_dir / "wicap_anomaly_events_v2.jsonl")
    prediction = _read_tail_json(capture_dir / "wicap_predictions.jsonl")
    payload = {
        "generated_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "control_plane": _control_plane_state(),
        "active_contracts": {
            "control_v1": str(control_intent_service.DEFAULT_CONTROL_CONTRACT_PATH),
            "control_v2": str(control_intent_service.DEFAULT_CONTROL_CONTRACT_V2_PATH),
        },
        "failover": _load_failover_state(),
        "intel_worker": {
            "latest_anomaly_ts": anomaly_v2.get("ts") if isinstance(anomaly_v2, dict) else None,
            "latest_prediction_ts": prediction.get("ts") if isinstance(prediction, dict) else None,
        },
    }
    return JSONResponse(status_code=200, content=payload)


@router.get("/api/system/failover-state")
async def api_system_failover_state(request: Request):
    """Return deterministic failover profile state for control-plane debugging."""
    state._validate_internal_access(request)
    payload = _load_failover_state()
    payload["generated_ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return JSONResponse(status_code=200, content=payload)


@router.get("/health")
async def health():
    """Health check endpoint."""
    scav_status = scavenger_service.scavenger_state.status
    try:
        await state.run_db(lambda conn: None)
        return {
            "status": "healthy",
            "database": "connected",
            "scavenger": scav_status,
        }
    except Exception:
        return {
            "status": "degraded",
            "database": "disconnected",
            "scavenger": scav_status,
        }
