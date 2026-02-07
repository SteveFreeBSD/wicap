import json
import os
import subprocess
import time
from pathlib import Path

from fastapi import APIRouter

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
