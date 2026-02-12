import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

import app.services.admin as admin_service
import app.services.docker_client as docker_client
import app.services.state as state
from nexus.intel.feature_engineering import build_feature_store

router = APIRouter()


def _parse_time_offset(value: str, now_ts: float) -> float:
    value = value.strip().lower()
    if value.endswith("d"):
        return now_ts - (float(value[:-1]) * 86400.0)
    if value.endswith("h"):
        return now_ts - (float(value[:-1]) * 3600.0)
    if value.endswith("m"):
        return now_ts - (float(value[:-1]) * 60.0)
    return float(value)


def _compact_time_label(ts_text: str) -> str:
    """Normalize raw timestamps to compact local HH:MM:SS display."""
    text = str(ts_text or "").strip()
    if not text:
        return ""

    # Native line timestamps: "YYYY-MM-DD HH:MM:SS,mmm" or "YYYY-MM-DD HH:MM:SS"
    # Treat these as UTC and convert to local display time for compact UI consistency.
    if " " in text and "-" in text:
        parsed_line = None
        for pattern in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed_line = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
        if parsed_line is not None:
            try:
                return parsed_line.replace(tzinfo=timezone.utc).astimezone().strftime("%H:%M:%S")
            except Exception:
                return parsed_line.strftime("%H:%M:%S")

    # Docker timestamp prefix: "YYYY-MM-DDTHH:MM:SS(.nnn)?(Z|+00:00)"
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$",
        text,
    )
    if match:
        base, frac, zone = match.groups()
        frac_part = ""
        if frac:
            frac_part = "." + frac[:6].ljust(6, "0")
        zone_part = ""
        if zone:
            if zone == "Z":
                zone_part = "+00:00"
            elif len(zone) == 5 and zone[3] != ":":
                zone_part = f"{zone[:3]}:{zone[3:]}"
            else:
                zone_part = zone
        try:
            parsed = datetime.fromisoformat(base + frac_part + zone_part)
            local_dt = parsed.astimezone() if parsed.tzinfo is not None else parsed
            return local_dt.strftime("%H:%M:%S")
        except Exception:
            pass

    return text


@router.get("/api/admin/captures", dependencies=[Depends(state._require_admin)])
async def api_list_captures():
    # List files in /app/captures.
    files = []
    if not admin_service.CAPTURE_DIR.exists():
        return []

    for entry in admin_service.CAPTURE_DIR.glob("*"):
        if entry.is_file():
            stat = entry.stat()
            # Simple human readable size
            size_str = f"{stat.st_size} B"
            if stat.st_size > 1024:
                size_str = f"{round(stat.st_size / 1024, 1)} KB"
            if stat.st_size > 1024 * 1024:
                size_str = f"{round(stat.st_size / (1024 * 1024), 1)} MB"

            files.append(
                {
                    "name": entry.name,
                    "size": size_str,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                }
            )
    # Sort by modified desc
    files.sort(key=lambda item: item["modified"], reverse=True)
    return files


@router.get("/api/admin/captures/{filename}/download", dependencies=[Depends(state._require_admin)])
async def api_download_capture(filename: str):
    if not admin_service._is_safe_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_path = admin_service._resolve_capture_path(filename)
    if file_path is None:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path=file_path, filename=filename, media_type="application/octet-stream")


@router.delete("/api/admin/captures/{filename}", dependencies=[Depends(state._require_admin)])
async def api_delete_capture(filename: str):
    # Sanitize filename
    if not admin_service._is_safe_filename(filename):
        return {"error": "Invalid filename"}

    file_path = admin_service._resolve_capture_path(filename)
    if file_path is None:
        return {"error": "Invalid filename"}
    if file_path.exists():
        os.remove(file_path)
        return {"status": "deleted"}
    return {"error": "File not found"}


@router.post("/api/admin/replay/{filename}", dependencies=[Depends(state._require_admin)])
async def api_replay_capture(filename: str):
    if not admin_service._is_safe_filename(filename):
        return {"status": "error", "message": "Invalid filename"}

    if not filename.lower().endswith(admin_service.REPLAY_ALLOWED_SUFFIXES):
        return {"status": "error", "message": "Unsupported capture format"}

    file_path = admin_service._resolve_capture_path(filename)
    if file_path is None:
        return {"status": "error", "message": "Invalid filename"}
    if not file_path.exists():
        return {"status": "error", "message": "File not found"}

    secret_required = os.getenv("WICAP_INTERNAL_SECRET_REQUIRED", "true").lower() in (
        "1",
        "true",
        "yes",
    )
    if secret_required and not os.getenv("WICAP_INTERNAL_SECRET"):
        return {
            "status": "error",
            "message": "WICAP_INTERNAL_SECRET is missing; replay cannot push to UI.",
        }

    replay_module = admin_service.REPO_ROOT / "replay_driver.py"
    if not replay_module.exists():
        return {"status": "error", "message": "Replay driver not found"}

    log_dir = Path(os.getenv("WICAP_REPLAY_LOG_DIR", "/tmp"))
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return {"status": "error", "message": "Unable to create replay log directory"}

    safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"wicap_replay_{safe_name}_{timestamp}.log"

    try:
        log_handle = open(log_path, "a")
    except Exception:
        return {"status": "error", "message": "Unable to open replay log file"}

    cmd = [
        sys.executable,
        "-m",
        "replay_driver",
        "--pcap",
        str(file_path),
        "--ui",
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(admin_service.REPO_ROOT),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:
        log_handle.close()
        return {"status": "error", "message": f"Failed to start replay: {exc}"}
    finally:
        log_handle.close()

    return {
        "status": "ok",
        "message": f"Replay started for {filename} (PID {proc.pid}). View /replay for playback.",
        "log_path": str(log_path),
    }


@router.get("/api/admin/logs", dependencies=[Depends(state._require_admin)])
async def api_get_logs():
    # Get wicap-core logs via Docker or Local File
    raw_logs = ""
    log_lookback_seconds = max(60, int(os.getenv("WICAP_ADMIN_LOG_LOOKBACK_SECONDS", "3600")))

    # Try Docker first
    try:
        client = docker_client.get_docker_client()
        if client:
            raw_logs = ""
            # Try to get logs from both scout and processor (and handle potential compose naming variations)
            for name in ["wicap-scout", "wicap-processor-1", "wicap-wicap-processor-1", "wicap-core"]:
                try:
                    container = client.containers.get(name)
                    c_logs = container.logs(
                        tail=200,
                        since=max(0, int(time.time()) - int(log_lookback_seconds)),
                        timestamps=True,
                    ).decode("utf-8", errors="replace")
                    if c_logs:
                        raw_logs += f"\n--- {name} ---\n{c_logs}"
                except Exception:
                    continue
    except Exception:
        # Fallback to local file: Check logs/soak/ and logs/ for recent core logs
        log_search_paths = [
            Path("wicap_core.log"),
            Path("../wicap_core.log"),
            Path("logs/soak"),
            Path("../logs/soak"),
            Path("logs"),
            Path("../logs"),
        ]

        candidates = []
        for item in log_search_paths:
            if item.is_file():
                candidates.append(item)
            elif item.is_dir():
                # Find all core_*.log or wicap_core.log files in directory
                candidates.extend(item.glob("core_*.log"))
                candidates.extend(item.glob("wicap_core.log"))

        # Sort by modification time, newest first
        candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)

        log_paths = candidates
        for path in log_paths:
            if path.exists():
                try:
                    with open(path, errors="replace") as handle:
                        # Simple tail
                        lines = handle.readlines()
                        raw_logs = "".join(lines[-200:])
                    break
                except Exception:
                    pass

    if not raw_logs:
        return []

    try:
        # specific ANSI strip regex
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        parsed_logs = []

        for line in raw_logs.split("\n"):
            if not line.strip():
                continue
            clean_line = ansi_escape.sub("", line)
            docker_ts = ""
            docker_prefix_match = re.match(
                r"^(\d{4}-\d{2}-\d{2}T[0-9:\.\+\-Z]+)\s+(.*)$",
                clean_line,
            )
            if docker_prefix_match:
                docker_ts = str(docker_prefix_match.group(1))
                clean_line = str(docker_prefix_match.group(2))

            # Parse [SERVICE] YYYY-MM-DD HH:MM:SS [LEVEL] module: message
            # Regex to capture: Service, Timestamp, Level, Rest
            match = re.search(
                r"^\[(\w+)\]\s+(?:(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)\s*)?\[(\w+)\]\s+(.*)",
                clean_line,
            )

            if match:
                service, ts, level, msg = match.groups()
                # Parse Message further to drop module if possible?
                # e.g. "wicap.scout: message" -> remove "wicap.scout: "
                if ":" in msg:
                    parts = msg.split(":", 1)
                    if "." in parts[0] or "nexus" in parts[0]:
                        msg = parts[1].strip()

                parsed_logs.append(
                    {
                        "service": service,
                        "time": _compact_time_label(ts if ts else docker_ts),
                        "level": level,
                        "message": msg,
                    }
                )
            else:
                # Fallback for non-standard lines
                parsed_logs.append(
                    {
                        "service": "SYSTEM",
                        "time": "",
                        "level": "INFO",
                        "message": clean_line,
                    }
                )

        return parsed_logs
    except Exception as exc:
        print(f"Log parsing error: {exc}")
        return []


@router.get("/api/admin/features", dependencies=[Depends(state._require_admin)])
async def api_export_feature_windows(
    since: str = "1h",
    until: str = "",
    limit: int = 1000,
    scope: str = "",
    bssid: str = "",
):
    """
    Export streaming feature windows for model training/debugging.

    since/until accept epoch seconds or offsets like "1h", "7d".
    """
    now_ts = time.time()
    try:
        since_ts = _parse_time_offset(since, now_ts) if since else now_ts - 3600.0
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid since value: {exc}") from exc
    try:
        until_ts = _parse_time_offset(until, now_ts) if until else now_ts
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid until value: {exc}") from exc

    limit = max(1, min(limit, 5000))
    scope = scope.strip().lower() or None
    bssid = bssid.strip().lower() or None

    store = build_feature_store(os.getenv("WICAP_REDIS_URL"))
    if store is None:
        raise HTTPException(status_code=503, detail="Feature store is not configured")

    windows = store.export_windows(
        since_ts,
        until_ts,
        scope=scope,
        bssid=bssid,
        limit=limit,
    )
    return {
        "count": len(windows),
        "since": since_ts,
        "until": until_ts,
        "scope": scope,
        "bssid": bssid,
        "windows": windows,
    }


@router.post("/api/admin/analyze/{filename}", dependencies=[Depends(state._require_admin)])
async def api_analyze_capture(filename: str):
    if not admin_service._is_safe_filename(filename):
        return {"status": "error", "message": "Invalid filename"}

    file_path = admin_service._resolve_capture_path(filename)
    if file_path is None or not file_path.exists():
        return {"status": "error", "message": "File not found"}

    return {
        "status": "error",
        "message": "Offline analysis is not wired. Use `python -m replay_driver --pcap <path> --sql` on the core host.",
    }
