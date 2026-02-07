from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

import app.services.scavenger as scavenger_service
import app.services.state as state
from nexus.utils import json_compat

router = APIRouter()


@router.get("/api/scavenger/status")
async def api_scavenger_status():
    """Get Scavenger analysis status."""
    clients = 0
    # Prefer DB count if available
    if scavenger_service.scavenger_dao:

        def _query(conn):
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM client_profiles")
            row = cursor.fetchone()
            return row[0] if row else 0

        try:
            clients = await state.run_db(_query)
        except Exception:
            pass

    return {
        "status": scavenger_service.scavenger_state.status,
        "progress": scavenger_service.scavenger_state.progress,
        "clients": clients,
        "error": scavenger_service.scavenger_state.error,
    }


@router.post("/api/scavenger/start")
async def api_scavenger_start(request: Request):
    """Start Scavenger analysis."""
    import threading

    if scavenger_service.scavenger_state.status == "running":
        return {"status": "error", "message": "Analysis already running"}

    try:
        config = await request.json()
    except Exception:
        config = {}

    file_selection = config.get("file_selection", "10")
    max_packets = config.get("max_packets", 100000)
    agents = config.get("agents", ["shadow", "crypt"])

    capture_dir = Path("/app/captures")
    if not capture_dir.exists():
        return {"status": "error", "message": "Capture directory not found"}

    def run_analysis():
        try:
            # Import here to avoid startup delays
            import sys

            sys.path.insert(0, "/app")
            from nexus.scavenger import ScavengerPipeline

            scavenger_service.scavenger_state.status = "running"
            scavenger_service.scavenger_state.progress["message"] = "Initializing pipeline..."

            # Create pipeline
            pipeline = ScavengerPipeline(capture_dir, agents=agents)
            scavenger_service.scavenger_state.pipeline = pipeline

            # Get files based on selection
            all_files = pipeline.streamer.list_captures()

            if file_selection == "all":
                files = all_files
            elif file_selection == "recent":
                cutoff = datetime.now().timestamp() - 86400
                files = [f for f in all_files if f.stat().st_mtime > cutoff]
            else:
                try:
                    limit = int(file_selection)
                    files = all_files[:limit]
                except (ValueError, TypeError):
                    files = all_files[:10]

            scavenger_service.scavenger_state.progress["files_total"] = len(files)
            scavenger_service.scavenger_state.progress["message"] = f"Processing {len(files)} files..."

            packets_processed = [0]

            def progress_callback(packets, filename):
                packets_processed[0] = packets
                scavenger_service.scavenger_state.progress["packets"] = packets
                scavenger_service.scavenger_state.progress["intelligence"] = pipeline._stats[
                    "intelligence_extracted"
                ]

                pct = min(100, int((packets / max(max_packets, 1)) * 100)) if max_packets else 50
                scavenger_service.scavenger_state.progress["percent"] = pct
                scavenger_service.scavenger_state.progress["message"] = f"Processing: {filename}"

                if max_packets and packets >= max_packets:
                    raise StopIteration("Max packets reached")

            try:
                results = pipeline.run(pcap_files=files, progress_callback=progress_callback)
            except StopIteration:
                results = pipeline._generate_summary()

            scavenger_service.scavenger_state.results = results
            scavenger_service.scavenger_state.progress["percent"] = 100
            scavenger_service.scavenger_state.progress["message"] = "Analysis complete"
            scavenger_service.scavenger_state.status = "complete"

        except Exception as exc:
            import traceback

            scavenger_service.scavenger_state.status = "error"
            scavenger_service.scavenger_state.error = str(exc)
            scavenger_service.scavenger_state.progress["message"] = f"Error: {exc}"
            print(f"Scavenger error: {traceback.format_exc()}")

    # Run in background thread
    scavenger_service.scavenger_state.reset()
    scavenger_service.scavenger_state._thread = threading.Thread(target=run_analysis, daemon=True)
    scavenger_service.scavenger_state._thread.start()

    return {"status": "started"}


@router.post("/api/scavenger/stop")
async def api_scavenger_stop():
    """Stop running Scavenger analysis."""
    scavenger_service.scavenger_state.status = "idle"
    scavenger_service.scavenger_state.progress["message"] = "Stopped by user"
    return {"status": "stopped"}


@router.get("/api/scavenger/results")
async def api_scavenger_results():
    """Get Scavenger analysis results."""
    if scavenger_service.scavenger_state.results:
        return scavenger_service.scavenger_state.results
    return {"status": "no_results", "findings": {}}


@router.get("/api/scavenger/dossiers")
async def api_scavenger_dossiers():
    """Get all client dossiers from DB."""
    dossiers = {}
    if scavenger_service.scavenger_dao:
        try:
            clients = await run_in_threadpool(scavenger_service.scavenger_dao.get_all_clients)
            # Convert list to dict map for frontend compatibility
            for client in clients:
                dossiers[client["mac"]] = client
        except Exception:
            pass

    return {"dossiers": dossiers}


@router.get("/api/scavenger/dossier/{mac}")
async def api_scavenger_dossier(mac: str):
    """Get dossier for a specific MAC address from DB."""
    try:
        if scavenger_service.scavenger_dao:

            def _query(conn):
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT mac_addr, vendor, probed_ssids, associated_bssids, first_seen, last_seen, probe_count "
                    "FROM client_profiles WHERE mac_addr = ?",
                    (mac,),
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "mac": row[0],
                        "vendor": row[1],
                        "probed_ssids": json_compat.loads(row[2]) if row[2] else [],
                        "associated_bssids": json_compat.loads(row[3]) if row[3] else [],
                        "first_seen": row[4],
                        "last_seen": row[5],
                        "probe_count": row[6],
                    }
                return None

            result = await state.run_db(_query)
            if result:
                return result
    except Exception as exc:
        return {"error": str(exc)}

    return {"error": "MAC not found"}


@router.post("/api/scavenger/clear")
async def api_scavenger_clear():
    """Clear Scavenger results."""
    if scavenger_service.scavenger_state.pipeline:
        scavenger_service.scavenger_state.pipeline.reset()
    scavenger_service.scavenger_state.reset()
    return {"status": "cleared"}


@router.get("/api/scavenger/export/dossiers")
async def api_scavenger_export_dossiers():
    """Export parameters as JSON download."""
    dossiers = {}
    if scavenger_service.scavenger_dao:
        try:
            clients = await run_in_threadpool(scavenger_service.scavenger_dao.get_all_clients)
            for client in clients:
                dossiers[client["mac"]] = client
        except Exception:
            pass

    return JSONResponse(
        content=dossiers,
        headers={
            "Content-Disposition": f"attachment; filename=scavenger_dossiers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        },
    )


@router.get("/api/scavenger/export/summary")
async def api_scavenger_export_summary():
    """Export analysis summary as JSON download."""
    if not scavenger_service.scavenger_state.results:
        return {"error": "No results to export"}

    return JSONResponse(
        content=scavenger_service.scavenger_state.results,
        headers={
            "Content-Disposition": f"attachment; filename=scavenger_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        },
    )


@router.get("/api/scavenger/settings")
async def api_scavenger_settings():
    """Get Scavenger settings."""
    capture_dir = Path("/app/captures")

    file_count = 0
    total_size = 0
    if capture_dir.exists():
        files = list(capture_dir.glob("*.pcap*")) + list(capture_dir.glob("*.cap"))
        file_count = len(files)
        total_size = sum(f.stat().st_size for f in files if f.is_file())

    return {
        "capture_dir": str(capture_dir),
        "file_count": file_count,
        "total_size_bytes": total_size,
        "total_size_human": f"{total_size / (1024**2):.1f} MB",
        "available_agents": ["shadow", "crypt", "cartographer", "snoopy"],
        "default_agents": ["shadow", "crypt"],
        "default_max_packets": 100000,
    }
