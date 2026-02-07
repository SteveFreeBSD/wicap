import asyncio
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Request

import app.services.state as state

router = APIRouter()


try:
    from nexus.strategy_engine import StrategyEngine

    strategy_engine = StrategyEngine()
except ImportError:
    strategy_engine = None
    print("Warning: StrategyEngine not found")


@router.post("/api/strategy/plan")
async def api_strategy_plan(request: Request):
    """Generate a Smart-Crack attack plan."""
    if not strategy_engine:
        return {"error": "Strategy Engine not available"}

    try:
        data = await request.json()
        ssid = data.get("ssid", "")
        bssid = data.get("bssid", "")
        priority = data.get("priority", 50)

        plan = strategy_engine.generate_plan(ssid, bssid, priority)

        # Convert dataclasses to dicts
        return {
            "target": {"ssid": ssid, "bssid": bssid, "priority": priority},
            "rounds": [
                {
                    "name": round_item.name,
                    "strategy": round_item.strategy,
                    "timeout": round_item.timeout_sec,
                    "description": round_item.description,
                    "min_priority": round_item.min_priority,
                    "config": round_item.config,
                }
                for round_item in plan
            ],
        }
    except Exception as exc:
        return {"error": str(exc)}


async def _run_crack_simulation(ssid, bssid, priority):
    """Simulates the execution of the Smart-Crack strategy."""
    try:
        # Generate Plan
        if not strategy_engine:
            return
        plan = strategy_engine.generate_plan(ssid, bssid, priority)

        await state.sio.emit("cmd_log", {"msg": f"> TARGET ACQUIRED: {ssid} ({bssid})", "type": "info"})
        await asyncio.sleep(0.5)
        await state.sio.emit(
            "cmd_log", {"msg": f"> STRATEGY ENGINE: Active. {len(plan)} stages planned.", "type": "success"}
        )
        await asyncio.sleep(0.8)

        for index, round_item in enumerate(plan):
            await state.sio.emit(
                "cmd_log",
                {"msg": f"> [STAGE {index + 1}/{len(plan)}] Initiating {round_item.name.upper()}...", "type": "info"},
            )
            await state.sio.emit("cmd_log", {"msg": f"  └─ Strategy: {round_item.strategy}"})

            # Simulate work (faster than real time)
            duration = min(round_item.timeout_sec / 10, 3)
            await asyncio.sleep(duration)

            await state.sio.emit(
                "cmd_log", {"msg": f"> [STAGE {index + 1}] Complete. Hash not found.", "type": "info"}
            )
            await asyncio.sleep(0.2)

        await state.sio.emit("cmd_log", {"msg": "> ALL STAGES EXHAUSTED.", "type": "warning"})
        await state.sio.emit("cmd_log", {"msg": "> SESSION TERMINATED.", "type": "system"})

    except Exception as exc:
        await state.sio.emit("cmd_log", {"msg": f"> FATAL ERROR: {str(exc)}", "type": "danger"})


@router.post("/api/crack/start")
async def api_crack_start(request: Request, background_tasks: BackgroundTasks):
    """Start a cracking job (Simulation)."""
    try:
        data = await request.json()
        ssid = data.get("ssid", "")
        bssid = data.get("bssid", "")
        priority = data.get("priority", 50)

        # Launch background task
        background_tasks.add_task(_run_crack_simulation, ssid, bssid, priority)

        return {"status": "started", "job_id": f"job_{int(datetime.now().timestamp())}"}
    except Exception as exc:
        return {"error": str(exc)}
