from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

import app.services.state as state

router = APIRouter()


class EmitRequest(BaseModel):
    event: str
    data: dict[str, Any]


@router.post("/api/internal/emit")
async def internal_emit(request: Request, payload: EmitRequest):
    """Internal webhook for wicap-core to push events to UI clients."""
    try:
        state._validate_internal_emit(request)
        await state.sio.emit(payload.event, payload.data)
        return {"status": "ok"}
    except HTTPException as exc:
        raise exc
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
