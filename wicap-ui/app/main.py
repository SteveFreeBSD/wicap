# WICAP Dashboard UI - FastAPI Application
# Real-time WiFi capture monitoring and control dashboard
import socketio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routes import admin, api, incidents, internal, pages, scavenger, strategy, system
from app.services import state

app = FastAPI(
    title="WICAP Dashboard",
    description="WiFi Capture and Password Auditing Dashboard",
    version="1.0.0",
    lifespan=state.lifespan,
)

# Socket.IO app
sio_app = socketio.ASGIApp(state.sio, socketio_path="socket.io")
app.mount("/socket.io", sio_app)

# Static assets
app.mount("/static", StaticFiles(directory=state.STATIC_DIR), name="static")

# Routes
app.include_router(internal.router)
app.include_router(pages.router)
app.include_router(api.router)
app.include_router(incidents.router)
app.include_router(admin.router)
app.include_router(scavenger.router)
app.include_router(strategy.router)
app.include_router(system.router)

# Re-exports for compatibility
get_db_connection = state.get_db_connection
run_db = state.run_db
evidence_collector = state.evidence_collector
templates = state.templates
manager = state.manager
sio = state.sio
