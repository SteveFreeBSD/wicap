import asyncio
import logging
import os
import queue
import re
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pyodbc
import socketio
from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

sys.path.insert(0, "/app")
from app.services import memprof
from nexus.intel.evidence import EvidenceCollector


def _get_env(*names: str, default: str = "") -> str:
    """Return the first non-empty env var from names, else default."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _get_sql_password() -> str:
    """Get SQL password from environment, fail if not set.

    SECURITY: No default passwords allowed. This ensures credentials
    must be explicitly provided via environment variables.

    Raises:
        ValueError: If WICAP_SQL_PASSWORD is not set or is too short.
    """
    password = os.environ.get("WICAP_SQL_PASSWORD")
    if not password:
        raise ValueError(
            "WICAP_SQL_PASSWORD environment variable is required. "
            "No default passwords are allowed for security. "
            "Please set WICAP_SQL_PASSWORD in your environment or .env file."
        )
    if len(password) < 12:
        raise ValueError(
            "WICAP_SQL_PASSWORD must be at least 12 characters long "
            f"(current length: {len(password)}). This is a security requirement."
        )
    return password


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _parse_allowlist(value: str) -> list[str]:
    return [entry.strip() for entry in value.split(",") if entry.strip()]


# =============================================================================
# Configuration
# =============================================================================
class Config:
    # Dashboard configuration - mirrors nexus.config for compatibility.
    sql_host: str = _get_env("WICAP_SQL_SERVER", "WICAP_SQL_HOST", default="192.168.4.25,1433")
    sql_database: str = os.environ.get("WICAP_SQL_DATABASE", "WifiInsanityDB")
    sql_user: str = _get_env("WICAP_SQL_USER", "WICAP_SQL_USERNAME", default="steve_linux")
    sql_driver: str = os.environ.get("WICAP_SQL_DRIVER", "ODBC Driver 18 for SQL Server")
    trust_cert: str = os.environ.get("WICAP_SQL_TRUST_CERT", "yes")
    db_pool_size: int = _parse_int(os.environ.get("WICAP_UI_DB_POOL_SIZE"), 5)

    def __init__(self):
        self.sql_password = _get_sql_password()

    @property
    def connection_string(self) -> str:
        # Standardize trust_cert to YES/NO for ODBC Driver 18
        trust = "yes" if str(self.trust_cert).lower() in ("yes", "true", "1", "y", "on") else "no"
        return (
            f"DRIVER={{{self.sql_driver}}};"
            f"SERVER={self.sql_host};"
            f"DATABASE={self.sql_database};"
            f"UID={self.sql_user};"
            f"PWD={self.sql_password};"
            f"TrustServerCertificate={trust};"
            f"Encrypt=yes;"
            "Connection Timeout=30;"
        )


config = Config()
INTERNAL_SECRET = os.environ.get("WICAP_INTERNAL_SECRET", "")
INTERNAL_SECRET_REQUIRED = _parse_bool(os.environ.get("WICAP_INTERNAL_SECRET_REQUIRED"), default=True)
INTERNAL_ALLOWLIST = _parse_allowlist(os.environ.get("WICAP_INTERNAL_ALLOWLIST", "127.0.0.1,::1"))

pyodbc.pooling = True
logger = logging.getLogger(__name__)
_TRANSIENT_DB_SQLSTATES = {"08S01", "08003", "08006", "HYT00", "HYT01"}


def _extract_sqlstate(exc: Exception) -> str:
    """Best-effort SQLSTATE extraction from pyodbc exceptions."""
    for arg in getattr(exc, "args", ()) or ():
        if isinstance(arg, str):
            match = re.search(r"\b([0-9A-Z]{5})\b", arg.upper())
            if match:
                return match.group(1)
    return ""


def _is_transient_db_error(exc: Exception) -> bool:
    """Return True for retryable connection/link level SQL failures."""
    return _extract_sqlstate(exc) in _TRANSIENT_DB_SQLSTATES


APP_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = APP_ROOT / "static"
TEMPLATES_DIR = APP_ROOT / "templates"


templates = Jinja2Templates(directory=TEMPLATES_DIR)
evidence_collector = EvidenceCollector()


# =============================================================================
# Internal Auth
# =============================================================================
def _validate_internal_access(request: Request) -> None:
    client_host = request.client.host if request.client else ""
    if INTERNAL_ALLOWLIST and client_host not in INTERNAL_ALLOWLIST:
        raise HTTPException(status_code=403, detail="Client not allowed")

    provided_secret = request.headers.get("X-WICAP-SECRET", "")
    if INTERNAL_SECRET:
        if provided_secret != INTERNAL_SECRET:
            raise HTTPException(status_code=401, detail="Unauthorized")
    elif INTERNAL_SECRET_REQUIRED:
        raise HTTPException(status_code=503, detail="WICAP_INTERNAL_SECRET not configured")


def _validate_internal_emit(request: Request) -> None:
    _validate_internal_access(request)


def _validate_admin_request(request: Request) -> None:
    _validate_internal_access(request)


def _require_admin(request: Request) -> None:
    _validate_admin_request(request)


def _normalize_source(source: str | None) -> str:
    value = (source or "live").strip().lower()
    return "replay" if value == "replay" else "live"


def _source_filter_sql(source: str) -> tuple[str, tuple]:
    """Return SQL WHERE clause and parameters for source filtering."""
    if source == "replay":
        return "payload_run_id LIKE ?", ("replay-%",)
    return "(payload_run_id IS NULL OR payload_run_id NOT LIKE ?)", ("replay-%",)


# =============================================================================
# Database
# =============================================================================
class DBPool:
    """Simple connection pool for blocking SQL Server access."""

    def __init__(self, conn_str: str, max_size: int):
        self.conn_str = conn_str
        self.max_size = max(1, max_size)
        self._pool: queue.Queue = queue.Queue(maxsize=self.max_size)
        self._created = 0
        self._lock = threading.Lock()

    def acquire(self):
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            with self._lock:
                if self._created < self.max_size:
                    self._created += 1
                    try:
                        return pyodbc.connect(self.conn_str)
                    except Exception:
                        self._created -= 1
                        raise
            return self._pool.get()

    def release(self, conn) -> None:
        if conn is None:
            return
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            try:
                conn.close()
            except Exception:
                pass
            finally:
                with self._lock:
                    if self._created > 0:
                        self._created -= 1

    def discard(self, conn) -> None:
        """Close a broken connection and decrement pool accounting."""
        if conn is None:
            return
        try:
            conn.close()
        except Exception:
            pass
        finally:
            with self._lock:
                if self._created > 0:
                    self._created -= 1

    @staticmethod
    def should_discard_error(exc: Exception) -> bool:
        return _is_transient_db_error(exc)

    def close_all(self) -> None:
        while True:
            try:
                conn = self._pool.get_nowait()
            except queue.Empty:
                break
            try:
                conn.close()
            except Exception:
                pass
        self._created = 0


db_pool = DBPool(config.connection_string, config.db_pool_size)


def get_db_connection():
    # Get SQL Server connection.
    return db_pool.acquire()


def _run_db(func):
    """Run a DB function with managed connection."""
    conn = get_db_connection()
    try:
        return func(conn)
    except Exception as exc:
        if db_pool.should_discard_error(exc):
            sqlstate = _extract_sqlstate(exc) or "unknown"
            logger.warning("Discarding DB connection after transient SQL error: %s", sqlstate)
            db_pool.discard(conn)
            conn = None
        raise
    finally:
        db_pool.release(conn)


async def run_db(func, retries: int = 1):
    """Execute blocking DB work in a threadpool with optional retries."""
    attempts = max(1, int(retries) + 1)
    for attempt in range(attempts):
        try:
            return await run_in_threadpool(_run_db, func)
        except Exception as exc:
            if attempt >= attempts - 1 or not db_pool.should_discard_error(exc):
                raise
            await asyncio.sleep(min(0.25 * (attempt + 1), 1.0))


# =============================================================================
# WebSocket Manager
# =============================================================================
class ConnectionManager:
    # Manage WebSocket connections for live updates.
    def __init__(self):
        self.active_connections: list[Any] = []

    async def connect(self, websocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass  # WebSocket disconnected, ignore


manager = ConnectionManager()


# =============================================================================
# Socket.IO
# =============================================================================
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")


@sio.event
async def connect(sid, environ):
    print(f"✅ Client connected: {sid}")
    await sio.emit("welcome", {"data": "Connected to WICAP Telemetry Stream"}, to=sid)


@sio.event
async def disconnect(sid):
    print(f"❌ Client disconnected: {sid}")


# =============================================================================
# Lifespan
# =============================================================================
@asynccontextmanager
async def lifespan(app):
    # Application startup/shutdown.
    print("🚀 WICAP Dashboard starting...")
    print(f"🧱 DB pool size: {db_pool.max_size}")
    memprof.start()
    memprof.try_start_deferred(reason="startup")
    if INTERNAL_SECRET_REQUIRED and not INTERNAL_SECRET:
        print("❌ WICAP_INTERNAL_SECRET_REQUIRED is set but WICAP_INTERNAL_SECRET is missing.")
    elif not INTERNAL_SECRET:
        print("⚠️  WICAP_INTERNAL_SECRET is not set; internal emit endpoint is unsecured.")
    if INTERNAL_ALLOWLIST:
        print(f"🔒 Internal emit allowlist: {', '.join(INTERNAL_ALLOWLIST)}")
    # Test DB connection
    try:
        await run_db(lambda conn: None)
        print("✅ SQL Server connection verified")
    except Exception as e:
        print(f"⚠️  SQL Server connection failed: {e}")
    yield
    db_pool.close_all()
    print("👋 WICAP Dashboard shutting down...")
