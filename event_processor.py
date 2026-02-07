"""
WiFiWizard Phase 3 - Event Processor

Standalone processor that tails event_queue.jsonl, deduplicates,
and writes curated events. Optionally pushes to SQL Server.

Usage:
    python -m wicap.event_processor watch [--push-to-sql] [--dry-run]
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from config import REDIS_QUEUE_KEY, ScoutConfig, get_scout_config, get_sql_config
from nexus.config import get_nexus_config
from nexus.utils import json_compat

# Optional streaming feature engineering (S2.1)
try:
    from nexus.intel.feature_engineering import build_feature_engineer
except ImportError:
    build_feature_engineer = None

# Optional streaming baseline builder (S2.2)
try:
    from nexus.intel.stream_baseline import build_baseline_updater
except ImportError:
    build_baseline_updater = None

# Optional streaming anomaly scoring (S2.3)
try:
    from nexus.intel.stream_scoring import build_stream_scorer
except ImportError:
    build_stream_scorer = None

# Device Fingerprinting (S3.1 / M2)
try:
    from nexus.device_fingerprint import DeviceFingerprinter
except ImportError:
    DeviceFingerprinter = None

# Phase 2: Import refactored components
# Try absolute import first, fall back to relative if src/ not in path
try:
    from src.wicap.core.processing.deduplicator import DedupCache
    from src.wicap.core.processing.persistence import PersistenceManager
except ImportError:
    # Fallback: ensure repo root is on sys.path so `src` namespace is importable.
    repo_root = Path(__file__).resolve().parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from src.wicap.core.processing.deduplicator import DedupCache
    from src.wicap.core.processing.persistence import PersistenceManager

# Configure logging
logger = logging.getLogger('wicap.processor')

# --- Queue Backends ---

class QueueBackend:
    """Abstract base class for event queue operations."""
    def read_batch(self, batch_size: int = 100) -> tuple[list[dict], Any]:
        """Read a batch of events. Returns (events, cursor_or_offset)."""
        raise NotImplementedError

    def commit(self, cursor: Any) -> None:
        """Mark as processed (if applicable)."""
        pass

class FileQueueBackend(QueueBackend):
    """Legacy file-based queue (event_queue.jsonl)."""
    def __init__(self, queue_path: Path, current_offset: int):
        self.queue_path = queue_path
        self._offset = current_offset
        self._file = None
        self._path_str = str(queue_path)

    def read_batch(self, batch_size: int = 100) -> tuple[list[dict], int]:
        events = []
        if not self.queue_path.exists():
            return events, self._offset

        try:
            if not self._file:
                self._file = open(self.queue_path)
                self._file.seek(self._offset)

            # Check for file rotation (inode change or shrinking)
            try:
                stat = self.queue_path.stat()
                if stat.st_size < self._offset:
                    logger.warning(f"Queue truncated, resetting offset: {self.queue_path}")
                    self._offset = 0
                    self._file.seek(0)
            except FileNotFoundError:
                # File rotated away?
                pass

            for _ in range(batch_size):
                line = self._file.readline()
                if not line:
                    break
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            new_offset = self._file.tell()
            self._offset = new_offset
            return events, new_offset

        except Exception as e:
            logger.error(f"File queue error: {e}")
            return [], self._offset

    def commit(self, offset: int) -> None:
        self._offset = offset

class RedisQueueBackend(QueueBackend):
    """Redis-backed queue using LPUSH/BRPOP pattern."""
    def __init__(self, redis_url: str, queue_key: str = REDIS_QUEUE_KEY):
        import redis
        self.redis = redis.from_url(redis_url)
        self.queue_key = queue_key
        logger.info(f"Connected to Redis Queue: {queue_key}")

    def read_batch(self, batch_size: int = 100) -> tuple[list[dict], None]:
        events = []
        try:
            # Pipeline RPOP to get batch
            pipe = self.redis.pipeline()
            for _ in range(batch_size):
                pipe.rpop(self.queue_key)
            results = pipe.execute()

            for res in results:
                if res:
                    try:
                        events.append(json.loads(res))
                    except json.JSONDecodeError:
                        pass
            return events, None
        except Exception as e:
            logger.error(f"Redis queue error: {e}")
            return [], None


# OUI vendor lookup
try:
    from nexus.device_fingerprint import OUI_DATABASE as OUI_VENDORS
except ImportError:
    # Fallback if nexus not available
    OUI_VENDORS = {}

# Interest category mapping (event_type -> category)
INTEREST_CATEGORIES = {
    'new_ssid': 'new_device',
    'new_bssid': 'new_device',
    'hidden_ssid': 'hidden_network',
    'probe_request': 'directed_probe',
    'probe_directed': 'directed_probe',
    'strong_rssi': 'strong_nearby',
    'deauth': 'possible_attack',
    'deauth_spike': 'possible_attack',
    'disassoc': 'possible_attack',
    'open_network': 'open_hotspot',
}


@dataclass
class ProcessorState:
    """Checkpoint state for restart-safe processing."""
    byte_offset: int = 0
    events_processed: int = 0
    events_curated: int = 0
    last_updated: float = 0.0
    queue_file: str = "event_queue.jsonl"

    def to_dict(self) -> dict:
        return {
            'byte_offset': self.byte_offset,
            'events_processed': self.events_processed,
            'events_curated': self.events_curated,
            'last_updated': self.last_updated,
            'queue_file': self.queue_file,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ProcessorState':
        return cls(
            byte_offset=data.get('byte_offset', 0),
            events_processed=data.get('events_processed', 0),
            events_curated=data.get('events_curated', 0),
            last_updated=data.get('last_updated', 0.0),
            queue_file=data.get('queue_file', "event_queue.jsonl"),
        )


@dataclass
class DedupeEntry:
    """Entry for deduplication tracking."""
    ts_epoch: float
    score: int
    event: dict


class EventProcessor:
    """
    Processes events from event_queue.jsonl with deduplication.

    Dedup key: (event_type, bssid, ssid, channel)
    Time window: 300 seconds
    Rule: Keep highest score, or earliest if tied
    Dedup cache is persisted to disk for restart safety.
    """

    DEDUP_WINDOW_SEC = 300  # 5 minutes
    DEDUP_MAX_ENTRIES = 10000  # Hard cap on dedup cache size
    SQL_BATCH_SIZE = 5
    SUMMARY_INTERVAL_SEC = 20  # Summary stats every 20 seconds for snappier UI
    DEAUTH_SPIKE_THRESHOLD = 10  # >10 deauths in window = spike
    DEAUTH_SPIKE_WINDOW_SEC = 30
    PROBE_STORM_THRESHOLD = 5  # >5 SSIDs probed in window = storm
    PROBE_STORM_WINDOW_SEC = 60

    def __init__(self, config: ScoutConfig, push_to_sql: bool = False):
        self.config = config
        self.push_to_sql = push_to_sql
        self._sql_config = None
        self.allow_legacy_sql_batch = os.getenv("WICAP_LEGACY_SQL_BATCH", "false").lower() in (
            "1",
            "true",
            "yes",
        )
        self.legacy_sql_batch_enabled = False
        self._sql_fallback_warned = False

        # Paths
        self.queue_path = config.captures_dir / "event_queue.jsonl"
        self.state_path = config.captures_dir / "processor.state.json"
        self.curated_path = config.captures_dir / "curated_events.jsonl"
        self.dedup_cache_path = config.captures_dir / "dedup_cache.json"
        self.summary_stats_path = config.captures_dir / "summary_stats.jsonl"

        # State
        self.state = self._load_state()

        # Phase 2: Use DedupCache for deduplication
        self.dedup_cache = DedupCache(
            cache_path=self.dedup_cache_path,
            window_sec=self.DEDUP_WINDOW_SEC,
            max_entries=(
                config.dedup_max_entries
                if getattr(config, "dedup_max_entries", 0) > 0
                else self.DEDUP_MAX_ENTRIES
            )
        )

        # Queue Backend
        if config.redis_url:
            try:
                self.queue = RedisQueueBackend(config.redis_url)
                logger.info("Using Redis Queue Backend")
            except ImportError:
                logger.error("Redis configured but 'redis' module missing. Falling back to file.")
                self.queue = FileQueueBackend(self.queue_path, self.state.byte_offset)
            except Exception as e:
                logger.error(f"Redis init failed: {e}. Falling back to file.")
                self.queue = FileQueueBackend(self.queue_path, self.state.byte_offset)
        else:
            self.queue = FileQueueBackend(self.queue_path, self.state.byte_offset)
            logger.info("Using File Queue Backend")

        # Phase 2: Use PersistenceManager for database operations
        self.persistence_manager: PersistenceManager | None = None
        if self.push_to_sql:
            try:
                sql_config = self._get_sql_config()
                # Build connection string
                conn_str = (
                    f"DRIVER={{{sql_config.driver}}};"
                    f"SERVER={sql_config.server};"
                    f"DATABASE={sql_config.database};"
                    f"UID={sql_config.username};"
                    f"PWD={sql_config.password};"
                    f"TrustServerCertificate=yes;"
                    f"Encrypt=yes;"
                    "Connection Timeout=30;"
                )
                self.persistence_manager = PersistenceManager(
                    connection_string=conn_str,
                    batch_size=self.SQL_BATCH_SIZE
                )
                # Try to connect (lazy connection, but validate config)
                logger.info("PersistenceManager initialized (lazy connection)")
            except Exception as e:
                logger.error(f"Failed to initialize PersistenceManager: {e}")
                if self.allow_legacy_sql_batch:
                    logger.warning("Legacy SQL batch enabled; falling back to legacy SQL batch mode")
                    self.persistence_manager = None
                else:
                    raise RuntimeError(
                        "PersistenceManager init failed and legacy SQL batch is disabled. "
                        "Set WICAP_LEGACY_SQL_BATCH=true to allow fallback."
                    ) from e

        # Legacy SQL connection (for methods not yet migrated)
        self._sql_conn = None
        self._sql_batch: list[dict] = []
        self._summary_batch: list[dict] = []
        self.legacy_sql_batch_enabled = (
            self.push_to_sql and self.allow_legacy_sql_batch and self.persistence_manager is None
        )

        # Anomaly tracking: {bssid: [ts, ts, ...]}
        self._deauth_tracker: dict[str, list[float]] = {}
        # Probe storm tracking: {src_mac: [(ts, ssid), ...]}
        self._probe_tracker: dict[str, list[tuple[float, str]]] = {}

        # Summary stats tracking (memory optimized)
        self._summary_window_start: float = 0.0
        self._summary_stats = {
            'count': 0,
            'unique_ssids': set(),
            'unique_bssids': set(),
            'channels': Counter(),
            'vendors': Counter(),
            'categories': Counter()
        }
        self._summary_run_id: str | None = None

        # Streaming feature engineering (optional, S2.1)
        self.feature_engineer = None
        self._feature_engineer_warned = False
        if build_feature_engineer is not None:
            try:
                self.feature_engineer = build_feature_engineer(config.redis_url)
                if self.feature_engineer:
                    logger.info(
                        "Streaming features enabled (window=%ds)",
                        self.feature_engineer.window_sec,
                    )
            except Exception as exc:
                logger.warning(f"Feature engineer init failed: {exc}")

        # Streaming baseline builder (optional, S2.2)
        self.baseline_updater = None
        self._baseline_warned = False
        if build_baseline_updater is not None and self.feature_engineer is not None:
            try:
                self.baseline_updater = build_baseline_updater(
                    self.feature_engineer.store,
                    config.redis_url,
                )
                if self.baseline_updater:
                    logger.info(
                        "Streaming baseline enabled (horizon=%ds)",
                        self.baseline_updater.horizon_sec,
                    )
            except Exception as exc:
                logger.warning(f"Baseline updater init failed: {exc}")

        # Streaming anomaly scoring (optional, S2.3)
        self.stream_scorer = None
        self._stream_scorer_warned = False
        if build_stream_scorer is not None and self.feature_engineer is not None:
            try:
                self.stream_scorer = build_stream_scorer(
                    self.feature_engineer.store,
                    config.redis_url,
                    connection_string=self._try_sql_connection_string(),
                )
                if self.stream_scorer:
                    logger.info("Streaming anomaly scoring enabled.")
            except Exception as exc:
                logger.warning(f"Stream scorer init failed: {exc}")

        # Webhook session (persistent connection)
        import requests
        self._http_session = requests.Session()

        # UI readiness tracking (avoids log spam during startup race)
        self._ui_ready = False
        self._ui_check_time = 0.0  # Last health check attempt
        self._ui_check_backoff = 1.0  # Exponential backoff (seconds)
        ui_base = os.getenv("WICAP_UI_URL", "http://localhost:8080").strip()
        if not ui_base:
            ui_base = "http://localhost:8080"
        self._ui_base_url = ui_base.rstrip("/")
        self._ui_secret = os.getenv("WICAP_INTERNAL_SECRET", "")
        self._ui_secret_required = os.getenv("WICAP_INTERNAL_SECRET_REQUIRED", "true").lower() in (
            "1",
            "true",
            "yes",
        )
        self._ui_secret_warned = False
        if self._ui_secret_required and not self._ui_secret:
            logger.warning(
                "WICAP_INTERNAL_SECRET_REQUIRED is set but WICAP_INTERNAL_SECRET is missing; "
                "UI push is disabled."
            )
            self._ui_secret_warned = True

        # Ensure captures dir exists
        config.captures_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Device Fingerprinter
        self.fingerprinter = None
        self._last_profile_flush = 0
        if DeviceFingerprinter and self.push_to_sql:
            try:
                self.fingerprinter = DeviceFingerprinter(get_nexus_config())
                logger.info("Device Fingerprinting enabled.")
            except Exception as e:
                logger.warning(f"Failed to init DeviceFingerprinter: {e}")
        elif DeviceFingerprinter:
            logger.debug("Device Fingerprinting profile persistence disabled (SQL push off).")

    def _list_rotated_queues(self) -> list[Path]:
        """List rotated queue files (oldest first)."""
        try:
            rotated = sorted(
                self.queue_path.parent.glob("event_queue_*.jsonl"),
                key=lambda p: p.stat().st_mtime,
            )
            return rotated
        except Exception as e:
            logger.warning(f"Failed to list rotated queues: {e}")
            return []

    def _select_queue_path(self) -> Path:
        """Select the next queue file to process, honoring rotations."""
        active = self.queue_path
        active_name = active.name
        rotated = self._list_rotated_queues()

        # If state points to a rotated file that still exists, continue it.
        if self.state.queue_file and self.state.queue_file != active_name:
            candidate = self.queue_path.parent / self.state.queue_file
            if candidate.exists():
                return candidate

        # Detect rotation while we were reading the active queue.
        if self.state.queue_file == active_name and active.exists():
            try:
                size = active.stat().st_size
            except Exception:
                size = None
            if size is not None and size < self.state.byte_offset:
                if rotated:
                    newest = rotated[-1]
                    logger.info(
                        f"Queue rotation detected; switching to {newest.name} at offset {self.state.byte_offset}"
                    )
                    self.state.queue_file = newest.name
                    return newest
                logger.warning("Queue file truncated; resetting offset to 0")
                self.state.byte_offset = 0

        # If rotated files exist, process the oldest backlog first.
        if rotated:
            oldest = rotated[0]
            if self.state.queue_file != oldest.name:
                self.state.queue_file = oldest.name
                self.state.byte_offset = 0
            return oldest

        # Default to active queue.
        self.state.queue_file = active_name
        return active

    def _execute_with_retry(self, operation_func, max_retries=3) -> bool:
        """Execute a SQL operation with connection retry logic."""
        if not self.push_to_sql:
             return True

        for attempt in range(max_retries):
            try:
                self._ensure_sql_connection()
                operation_func(self._sql_conn.cursor())
                self._sql_conn.commit()
                return True
            except Exception as e:
                logger.warning(f"SQL operation failed (attempt {attempt+1}/{max_retries}): {e}")
                self._close_sql_connection()
                time.sleep(1 * (attempt + 1)) # Backoff

        logger.error("SQL operation failed after all retries")
        return False

    def _ensure_sql_connection(self) -> None:
        """Ensure usable SQL connection exists."""
        if self._sql_conn:
            return

        import pyodbc
        try:
            conn_str = self._sql_connection_string()
            self._sql_conn = pyodbc.connect(conn_str, timeout=30)

            # Verify schema on connect
            self._ensure_sql_table()

        except Exception as e:
            logger.error(f"SQL connection failed: {e}")
            raise

    def _close_sql_connection(self) -> None:
        """Safely close SQL connection."""
        if self._sql_conn:
            try:
                self._sql_conn.close()
            except Exception:
                pass
            self._sql_conn = None

    def _sql_connection_string(self) -> str:
        """Build SQL Server connection string."""
        sql_config = self._get_sql_config()
        # SECURITY: TrustServerCertificate defaults to YES (for dev environment)
        os.getenv("WICAP_SQL_TRUST_CERT", "true").lower()
        return (
            f"DRIVER={{{sql_config.driver}}};"
            f"SERVER={sql_config.server};"
            f"DATABASE={sql_config.database};"
            f"UID={sql_config.username};"
            f"PWD={sql_config.password};"
            f"TrustServerCertificate=yes;"
        )

    def _get_sql_config(self):
        """Lazily load SQL config only when SQL features are actually used."""
        if self._sql_config is None:
            self._sql_config = get_sql_config()
        return self._sql_config

    def _try_sql_connection_string(self) -> str | None:
        """
        Best-effort SQL connection string for optional components.

        In non-SQL runs (e.g., replay/dry-run), missing SQL credentials should
        disable SQL-backed optional features rather than abort processor startup.
        """
        try:
            return self._sql_connection_string()
        except Exception as exc:
            if self.push_to_sql:
                raise
            logger.debug(f"SQL config unavailable for optional components: {exc}")
            return None

    def _load_state(self) -> ProcessorState:
        """Load processor state from checkpoint file."""
        if self.state_path.exists():
            try:
                with open(self.state_path) as f:
                    data = json.load(f)
                state = ProcessorState.from_dict(data)
                logger.info(f"Restored state: offset={state.byte_offset}, processed={state.events_processed}")
                return state
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
        return ProcessorState()

    def _save_state(self) -> None:
        """Save processor state atomically via temp file + rename."""
        self.state.last_updated = time.time()
        temp_path = self.state_path.with_suffix('.tmp')

        try:
            with open(temp_path, 'w') as f:
                json.dump(self.state.to_dict(), f)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename
            os.replace(temp_path, self.state_path)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
            # Clean up temp file if it exists
            try:
                temp_path.unlink()
            except Exception:
                pass

    # ========== Phase 2: Enrichment Methods ==========

    def _lookup_vendor(self, mac: str | None) -> str | None:
        """Look up vendor from MAC address OUI (handles various formats)."""
        if not mac:
            return None

        # Normalize MAC (remove : - .)
        mac_clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')
        if len(mac_clean) < 6:
            return None

        # Try OUI lookup (first 6 hex chars formatted as XX:XX:XX) -- matches device_fingerprint.py format
        oui = f'{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}'
        return OUI_VENDORS.get(oui)

    def _categorize_event(self, event: dict) -> str:
        """Assign interest category based on event type."""
        event_type = event.get('event_type', '')
        return INTEREST_CATEGORIES.get(event_type, 'other')

    def _detect_anomalies(self, event: dict) -> list[str]:
        """Detect anomalies and return list of flags."""
        flags = []
        ts = event.get('ts_epoch', time.time())
        event_type = event.get('event_type', '')
        keys = event.get('keys', {})
        bssid = keys.get('bssid')
        src_mac = keys.get('sa')
        ssid = keys.get('ssid')

        # Deauth spike detection
        if event_type in ('deauth', 'deauth_spike', 'disassoc') and bssid:
            # Add to tracker
            if bssid not in self._deauth_tracker:
                self._deauth_tracker[bssid] = []
            self._deauth_tracker[bssid].append(ts)

            # Clean old entries
            cutoff = ts - self.DEAUTH_SPIKE_WINDOW_SEC
            self._deauth_tracker[bssid] = [t for t in self._deauth_tracker[bssid] if t > cutoff]

            # Check threshold
            if len(self._deauth_tracker[bssid]) > self.DEAUTH_SPIKE_THRESHOLD:
                flags.append('deauth_spike')

        # Probe storm detection
        if event_type in ('probe_request', 'probe_directed') and src_mac and ssid:
            # Add to tracker
            if src_mac not in self._probe_tracker:
                self._probe_tracker[src_mac] = []
            self._probe_tracker[src_mac].append((ts, ssid))

            # Clean old entries
            cutoff = ts - self.PROBE_STORM_WINDOW_SEC
            self._probe_tracker[src_mac] = [(t, s) for t, s in self._probe_tracker[src_mac] if t > cutoff]

            # Check unique SSIDs probed
            unique_ssids = {s for _, s in self._probe_tracker[src_mac]}
            if len(unique_ssids) > self.PROBE_STORM_THRESHOLD:
                flags.append('probe_storm')

        return flags

    def _enrich_event(self, event: dict) -> dict:
        """Add wizard enrichment fields to event."""
        keys = event.get('keys', {})

        # Vendor lookup (try BSSID first, then source MAC)
        vendor = self._lookup_vendor(keys.get('bssid')) or self._lookup_vendor(keys.get('sa'))

        # Interest category
        category = self._categorize_event(event)

        # Anomaly flags: already computed in process_batch and stored in event
        # Don't re-call _detect_anomalies here
        anomaly_flags = event.get('anomaly_flags', [])

        # Dwell file path: set to null until queue provides actual path
        # (The event timestamp != actual dwell start time, so we can't infer it)
        dwell_file = event.get('dwell_file')  # Will be null unless queue sets it

        # Return enriched event
        enriched = dict(event)
        enriched['vendor'] = vendor
        enriched['interest_category'] = category
        enriched['anomaly_flags'] = anomaly_flags
        enriched['dwell_file'] = dwell_file

        return enriched

    # ========== End Phase 2 Enrichment ==========


    def _write_curated_event(self, event: dict) -> None:
        """Write an enriched curated event to output file."""
        # Enrich event with Phase 2 wizard fields
        enriched = self._enrich_event(event)

        with open(self.curated_path, 'a') as f:
            f.write(json_compat.dumps(enriched, separators=(',', ':')) + '\n')
        self.state.events_curated += 1

        # Track for summary stats (counters)
        self._update_summary_stats(enriched)
        self._check_summary_window(enriched['ts_epoch'])

        # Push to UI (Real-time)
        self._push_to_ui_webhook("new_packet", enriched)

        # Check for anomalies and push them too
        if enriched.get('anomaly_flags'):
            for flag in enriched['anomaly_flags']:
                self._push_to_ui_webhook("anomaly", {
                    "type": flag,
                    "target": enriched.get('keys', {}).get('bssid') or "Unknown",
                    "timestamp": enriched.get('ts_epoch'),
                    "run_id": enriched.get('run_id'),
                })

        # Streaming feature engineering (S2.1)
        if self.feature_engineer:
            try:
                self.feature_engineer.ingest_event(enriched)
            except Exception as exc:
                if not self._feature_engineer_warned:
                    logger.warning(f"Feature engineer ingest failed: {exc}")
                    self._feature_engineer_warned = True

        # Phase 2: Use PersistenceManager for SQL insertion
        if self.push_to_sql and event.get('event_type') != 'telemetry_pulse':
            if self.persistence_manager:
                try:
                    if event.get('protocol') == 'bt':
                        self.persistence_manager.add_bt_event(enriched)
                    else:
                        self.persistence_manager.add_event(enriched)
                except Exception as e:
                    logger.warning(f"Failed to add event to persistence manager: {e}")
            elif self.legacy_sql_batch_enabled:
                self._sql_batch.append(enriched)
                if len(self._sql_batch) >= self.SQL_BATCH_SIZE:
                    if not self._execute_with_retry(self._flush_sql_batch):
                        logger.warning(
                            "SQL batch failed after retries - dropping "
                            f"{len(self._sql_batch)} events from SQL layer"
                        )
                        self._sql_batch.clear()
            elif not self._sql_fallback_warned:
                logger.error(
                    "SQL persistence unavailable: PersistenceManager is disabled and "
                    "legacy SQL batch fallback is not enabled."
                )
                self._sql_fallback_warned = True

    def _push_to_ui_webhook(self, event_name: str, payload: dict) -> None:
        """
        Fire-and-forget push to UI WebSocket manager.
        Uses readiness check to avoid spamming logs during startup race.
        """
        # Check if UI is ready (with exponential backoff)
        if self._ui_secret_required and not self._ui_secret:
            if not self._ui_secret_warned:
                logger.warning(
                    "WICAP_INTERNAL_SECRET_REQUIRED is set but WICAP_INTERNAL_SECRET is missing; "
                    "UI push is disabled."
                )
                self._ui_secret_warned = True
            return

        if not self._ui_ready:
            now = time.time()
            if now - self._ui_check_time < self._ui_check_backoff:
                return  # Skip silently during backoff

            self._ui_check_time = now
            try:
                resp = self._http_session.get(
                    f"{self._ui_base_url}/health",
                    timeout=1.0
                )
                if resp.status_code == 200:
                    self._ui_ready = True
                    self._ui_check_backoff = 1.0  # Reset backoff
                    logger.info("UI is now ready, enabling real-time push")
                else:
                    self._ui_check_backoff = min(self._ui_check_backoff * 2, 30)  # Max 30s
                    return
            except Exception:
                self._ui_check_backoff = min(self._ui_check_backoff * 2, 30)
                return

        try:
            logger.debug(f"Pushing event: {event_name}")
            headers = {}
            if self._ui_secret:
                headers["X-WICAP-SECRET"] = self._ui_secret

            resp = self._http_session.post(
                f"{self._ui_base_url}/api/internal/emit",
                json={"event": event_name, "data": payload},
                headers=headers,
                timeout=0.5
            )
            if resp.status_code != 200:
                logger.warning(f"UI push failed: {resp.status_code} {resp.text}")
        except Exception as e:
            # UI may have gone down - reset readiness and backoff
            self._ui_ready = False
            self._ui_check_backoff = 1.0
            logger.debug(f"UI push failed, will retry health check: {e}")

    def _init_sql(self) -> bool:
        """Initialize SQL connection. Returns True if successful."""
        if self._sql_conn is not None:
            return True

        try:
            self._ensure_sql_connection()
            logger.info("SQL connection established")
            return True

        except ImportError:
            logger.error("pyodbc not installed. Run: pip install pyodbc")
            return False
        except Exception as e:
            logger.error(f"SQL connection failed: {e}")
            return False

    def _ensure_sql_table(self) -> None:
        """
        Create or migrate curated_events table for idempotent inserts.

        Handles:
        - New install: creates table with event_id CHAR(64) PK
        - Existing v1 (BIGINT IDENTITY): migrates to v2 schema
        """
        if not self._sql_conn:
            return

        cursor = self._sql_conn.cursor()

        try:
            # Check if table exists
            cursor.execute("""
                SELECT 1 FROM sys.tables WHERE name = 'curated_events'
            """)
            table_exists = cursor.fetchone() is not None

            if not table_exists:
                # Fresh install - create v2 schema
                self._create_sql_table_v2(cursor)
                return

            # Table exists - check if it has the correct event_id column
            cursor.execute("""
                SELECT t.name, c.max_length
                FROM sys.columns c
                JOIN sys.types t ON c.user_type_id = t.user_type_id
                WHERE c.object_id = OBJECT_ID('curated_events') AND c.name = 'event_id'
            """)
            row = cursor.fetchone()

            if row is None:
                # v1 schema (no event_id column) - migrate
                logger.warning("Detected v1 schema without event_id - migrating to v2")
                self._migrate_sql_v1_to_v2(cursor)
            elif row[0] == 'bigint':
                # v1 schema with BIGINT IDENTITY event_id - migrate
                logger.warning("Detected v1 schema with BIGINT event_id - migrating to v2")
                self._migrate_sql_v1_to_v2(cursor)
            elif row[0] == 'char' and row[1] == 64:
                # Already v2 schema
                logger.info("SQL table curated_events is v2 schema (OK)")
            else:
                logger.warning(f"Unexpected event_id type: {row[0]}({row[1]})")

            # Always ensure summary_stats exists (even for existing v2 installs)
            self._ensure_summary_stats_table(cursor)
            self._ensure_curated_events_columns(cursor)
            self._ensure_curated_events_indexes(cursor)
            self._ensure_attack_alerts_table(cursor)
            self._ensure_incidents_table(cursor)
            self._ensure_investigations_table(cursor)

        except Exception as e:
            logger.error(f"SQL table check failed: {e}")

    def _create_sql_table_v2(self, cursor) -> None:
        """Create v2 schema with CHAR(64) event_id as PK, plus summary_stats."""
        create_sql = """
        CREATE TABLE curated_events (
            id BIGINT IDENTITY,
            event_id CHAR(64) NOT NULL,
            ts_epoch DECIMAL(19,9) NOT NULL,
            event_type VARCHAR(50) NOT NULL,
            channel INT NOT NULL,
            score INT NOT NULL,
            payload NVARCHAR(MAX) NOT NULL,
            inserted_at DATETIME2 DEFAULT SYSDATETIME(),
            CONSTRAINT PK_curated_events PRIMARY KEY (event_id)
        )
        """
        try:
            cursor.execute(create_sql)
            self._sql_conn.commit()
            logger.info("Created SQL table curated_events (v2 schema)")
        except Exception as e:
            logger.error(f"Failed to create table: {e}")

        # Also create summary_stats
        self._ensure_summary_stats_table(cursor)
        self._ensure_curated_events_columns(cursor)
        self._ensure_curated_events_indexes(cursor)

    def _ensure_curated_events_columns(self, cursor) -> None:
        """Ensure computed columns used by UI queries exist."""
        columns = [
            ("payload_run_id", "AS CAST(JSON_VALUE(payload, '$.run_id') AS NVARCHAR(64)) PERSISTED"),
            ("payload_vendor", "AS CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100)) PERSISTED"),
            ("payload_encryption", "AS CAST(JSON_VALUE(payload, '$.encryption') AS NVARCHAR(64)) PERSISTED"),
            ("payload_keys_sa", "AS CAST(JSON_VALUE(payload, '$.keys.sa') AS NVARCHAR(17)) PERSISTED"),
            ("payload_keys_da", "AS CAST(JSON_VALUE(payload, '$.keys.da') AS NVARCHAR(17)) PERSISTED"),
            ("payload_keys_bssid", "AS CAST(JSON_VALUE(payload, '$.keys.bssid') AS NVARCHAR(17)) PERSISTED"),
            ("payload_keys_ssid", "AS CAST(JSON_VALUE(payload, '$.keys.ssid') AS NVARCHAR(64)) PERSISTED"),
            ("payload_source", "AS CAST(JSON_VALUE(payload, '$.source') AS NVARCHAR(17)) PERSISTED"),
            ("payload_dest", "AS CAST(JSON_VALUE(payload, '$.dest') AS NVARCHAR(17)) PERSISTED"),
            ("payload_effective_bssid", "AS CAST(COALESCE(JSON_VALUE(payload, '$.keys.bssid'), JSON_VALUE(payload, '$.bssid')) AS NVARCHAR(17)) PERSISTED"),
            ("payload_effective_ssid", "AS CAST(COALESCE(JSON_VALUE(payload, '$.keys.ssid'), JSON_VALUE(payload, '$.ssid')) AS NVARCHAR(64)) PERSISTED"),
            ("payload_rssi_int", "AS TRY_CAST(COALESCE(JSON_VALUE(payload, '$.keys.rssi_dbm'), JSON_VALUE(payload, '$.rssi')) AS INT) PERSISTED"),
            ("payload_freq", "AS TRY_CAST(JSON_VALUE(payload, '$.freq') AS INT) PERSISTED"),
            ("payload_band", "AS CAST(JSON_VALUE(payload, '$.band') AS NVARCHAR(16)) PERSISTED"),
            ("payload_wifi6", "AS CAST(JSON_VALUE(payload, '$.fingerprint.is_wifi6') AS BIT) PERSISTED"),
            ("device_identity_id", "AS CAST(JSON_VALUE(payload, '$.device_identity_id') AS NVARCHAR(8)) PERSISTED"),
            ("payload_protocol", "AS CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8)) PERSISTED"),
            ("payload_bt_addr", "AS CAST(JSON_VALUE(payload, '$.bt.addr') AS NVARCHAR(17)) PERSISTED"),
            ("payload_bt_rssi", "AS TRY_CAST(JSON_VALUE(payload, '$.bt.rssi') AS INT) PERSISTED"),
            ("payload_bt_company_id", "AS CAST(JSON_VALUE(payload, '$.bt.company_id') AS NVARCHAR(16)) PERSISTED"),
            ("payload_bt_local_name", "AS CAST(JSON_VALUE(payload, '$.bt.local_name') AS NVARCHAR(128)) PERSISTED"),
            ("payload_bt_adv_type", "AS CAST(JSON_VALUE(payload, '$.bt.adv_type') AS NVARCHAR(16)) PERSISTED"),
            ("payload_bt_addr_type", "AS CAST(JSON_VALUE(payload, '$.bt.addr_type') AS NVARCHAR(16)) PERSISTED"),
        ]

        for column_name, column_def in columns:
            cursor.execute(
                f"""
                IF COL_LENGTH('curated_events', '{column_name}') IS NULL
                    ALTER TABLE curated_events ADD {column_name} {column_def};
                """
            )

    def _ensure_curated_events_indexes(self, cursor) -> None:
        """Ensure indexes exist for computed columns used in UI filters."""
        indexes = [
            ("IX_curated_events_run_id", "payload_run_id"),
            ("IX_curated_events_vendor", "payload_vendor"),
            ("IX_curated_events_keys_sa", "payload_keys_sa"),
            ("IX_curated_events_keys_da", "payload_keys_da"),
            ("IX_curated_events_effective_bssid", "payload_effective_bssid"),
            ("IX_curated_events_effective_ssid", "payload_effective_ssid"),
            ("IX_curated_events_protocol", "payload_protocol"),
            ("IX_curated_events_bt_addr", "payload_bt_addr"),
        ]
        for index_name, column_name in indexes:
            cursor.execute(
                f"""
                IF NOT EXISTS (
                    SELECT 1 FROM sys.indexes
                    WHERE name = '{index_name}' AND object_id = OBJECT_ID('curated_events')
                )
                    CREATE NONCLUSTERED INDEX {index_name} ON curated_events({column_name});
                """
            )

    def _ensure_summary_stats_table(self, cursor) -> None:
        """Create summary_stats table if it doesn't exist."""
        summary_sql = """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='summary_stats' AND xtype='U')
        CREATE TABLE summary_stats (
            stat_id BIGINT IDENTITY PRIMARY KEY,
            window_start DATETIME2 NOT NULL,
            window_end DATETIME2 NOT NULL,
            events_count INT NOT NULL,
            unique_bssids INT NOT NULL,
            unique_ssids INT NOT NULL,
            top_category NVARCHAR(50),
            top_vendor NVARCHAR(100),
            inserted_at DATETIME2 DEFAULT SYSDATETIME()
        )
        """
        try:
            cursor.execute(summary_sql)
            self._sql_conn.commit()
            logger.info("Ensured SQL table summary_stats exists")
        except Exception as e:
            logger.error(f"Failed to ensure summary_stats: {e}")

    def _ensure_attack_alerts_table(self, cursor) -> None:
        """Create attack_alerts table for WIDS alert persistence."""
        alerts_sql = """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='attack_alerts' AND xtype='U')
        CREATE TABLE attack_alerts (
            alert_id NVARCHAR(8) NOT NULL,
            alert_signature NVARCHAR(256),
            alert_type NVARCHAR(50) NOT NULL,
            severity INT NOT NULL,
            title NVARCHAR(200),
            description NVARCHAR(500),
            ts_epoch DECIMAL(19,9) NOT NULL,
            first_seen DATETIME2 NULL,
            last_seen DATETIME2 NULL,
            source_mac NVARCHAR(17),
            target_mac NVARCHAR(17),
            bssid NVARCHAR(17),
            ssid NVARCHAR(64),
            channel INT,
            event_count INT DEFAULT 1,
            acknowledged BIT DEFAULT 0,
            acknowledged_at DATETIME2 NULL,
            inserted_at DATETIME2 DEFAULT SYSDATETIME(),
            CONSTRAINT PK_attack_alerts PRIMARY KEY (alert_id)
        )
        """
        try:
            cursor.execute(alerts_sql)
            cursor.execute(
                """
                IF COL_LENGTH('attack_alerts', 'alert_signature') IS NULL
                ALTER TABLE attack_alerts ADD alert_signature NVARCHAR(256)
                """
            )
            cursor.execute(
                """
                IF COL_LENGTH('attack_alerts', 'first_seen') IS NULL
                ALTER TABLE attack_alerts ADD first_seen DATETIME2 NULL
                """
            )
            cursor.execute(
                """
                IF COL_LENGTH('attack_alerts', 'last_seen') IS NULL
                ALTER TABLE attack_alerts ADD last_seen DATETIME2 NULL
                """
            )
            cursor.execute(
                """
                IF COL_LENGTH('attack_alerts', 'acknowledged_at') IS NULL
                ALTER TABLE attack_alerts ADD acknowledged_at DATETIME2 NULL
                """
            )
            cursor.execute(
                """
                IF NOT EXISTS (
                    SELECT 1 FROM sys.indexes
                    WHERE name = 'IX_attack_alerts_last_seen' AND object_id = OBJECT_ID('attack_alerts')
                )
                CREATE INDEX IX_attack_alerts_last_seen ON attack_alerts(ts_epoch DESC)
                """
            )

            # Ensure incident_id column exists (migration)
            cursor.execute("""
                IF COL_LENGTH('attack_alerts', 'incident_id') IS NULL
                    ALTER TABLE attack_alerts ADD incident_id NVARCHAR(32) NULL;
            """)

            # Index for incident lookup
            cursor.execute("""
                IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_alerts_incident' AND object_id = OBJECT_ID('attack_alerts'))
                    CREATE INDEX IX_alerts_incident ON attack_alerts(incident_id);
            """)

            self._sql_conn.commit()
            logger.info("Ensured SQL table attack_alerts exists")
        except Exception as e:
            logger.error(f"Failed to ensure attack_alerts: {e}")

    def _ensure_investigations_table(self, cursor) -> None:
        """Create investigations table for investigation workflow persistence."""
        inv_sql = """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='investigations' AND xtype='U')
        CREATE TABLE investigations (
            investigation_id NVARCHAR(8) NOT NULL,
            title NVARCHAR(200) NOT NULL,
            alert_type NVARCHAR(50),
            status NVARCHAR(20) DEFAULT 'open',
            severity INT DEFAULT 1,
            primary_mac NVARCHAR(17),
            primary_bssid NVARCHAR(17),
            primary_ssid NVARCHAR(64),
            timeline_json NVARCHAR(MAX),
            pcap_files_json NVARCHAR(MAX),
            notes_json NVARCHAR(MAX),
            created_at DECIMAL(19,9),
            inserted_at DATETIME2 DEFAULT SYSDATETIME(),
            CONSTRAINT PK_investigations PRIMARY KEY (investigation_id)
        )
        """
        try:
            cursor.execute(inv_sql)
            self._sql_conn.commit()
            logger.info("Ensured SQL table investigations exists")
        except Exception as e:
            logger.error(f"Failed to ensure investigations: {e}")

    def _ensure_incidents_table(self, cursor) -> None:
        """Create incidents table for consolidated alerts."""
        sql = """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='incidents' AND xtype='U')
        CREATE TABLE incidents (
            incident_id NVARCHAR(32) NOT NULL,
            status NVARCHAR(16) DEFAULT 'active',
            severity INT NOT NULL,
            title NVARCHAR(200),
            description NVARCHAR(MAX),
            first_seen DATETIME2 NOT NULL,
            last_seen DATETIME2 NOT NULL,
            alert_count INT DEFAULT 0,
            evidence_path NVARCHAR(MAX),
            created_at DATETIME2 DEFAULT SYSDATETIME(),
            updated_at DATETIME2 DEFAULT SYSDATETIME(),
            CONSTRAINT PK_incidents PRIMARY KEY (incident_id)
        );
        """
        try:
            cursor.execute(sql)

            # Indexes
            cursor.execute("""
                IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_incidents_status' AND object_id = OBJECT_ID('incidents'))
                    CREATE INDEX IX_incidents_status ON incidents(status);
            """)
            cursor.execute("""
                IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_incidents_last_seen' AND object_id = OBJECT_ID('incidents'))
                    CREATE INDEX IX_incidents_last_seen ON incidents(last_seen);
            """)

            self._sql_conn.commit()
            logger.debug("Ensured SQL table incidents")
        except Exception as e:
            logger.error(f"Failed to ensure incidents table: {e}")

    def _migrate_sql_v1_to_v2(self, cursor) -> None:
        """
        Migrate v1 schema to v2 by renaming old table and creating new one.
        Data from v1 is not migrated (curated_events.jsonl is source of truth).
        Uses timestamped backup name to avoid collision on repeated migrations.
        """
        from datetime import datetime

        try:
            # Generate timestamped backup name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"curated_events_v1_backup_{timestamp}"

            # Rename old table
            cursor.execute(f"""
                IF EXISTS (SELECT 1 FROM sys.tables WHERE name = 'curated_events')
                    EXEC sp_rename 'curated_events', '{backup_name}'
            """)
            self._sql_conn.commit()
            logger.info(f"Renamed curated_events to {backup_name}")

            # Create new v2 table
            self._create_sql_table_v2(cursor)

            logger.info(f"Migration complete. Old data in {backup_name}. "
                       "Replay from curated_events.jsonl if needed.")

        except Exception as e:
            logger.error(f"Migration failed: {e}")
            raise

    def _flush_sql_batch(self, cursor) -> None:
        """Flush accumulated events to SQL using Staging Table MERGE (High Performance)."""
        if not self._sql_batch:
            return

        count = len(self._sql_batch)

        # Prepare data
        rows = []
        for event in self._sql_batch:
             # Ensure event_id
            event_id = event.get('event_id', '')
            if not event_id:
                import hashlib
                content = json.dumps(event, sort_keys=True, separators=(',', ':'))
                event_id = hashlib.sha256(content.encode()).hexdigest()

            rows.append((
                event_id,
                event.get('ts_epoch', 0),
                event.get('event_type', 'unknown'),
                event.get('channel', 0),
                event.get('score', 0),
                json_compat.dumps(event)
            ))

        # Create or reuse temp staging table to avoid per-batch DDL overhead
        cursor.execute(
            """
            IF OBJECT_ID('tempdb..#BatchStaging') IS NULL
                CREATE TABLE #BatchStaging (
                    event_id CHAR(64) PRIMARY KEY,
                    ts_epoch DECIMAL(19,9),
                    event_type VARCHAR(50),
                    channel INT,
                    score INT,
                    payload NVARCHAR(MAX)
                )
            ELSE
                TRUNCATE TABLE #BatchStaging
            """
        )

        # Bulk Insert
        # NOTE: fast_executemany defaults to 510-byte buffer for NVARCHAR parameters.
        # Use setinputsizes() to override: (SQL_WVARCHAR, 0, 0) means "MAX" length.
        import pyodbc
        cursor.fast_executemany = True
        cursor.setinputsizes([
            (pyodbc.SQL_CHAR, 64, 0),      # event_id CHAR(64)
            (pyodbc.SQL_DECIMAL, 19, 9),   # ts_epoch DECIMAL(19,9)
            (pyodbc.SQL_VARCHAR, 50, 0),   # event_type VARCHAR(50)
            (pyodbc.SQL_INTEGER, 0, 0),    # channel INT
            (pyodbc.SQL_INTEGER, 0, 0),    # score INT
            (pyodbc.SQL_WVARCHAR, 0, 0),   # payload NVARCHAR(MAX) - 0 = MAX
        ])
        cursor.executemany("INSERT INTO #BatchStaging VALUES (?, ?, ?, ?, ?, ?)", rows)

        # MERGE
        cursor.execute("""
            MERGE curated_events AS target
            USING #BatchStaging AS source
            ON target.event_id = source.event_id
            WHEN NOT MATCHED THEN
                INSERT (event_id, ts_epoch, event_type, channel, score, payload)
                VALUES (source.event_id, source.ts_epoch, source.event_type, source.channel, source.score, source.payload);
        """)

        logger.info(f"Pushed {count} events to SQL")
        self._sql_batch.clear()

    def process_batch(self) -> tuple[int, int, int]:
        """
        Process new events from queue backend (File or Redis).
        Returns (new_events, curated_events, suppressed_events)
        """
        raw_events, cursor = self.queue.read_batch(batch_size=100)

        if not raw_events:
            return (0, 0, 0)

        new_count = 0
        curated_count = 0
        suppressed_count = 0

        for event in raw_events:
            try:
                new_count += 1
                self.state.events_processed += 1

                # Phase 2: Use DedupCache
                current_ts = event.get('ts_epoch', time.time())
                self.dedup_cache.cleanup(current_ts)

                # Run anomaly detection on EVERY event
                anomaly_flags = self._detect_anomalies(event)
                event['anomaly_flags'] = anomaly_flags

                # Dedup check using DedupCache
                if event.get('event_type') == 'telemetry_pulse':
                    self._write_curated_event(event)
                    curated_count += 1
                elif self.dedup_cache.should_keep(event):
                    self._write_curated_event(event)
                    curated_count += 1
                elif anomaly_flags:
                    event['_anomaly_bypass'] = True
                    self._write_curated_event(event)
                    curated_count += 1
                    logger.info(f"Anomaly bypass: {anomaly_flags} on {event.get('event_type')}")
                else:
                    suppressed_count += 1

                # Fingerprinting Hook
                if self.fingerprinter:
                    try:
                        etype = event.get('event_type')
                        keys = event.get('keys', {})

                        if etype in ('probe_request', 'probe_directed', 'probe_broadcast'):
                            self.fingerprinter.update_from_probe_request(
                                mac=keys.get('sa'),
                                ssid=event.get('ssid') or keys.get('ssid'),
                                channel=event.get('channel', 0),
                                rssi=event.get('rssi'),
                                ie_tags=event.get('ie_tags') or event.get('payload', {}).get('ie_tags'),
                                timestamp=event.get('ts_epoch')
                            )
                        elif etype == 'association':
                            self.fingerprinter.update_from_data_frame(
                                src_mac=keys.get('sa'),
                                dst_mac=keys.get('da'),
                                bssid=keys.get('bssid'),
                                channel=event.get('channel', 0),
                                rssi=event.get('rssi')
                            )
                    except Exception:
                        # Don't crash main loop for fingerprinting errors
                        pass

            except Exception as e:
                logger.error(f"Event processing error: {e}")

        # Commit cursor if backend supports it
        if cursor is not None:
            self.queue.commit(cursor)
            # Update state for checkpointing (File backend uses byte offset, Redis likely ignores this)
            if isinstance(self.queue, FileQueueBackend):
                self.state.byte_offset = cursor

        if self.feature_engineer:
            try:
                self.feature_engineer.flush_expired(time.time())
            except Exception as exc:
                if not self._feature_engineer_warned:
                    logger.warning(f"Feature engineer flush failed: {exc}")
                    self._feature_engineer_warned = True

        if self.baseline_updater:
            try:
                self.baseline_updater.maybe_refresh(time.time())
            except Exception as exc:
                if not self._baseline_warned:
                    logger.warning(f"Baseline refresh failed: {exc}")
                    self._baseline_warned = True

        if self.stream_scorer:
            try:
                scores = self.stream_scorer.score_recent_windows(time.time())
                if scores:
                    self.stream_scorer.persist_anomalies(scores)
            except Exception as exc:
                if not self._stream_scorer_warned:
                    logger.warning(f"Stream anomaly scoring failed: {exc}")
                    self._stream_scorer_warned = True

        # Flush profiles periodically (every 60s)
        if self.fingerprinter and self.push_to_sql:
            now = time.time()
            if now - self._last_profile_flush > 60:
                try:
                    count = self.fingerprinter.save_all_profiles()
                    if count > 0:
                        logger.debug(f"Flushed {count} device profiles")
                    self._last_profile_flush = now
                except Exception as e:
                    logger.warning(f"Failed to flush profiles: {e}")

        return (new_count, curated_count, suppressed_count)

    def _update_summary_stats(self, event: dict) -> None:
        """Update in-memory counters for summary stats."""
        self._summary_stats['count'] += 1

        run_id = event.get('run_id')
        if self._summary_run_id is None:
            self._summary_run_id = run_id
        elif self._summary_run_id != run_id:
            self._summary_run_id = "mixed"

        keys = event.get('keys', {})
        if keys.get('ssid'):
            self._summary_stats['unique_ssids'].add(keys['ssid'])
        if keys.get('bssid'):
            self._summary_stats['unique_bssids'].add(keys['bssid'])

        self._summary_stats['channels'][event.get('channel', 0)] += 1

        cat = event.get('interest_category', 'other')
        self._summary_stats['categories'][cat] += 1

        vendor = event.get('vendor')
        if vendor:
            self._summary_stats['vendors'][vendor] += 1

    def _check_summary_window(self, event_ts: float) -> None:
        """Check if summary window should close based on event time."""
        if self._summary_window_start == 0.0:
            self._summary_window_start = event_ts
            return

        if event_ts >= self._summary_window_start + self.SUMMARY_INTERVAL_SEC:
            # Determine window end (aligned or gap-filling?)
            window_end = self._summary_window_start + self.SUMMARY_INTERVAL_SEC

            self._compute_and_push_summary(self._summary_window_start, window_end)

            # Start new window at current event's time for simplicity
            self._summary_window_start = event_ts

            # Reset stats
            self._summary_stats = {
                'count': 0,
                'unique_ssids': set(),
                'unique_bssids': set(),
                'channels': Counter(),
                'vendors': Counter(),
                'categories': Counter()
            }
            self._summary_run_id = None

    def _compute_and_push_summary(self, window_start_ts: float, window_end_ts: float) -> None:
        """Compute summary stats for the completed window and push."""
        stats = self._summary_stats
        if stats['count'] == 0:
            return

        window_start = datetime.fromtimestamp(window_start_ts)
        window_end = datetime.fromtimestamp(window_end_ts)

        top_category = stats['categories'].most_common(1)[0][0] if stats['categories'] else None
        top_vendor = stats['vendors'].most_common(1)[0][0] if stats['vendors'] else None

        summary = {
            'window_start': window_start.isoformat(),
            'window_end': window_end.isoformat(),
            'events_count': stats['count'],
            'unique_bssids': len(stats['unique_bssids']),
            'unique_ssids': len(stats['unique_ssids']),
            'top_category': top_category,
            'top_vendor': top_vendor,
            'run_id': self._summary_run_id,
        }

        # Log summary
        logger.info(f"📊 Summary [{window_start_ts:.0f}-{window_end_ts:.0f}]: {stats['count']} events, "
                   f"top:{top_category}, vendor:{top_vendor}")

        # Write to JSONL
        with open(self.summary_stats_path, 'a') as f:
            f.write(json_compat.dumps(summary, separators=(',', ':')) + '\n')

        # Push to UI (WebSocket)
        self._push_to_ui_webhook("telemetry_summary", summary)

        # Push to SQL (using retry helper)
        if self.push_to_sql:
             def push_summary_op(cursor) -> None:
                 sql = """
                 INSERT INTO summary_stats
                 (window_start, window_end, events_count, unique_bssids, unique_ssids, top_category, top_vendor)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 """
                 params = (
                     summary['window_start'],
                     summary['window_end'],
                     summary['events_count'],
                     summary['unique_bssids'],
                     summary['unique_ssids'],
                     summary['top_category'],
                     summary['top_vendor']
                 )
                 cursor.execute(sql, params)

             self._execute_with_retry(push_summary_op)

    def watch(self, poll_interval: float = 1.0) -> None:
        """
        Watch the event queue and process new events continuously.

        Args:
            poll_interval: Seconds between polls when no new data.
        """
        logger.info(f"Watching event queue: {self.queue_path}")
        logger.info(f"Curated output: {self.curated_path}")
        logger.info(f"SQL push: {'enabled' if self.push_to_sql else 'disabled (dry-run)'}")
        logger.info("🧙 Phase 2 enrichment: vendor lookup, categories, anomaly detection")

        if self.push_to_sql and self.legacy_sql_batch_enabled:
            if not self._init_sql():
                logger.warning("SQL initialization failed - continuing without SQL")
                self.push_to_sql = False
                self.legacy_sql_batch_enabled = False

        try:
            while True:
                new, curated, suppressed = self.process_batch()

                if new > 0:
                    logger.info(f"Processed {new} new events, curated {curated}, suppressed {suppressed}")
                    self._save_state()
                    # Phase 2: Use DedupCache
                    self.dedup_cache.save()
                    # Phase 2: Flush PersistenceManager if needed
                    if self.persistence_manager:
                        self.persistence_manager.flush()

                # Summary stats are now event-driven (using ts_epoch) inside process_batch

                if new == 0:
                    time.sleep(poll_interval)

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            # Final summary
            now = time.time()
            if self._summary_window_start > 0 and now > self._summary_window_start:
                 self._compute_and_push_summary(self._summary_window_start, now)

            # Phase 2: Final flush using PersistenceManager
            if self.persistence_manager:
                try:
                    count = self.persistence_manager.flush()
                    if count > 0:
                        logger.info(f"Final flush: {count} events persisted")
                except Exception as e:
                    logger.error(f"Final flush failed: {e}")
            elif self.legacy_sql_batch_enabled and self._sql_batch:
                def final_flush_op(cursor) -> None:
                    self._flush_sql_batch(cursor)
                self._execute_with_retry(final_flush_op)

            self._save_state()
            # Phase 2: Use DedupCache
            self.dedup_cache.save()

            if self.feature_engineer:
                try:
                    self.feature_engineer.flush_all()
                except Exception as exc:
                    logger.warning(f"Feature engineer final flush failed: {exc}")

            if self.baseline_updater:
                try:
                    self.baseline_updater.refresh(time.time())
                except Exception as exc:
                    logger.warning(f"Baseline final refresh failed: {exc}")

            if self.stream_scorer:
                try:
                    scores = self.stream_scorer.score_recent_windows(time.time())
                    if scores:
                        self.stream_scorer.persist_anomalies(scores)
                except Exception as exc:
                    logger.warning(f"Stream anomaly final flush failed: {exc}")

            # Phase 2: Disconnect PersistenceManager
            if self.persistence_manager:
                self.persistence_manager.disconnect()
            else:
                self._close_sql_connection()

            logger.info(f"Processor stopped. Total: processed={self.state.events_processed}, curated={self.state.events_curated}")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='WiFiWizard Event Processor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m wicap.event_processor watch              # Dry-run (no SQL)
  python -m wicap.event_processor watch --dry-run    # Same as above
  python -m wicap.event_processor watch --push-to-sql # Enable SQL push
        """
    )
    parser.add_argument('command', choices=['watch'], help='Command to run')
    parser.add_argument('--dry-run', action='store_true',
                        help='Dry-run mode, no SQL push (this is the default)')
    parser.add_argument('--push-to-sql', action='store_true',
                        help='Enable SQL push to 192.168.4.25')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    config = get_scout_config()

    # SQL push only if explicitly requested AND not --dry-run
    push_to_sql = args.push_to_sql and not args.dry_run

    if args.command == 'watch':
        processor = EventProcessor(config, push_to_sql=push_to_sql)
        processor.watch()


if __name__ == '__main__':
    main()
