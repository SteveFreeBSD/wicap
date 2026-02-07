"""
Event Deduplicator

Handles event deduplication logic with time-windowed caching.
This isolates the deduplication logic from the main processor,
making it easier to test and debug race conditions.
"""
import json
import logging
import os
import time
from pathlib import Path

from nexus.utils import json_compat

logger = logging.getLogger('wicap.processing.deduplicator')


class DedupCache:
    """Deduplication cache with time-windowed entries and persistence.

    This class manages the deduplication window and cache persistence,
    isolating the dedup logic from the main event processor.
    """

    # Default configuration
    DEDUP_WINDOW_SEC = 300  # 5 minutes
    DEDUP_MAX_ENTRIES = 10000  # Hard cap on dedup cache size

    def __init__(
        self,
        cache_path: Path,
        window_sec: int = DEDUP_WINDOW_SEC,
        max_entries: int = DEDUP_MAX_ENTRIES
    ):
        """Initialize deduplication cache.

        Args:
            cache_path: Path to cache file for persistence
            window_sec: Time window for deduplication (seconds)
            max_entries: Maximum number of entries to keep
        """
        self.cache_path = cache_path
        self.window_sec = window_sec
        self.max_entries = max_entries
        self._dedup_window: dict[str, dict] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """Load dedup cache from disk, prune expired entries."""
        if self.cache_path.exists():
            try:
                with open(self.cache_path) as f:
                    data = json.load(f)

                # Prune expired entries on load
                now = time.time()
                cutoff = now - self.window_sec
                self._dedup_window = {
                    k: v for k, v in data.items()
                    if v.get('ts', 0) > cutoff
                }

                logger.info(
                    f"Loaded dedup cache: {len(self._dedup_window)} entries "
                    f"(pruned expired)"
                )
            except Exception as e:
                logger.warning(f"Failed to load dedup cache: {e}")
                self._dedup_window = {}
        else:
            self._dedup_window = {}

    def _save_cache(self) -> None:
        """Save dedup cache atomically with TTL pruning."""
        # Prune before saving
        now = time.time()
        cutoff = now - self.window_sec
        self._dedup_window = {
            k: v for k, v in self._dedup_window.items()
            if v.get('ts', 0) > cutoff
        }

        # Enforce hard cap (keep most recent entries)
        if len(self._dedup_window) > self.max_entries:
            # Sort by timestamp descending, keep newest
            sorted_items = sorted(
                self._dedup_window.items(),
                key=lambda x: x[1].get('ts', 0),
                reverse=True
            )
            self._dedup_window = dict(sorted_items[:self.max_entries])
            logger.warning(
                f"Dedup cache capped at {self.max_entries} entries"
            )

        temp_path = self.cache_path.with_suffix('.tmp')
        try:
            with open(temp_path, 'w') as f:
                json.dump(self._dedup_window, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.cache_path)
        except Exception as e:
            logger.error(f"Failed to save dedup cache: {e}")
            try:
                temp_path.unlink()
            except Exception:
                pass

    def make_key(self, event: dict) -> str:
        """Create deduplication key from event (collision-safe JSON encoding).

        Args:
            event: Event dictionary

        Returns:
            Deduplication key string
        """
        keys = event.get('keys', {})
        # Use JSON array for collision-safe key (handles | in SSID, None values, etc.)
        key_parts = [
            event.get('event_type', ''),
            keys.get('bssid'),
            keys.get('ssid'),
            event.get('channel', 0),
        ]
        return json_compat.dumps(key_parts, separators=(',', ':'))

    def cleanup(self, current_ts: float) -> None:
        """Remove expired entries from dedup window.

        Args:
            current_ts: Current timestamp
        """
        cutoff = current_ts - self.window_sec
        expired = [
            k for k, v in self._dedup_window.items()
            if v.get('ts', 0) < cutoff
        ]
        for k in expired:
            del self._dedup_window[k]

    def should_keep(self, event: dict) -> bool:
        """Check if event should be kept based on dedup rules.

        Returns True if this event should be emitted (new or better than existing).

        Args:
            event: Event dictionary

        Returns:
            True if event should be kept, False if it should be suppressed
        """
        key = self.make_key(event)
        ts = event.get('ts_epoch', 0)
        score = event.get('score', 0)

        if key not in self._dedup_window:
            # New key - keep it
            self._dedup_window[key] = {'ts': ts, 'score': score}
            return True

        existing = self._dedup_window[key]
        existing_ts = existing.get('ts', 0)
        existing_score = existing.get('score', 0)

        # Keep if higher score
        if score > existing_score:
            self._dedup_window[key] = {'ts': ts, 'score': score}
            return True

        # Keep if same score but earlier
        if score == existing_score and ts < existing_ts:
            self._dedup_window[key] = {'ts': ts, 'score': score}
            return True

        # Suppress
        return False

    def save(self) -> None:
        """Save cache to disk."""
        self._save_cache()

    @property
    def size(self) -> int:
        """Get current cache size."""
        return len(self._dedup_window)
