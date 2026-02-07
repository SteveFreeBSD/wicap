"""
Lightweight memory profiling helpers for the UI service.

Enabled via WICAP_UI_MEMPROF=1 to avoid overhead in normal runs.
"""
from __future__ import annotations

import gc
import os
import resource
import time
import tracemalloc
from typing import Any

_STARTED_AT: float | None = None
_STARTED_BY: str | None = None
_DEFERRED: bool = False
_BOOT_AT: float = time.time()


def _env_truthy(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def enabled() -> bool:
    value = os.environ.get("WICAP_UI_MEMPROF")
    if value is None:
        return False
    if value.strip().lower() in {"ondemand", "on-demand"}:
        return True
    return _env_truthy("WICAP_UI_MEMPROF", False)


def start(mode: str = "startup") -> None:
    global _STARTED_AT
    global _STARTED_BY
    global _DEFERRED

    if not enabled() or tracemalloc.is_tracing():
        return
    if _is_on_demand():
        _DEFERRED = True
        return
    defer_seconds = int(os.environ.get("WICAP_UI_MEMPROF_DEFER_SECONDS", "0") or "0")
    if defer_seconds > 0:
        _DEFERRED = True
        return
    frames = _frames()
    tracemalloc.start(frames)
    _STARTED_AT = time.time()
    _STARTED_BY = mode


def _frames() -> int:
    try:
        return int(os.environ.get("WICAP_UI_MEMPROF_FRAMES", "25"))
    except ValueError:
        return 25


def _is_on_demand() -> bool:
    value = os.environ.get("WICAP_UI_MEMPROF", "")
    return value.strip().lower() in {"ondemand", "on-demand"}


def try_start_deferred(reason: str = "deferred") -> bool:
    """Start tracemalloc if enabled and deferred."""
    global _STARTED_AT
    global _STARTED_BY
    global _DEFERRED

    if tracemalloc.is_tracing():
        return True
    if not enabled():
        return False
    if _is_on_demand() and reason != "on-demand":
        return False

    defer_seconds = int(os.environ.get("WICAP_UI_MEMPROF_DEFER_SECONDS", "0") or "0")
    if defer_seconds > 0 and _STARTED_AT is None:
        if (time.time() - _BOOT_AT) < defer_seconds:
            return False

    frames = _frames()
    tracemalloc.start(frames)
    _STARTED_AT = time.time()
    _STARTED_BY = reason
    _DEFERRED = False
    return True


def _rss_mb() -> float:
    # ru_maxrss is kilobytes on Linux.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def summary() -> dict[str, Any]:
    data: dict[str, Any] = {
        "enabled": enabled(),
        "deferred": _DEFERRED,
        "mode": os.environ.get("WICAP_UI_MEMPROF"),
        "rss_mb": round(_rss_mb(), 2),
        "gc_counts": gc.get_count(),
    }

    if tracemalloc.is_tracing():
        current, peak = tracemalloc.get_traced_memory()
        data.update(
            {
                "tracemalloc_current_mb": round(current / (1024 * 1024), 2),
                "tracemalloc_peak_mb": round(peak / (1024 * 1024), 2),
                "tracemalloc_started_at": _STARTED_AT,
                "tracemalloc_started_by": _STARTED_BY,
            }
        )
    return data


def top_allocations(limit: int = 10) -> list[dict[str, Any]]:
    if not tracemalloc.is_tracing():
        return []
    snapshot = tracemalloc.take_snapshot()
    stats = snapshot.statistics("lineno")
    results = []
    for stat in stats[:limit]:
        frame = stat.traceback[0]
        results.append(
            {
                "file": frame.filename,
                "line": frame.lineno,
                "size_kb": round(stat.size / 1024, 2),
                "count": stat.count,
            }
        )
    return results
