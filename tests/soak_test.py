#!/usr/bin/env python3
"""
WICAP 30-Minute Soak Test with Playwright Checkpoints

Runs for 30 minutes with Playwright UI checks every 5 minutes.
Monitors for errors, memory usage, and performance metrics.
"""

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _resolve_playwright_browsers_path() -> str:
    """Best-effort path to Playwright browser cache.

    Prefer explicit env var. When running via sudo, fall back to the invoking
    user's cache to avoid permission issues and unnecessary downloads.
    """
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if configured:
        return configured

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd

            home_dir = pwd.getpwnam(sudo_user).pw_dir
            return str(Path(home_dir) / ".cache" / "ms-playwright")
        except Exception:
            pass

    return str(Path.home() / ".cache" / "ms-playwright")


# Configuration
DURATION_MINUTES = _env_int("WICAP_SOAK_DURATION_MINUTES", 30)
PLAYWRIGHT_INTERVAL_MINUTES = _env_int("WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES", 15)
# PLAYWRIGHT_TIMEOUT_SECONDS controls per-page timeout in tests (passed via env)
PLAYWRIGHT_PAGE_TIMEOUT_SECONDS = _env_int("PLAYWRIGHT_TIMEOUT_SECONDS", 120)
# SUBPROCESS_TIMEOUT is how long we wait for the full pytest run
# Base timeout + per-test margin; can be overridden
_SUBPROCESS_BASE_TIMEOUT = _env_int("SOAK_PYTEST_TIMEOUT_SECONDS", 0)
SUBPROCESS_TIMEOUT_PER_TEST_SECONDS = 30  # Margin per test
BASE_URL = "http://localhost:8080"
LOG_DIR = Path("logs/soak")
LOG_DIR.mkdir(parents=True, exist_ok=True)
BASELINE_PATH = Path(os.environ.get("WICAP_SOAK_BASELINE_PATH", "docs/reports/soak/baseline.json"))
BASELINE_ENFORCE = _env_bool("WICAP_SOAK_BASELINE_ENFORCE", False)
BASELINE_UPDATE = _env_bool("WICAP_SOAK_BASELINE_UPDATE", False)
MAX_RSS_GROWTH_PCT = float(os.environ.get("WICAP_SOAK_BASELINE_MAX_RSS_GROWTH_PCT", "30"))
MAX_EPS_DROP_PCT = float(os.environ.get("WICAP_SOAK_BASELINE_MAX_EPS_DROP_PCT", "25"))
MIN_UI_PASS_RATE = float(os.environ.get("WICAP_SOAK_BASELINE_MIN_UI_PASS_RATE", "1.0"))
SHUTDOWN_ON_COMPLETE = _env_bool("WICAP_SOAK_SHUTDOWN_ON_COMPLETE", True)


def configure_runtime(
    *,
    duration_minutes: int | None = None,
    playwright_interval_minutes: int | None = None,
    playwright_timeout_seconds: int | None = None,
    baseline_path: str | None = None,
    baseline_enforce: bool | None = None,
    baseline_update: bool | None = None,
    pytest_timeout_seconds: int | None = None,
    shutdown_on_complete: bool | None = None,
) -> None:
    """Apply runtime overrides from CLI while preserving env defaults."""
    global DURATION_MINUTES
    global PLAYWRIGHT_INTERVAL_MINUTES
    global PLAYWRIGHT_PAGE_TIMEOUT_SECONDS
    global BASELINE_PATH
    global BASELINE_ENFORCE
    global BASELINE_UPDATE
    global _SUBPROCESS_BASE_TIMEOUT
    global SHUTDOWN_ON_COMPLETE

    if duration_minutes is not None:
        DURATION_MINUTES = duration_minutes
    if playwright_interval_minutes is not None:
        PLAYWRIGHT_INTERVAL_MINUTES = playwright_interval_minutes
    if playwright_timeout_seconds is not None:
        PLAYWRIGHT_PAGE_TIMEOUT_SECONDS = playwright_timeout_seconds
    if baseline_path:
        BASELINE_PATH = Path(baseline_path)
    if baseline_enforce is not None:
        BASELINE_ENFORCE = baseline_enforce
    if baseline_update is not None:
        BASELINE_UPDATE = baseline_update
    if pytest_timeout_seconds is not None:
        _SUBPROCESS_BASE_TIMEOUT = pytest_timeout_seconds
    if shutdown_on_complete is not None:
        SHUTDOWN_ON_COMPLETE = shutdown_on_complete

    if DURATION_MINUTES <= 0:
        raise ValueError("--duration-minutes must be > 0")
    if PLAYWRIGHT_INTERVAL_MINUTES <= 0:
        raise ValueError("--playwright-interval-minutes must be > 0")

    # Keep results metadata aligned with runtime overrides.
    results["duration_minutes"] = DURATION_MINUTES


def _get_subprocess_timeout(test_count: int = 15) -> int:
    """Calculate subprocess timeout based on test count or use override."""
    if _SUBPROCESS_BASE_TIMEOUT > 0:
        return _SUBPROCESS_BASE_TIMEOUT
    # Base time (120s) + per-test margin + buffer for slow startup
    return 120 + (test_count * SUBPROCESS_TIMEOUT_PER_TEST_SECONDS) + 60


def _parse_mem_mib(mem_str: str) -> float:
    if not mem_str:
        return 0.0
    token = mem_str.split("/")[0].strip()
    if token.lower().endswith("gib"):
        return float(token[:-3].strip()) * 1024
    if token.lower().endswith("mib"):
        return float(token[:-3].strip())
    return 0.0


def _extract_rss_mb(label: str) -> float:
    snapshot = results.get("memory_snapshots", {}).get(label) or {}
    summary = snapshot.get("summary", {}) if isinstance(snapshot, dict) else {}
    rss = summary.get("rss_mb")
    if rss is not None:
        try:
            return float(rss)
        except (TypeError, ValueError):
            pass
    # Fallback to docker stats
    docker_stats = results.get("metrics", {}).get(label, {}).get("docker_stats", {})
    mem_str = docker_stats.get("wicap-ui", {}).get("mem", "")
    return _parse_mem_mib(mem_str)


def _compute_eps_avg() -> float:
    samples = results.get("telemetry", {}).get("eps_samples", [])
    if samples:
        values = [s.get("eps", 0) for s in samples if isinstance(s, dict)]
        values = [float(v) for v in values if v is not None]
        return round(sum(values) / len(values), 3) if values else 0.0
    # Fallback: compute from total_events delta
    start_events = results.get("metrics", {}).get("start", {}).get("app_stats", {}).get("total_events", 0)
    end_events = results.get("metrics", {}).get("end", {}).get("app_stats", {}).get("total_events", 0)
    duration_sec = results.get("duration_minutes", 0) * 60
    if duration_sec <= 0:
        return 0.0
    return round((end_events - start_events) / duration_sec, 3)


def _compute_ui_pass_rate() -> float:
    checks = results.get("playwright_checks", [])
    total = len(checks)
    if total == 0:
        return 0.0
    passed = sum(1 for c in checks if c.get("passed"))
    return round(passed / total, 3)


def _compute_baseline_snapshot() -> dict:
    return {
        "timestamp": datetime.now().isoformat(),
        "duration_minutes": results.get("duration_minutes"),
        "ui_rss_start_mb": _extract_rss_mb("start"),
        "ui_rss_end_mb": _extract_rss_mb("end"),
        "eps_avg": _compute_eps_avg(),
        "ui_check_pass_rate": _compute_ui_pass_rate(),
    }


def _load_baseline(path: Path) -> dict | None:
    try:
        if path.exists():
            with open(path) as f:
                return json.load(f)
    except Exception:
        return None
    return None


def _write_baseline(path: Path, snapshot: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2)


def _compare_to_baseline(current: dict, baseline: dict) -> list[str]:
    regressions = []
    try:
        base_end = float(baseline.get("ui_rss_end_mb") or 0)
        curr_end = float(current.get("ui_rss_end_mb") or 0)
        if base_end > 0:
            pct = ((curr_end - base_end) / base_end) * 100
            if pct > MAX_RSS_GROWTH_PCT:
                regressions.append(f"UI RSS end grew {pct:.1f}% vs baseline (max {MAX_RSS_GROWTH_PCT}%).")
    except Exception:
        pass
    try:
        base_eps = float(baseline.get("eps_avg") or 0)
        curr_eps = float(current.get("eps_avg") or 0)
        if base_eps > 0:
            drop_pct = ((base_eps - curr_eps) / base_eps) * 100
            if drop_pct > MAX_EPS_DROP_PCT:
                regressions.append(f"EPS dropped {drop_pct:.1f}% vs baseline (max {MAX_EPS_DROP_PCT}%).")
    except Exception:
        pass
    try:
        curr_pass = float(current.get("ui_check_pass_rate") or 0)
        if curr_pass < MIN_UI_PASS_RATE:
            regressions.append(f"UI check pass rate {curr_pass:.2f} below min {MIN_UI_PASS_RATE:.2f}.")
    except Exception:
        pass
    return regressions


# Memory checkpoint minutes (for steady-state analysis)
MEMORY_CHECKPOINT_MINUTES = [10, 30, 60, 120]  # Will only trigger if soak runs that long

# Live status file for monitoring long soaks
LIVE_STATUS_PATH = Path(".soak_status.json")
LIVE_STATUS_TMP_PATH = Path(".soak_status.json.tmp")


def _update_live_status(elapsed_min: float, start_ts: float) -> None:
    """Update live status file for easy monitoring of long soaks.

    Usage: watch -n 30 cat .soak_status.json
    """
    try:
        # Get current memory from docker stats
        docker_stats = get_docker_stats()
        ui_mem = docker_stats.get("wicap-ui", {}).get("mem", "N/A")

        # Latest EPS
        eps_samples = results.get("telemetry", {}).get("eps_samples", [])
        latest_eps = eps_samples[-1].get("eps", 0) if eps_samples else 0

        # Check counts
        pw_checks = results.get("playwright_checks", [])
        passed = sum(1 for c in pw_checks if c.get("passed"))
        total = len(pw_checks)

        status = {
            "updated_at": datetime.now().isoformat(),
            "elapsed_min": round(elapsed_min, 1),
            "remaining_min": round(DURATION_MINUTES - elapsed_min, 1),
            "progress_pct": round((elapsed_min / DURATION_MINUTES) * 100, 1),
            "next_check_min": ((total) * PLAYWRIGHT_INTERVAL_MINUTES) if total > 0 else PLAYWRIGHT_INTERVAL_MINUTES,
            "ui_memory": ui_mem,
            "current_eps": latest_eps,
            "playwright_checks": f"{passed}/{total} passed",
            "errors": len(results.get("errors", [])),
            "warnings": len(results.get("warnings", [])),
            "alive": True,
        }

        with open(LIVE_STATUS_TMP_PATH, "w") as f:
            json.dump(status, f, indent=2)
        LIVE_STATUS_TMP_PATH.replace(LIVE_STATUS_PATH)
    except Exception:
        pass  # Don't crash soak if status update fails


# Results tracking - unified metrics payload
results = {
    "start_time": None,
    "end_time": None,
    "duration_minutes": DURATION_MINUTES,
    "playwright_checks": [],
    "errors": [],
    "warnings": [],
    "metrics": {
        "start": {},
        "end": {},
    },
    "api_health_checks": [],
    "postflight_checks": {},
    "memory_snapshots": {
        "start": None,
        "end": None,
        "checkpoints": [],  # Memory at key intervals (minute 10, 60, etc.)
    },
    # Unified metrics payload for observability
    "telemetry": {
        "eps_samples": [],          # EPS at each interval {minute, eps}
        "container_starts": {},     # Container start times (detect restarts)
        "disk_usage": [],           # Capture dir size samples {minute, bytes}
        "latency_samples": [],      # API latency {minute, endpoint, ms}
    },
}


def log(msg):
    """Log with timestamp and flush to ensure visibility in detached mode."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _add_warning(msg: str) -> None:
    results["warnings"].append(msg)


def _add_error(msg: str) -> None:
    results["errors"].append(msg)


def _fetch_json(endpoint: str, timeout: int = 5):
    import urllib.request
    url = f"{BASE_URL}{endpoint}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


def _fetch_json_with_latency(endpoint: str, timeout: int = 5):
    """Fetch JSON and return (data, latency_ms) tuple."""
    import time
    import urllib.request
    url = f"{BASE_URL}{endpoint}"
    start = time.time()
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        data = json.load(resp)
    latency_ms = round((time.time() - start) * 1000, 1)
    return data, latency_ms


def _capture_eps(minute: float) -> None:
    """Capture current EPS and add to telemetry."""
    try:
        data = _fetch_json("/api/system/status", timeout=5)
        eps = data.get("eps", 0) if data else 0
        results["telemetry"]["eps_samples"].append({
            "minute": round(minute, 1),
            "eps": eps,
        })
    except Exception:
        pass


def _capture_container_starts() -> dict:
    """Capture container runtime metadata used to detect real restarts."""
    starts = {}
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}|{{.ID}}|{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in out.stdout.strip().split("\n"):
            if "|" not in line:
                continue

            parts = line.split("|", 2)
            if len(parts) != 3:
                continue

            name = parts[0].strip()
            container_id = parts[1].strip()
            status = parts[2].strip()

            inspect = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.StartedAt}}|{{.RestartCount}}",
                    container_id,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            started_at = ""
            restart_count = 0
            if inspect.returncode == 0 and "|" in inspect.stdout:
                inspect_parts = inspect.stdout.strip().split("|", 1)
                if len(inspect_parts) == 2:
                    started_at = inspect_parts[0].strip()
                    try:
                        restart_count = int(inspect_parts[1].strip())
                    except ValueError:
                        restart_count = 0

            starts[name] = {
                "id": container_id,
                "status": status,
                "started_at": started_at,
                "restart_count": restart_count,
            }
    except Exception:
        pass
    return starts


def _capture_disk_usage(minute: float) -> None:
    """Capture disk usage of captures directory."""
    try:
        import subprocess
        capture_dir = os.environ.get("WICAP_CAPTURE_DIR", "./captures")
        out = subprocess.run(
            ["du", "-sb", capture_dir],
            capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0:
            size_bytes = int(out.stdout.split()[0])
            results["telemetry"]["disk_usage"].append({
                "minute": round(minute, 1),
                "bytes": size_bytes,
            })
    except Exception:
        pass


def _capture_latency(minute: float, endpoint: str = "/api/system/status") -> None:
    """Capture API latency sample."""
    try:
        _, latency_ms = _fetch_json_with_latency(endpoint, timeout=10)
        results["telemetry"]["latency_samples"].append({
            "minute": round(minute, 1),
            "endpoint": endpoint,
            "ms": latency_ms,
        })
    except Exception:
        pass


def run_postflight_checks():
    """Verify identity graph, vendor stats, BLE stats, and SIEM export."""
    log("🔍 Running postflight checks...")
    checks = {}

    # Identity Graph
    try:
        data = _fetch_json("/api/identity/graph/summary", timeout=15)
        clusters = int(data.get("cluster_count", 0)) if isinstance(data, dict) else 0
        edges = int(data.get("edge_count", 0)) if isinstance(data, dict) else 0
        ok = isinstance(data, dict) and not data.get("error")
        checks["identity_graph"] = {
            "ok": ok,
            "clusters": clusters,
            "edges": edges,
            "cached": data.get("cached"),
        }
        if not ok:
            _add_error("Identity graph API returned an error.")
        elif not clusters:
            _add_warning("Identity graph has zero clusters (no data yet).")
    except Exception as exc:
        _add_error(f"Identity graph check failed: {exc}")
        checks["identity_graph"] = {"ok": False, "error": str(exc)}

    # Vendor stats (Wi-Fi)
    try:
        data = _fetch_json("/api/charts/vendors?source=live", timeout=15)
        labels = data.get("labels", []) if isinstance(data, dict) else []
        ok = isinstance(data, dict) and not data.get("error")
        checks["vendors_wifi"] = {
            "ok": ok,
            "labels": len(labels),
        }
        if not ok:
            _add_error("Vendor chart API returned an error.")
        elif not labels:
            _add_warning("Vendor chart has no labels (no Wi-Fi vendor data yet).")
    except Exception as exc:
        _add_error(f"Vendor chart check failed: {exc}")
        checks["vendors_wifi"] = {"ok": False, "error": str(exc)}

    # BLE stats
    try:
        data = _fetch_json("/api/devices/bluetooth", timeout=15)
        stats = data.get("stats", {}) if isinstance(data, dict) else {}
        total_devices = stats.get("total_devices", 0)
        ok = isinstance(data, dict) and not data.get("error")
        checks["vendors_ble"] = {
            "ok": ok,
            "total_devices": total_devices,
            "unique_vendors": stats.get("unique_vendors", 0),
        }
        if not ok:
            _add_error("Bluetooth devices API returned an error.")
        elif total_devices == 0:
            _add_warning("Bluetooth devices list is empty (no BLE data yet).")
    except Exception as exc:
        _add_error(f"Bluetooth stats check failed: {exc}")
        checks["vendors_ble"] = {"ok": False, "error": str(exc)}

    # SIEM export (evidence pointers)
    try:
        data = _fetch_json("/api/ops/siem?since_hours=1&limit=10", timeout=15)
        ok = isinstance(data, dict) and "alerts" in data
        checks["siem_export"] = {
            "ok": ok,
            "alerts": len(data.get("alerts", [])) if isinstance(data, dict) else 0,
        }
        if not ok:
            _add_error("SIEM export API returned an invalid payload.")
    except Exception as exc:
        _add_error(f"SIEM export check failed: {exc}")
        checks["siem_export"] = {"ok": False, "error": str(exc)}

    return checks


def capture_ui_memory_snapshot(label: str, retries: int = 3) -> None:
    """Capture UI memory snapshot via API with retry and docker stats fallback."""
    import time

    for attempt in range(retries):
        try:
            data = _fetch_json("/api/system/memory", timeout=15)
            results["memory_snapshots"][label] = data
            return
        except Exception as exc:
            if attempt < retries - 1:
                time.sleep(2)
            else:
                _add_warning(f"UI memory API ({label}) failed after {retries} attempts: {exc}")

    # Fallback: use docker stats for RSS
    try:
        docker_stats = get_docker_stats()
        ui_stats = docker_stats.get("wicap-ui", {})
        mem_str = ui_stats.get("mem", "0MiB")
        # Parse "387.6MiB / 62.58GiB" -> 387.6
        rss_mb = float(mem_str.split()[0].replace("MiB", "").replace("GiB", ""))
        if "GiB" in mem_str.split()[0]:
            rss_mb *= 1024
        results["memory_snapshots"][label] = {
            "summary": {"rss_mb": rss_mb, "source": "docker_stats_fallback"},
            "top_allocations": [],
        }
        log(f"   📊 Memory ({label}) from docker stats fallback: {rss_mb:.1f} MiB")
    except Exception as fallback_exc:
        _add_warning(f"Memory snapshot fallback ({label}) also failed: {fallback_exc}")


def get_docker_stats():
    """Get Docker container memory/CPU stats."""
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}}"],
            capture_output=True, text=True, timeout=10
        )
        stats = {}
        for line in result.stdout.strip().split("\n"):
            if line and "wicap" in line.lower():
                parts = line.split(",")
                if len(parts) >= 4:
                    stats[parts[0]] = {
                        "cpu": parts[1],
                        "mem": parts[2],
                        "mem_pct": parts[3],
                    }
        return stats
    except Exception as e:
        return {"error": str(e)}


def check_api_health():
    """Check API endpoints."""
    import urllib.request
    endpoints = ["/", "/api/alerts", "/api/devices", "/api/stats"]
    results = []

    for endpoint in endpoints:
        try:
            start = time.time()
            req = urllib.request.Request(f"{BASE_URL}{endpoint}")
            with urllib.request.urlopen(req, timeout=5) as resp:
                elapsed = time.time() - start
                results.append({
                    "endpoint": endpoint,
                    "status": resp.status,
                    "time_ms": round(elapsed * 1000, 1),
                })
        except Exception as e:
            results.append({
                "endpoint": endpoint,
                "status": "error",
                "error": str(e),
            })

    return results


def run_playwright_check(check_number):
    """Run Playwright tests and capture results."""
    log(f"🎭 Starting Playwright check #{check_number}")

    # Run full e2e ui suite
    sudo_user = os.environ.get("SUDO_USER")
    skip_slow = os.environ.get("WICAP_SOAK_SKIP_SLOW", "1").strip().lower() not in ("0", "false", "no")
    marker_expr = "e2e and not slow" if skip_slow else "e2e"
    base_cmd = [
        sys.executable, "-m", "pytest",
        "-m", marker_expr,
        "-v", "--tb=short"
    ]

    extra_args = os.environ.get("PYTEST_ARGS", "").strip()
    if extra_args:
        base_cmd.extend(extra_args.split())

    if sudo_user and os.getuid() == 0:
        cmd = ["sudo", "-E", "-u", sudo_user, *base_cmd]
    else:
        cmd = base_cmd

    env = {
        **os.environ,
        "WICAP_UI_URL": BASE_URL,
        "PLAYWRIGHT_BROWSERS_PATH": _resolve_playwright_browsers_path(),
        # Pass page timeout to tests (in ms for Playwright)
        "PLAYWRIGHT_PAGE_TIMEOUT_MS": str(PLAYWRIGHT_PAGE_TIMEOUT_SECONDS * 1000),
    }

    # Count tests for dynamic timeout (use --collect-only if needed, else estimate)
    test_count = 15  # Conservative estimate for e2e tests
    subprocess_timeout = _get_subprocess_timeout(test_count)

    result = subprocess.run(
        cmd,
        capture_output=True, text=True, timeout=subprocess_timeout,
        cwd=str(REPO_ROOT),
        env=env,
    )

    passed = result.returncode == 0

    check_result = {
        "check_number": check_number,
        "timestamp": datetime.now().isoformat(),
        "passed": passed,
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-1000:] if result.stdout else "", # Capture more log
        "stderr_tail": result.stderr[-500:] if result.stderr else "",
    }

    if passed:
        log(f"✅ Playwright check #{check_number} PASSED")
    else:
        log(f"❌ Playwright check #{check_number} FAILED")
        results["errors"].append(f"Playwright check #{check_number} failed")

    return check_result


def check_docker_logs_for_errors():
    """Check Docker logs for errors."""
    error_count = 0
    for container in ["wicap-ui"]:
        try:
            result = subprocess.run(
                ["docker", "logs", "--tail", "100", container],
                capture_output=True, text=True, timeout=10
            )
            logs = result.stdout + result.stderr
            for line in logs.split("\n"):
                lower = line.lower()
                if "error" in lower or "exception" in lower or "traceback" in lower:
                    if "error_page" not in lower and "error.html" not in lower:
                        error_count += 1
        except Exception:
            pass

    return error_count

def verify_optimizations():
    """Verify code optimizations are present."""
    log("🔍 Verifying Optimizations...")

    # 1. Check Multi-Worker Implementation in dwell_watcher.py
    try:
        with open("nexus/dwell_watcher.py") as f:
            tree = ast.parse(f.read())

        has_multiprocessing = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "ThreadPoolExecutor":
                    for kw in node.keywords:
                        if kw.arg == "max_workers":
                            val = ast.unparse(kw.value)
                            if "cpu_count" in val:
                                has_multiprocessing = True
                                log(f"   ✅ Multi-Worker: Enabled (max_workers={val})")
        if not has_multiprocessing:
            log("   ❌ Multi-Worker: NOT ENABLED (Hardcoded to 1?)")
    except Exception as e:
        log(f"   ⚠️ Could not verify dwell_watcher.py: {e}")

    # 2. Check TShark Availability
    tshark_path = shutil.which("tshark")
    if tshark_path:
        log(f"   ✅ TShark: Available at {tshark_path}")
    else:
        log("   ⚠️ TShark: NOT FOUND (Falling back to Scapy)")

    # 3. Check SQL Batching in event_processor.py
    try:
        with open("event_processor.py") as f:
            content = f.read()
        if "self._sql_batch" in content and "self._flush_sql_batch" in content:
            log("   ✅ SQL Batching: Logic present")
        else:
            log("   ❌ SQL Batching: Logic MISSING")
    except Exception as e:
        log(f"   ⚠️ Could not verify event_processor.py: {e}")

    log("   (Optimization verification complete)")

    log("   (Optimization verification complete)")

def check_governor_activity(min_eps: float = 0.2, lookback_lines: int = 500):
    """Verify Neuro-Adaptive Governor is active in logs when EPS is meaningful.

    Uses a longer lookback window to reduce false positives during slow periods.
    """
    # Only warn if events are actually flowing.
    try:
        status = _fetch_json("/api/system/status", timeout=5)
        eps = float(status.get("eps") or 0)
        if eps < min_eps:
            return None  # Not enough data to judge
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", str(lookback_lines), "wicap-scout"],
            capture_output=True, text=True, timeout=10
        )
        combined = result.stdout + result.stderr
        # Look for any governor activity indicators
        if "🧠 Governor" in combined or "Governor:" in combined or "dwell" in combined.lower():
            return True
        return False
    except Exception:
        return False


# Track last governor warning time for backoff
_last_governor_warning = 0.0
_GOVERNOR_WARNING_INTERVAL_SEC = 300  # Only warn every 5 min

def run_soak_test():
    """Main soak test loop."""
    log("=" * 60)
    log("WICAP 30-Minute Soak Test Starting")
    log("=" * 60)

    # Verify optimizations before starting
    verify_optimizations()

    # Verify Governor (Phase 3)
    # We might not see logs immediately if it just started, so checking loop will handle it.
    log("🧠 Verifying Neuro-Adaptive Governor...")
    # (We rely on monitoring loop to verify it's running)

    results["start_time"] = datetime.now().isoformat()
    start_ts = time.time()

    # Baseline metrics
    log("📊 Capturing baseline metrics...")

    # Get initial event count for throughput calc
    initial_stats = {}
    try:
        import urllib.request
        with urllib.request.urlopen(f"{BASE_URL}/api/stats", timeout=5) as resp:
            initial_stats = json.load(resp)
    except Exception as e:
        log(f"⚠️ Failed to get initial stats: {e}")

    results["metrics"]["start"] = {
        "docker_stats": get_docker_stats(),
        "api_health": check_api_health(),
        "error_count": check_docker_logs_for_errors(),
        "app_stats": initial_stats
    }
    capture_ui_memory_snapshot("start")

    # Initial Playwright Check (Check #0) to fail fast if UI is broken
    log("🚀 Running initial UI health check...")
    results["playwright_checks"].append(run_playwright_check(0))

    total_checks = DURATION_MINUTES // PLAYWRIGHT_INTERVAL_MINUTES
    check_num = 0

    # Store history for averages
    cpu_history = {"wicap-core": [], "wicap-ui": []}
    mem_history = {"wicap-core": [], "wicap-ui": []}

    # Track which checkpoints have been captured
    triggered_checkpoints = set()

    while True:
        elapsed_min = (time.time() - start_ts) / 60

        if elapsed_min >= DURATION_MINUTES:
            break

        # Memory checkpoints at key intervals (steady-state analysis)
        for checkpoint_min in MEMORY_CHECKPOINT_MINUTES:
            if checkpoint_min not in triggered_checkpoints and elapsed_min >= checkpoint_min:
                triggered_checkpoints.add(checkpoint_min)
                log(f"📸 Memory checkpoint at {checkpoint_min}m")
                try:
                    snapshot = _fetch_json("/api/system/memory", timeout=10)
                    if snapshot:
                        results["memory_snapshots"]["checkpoints"].append({
                            "minute": checkpoint_min,
                            "timestamp": datetime.now().isoformat(),
                            "summary": snapshot.get("summary", {}),
                        })
                except Exception as e:
                    log(f"   ⚠️ Checkpoint failed: {e}")

        # Check if time for Playwright
        next_check_at = (check_num + 1) * PLAYWRIGHT_INTERVAL_MINUTES

        if elapsed_min >= next_check_at and check_num < total_checks:
            check_num += 1

            # API health
            health = check_api_health()
            results["api_health_checks"].append({
                "minute": round(elapsed_min, 1),
                "checks": health,
            })

            # Playwright check
            pw_result = run_playwright_check(check_num)
            results["playwright_checks"].append(pw_result)

            # Governor functionality verification (with warning backoff)
            global _last_governor_warning
            governor_status = check_governor_activity()
            if governor_status is True:
                log("   ✅ Governor: Active (Logs confirmed)")
            elif governor_status is False:
                # Only warn every N seconds to avoid log spam
                now = time.time()
                if now - _last_governor_warning > _GOVERNOR_WARNING_INTERVAL_SEC:
                    log("   ⚠️ Governor: No activity seen recently")
                    _last_governor_warning = now

            # Docker stats
            stats = get_docker_stats()
            log(f"📊 Docker stats: {stats}")

            # Record for averages
            for container, metrics in stats.items():
                if container in cpu_history:
                    # Clean "12.5%" -> 12.5
                    try:
                        cpu_val = float(metrics["cpu"].replace("%", ""))
                        mem_val = float(metrics["mem"].split()[0].replace("MiB", "").replace("GiB", "")) # Rough parse
                        cpu_history[container].append(cpu_val)
                        mem_history[container].append(mem_val)
                    except Exception:
                        pass

            # === Telemetry capture ===
            # EPS trend
            _capture_eps(elapsed_min)

            # Container restart detection
            current_starts = _capture_container_starts()
            if not results["telemetry"]["container_starts"]:
                results["telemetry"]["container_starts"] = {
                    "initial": current_starts,
                    "last": current_starts,
                    "samples": [],
                }
            else:
                # Check for real restarts: restart count increments, new container ID,
                # or container started-at timestamp change.
                state_store = results["telemetry"]["container_starts"]
                last_seen = state_store.get("last", {})
                for name, current in current_starts.items():
                    previous = last_seen.get(name)
                    if not isinstance(previous, dict):
                        continue

                    previous_restart_count = int(previous.get("restart_count", 0) or 0)
                    current_restart_count = int(current.get("restart_count", 0) or 0)
                    previous_id = previous.get("id")
                    current_id = current.get("id")
                    previous_started = previous.get("started_at")
                    current_started = current.get("started_at")

                    restart_reason = None
                    if current_restart_count > previous_restart_count:
                        restart_reason = (
                            f"restart_count {previous_restart_count}->{current_restart_count}"
                        )
                    elif previous_id and current_id and current_id != previous_id:
                        restart_reason = f"id changed {previous_id[:12]}->{current_id[:12]}"
                    elif (
                        previous_started
                        and current_started
                        and previous_started != current_started
                    ):
                        restart_reason = "started_at changed"

                    if restart_reason:
                        log(f"   ⚠️ Container {name} restart detected ({restart_reason})")
                        _add_warning(f"Container restart detected: {name} ({restart_reason})")

                state_store["last"] = current_starts
                state_store["samples"].append({
                    "minute": round(elapsed_min, 1),
                    "statuses": current_starts,
                })

            # Disk usage
            _capture_disk_usage(elapsed_min)

            # Latency sample
            _capture_latency(elapsed_min)

            # Error count
            errors = check_docker_logs_for_errors()
            log(f"📝 Log errors: {errors}")

            # Update live status file for monitoring
            _update_live_status(elapsed_min, start_ts)

        # Progress update every 2 minutes
        if int(elapsed_min) % 2 == 0 and int(elapsed_min) > 0:
            remaining = DURATION_MINUTES - elapsed_min
            log(f"⏱️ {elapsed_min:.1f} min elapsed, {remaining:.1f} min remaining")

        # Update live status every loop tick for a heartbeat
        _update_live_status(elapsed_min, start_ts)

        time.sleep(30)  # Check every 30 seconds

    # Final metrics
    log("📊 Capturing final metrics...")

    final_stats = {}
    try:
        import urllib.request
        with urllib.request.urlopen(f"{BASE_URL}/api/stats", timeout=5) as resp:
            final_stats = json.load(resp)
    except Exception as e:
        log(f"⚠️ Failed to get final stats: {e}")

    results["metrics"]["end"] = {
        "docker_stats": get_docker_stats(),
        "api_health": check_api_health(),
        "error_count": check_docker_logs_for_errors(),
        "app_stats": final_stats
    }
    capture_ui_memory_snapshot("end")

    # Postflight checks (identity graph, vendors, SIEM)
    results["postflight_checks"] = run_postflight_checks()

    # Baseline comparison gate
    baseline = _load_baseline(BASELINE_PATH)
    current = _compute_baseline_snapshot()
    regressions = []
    if baseline:
        regressions = _compare_to_baseline(current, baseline)
        if regressions:
            for msg in regressions:
                if BASELINE_ENFORCE:
                    _add_error(f"Baseline regression: {msg}")
                else:
                    _add_warning(f"Baseline regression: {msg}")
    else:
        log(f"🧭 No baseline found at {BASELINE_PATH}; creating one from this run.")

    if baseline is None or BASELINE_UPDATE:
        _write_baseline(BASELINE_PATH, current)
        log(f"🧭 Baseline written to {BASELINE_PATH}")

    results["baseline"] = {
        "path": str(BASELINE_PATH),
        "current": current,
        "baseline": baseline,
        "regressions": regressions,
        "enforced": BASELINE_ENFORCE,
    }

    results["end_time"] = datetime.now().isoformat()

    # Mark live status as complete (or remove it)
    try:
        if LIVE_STATUS_PATH.exists():
            with open(LIVE_STATUS_PATH, "w") as f:
                json.dump({"alive": False, "completed_at": results["end_time"], "status": "COMPLETE"}, f, indent=2)
    except Exception:
        pass

    # Save results
    results_file = LOG_DIR / f"soak_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    log(f"💾 Results saved to {results_file}")

    # Generate Performance Report
    generate_performance_report(results, initial_stats, final_stats, cpu_history, mem_history)

    return results


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WICAP soak test runner",
    )
    parser.add_argument(
        "--duration-minutes",
        type=int,
        default=None,
        help="Total soak duration in minutes (default: env WICAP_SOAK_DURATION_MINUTES or 30).",
    )
    parser.add_argument(
        "--playwright-interval-minutes",
        type=int,
        default=None,
        help="Run Playwright checks every N minutes (default: env WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES or 15).",
    )
    parser.add_argument(
        "--playwright-timeout-seconds",
        type=int,
        default=None,
        help="Per-page Playwright timeout in seconds (default: env PLAYWRIGHT_TIMEOUT_SECONDS or 120).",
    )
    parser.add_argument(
        "--pytest-timeout-seconds",
        type=int,
        default=None,
        help="Override total pytest subprocess timeout for each Playwright checkpoint.",
    )
    parser.add_argument(
        "--baseline-path",
        type=str,
        default=None,
        help="Path to baseline JSON file (default: env WICAP_SOAK_BASELINE_PATH).",
    )

    baseline_enforce = parser.add_mutually_exclusive_group()
    baseline_enforce.add_argument(
        "--baseline-enforce",
        dest="baseline_enforce",
        action="store_true",
        help="Treat baseline regressions as errors.",
    )
    baseline_enforce.add_argument(
        "--no-baseline-enforce",
        dest="baseline_enforce",
        action="store_false",
        help="Treat baseline regressions as warnings.",
    )
    parser.set_defaults(baseline_enforce=None)

    baseline_update = parser.add_mutually_exclusive_group()
    baseline_update.add_argument(
        "--baseline-update",
        dest="baseline_update",
        action="store_true",
        help="Write the current run as baseline.",
    )
    baseline_update.add_argument(
        "--no-baseline-update",
        dest="baseline_update",
        action="store_false",
        help="Do not write/update baseline file.",
    )
    parser.set_defaults(baseline_update=None)

    shutdown_group = parser.add_mutually_exclusive_group()
    shutdown_group.add_argument(
        "--shutdown-on-complete",
        dest="shutdown_on_complete",
        action="store_true",
        help="Run WICAP shutdown sequence after soak completes (default: enabled).",
    )
    shutdown_group.add_argument(
        "--no-shutdown-on-complete",
        dest="shutdown_on_complete",
        action="store_false",
        help="Skip shutdown sequence after soak completes.",
    )
    parser.set_defaults(shutdown_on_complete=None)

    return parser.parse_args()


def _run_shutdown_sequence() -> None:
    """Run teardown sequence to return host to clean post-soak state."""
    repo_root = Path(__file__).resolve().parents[1]
    stop_script = repo_root / "scripts" / "stop_wicap.py"
    log("🛑 Running post-soak shutdown sequence...")
    try:
        subprocess.run([sys.executable, str(stop_script)], cwd=str(repo_root), check=False, text=True)
    except Exception as exc:
        log(f"⚠️ stop_wicap.py execution failed: {exc}")

    try:
        subprocess.run(
            ["docker", "compose", "down", "--remove-orphans"],
            cwd=str(repo_root),
            check=False,
            text=True,
        )
    except Exception as exc:
        log(f"⚠️ docker compose down failed: {exc}")


def generate_performance_report(results, start_stats, end_stats, cpu_hist, mem_hist):
    """Print detailed performance review."""
    log("\n" + "=" * 60)
    log("🚀 PERFORMANCE OPTIMIZATION REVIEW")
    log("=" * 60)

    # 1. Throughput
    start_events = start_stats.get("total_events", 0)
    end_events = end_stats.get("total_events", 0)
    total_processed = end_events - start_events
    duration_min = results["duration_minutes"]
    eps = total_processed / (duration_min * 60) if duration_min > 0 else 0

    log("Processing Throughput:")
    log(f"  - Total Events:     {total_processed}")
    log(f"  - Duration:         {duration_min} min")
    log(f"  - Avg Events/Sec:   {eps:.2f} EPS")

    # 2. Resource Usage
    log("\nResource Usage (Average):")
    for container in ["wicap-core", "wicap-ui"]:
        cpus = cpu_hist.get(container, [])
        mems = mem_hist.get(container, [])
        avg_cpu = sum(cpus)/len(cpus) if cpus else 0
        avg_mem = sum(mems)/len(mems) if mems else 0
        log(f"  - {container}:  CPU {avg_cpu:.1f}%  |  Mem {avg_mem:.1f} MiB")

    def _parse_mem_mib(mem_str: str) -> float:
        if not mem_str:
            return 0.0
        # Format: "123.4MiB / 1.95GiB"
        token = mem_str.split("/")[0].strip()
        if token.lower().endswith("gib"):
            return float(token[:-3].strip()) * 1024
        if token.lower().endswith("mib"):
            return float(token[:-3].strip())
        return 0.0

    try:
        start_mem = start_stats.get("docker_stats", {}).get("wicap-ui", {}).get("mem", "")
        end_mem = end_stats.get("docker_stats", {}).get("wicap-ui", {}).get("mem", "")
        start_mib = _parse_mem_mib(start_mem)
        end_mib = _parse_mem_mib(end_mem)
        delta = end_mib - start_mib
        if delta > 200:
            warning = f"wicap-ui memory grew by {delta:.1f} MiB during soak."
            results["warnings"].append(warning)
            log(f"\n⚠️ Memory Watch: {warning}")
    except Exception:
        pass

    # Tracemalloc deltas (if snapshots exist)
    try:
        snap_start = results.get("memory_snapshots", {}).get("start") or {}
        snap_end = results.get("memory_snapshots", {}).get("end") or {}
        s_summary = snap_start.get("summary", {})
        e_summary = snap_end.get("summary", {})
        s_cur = float(s_summary.get("tracemalloc_current_mb") or 0)
        e_cur = float(e_summary.get("tracemalloc_current_mb") or 0)
        if e_cur > s_cur + 50:
            warning = f"tracemalloc current grew by {e_cur - s_cur:.1f} MiB during soak."
            results["warnings"].append(warning)
            log(f"\n⚠️ Memory Watch: {warning}")
    except Exception:
        pass

    # 3. Stability
    log("\nStability:")
    err_count = len(results["errors"])
    log(f"  - Errors Logged:    {err_count}")

    passed_checks = sum(1 for c in results["playwright_checks"] if c["passed"])
    total_checks = len(results["playwright_checks"])
    log(f"  - UI Checks:        {passed_checks}/{total_checks} Passed")

    log("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    args = _parse_args()
    configure_runtime(
        duration_minutes=args.duration_minutes,
        playwright_interval_minutes=args.playwright_interval_minutes,
        playwright_timeout_seconds=args.playwright_timeout_seconds,
        baseline_path=args.baseline_path,
        baseline_enforce=args.baseline_enforce,
        baseline_update=args.baseline_update,
        pytest_timeout_seconds=args.pytest_timeout_seconds,
        shutdown_on_complete=args.shutdown_on_complete,
    )

    try:
        run_soak_test()
    except KeyboardInterrupt:
        log("Soak test interrupted")
        sys.exit(1)
    finally:
        if SHUTDOWN_ON_COMPLETE:
            _run_shutdown_sequence()
