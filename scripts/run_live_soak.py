#!/usr/bin/env python3
"""
WICAP Live Soak Runner
Wrapper script to launch the full system and run the soak test with mandatory UI checks.
"""
import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Ensure repo root is in path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(REPO_ROOT))

def log(msg):
    print(f"🌊 [RUNNER] {msg}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WICAP live soak launcher")
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
        help="Playwright page timeout in seconds (passed through to soak test).",
    )
    parser.add_argument(
        "--baseline-path",
        type=str,
        default=None,
        help="Optional baseline JSON path passed to soak test.",
    )
    parser.add_argument(
        "--baseline-enforce",
        action="store_true",
        help="Treat baseline regressions as errors in soak test.",
    )
    parser.add_argument(
        "--baseline-update",
        action="store_true",
        help="Write/update baseline from this soak run.",
    )
    return parser.parse_args()

def cleanup(process=None):
    log("Shutting down...")

    if process and process.poll() is None:
        log("Sending SIGINT to start_wicap.py...")
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            log("Force killing start_wicap.py...")
            process.kill()

    # Docker Cleanup
    log("Running docker compose down...")
    subprocess.run(["docker", "compose", "down"], cwd=str(REPO_ROOT))

    # Run the robust stop script to catch anything else
    log("Running stop_wicap.py to ensure clean slate...")
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts/stop_wicap.py")])

def _apply_env_exports(output: str) -> None:
    import shlex
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ[key.strip()] = shlex.split(value.strip())[0]


def run_soak_preflight():
    if os.environ.get("WICAP_SOAK_PREFLIGHT_DONE") == "1":
        return

    log("Running soak preflight...")
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/soak_preflight.py"), "--print-env"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log(result.stdout.strip())
        log(result.stderr.strip())
        log("❌ Soak preflight failed.")
        sys.exit(1)

    _apply_env_exports(result.stdout)
    os.environ["WICAP_SOAK_PREFLIGHT_DONE"] = "1"

    subprocess.run([str(REPO_ROOT / "scripts/verify_capture_paths.sh")], check=True)
    if os.environ.get("WICAP_BT_ENABLED", "false").lower() == "true":
        subprocess.run([str(REPO_ROOT / "scripts/bt_preflight.sh")], check=True)

def check_playwright_env():
    log("Checking Playwright environment...")

    # Prefer an existing browser cache to avoid network installs.
    browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if browser_path and os.path.isdir(browser_path):
        log(f"Using Playwright browser cache: {browser_path}")
        return

    # Try to detect SUDO_USER to find their browser cache.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd

            user_home = pwd.getpwnam(sudo_user).pw_dir
        except Exception:
            user_home = f"/home/{sudo_user}"
        candidate = os.path.join(user_home, ".cache", "ms-playwright")
        if os.path.isdir(candidate):
            log(f"Found user browser cache: {candidate}")
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = candidate
            return

    # Best-effort install. Avoid --with-deps when not root to prevent sudo prompts.
    try:
        cmd = ["playwright", "install", "chromium"]
        if os.geteuid() == 0:
            cmd.append("--with-deps")
        subprocess.run(cmd, check=True)
    except Exception as e:
        log(f"⚠️ Playwright install warning (might be offline): {e}")
        # Playwright might still work if installed globally or via a shared cache.

def wait_for_ui(url="http://localhost:8080", timeout=60):
    log(f"Waiting for UI at {url}...")
    import urllib.request
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    log("✅ UI is UP!")
                    return True
        except Exception:
            time.sleep(2)
    return False


def wait_for_live_data(url="http://localhost:8080/api/system/status", timeout=120):
    log("Waiting for live data (EPS > 0 or recent insert)...")
    import json as _json
    import urllib.request
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status != 200:
                    time.sleep(2)
                    continue
                payload = _json.loads(r.read().decode("utf-8"))
                eps = float(payload.get("eps") or 0)
                last_insert = payload.get("last_insert")
                service_status = payload.get("service_status")
                if service_status not in ("running", "up"):
                    time.sleep(2)
                    continue
                if eps > 0:
                    log(f"✅ Live data detected (EPS={eps}).")
                    return True
                if last_insert:
                    log(f"✅ Recent insert detected at {last_insert}.")
                    return True
        except Exception:
            time.sleep(2)
    return False

def main():
    args = _parse_args()

    if os.geteuid() != 0:
        log("⚠️ WARNING: Not running as root. Capture might fail or require password.")
        log("   Recommend running with: sudo .venv/bin/python scripts/run_live_soak.py")
        time.sleep(2)

    # Allow explicit CLI flags to override environment defaults.
    if args.duration_minutes is not None:
        os.environ["WICAP_SOAK_DURATION_MINUTES"] = str(args.duration_minutes)
    if args.playwright_interval_minutes is not None:
        os.environ["WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES"] = str(args.playwright_interval_minutes)
    if args.playwright_timeout_seconds is not None:
        os.environ["PLAYWRIGHT_TIMEOUT_SECONDS"] = str(args.playwright_timeout_seconds)
    if args.baseline_path:
        os.environ["WICAP_SOAK_BASELINE_PATH"] = args.baseline_path
    if args.baseline_enforce:
        os.environ["WICAP_SOAK_BASELINE_ENFORCE"] = "1"
    if args.baseline_update:
        os.environ["WICAP_SOAK_BASELINE_UPDATE"] = "1"

    run_soak_preflight()

    # 1. Cleanup before start
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts/stop_wicap.py")])
    subprocess.run(["docker", "compose", "down"], cwd=str(REPO_ROOT))

    # 2. Check Playwright
    check_playwright_env()

    # 3. Start WICAP (Docker)
    log("🚀 Starting WICAP Stack (Docker Compose)...")

    # Run in background
    # We use 'up -d' so this returns immediately
    try:
        subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=str(REPO_ROOT), check=True)
        proc = None # No single process to track, docker daemon handles it
    except subprocess.CalledProcessError as e:
        log(f"❌ Docker compose failed: {e}")
        sys.exit(1)

    try:
        # 4. Wait for UI
        if not wait_for_ui():
            log("❌ UI failed to come up. Aborting.")
            cleanup(proc)
            sys.exit(1)

        # 5. Ensure live data before soak
        if not wait_for_live_data():
            log("❌ Live data not detected. Aborting soak.")
            cleanup(proc)
            sys.exit(1)

        # 6. Run Soak Test
        log("🧪 Running Soak Test (tests/soak_test.py)...")

        # Prepare environment - inherit from parent (run_soak.sh sets these)
        env = os.environ.copy()

        # Ensure duration is set (from env or default)
        duration = env.get("WICAP_SOAK_DURATION_MINUTES", "30")
        interval = env.get("WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES", "15")

        # Re-export to ensure child process sees them
        env["WICAP_SOAK_DURATION_MINUTES"] = duration
        env["WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES"] = interval

        log(f"Soak config: duration={duration} min, UI check interval={interval} min")

        # Runner owns teardown in `finally`, so keep soak test focused on validation.
        soak_cmd = [
            sys.executable,
            str(REPO_ROOT / "tests/soak_test.py"),
            "--no-shutdown-on-complete",
        ]
        if args.duration_minutes is not None:
            soak_cmd.extend(["--duration-minutes", str(args.duration_minutes)])
        if args.playwright_interval_minutes is not None:
            soak_cmd.extend(["--playwright-interval-minutes", str(args.playwright_interval_minutes)])
        if args.playwright_timeout_seconds is not None:
            soak_cmd.extend(["--playwright-timeout-seconds", str(args.playwright_timeout_seconds)])
        if args.baseline_path:
            soak_cmd.extend(["--baseline-path", args.baseline_path])
        if args.baseline_enforce:
            soak_cmd.append("--baseline-enforce")
        if args.baseline_update:
            soak_cmd.append("--baseline-update")

        res = subprocess.run(
            soak_cmd,
            cwd=str(REPO_ROOT),
            text=True,
            env=env
        )

        if res.returncode != 0:
            log("❌ Soak test failed!")
        else:
            log("✅ Soak test completed successfully!")

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"❌ Error during run: {e}")
    finally:
        cleanup(proc)

if __name__ == "__main__":
    main()
