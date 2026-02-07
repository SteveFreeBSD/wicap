#!/usr/bin/env python3
"""
WICAP Unified Test Suite
=========================

A comprehensive, modular test runner for the entire WICAP system including:
- Unit tests (NEXUS modules, Strategy Engine)
- Component tests (Scavenger forensics, deterministic replay fixtures)
- Integration tests (DB injection, audit pipeline)
- UI tests (endpoint availability, API responses)

Usage:
    python3 wicap_test_suite.py              # Unit + Component tests only
    python3 wicap_test_suite.py --live       # Include integration tests (requires DB)
    python3 wicap_test_suite.py --ui         # Include UI tests (requires containers)
    python3 wicap_test_suite.py --full       # All tests (includes e2e)
    python3 wicap_test_suite.py --e2e        # Include Playwright e2e tests
    python3 wicap_test_suite.py --verbose    # Detailed output
    python3 scripts/run_live_soak.py --duration-minutes 30 --playwright-minutes 10,25
"""

import argparse
import importlib.util
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0.0"
PROJECT_ROOT = Path(__file__).parent
LOG_DIR = Path("/tmp/wicap_test_logs")

# Test modules to run (in order)
UNIT_TEST_MODULES = [
    ("NEXUS Core Suite", [sys.executable, str(PROJECT_ROOT / "nexus" / "tests" / "test_nexus.py")]),
    ("Strategy Engine", [sys.executable, str(PROJECT_ROOT / "nexus" / "tests" / "test_smart_crack_engine.py"), "--verbose"]),
]

COMPONENT_TEST_MODULES = [
    ("Scavenger Harness", [sys.executable, str(PROJECT_ROOT / "nexus" / "tests" / "test_scavenger_harness.py"), "--quiet"]),
]

PYTEST_PATHS = [
    PROJECT_ROOT / "nexus" / "tests",
    PROJECT_ROOT / "tests",
]

REPLAY_MANIFEST = PROJECT_ROOT / "tests" / "fixtures" / "manifest.json"


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TestModuleResult:
    """Result of running a test module."""
    name: str
    passed: bool
    duration_sec: float
    output: str = ""
    error: str | None = None


@dataclass
class TestSuiteReport:
    """Complete test suite report."""
    timestamp: str = ""
    duration_sec: float = 0.0
    modules: list[TestModuleResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for m in self.modules if m.passed)

    @property
    def failed(self) -> int:
        return sum(1 for m in self.modules if not m.passed)

    @property
    def total(self) -> int:
        return len(self.modules)


# ═══════════════════════════════════════════════════════════════════════════════
# Logging Setup
# ═══════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with file and console handlers."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"wicap_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logger = logging.getLogger('wicap_test_suite')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(ch)

    logger.info(f"📝 Log file: {log_file}")
    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# Test Runners
# ═══════════════════════════════════════════════════════════════════════════════

def run_module(name: str, cmd: list[str], logger: logging.Logger, timeout: int = 300) -> TestModuleResult:
    """Run a single test module."""
    logger.info(f"\n{'═' * 70}")
    logger.info(f"  📦 {name}")
    logger.info(f"{'═' * 70}")

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=PROJECT_ROOT
        )
        duration = time.time() - start

        passed = result.returncode == 0
        output = result.stdout + result.stderr

        if passed:
            logger.info(f"  ✅ PASSED ({duration:.1f}s)")
        else:
            logger.error(f"  ❌ FAILED ({duration:.1f}s)")
            logger.debug(f"Output:\n{output[:2000]}")

        return TestModuleResult(
            name=name,
            passed=passed,
            duration_sec=duration,
            output=output,
            error=result.stderr if not passed else None
        )

    except subprocess.TimeoutExpired:
        logger.error(f"  ⏰ TIMEOUT after {timeout}s")
        return TestModuleResult(name=name, passed=False, duration_sec=timeout, error="Timeout")
    except Exception as e:
        logger.error(f"  💥 ERROR: {e}")
        return TestModuleResult(name=name, passed=False, duration_sec=time.time() - start, error=str(e))


def run_pytest(paths: list[Path], logger: logging.Logger, include_e2e: bool) -> TestModuleResult:
    """Run pytest on specified directories."""
    valid_paths = [str(p) for p in paths if p.exists()]
    if not valid_paths:
        return TestModuleResult(name="Pytest", passed=True, duration_sec=0, output="No test paths found")

    if importlib.util.find_spec("pytest") is None:
        logger.warning("  ⚠️ pytest not installed, skipping")
        return TestModuleResult(name="Pytest", passed=True, duration_sec=0, output="Skipped (not installed)")
    extra_args = ["-v", "--tb=short"]
    if not include_e2e:
        extra_args += ["-m", "not e2e"]
    cmd = [sys.executable, "-m", "pytest"] + valid_paths + extra_args
    return run_module("Pytest Unit Tests", cmd, logger)


def run_integration_tests(logger: logging.Logger) -> TestModuleResult:
    """Run integration tests (requires live database)."""
    logger.info(f"\n{'═' * 70}")
    logger.info("  🔗 Integration Tests (Live Database)")
    logger.info(f"{'═' * 70}")

    integration_script = PROJECT_ROOT / "tests" / "integration_tests.py"
    if integration_script.exists():
        return run_module("Integration Tests", [sys.executable, str(integration_script)], logger)
    return TestModuleResult(name="Integration", passed=True, duration_sec=0, output="No integration tests found")


def run_ui_tests(logger: logging.Logger) -> TestModuleResult:
    """Run UI tests (requires running containers)."""
    logger.info(f"\n{'═' * 70}")
    logger.info("  🌐 UI Tests (Endpoint Availability)")
    logger.info(f"{'═' * 70}")

    ui_script = PROJECT_ROOT / "tests" / "ui_tests.py"
    if ui_script.exists():
        return run_module("UI Tests", [sys.executable, str(ui_script)], logger)
    else:
        logger.warning("  ⚠️ UI test module not found")
        return TestModuleResult(name="UI Tests", passed=True, duration_sec=0, output="Skipped (module not found)")


def run_replay_tests(logger: logging.Logger) -> TestModuleResult:
    """Run deterministic replay fixture validation."""
    logger.info(f"\n{'═' * 70}")
    logger.info("  🔁 Replay Fixtures (Deterministic Validation)")
    logger.info(f"{'═' * 70}")

    if not REPLAY_MANIFEST.exists():
        logger.warning("  ⚠️ Replay manifest not found, skipping")
        return TestModuleResult(
            name="Replay Fixtures",
            passed=True,
            duration_sec=0,
            output="Skipped (manifest not found)",
        )

    cmd = [sys.executable, "-m", "replay_driver", "--batch", str(REPLAY_MANIFEST)]
    return run_module("Replay Fixtures", cmd, logger, timeout=600)


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    """Print the test suite banner."""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                    WICAP UNIFIED TEST SUITE                          ║
║                         Version 2.0.0                                ║
╚══════════════════════════════════════════════════════════════════════╝
    """)


def print_summary(report: TestSuiteReport, logger: logging.Logger):
    """Print the final test summary."""
    logger.info(f"\n{'═' * 70}")
    logger.info("  📊 TEST SUMMARY")
    logger.info(f"{'═' * 70}")

    for m in report.modules:
        status = "✅" if m.passed else "❌"
        logger.info(f"  {status} {m.name} ({m.duration_sec:.1f}s)")

    logger.info(f"\n  {'─' * 40}")
    logger.info(f"  Total:    {report.total}")
    logger.info(f"  Passed:   {report.passed}")
    logger.info(f"  Failed:   {report.failed}")
    logger.info(f"  Duration: {report.duration_sec:.1f}s")

    rate = (report.passed / report.total * 100) if report.total > 0 else 0
    logger.info(f"  Success:  {rate:.1f}%")
    logger.info(f"{'═' * 70}\n")


def main():
    parser = argparse.ArgumentParser(description='WICAP Unified Test Suite')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--live', action='store_true', help='Include integration tests (requires DB)')
    parser.add_argument('--ui', action='store_true', help='Include UI tests (requires containers)')
    parser.add_argument('--full', action='store_true', help='Run all tests')
    parser.add_argument('--e2e', action='store_true', help='Include Playwright e2e tests (requires UI)')
    parser.add_argument('--skip-unit', action='store_true', help='Skip unit tests')
    parser.add_argument('--skip-component', action='store_true', help='Skip component tests')
    args = parser.parse_args()

    if args.full:
        args.live = True
        args.ui = True
        args.e2e = True

    print_banner()
    logger = setup_logging(args.verbose)

    report = TestSuiteReport(timestamp=datetime.now().isoformat())
    start_time = time.time()

    # 1. Unit Tests
    if not args.skip_unit:
        for name, cmd in UNIT_TEST_MODULES:
            result = run_module(name, cmd, logger)
            report.modules.append(result)

        # Pytest
        result = run_pytest(PYTEST_PATHS, logger, include_e2e=args.e2e)
        report.modules.append(result)

    # 2. Component Tests
    if not args.skip_component:
        for name, cmd in COMPONENT_TEST_MODULES:
            result = run_module(name, cmd, logger)
            report.modules.append(result)

        # Deterministic replay fixture validation
        result = run_replay_tests(logger)
        report.modules.append(result)

    # 3. Integration Tests (optional)
    if args.live:
        result = run_integration_tests(logger)
        report.modules.append(result)

    # 4. UI Tests (optional)
    if args.ui:
        result = run_ui_tests(logger)
        report.modules.append(result)

    report.duration_sec = time.time() - start_time
    print_summary(report, logger)

    return 0 if report.failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
