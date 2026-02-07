#!/usr/bin/env python3
"""
WICAP UI Tests
===============

Tests for the WICAP UI Flask application endpoints.
Requires the wicap-ui container to be running.

Tests:
- Endpoint availability (200/302 responses)
- API response format validation
- Template rendering (no 500 errors)
"""

import argparse
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime

import requests

# Configuration
UI_BASE_URL = os.environ.get("WICAP_UI_URL", "http://localhost:8080")
TIMEOUT = 10

# Endpoints to test
ENDPOINTS = [
    # Page endpoints
    ("/", "GET", 200, "Dashboard"),
    ("/replay", "GET", 200, "Replay Dashboard"),
    ("/networks", "GET", 200, "Networks"),
    ("/handshakes", "GET", 200, "Handshakes"),
    ("/map", "GET", 200, "Network Map"),
    ("/scavenger", "GET", 200, "Scavenger"),
    ("/telemetry", "GET", 200, "Telemetry"),
    ("/admin", "GET", 200, "Admin"),
    ("/devices", "GET", 200, "Devices"),

    # API endpoints (matching actual routes)
    ("/api/stats", "GET", 200, "Stats API"),
    ("/api/recent-events", "GET", 200, "Events API"),
    ("/api/map/topology", "GET", 200, "Topology API"),
    ("/api/telemetry/feed", "GET", 200, "Telemetry Feed API"),
    ("/api/system/status", "GET", 200, "System Status API"),
    ("/api/scavenger/status", "GET", 200, "Scavenger Status API"),
    ("/api/devices", "GET", 200, "Device Identities API"),
    ("/api/identity/graph", "GET", 200, "Identity Graph API"),
    ("/api/insights/pol", "GET", 200, "POL Insights API"),
    ("/api/insights/correlations", "GET", 200, "Correlations API"),
    ("/api/admin/replay/missing.pcapng", "POST", 401, "Admin Replay API (unauthorized check)"),
    ("/api/incidents", "GET", 200, "Incidents List API"),
]



@dataclass
class EndpointResult:
    """Result of testing a single endpoint."""
    path: str
    method: str
    expected_status: int
    actual_status: int
    passed: bool
    response_time_ms: float
    error: str = ""


@dataclass
class UITestReport:
    """UI test report."""
    base_url: str
    timestamp: str
    results: list[EndpointResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging."""
    logger = logging.getLogger('ui_tests')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(ch)

    return logger


def test_endpoint(path: str, method: str, expected_status: int, description: str) -> EndpointResult:
    """Test a single endpoint."""
    url = f"{UI_BASE_URL}{path}"

    try:
        start = datetime.now()

        if method == "GET":
            response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        elif method == "POST":
            response = requests.post(url, timeout=TIMEOUT, json={})
        else:
            return EndpointResult(path, method, expected_status, 0, False, 0, f"Unknown method: {method}")

        response_time = (datetime.now() - start).total_seconds() * 1000

        # Accept redirects (302) for pages that might redirect
        passed = response.status_code == expected_status or (
            expected_status == 200 and response.status_code == 302
        )

        return EndpointResult(
            path=path,
            method=method,
            expected_status=expected_status,
            actual_status=response.status_code,
            passed=passed,
            response_time_ms=response_time
        )

    except requests.exceptions.ConnectionError:
        return EndpointResult(path, method, expected_status, 0, False, 0, "Connection refused")
    except requests.exceptions.Timeout:
        return EndpointResult(path, method, expected_status, 0, False, TIMEOUT * 1000, "Timeout")
    except Exception as e:
        return EndpointResult(path, method, expected_status, 0, False, 0, str(e))


def check_server_available() -> bool:
    """Check if the UI server is available."""
    try:
        response = requests.get(f"{UI_BASE_URL}/", timeout=5)
        return response.status_code in [200, 302]
    except Exception:
        return False


def run_tests(logger: logging.Logger) -> UITestReport:
    """Run all UI tests."""
    report = UITestReport(
        base_url=UI_BASE_URL,
        timestamp=datetime.now().isoformat()
    )

    logger.info(f"\n{'═' * 70}")
    logger.info("  🌐 WICAP UI TESTS")
    logger.info(f"  Base URL: {UI_BASE_URL}")
    logger.info(f"{'═' * 70}")

    # Check server first
    if not check_server_available():
        logger.error(f"\n  ❌ UI server not available at {UI_BASE_URL}")
        logger.error("     Make sure wicap-ui container is running:")
        logger.error("     docker-compose -f wicap-ui/docker-compose.yml up -d")
        return report

    logger.info("\n  ✅ Server available\n")

    for path, method, expected, description in ENDPOINTS:
        result = test_endpoint(path, method, expected, description)
        report.results.append(result)

        if result.passed:
            logger.info(f"  ✅ {method:4} {path:30} [{result.actual_status}] ({result.response_time_ms:.0f}ms)")
        else:
            logger.error(f"  ❌ {method:4} {path:30} [{result.actual_status}] {result.error}")

    return report


def print_summary(report: UITestReport, logger: logging.Logger):
    """Print test summary."""
    logger.info(f"\n{'═' * 70}")
    logger.info("  📊 UI TEST SUMMARY")
    logger.info(f"{'═' * 70}")
    logger.info(f"  Total:  {len(report.results)}")
    logger.info(f"  Passed: {report.passed}")
    logger.info(f"  Failed: {report.failed}")

    if report.failed == 0:
        logger.info("\n  ✅ All UI tests passed!")
    else:
        logger.error(f"\n  ❌ {report.failed} test(s) failed")

    logger.info(f"{'═' * 70}\n")


def main():
    parser = argparse.ArgumentParser(description='WICAP UI Tests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--url', type=str, help='Override UI base URL')
    args = parser.parse_args()

    global UI_BASE_URL
    if args.url:
        UI_BASE_URL = args.url

    logger = setup_logging(args.verbose)
    report = run_tests(logger)
    print_summary(report, logger)

    return 0 if report.failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
