"""
WICAP Bluetooth UI Tests
========================

Tests for the Bluetooth Intelligence UI.
See tests/test_e2e_ui.py for shared fixtures and setup.
"""

import json
import os
import re

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect, sync_playwright

pytestmark = pytest.mark.e2e

BASE_URL = os.environ.get("WICAP_UI_URL", "http://localhost:8080")

# =============================================================================
# Fixtures (Copied from test_e2e_ui.py)
# =============================================================================
def _playwright_timeout_ms() -> int:
    raw = os.environ.get("PLAYWRIGHT_PAGE_TIMEOUT_MS")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    seconds = os.environ.get("PLAYWRIGHT_TIMEOUT_SECONDS")
    if seconds:
        try:
            return int(float(seconds)) * 1000
        except ValueError:
            pass
    return 60000


@pytest.fixture(scope="module")
def browser():
    """Shared browser instance for test module."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    """Fresh page for each test."""
    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
    )
    page = context.new_page()
    timeout_ms = _playwright_timeout_ms()
    page.set_default_timeout(timeout_ms)
    page.set_default_navigation_timeout(timeout_ms)
    yield page
    context.close()

# =============================================================================
# Tests
# =============================================================================

def test_bluetooth_page_load(page):
    """Bluetooth page should load with correct title."""
    page.goto(f"{BASE_URL}/bluetooth")
    expect(page).to_have_title(re.compile("WICAP - Bluetooth Intelligence"))

    # Check header
    expect(page.locator("h1")).to_contain_text("Bluetooth Intelligence")

def test_bluetooth_api_call(page):
    """Page should call /api/devices/bluetooth on load."""
    # We use a flag to track if the request happened
    request_made = False

    def on_request(request):
        nonlocal request_made
        if "/api/devices/bluetooth" in request.url:
            request_made = True

    page.on("request", on_request)
    page.goto(f"{BASE_URL}/bluetooth")
    page.wait_for_timeout(1000) # Wait for page load scripts

    assert request_made, "Dashboard did not call /api/devices/bluetooth"

def test_bluetooth_empty_state_or_table(page):
    """Table should show loading or empty state initially."""
    page.goto(f"{BASE_URL}/bluetooth")

    # Should have a table
    table = page.locator("table.glass-table")
    expect(table).to_be_visible()

    # Should have headers
    expect(table.locator("th").first).to_contain_text("Address")
    expect(page.locator("th", has_text="Confidence")).to_be_visible()
    expect(page.locator("th", has_text="Behavior")).to_be_visible()


def test_bluetooth_confidence_and_service_summary_render(page):
    """Bluetooth table should render confidence badges and vendor UUID summaries."""
    payload = {
        "stats": {
            "total_devices": 1,
            "total_observations": 24,
            "active_5m": 1,
            "unique_vendors": 1,
            "top_vendors": [{"vendor": "Acme", "count": 1}],
        },
        "devices": [
            {
                "addr": "aa:bb:cc:dd:ee:ff",
                "vendor": "Acme",
                "type": "BLE",
                "name": "Beacon Alpha",
                "rssi_last": -63,
                "services": ["Battery Service (0x180F)"],
                "service_unknown_count": 2,
                "last_seen": "2026-02-06T12:34:56",
                "confidence_score": 82,
                "confidence_tier": "high",
                "why_matters": "High-confidence profile suitable for vendor attribution and repeat-presence tracking.",
                "is_randomized": False,
                "behavior_label": "steady",
                "behavior_summary": "Steady BLE cadence supports repeat-presence tracking and stronger attribution confidence.",
                "dwell_minutes": 142.5,
                "observation_rate_per_hour": 48.0,
                "rotation_risk_score": 22,
                "rotation_cluster_size": 2,
                "rotation_peer_count": 1,
                "rotation_suspected": True,
                "rotation_correlation_score": 73,
                "rotation_summary": "Possible BLE address rotation: 1 correlated peer address shares a similar fingerprint.",
                "recurrence_label": "steady",
                "recurrence_score": 78,
                "recurrence_summary": "Stable recurrence pattern with low cadence drift; useful for baseline tracking.",
                "recurrence_handoff_count": 0,
                "recurrence_peer_presence_ratio": 0.2,
            }
        ],
    }

    page.route(
        "**/api/devices/bluetooth*",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(payload),
        ),
    )

    page.goto(f"{BASE_URL}/bluetooth")
    row = page.locator("#bt-table-body tr").first
    expect(row).to_contain_text("82% HIGH")
    expect(row).to_contain_text("Battery Service (0x180F)")
    expect(row).to_contain_text("Fingerprint UUIDs hidden: 2")
    expect(row).to_contain_text("STEADY")
    expect(row).to_contain_text("Risk 22")
    expect(row).to_contain_text("Cluster 2")
    expect(row).to_contain_text("Recurrence STEADY")


def test_bluetooth_device_page_load(page):
    """BLE dossier page should load for a valid address."""
    resp = page.goto(f"{BASE_URL}/bluetooth/aa:bb:cc:dd:ee:ff")
    if resp and resp.status == 404:
        pytest.skip("Bluetooth dossier route not available on server")
    expect(page).to_have_title(re.compile("Bluetooth Device"))
    expect(page.locator("h1")).to_contain_text("Bluetooth Device")
    expect(page.locator("text=Why this matters")).to_be_visible()
    expect(page.locator(".label", has_text="Confidence")).to_be_visible()
    expect(page.locator("text=Pattern")).to_be_visible()
    expect(page.locator("text=Rotation Correlation")).to_be_visible()
    expect(page.locator("text=Timeline & Recurrence")).to_be_visible()

def test_nav_link_active(page):
    """Bluetooth nav link should be active."""
    page.goto(f"{BASE_URL}/bluetooth")
    link = page.locator("nav a[href='/bluetooth']")
    expect(link).to_have_class(re.compile(r"active"))
