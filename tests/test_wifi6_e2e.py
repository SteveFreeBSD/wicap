import json
import os

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Page, expect, sync_playwright

pytestmark = pytest.mark.e2e

BASE_URL = os.environ.get("WICAP_UI_URL", "http://localhost:8080")

@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()

@pytest.fixture
def page(browser):
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()

def test_wifi6_badge_rendering(page: Page):
    """
    Verify that devices with is_wifi6=True render the AX badge.
    Since we can't easily inject a real Wifi 6 packet in E2E without complex setup,
    we will mock the API response to force a Wifi 6 device.
    """
    # Mock /api/devices to return a Wifi 6 device
    mock_response = {
        "identities": [
            {
                "id": "device-1",
                "macs": ["00:11:22:33:44:55"],
                "vendor": "Intel Corporate",
                "is_wifi6": True,  # FORCE TRUE
                "confidence_score": 85,
                "fingerprint_hash": "test_hash"
            },
            {
                "id": "device-2",
                "macs": ["AA:BB:CC:DD:EE:FF"],
                "vendor": "Legacy Device",
                "is_wifi6": False, # FORCE FALSE
                "confidence_score": 50,
                "fingerprint_hash": "legacy_hash"
            }
        ],
        "total": 2
    }

    page.route("**/api/devices", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body=json.dumps(mock_response)
    ))

    # Go to Devices page
    # Assuming the app is running at the base URL configured in conftest or default
    page.goto(f"{BASE_URL}/devices")

    # Wait for grid to load
    page.wait_for_selector(".device-card")

    # Check for Badge on Device 1
    # text="AX" inside a badge
    ax_badge = page.locator(".device-card", has_text="Device device-1").locator("span", has_text="AX")
    expect(ax_badge).to_be_visible()

    # Check that Device 2 does NOT have badge
    legacy_card = page.locator(".device-card", has_text="Device device-2")
    expect(legacy_card).to_be_visible()
    # Ensure no AX badge in this card
    # We can check count of badges inside this card
    count = legacy_card.locator("span", has_text="AX").count()
    assert count == 0, "Legacy device should not have AX badge"
