"""
Unit tests for WIDS Engine.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import time
from dataclasses import dataclass

import pytest

from nexus.intel.network_baseline import NetworkBaselineSnapshot
from nexus.intel.wids import WIDSEngine


@dataclass
class MockFrame:
    """Mock ParsedFrame for testing."""
    is_deauth: bool = False
    is_disassoc: bool = False
    src_mac: str | None = None
    dst_mac: str | None = None
    bssid: str | None = None
    ssid: str | None = None
    channel: int = 1
    rssi: int = -50
    timestamp: float = 0.0
    encryption: str | None = None
    security: object | None = None


@pytest.fixture
def wids():
    """Create a WIDS engine with low thresholds for testing."""
    return WIDSEngine(
        deauth_threshold=5,
        deauth_window_sec=2.0,
        alert_cooldown_sec=1.0,
        max_alerts_per_min=5,
    )


@pytest.fixture
def baseline_snapshot():
    return NetworkBaselineSnapshot(
        scope="global",
        horizon_days=30,
        since_ts=0.0,
        until_ts=time.time(),
        updated_at=time.time(),
        ssid_bssids={"CorpWiFi": ["11:22:33:44:55:66"]},
        bssid_security={"11:22:33:44:55:66": "WPA2"},
        bssid_channel={"11:22:33:44:55:66": 6},
        bssid_ssid={"11:22:33:44:55:66": "CorpWiFi"},
    )


@pytest.fixture
def wids_with_baseline(baseline_snapshot):
    return WIDSEngine(
        deauth_threshold=5,
        deauth_window_sec=2.0,
        alert_cooldown_sec=1.0,
        max_alerts_per_min=5,
        baseline_snapshot=baseline_snapshot,
    )


class TestDeauthFlood:
    """Test deauthentication flood detection."""

    def test_no_alert_below_threshold(self, wids):
        """Should not alert below threshold."""
        for _i in range(4):  # Below threshold of 5
            frame = MockFrame(
                is_deauth=True,
                src_mac="AA:BB:CC:DD:EE:FF",
                bssid="11:22:33:44:55:66",
                timestamp=time.time(),
            )
            alert = wids.process_frame(frame)
            assert alert is None

    def test_alert_at_threshold(self, wids):
        """Should alert when reaching threshold."""
        now = time.time()
        for i in range(5):  # At threshold
            frame = MockFrame(
                is_deauth=True,
                src_mac="AA:BB:CC:DD:EE:FF",
                bssid="11:22:33:44:55:66",
                timestamp=now + i * 0.1,
            )
            alert = wids.process_frame(frame)

        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_DEAUTH_FLOOD
        assert alert.severity == 4
        assert alert.event_count == 5

    def test_old_events_pruned(self, wids):
        """Events outside window should be pruned."""
        now = time.time()

        # Add old events (outside 2s window)
        for _i in range(3):
            frame = MockFrame(
                is_deauth=True,
                src_mac="AA:BB:CC:DD:EE:FF",
                bssid="11:22:33:44:55:66",
                timestamp=now - 5.0,  # 5 seconds ago
            )
            wids.process_frame(frame)

        # Add new events (inside window) - not enough for threshold
        for _i in range(3):
            frame = MockFrame(
                is_deauth=True,
                src_mac="AA:BB:CC:DD:EE:FF",
                bssid="11:22:33:44:55:66",
                timestamp=now,
            )
            alert = wids.process_frame(frame)

        # Should not alert (old events pruned)
        assert alert is None


class TestEvilTwin:
    """Test evil twin detection."""

    def test_first_bssid_no_alert(self, wids):
        """First BSSID for SSID should not alert."""
        frame = MockFrame(
            ssid="TestNetwork",
            bssid="11:22:33:44:55:66",
            rssi=-50,
            timestamp=time.time(),
        )
        alert = wids.process_frame(frame)
        assert alert is None

    def test_second_bssid_alerts(self, wids):
        """Second BSSID for same SSID should alert."""
        now = time.time()

        # First AP
        frame1 = MockFrame(
            ssid="TestNetwork",
            bssid="11:22:33:44:55:66",
            rssi=-50,
            timestamp=now,
        )
        wids.process_frame(frame1)

        # Second AP (evil twin candidate)
        frame2 = MockFrame(
            ssid="TestNetwork",
            bssid="AA:BB:CC:DD:EE:FF",
            rssi=-50,
            timestamp=now + 1,
        )
        alert = wids.process_frame(frame2)

        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_EVIL_TWIN
        assert "TestNetwork" in alert.title

    def test_weak_signal_ignored(self, wids):
        """Weak evil twin signals should be ignored."""
        now = time.time()

        # First AP
        frame1 = MockFrame(
            ssid="TestNetwork",
            bssid="11:22:33:44:55:66",
            rssi=-50,
            timestamp=now,
        )
        wids.process_frame(frame1)

        # Weak second AP
        frame2 = MockFrame(
            ssid="TestNetwork",
            bssid="AA:BB:CC:DD:EE:FF",
            rssi=-85,  # Weak signal
            timestamp=now + 1,
        )
        alert = wids.process_frame(frame2)

        # Should not alert for weak signal
        assert alert is None


class TestCryptoDowngrade:
    """Test crypto downgrade detection."""

    def test_no_alert_for_first_encryption(self, wids):
        """First encryption observation should not alert."""
        frame = MockFrame(
            bssid="11:22:33:44:55:66",
            ssid="TestNetwork",
            encryption="WPA2",
            timestamp=time.time(),
        )
        alert = wids.process_frame(frame)
        assert alert is None


class TestBaselineDrift:
    def test_new_ssid_alert(self, wids_with_baseline):
        frame = MockFrame(
            ssid="GuestNetwork",
            bssid="AA:BB:CC:DD:EE:FF",
            rssi=-55,
            timestamp=time.time(),
        )
        alert = wids_with_baseline.process_frame(frame)
        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_BASELINE_NEW_SSID

    def test_new_bssid_alert(self, wids_with_baseline):
        frame = MockFrame(
            ssid="CorpWiFi",
            bssid="AA:BB:CC:DD:EE:FF",
            rssi=-50,
            timestamp=time.time(),
        )
        alert = wids_with_baseline.process_frame(frame)
        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_BASELINE_NEW_BSSID

    def test_security_downgrade_alert(self, wids_with_baseline):
        frame = MockFrame(
            ssid="CorpWiFi",
            bssid="11:22:33:44:55:66",
            encryption="Open",
            timestamp=time.time(),
        )
        alert = wids_with_baseline.process_frame(frame)
        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_BASELINE_SECURITY_DOWNGRADE

    def test_channel_drift_alert(self, wids_with_baseline):
        frame = MockFrame(
            ssid="CorpWiFi",
            bssid="11:22:33:44:55:66",
            channel=11,
            rssi=-55,
            timestamp=time.time(),
        )
        alert = wids_with_baseline.process_frame(frame)
        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_BASELINE_CHANNEL_DRIFT

    def test_alert_on_downgrade(self, wids):
        """Should alert when encryption is downgraded."""
        now = time.time()

        # First: WPA2
        frame1 = MockFrame(
            bssid="11:22:33:44:55:66",
            ssid="TestNetwork",
            encryption="WPA2",
            timestamp=now,
        )
        wids.process_frame(frame1)

        # Second: Open (downgrade!)
        frame2 = MockFrame(
            bssid="11:22:33:44:55:66",
            ssid="TestNetwork",
            encryption="Open",
            timestamp=now + 1,
        )
        alert = wids.process_frame(frame2)

        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_CRYPTO_DOWNGRADE
        assert alert.severity == 5  # Critical
        assert "WPA2" in alert.description
        assert "Open" in alert.description

    def test_no_alert_on_upgrade(self, wids):
        """Should not alert when encryption is upgraded."""
        now = time.time()

        # First: WPA
        frame1 = MockFrame(
            bssid="11:22:33:44:55:66",
            ssid="TestNetwork",
            encryption="WPA",
            timestamp=now,
        )
        wids.process_frame(frame1)

        # Second: WPA2 (upgrade)
        frame2 = MockFrame(
            bssid="11:22:33:44:55:66",
            ssid="TestNetwork",
            encryption="WPA2",
            timestamp=now + 1,
        )
        alert = wids.process_frame(frame2)

        assert alert is None


class TestThrottleLogic:
    """Test alert throttle/suppression logic."""

    def test_cooldown_suppresses_duplicates(self, wids):
        """Duplicate alerts should be suppressed during cooldown."""
        now = time.time()

        # Generate first alert
        for i in range(5):
            frame = MockFrame(
                is_deauth=True,
                src_mac="AA:BB:CC:DD:EE:FF",
                bssid="11:22:33:44:55:66",
                timestamp=now + i * 0.1,
            )
            wids.process_frame(frame)

        # Try to generate second alert immediately
        for i in range(5):
            frame = MockFrame(
                is_deauth=True,
                src_mac="AA:BB:CC:DD:EE:FF",
                bssid="11:22:33:44:55:66",
                timestamp=now + 1 + i * 0.1,
            )
            alert = wids.process_frame(frame)

        # Second alert should be suppressed (within 1s cooldown)
        assert alert is None

        stats = wids.get_stats()
        assert stats["suppressed_alerts"] > 0

    def test_acknowledge_alert(self, wids):
        """Should be able to acknowledge alerts."""
        now = time.time()

        # Generate alert
        for i in range(5):
            frame = MockFrame(
                is_deauth=True,
                src_mac="AA:BB:CC:DD:EE:FF",
                bssid="11:22:33:44:55:66",
                timestamp=now + i * 0.1,
            )
            alert = wids.process_frame(frame)

        assert alert is not None
        assert not alert.acknowledged

        # Acknowledge it
        result = wids.acknowledge(alert.id)
        assert result is True

        # Check it's acknowledged
        all_alerts = wids.get_all_alerts()
        assert all_alerts[0].acknowledged is True

        # Active alerts should be empty
        active = wids.get_active_alerts()
        assert len(active) == 0
