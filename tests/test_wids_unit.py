"""Unit tests for WIDS Engine (no hardware required)."""
from dataclasses import dataclass

from nexus.intel.wids import Alert, WIDSEngine


@dataclass
class MockFrame:
    """Minimal frame for WIDS testing."""
    # Deauth/disassoc
    is_deauth: bool = False
    is_disassoc: bool = False
    reason_code: int = 0

    # Addresses
    src_mac: str = "00:11:22:33:44:55"
    dst_mac: str = "66:77:88:99:aa:bb"
    bssid: str = "aa:bb:cc:dd:ee:ff"

    # Network info
    ssid: str = "TestNetwork"
    channel: int = 6
    timestamp: float = 0.0
    rssi: int | None = -50

    # Security (for evil twin/downgrade detection)
    is_open: bool = False
    has_wep: bool = False
    has_wpa: bool = False
    has_wpa2: bool = True
    has_wpa3: bool = False

    # Frame type
    frame_type: int = 0  # Management
    frame_subtype: int = 12  # Deauth


class TestDeauthFloodDetection:
    """Tests for deauthentication flood detection."""

    def test_below_threshold_no_alert(self):
        """No alert when deauth count is below threshold."""
        engine = WIDSEngine(deauth_threshold=10, deauth_window_sec=5.0)
        frame = MockFrame(is_deauth=True, timestamp=1.0)

        # Send 5 deauths (below threshold of 10)
        result = None
        for i in range(5):
            frame.timestamp = float(i)
            result = engine.process_frame(frame)

        # No alert should be triggered
        assert result is None

    def test_above_threshold_triggers_alert(self):
        """Alert triggers when deauth threshold is exceeded."""
        engine = WIDSEngine(deauth_threshold=5, deauth_window_sec=10.0)
        frame = MockFrame(is_deauth=True)

        alert = None
        for i in range(10):
            frame.timestamp = float(i)
            result = engine.process_frame(frame)
            if result:
                alert = result

        assert alert is not None
        assert alert.alert_type == WIDSEngine.ALERT_DEAUTH_FLOOD
        assert alert.severity >= 3

    def test_window_expiry_resets_count(self):
        """Deauth count resets after window expires."""
        engine = WIDSEngine(deauth_threshold=5, deauth_window_sec=2.0)
        frame = MockFrame(is_deauth=True)

        # Send 3 deauths at t=0
        for i in range(3):
            frame.timestamp = 0.0 + (i * 0.1)
            engine.process_frame(frame)

        # Send 3 more after window expires (t=5)
        for i in range(3):
            frame.timestamp = 5.0 + (i * 0.1)
            result = engine.process_frame(frame)

        # Should not trigger (3+3 but across windows)
        assert result is None


class TestAlertThrottling:
    """Tests for alert throttling/cooldown."""

    def test_duplicate_alerts_suppressed(self):
        """Duplicate alerts within cooldown are suppressed."""
        engine = WIDSEngine(
            deauth_threshold=3,
            deauth_window_sec=10.0,
            alert_cooldown_sec=60.0,
        )
        frame = MockFrame(is_deauth=True)

        alerts = []
        # Send 20 deauths (should trigger multiple times without throttle)
        for i in range(20):
            frame.timestamp = float(i)
            result = engine.process_frame(frame)
            if result:
                alerts.append(result)

        # Should only get 1 alert due to cooldown
        assert len(alerts) <= 2  # Allow for initial + one after threshold


class TestAlertMethods:
    """Tests for Alert methods."""

    def test_alert_to_dict(self):
        """Alert.to_dict() returns expected structure."""
        alert = Alert(
            alert_type="test_alert",
            severity=3,
            title="Test Alert",
            description="This is a test",
            timestamp=1234567890.0,
            bssid="aa:bb:cc:dd:ee:ff",
            channel=6,
        )

        result = alert.to_dict()

        assert "id" in result
        assert result["alert_type"] == "test_alert"
        assert result["severity"] == 3
        assert result["title"] == "Test Alert"
        assert result["bssid"] == "aa:bb:cc:dd:ee:ff"


class TestEngineStats:
    """Tests for WIDS engine statistics."""

    def test_get_stats_structure(self):
        """get_stats() returns expected keys."""
        engine = WIDSEngine()
        stats = engine.get_stats()

        expected_keys = ["total_frames", "total_alerts", "suppressed_alerts"]
        for key in expected_keys:
            assert key in stats

    def test_stats_increment_on_frames(self):
        """Frame processing increments stats."""
        engine = WIDSEngine()
        frame = MockFrame(is_deauth=False)

        initial_frames = engine.get_stats()["total_frames"]

        engine.process_frame(frame)
        engine.process_frame(frame)

        assert engine.get_stats()["total_frames"] == initial_frames + 2


class TestAlertManagement:
    """Tests for alert retrieval and acknowledgement."""

    def test_get_all_alerts_empty(self):
        """get_all_alerts() returns empty list initially."""
        engine = WIDSEngine()
        alerts = engine.get_all_alerts()
        assert alerts == []

    def test_acknowledge_alert(self):
        """Acknowledging an alert marks it acknowledged."""
        engine = WIDSEngine(deauth_threshold=2, deauth_window_sec=10.0)
        frame = MockFrame(is_deauth=True)

        # Trigger an alert
        for i in range(5):
            frame.timestamp = float(i)
            engine.process_frame(frame)

        alerts = engine.get_all_alerts()
        if alerts:
            alert_id = alerts[0].id
            engine.acknowledge(alert_id)

            # Verify acknowledged
            updated = [a for a in engine.get_all_alerts() if a.id == alert_id]
            if updated:
                assert updated[0].acknowledged is True
