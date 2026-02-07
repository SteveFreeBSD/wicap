"""
Unit tests for Remote Sensor protocol.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import time

import pytest

from nexus.intel.remote_sensor import (
    SensorClient,
    SensorInfo,
    SensorMessage,
    SensorServer,
    SensorWebSocketClient,
    SensorWebSocketServer,
    ws_connect,
)


class TestSensorMessage:
    """Test SensorMessage serialization."""

    def test_to_json(self):
        msg = SensorMessage(
            msg_type='frame',
            sensor_id='abc123',
            timestamp=1000.0,
            payload={'test': 'data'}
        )
        json_str = msg.to_json()
        assert '"msg_type":"frame"' in json_str
        assert '"sensor_id":"abc123"' in json_str

    def test_from_json(self):
        json_str = '{"msg_type":"alert","sensor_id":"xyz789","timestamp":2000.0,"payload":{"level":"high"}}'
        msg = SensorMessage.from_json(json_str)
        assert msg.msg_type == 'alert'
        assert msg.sensor_id == 'xyz789'
        assert msg.payload['level'] == 'high'

    def test_roundtrip(self):
        original = SensorMessage(
            msg_type='heartbeat',
            sensor_id='test123',
            payload={'status': 'ok'}
        )
        json_str = original.to_json()
        restored = SensorMessage.from_json(json_str)
        assert restored.msg_type == original.msg_type
        assert restored.sensor_id == original.sensor_id
        assert restored.payload == original.payload


class TestSensorInfo:
    """Test SensorInfo dataclass."""

    def test_to_dict(self):
        info = SensorInfo(
            sensor_id='sensor1',
            name='Test Sensor',
            interface='wlan0',
            location='Office'
        )
        d = info.to_dict()
        assert d['sensor_id'] == 'sensor1'
        assert d['name'] == 'Test Sensor'
        assert d['interface'] == 'wlan0'
        assert d['location'] == 'Office'


class TestSensorServer:
    """Test SensorServer functionality."""

    @pytest.fixture
    def server(self):
        """Create a test server."""
        s = SensorServer(host='127.0.0.1', port=0)  # Port 0 = random available
        yield s
        s.stop()

    def test_start_stop(self, server):
        """Server should start and stop cleanly."""
        result = server.start()
        assert result is True
        assert server._running is True

        server.stop()
        assert server._running is False

    def test_initial_stats(self, server):
        """Initial stats should be zero."""
        server.start()
        stats = server.get_stats()
        assert stats['sensor_count'] == 0
        assert stats['total_frames'] == 0
        assert stats['total_alerts'] == 0

    def test_get_sensors_empty(self, server):
        """No sensors initially."""
        server.start()
        sensors = server.get_sensors()
        assert len(sensors) == 0


class TestSensorClient:
    """Test SensorClient functionality."""

    def test_initialization(self):
        """Client should initialize with correct values."""
        client = SensorClient(
            server_host='127.0.0.1',
            server_port=9999,
            sensor_name='test',
            interface='wlan0',
        )
        assert client.server_host == '127.0.0.1'
        assert client.server_port == 9999
        assert client.sensor_name == 'test'
        assert client._connected is False

    def test_get_stats(self):
        """Stats should be available."""
        client = SensorClient(
            server_host='127.0.0.1',
            server_port=9999,
        )
        stats = client.get_stats()
        assert 'sensor_id' in stats
        assert stats['connected'] is False
        assert stats['frames_sent'] == 0


class TestClientServerIntegration:
    """Test client-server communication."""

    def test_connect_and_register(self):
        """Client should connect and register with server."""
        frames_received = []
        registrations = []

        def on_frame(sensor_id, data):
            frames_received.append((sensor_id, data))

        def on_register(sensor_id, info, payload):
            registrations.append((sensor_id, info, payload))

        # Start server
        server = SensorServer(
            host='127.0.0.1',
            port=19999,
            on_frame=on_frame,
            on_register=on_register,
        )
        assert server.start() is True

        time.sleep(0.1)  # Let server start

        # Connect client
        client = SensorClient(
            server_host='127.0.0.1',
            server_port=19999,
            sensor_name='test_sensor',
        )
        assert client.connect() is True

        time.sleep(0.2)  # Let registration complete

        # Check server saw registration
        sensors = server.get_sensors()
        assert len(sensors) == 1
        assert sensors[0].name == 'test_sensor'
        assert len(registrations) == 1
        assert registrations[0][0] == sensors[0].sensor_id
        assert registrations[0][2].get('name') == 'test_sensor'

        # Cleanup
        client.disconnect()
        server.stop()

    def test_send_frame_data(self):
        """Frames should be forwarded to server."""
        frames_received = []

        def on_frame(sensor_id, data):
            frames_received.append((sensor_id, data))

        server = SensorServer(
            host='127.0.0.1',
            port=19998,
            on_frame=on_frame,
        )
        server.start()
        time.sleep(0.1)

        client = SensorClient(
            server_host='127.0.0.1',
            server_port=19998,
        )
        client.connect()
        time.sleep(0.1)

        # Send frame data
        client.send_frame_data({'mac': 'AA:BB:CC:DD:EE:FF', 'rssi': -50})
        time.sleep(0.2)

        # Check server received it
        assert len(frames_received) == 1
        assert frames_received[0][1]['mac'] == 'AA:BB:CC:DD:EE:FF'

        client.disconnect()
        server.stop()

    def test_send_event(self):
        """Events should be forwarded to server."""
        events_received = []

        def on_event(sensor_id, data):
            events_received.append((sensor_id, data))

        server = SensorServer(
            host='127.0.0.1',
            port=19992,
            on_event=on_event,
        )
        server.start()
        time.sleep(0.1)

        client = SensorClient(
            server_host='127.0.0.1',
            server_port=19992,
        )
        client.connect()
        time.sleep(0.1)

        payload = {"event_type": "probe_request", "channel": 6}
        assert client.send_event(payload) is True
        time.sleep(0.2)

        assert len(events_received) == 1
        assert events_received[0][1]["event_type"] == "probe_request"
        sensors = server.get_sensors()
        assert sensors[0].events_received == 1

        client.disconnect()
        server.stop()

    def test_heartbeat_callback(self):
        """Heartbeat callback should fire for connected sensors."""
        heartbeats = []

        def on_heartbeat(sensor_id, info, payload):
            heartbeats.append((sensor_id, payload))

        server = SensorServer(
            host='127.0.0.1',
            port=19994,
            on_heartbeat=on_heartbeat,
        )
        server.start()
        time.sleep(0.1)

        client = SensorClient(
            server_host='127.0.0.1',
            server_port=19994,
            heartbeat_interval=0.1,
        )
        client.connect()
        time.sleep(0.3)

        assert len(heartbeats) >= 1

        client.disconnect()
        server.stop()


class TestAuthentication:
    """Test token-based authentication."""

    def test_auth_success(self):
        """Client with correct token should connect."""
        server = SensorServer(
            host='127.0.0.1',
            port=19997,
            auth_token='secret123',
        )
        server.start()
        time.sleep(0.1)

        client = SensorClient(
            server_host='127.0.0.1',
            server_port=19997,
            auth_token='secret123',
        )
        assert client.connect() is True
        time.sleep(0.2)

        # Should be registered
        sensors = server.get_sensors()
        assert len(sensors) == 1

        client.disconnect()
        server.stop()

    def test_auth_failure(self):
        """Client with wrong token should not register."""
        server = SensorServer(
            host='127.0.0.1',
            port=19996,
            auth_token='correct_token',
        )
        server.start()
        time.sleep(0.1)

        client = SensorClient(
            server_host='127.0.0.1',
            server_port=19996,
            auth_token='wrong_token',
        )
        assert client.connect() is True  # TCP connects, but auth fails
        time.sleep(0.2)

        # Should NOT be registered (auth failed)
        sensors = server.get_sensors()
        assert len(sensors) == 0

        client.disconnect()
        server.stop()

    def test_no_auth_when_not_required(self):
        """Client should connect without token if server doesn't require it."""
        server = SensorServer(
            host='127.0.0.1',
            port=19995,
            # No auth_token set
        )
        server.start()
        time.sleep(0.1)

        client = SensorClient(
            server_host='127.0.0.1',
            server_port=19995,
            # No auth_token
        )
        assert client.connect() is True
        time.sleep(0.2)

        # Should be registered
        sensors = server.get_sensors()
        assert len(sensors) == 1

        client.disconnect()
        server.stop()


class TestWebSocketIntegration:
    """Test WebSocket sensor transport."""

    def test_ws_event_flow(self):
        """WebSocket client should send events to server."""
        if ws_connect is None:
            pytest.skip("websockets sync API not available")

        events_received = []

        def on_event(sensor_id, data):
            events_received.append((sensor_id, data))

        server = SensorWebSocketServer(
            host='127.0.0.1',
            port=0,
            on_event=on_event,
        )
        assert server.start() is True

        client = SensorWebSocketClient(
            server_host='127.0.0.1',
            server_port=server.port,
            sensor_name='ws_sensor',
        )
        assert client.connect() is True

        payload = {"event_type": "beacon", "channel": 11}
        assert client.send_event(payload) is True
        time.sleep(0.2)

        assert len(events_received) == 1
        assert events_received[0][1]["event_type"] == "beacon"
        sensors = server.get_sensors()
        assert sensors[0].events_received == 1

        client.disconnect()
        server.stop()
