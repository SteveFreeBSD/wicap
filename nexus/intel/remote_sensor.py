"""
Remote Sensor Protocol - Distributed WIDS

Enables multiple capture sensors to report to a central WIDS server.
Uses JSON over TCP for simplicity and cross-platform compatibility.

Architecture:
- SensorClient: Runs on capture nodes, forwards frames/alerts
- SensorServer: Aggregates data from multiple sensors
- SensorMessage: Wire format for sensor communication
"""

import json
import logging
import socket
import ssl
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from queue import Empty, Queue

try:
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.client import connect as ws_connect
    from websockets.sync.server import serve as ws_serve
except Exception:
    ws_connect = None
    ws_serve = None
    ConnectionClosed = Exception

logger = logging.getLogger(__name__)


@dataclass
class SensorMessage:
    """Wire format for sensor communication."""
    msg_type: str  # 'register', 'heartbeat', 'frame', 'alert', 'event', 'stats'
    sensor_id: str
    timestamp: float = field(default_factory=time.time)
    payload: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(',', ':'))

    @classmethod
    def from_json(cls, data: str) -> 'SensorMessage':
        d = json.loads(data)
        return cls(**d)


@dataclass
class SensorInfo:
    """Information about a connected sensor."""
    sensor_id: str
    name: str
    interface: str
    location: str | None = None
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    frames_received: int = 0
    alerts_received: int = 0
    events_received: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


class SensorClient:
    """
    Client that runs on capture sensor nodes.

    Connects to central server and forwards frame data and alerts.
    """

    def __init__(
        self,
        server_host: str,
        server_port: int = 9999,
        sensor_name: str = "sensor",
        interface: str = "wlan0",
        location: str | None = None,
        heartbeat_interval: float = 30.0,
        auth_token: str | None = None,
        use_tls: bool = False,
        tls_verify: bool = True,
        sensor_id: str | None = None,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.sensor_id = sensor_id or str(uuid.uuid4())[:8]
        self.sensor_name = sensor_name
        self.interface = interface
        self.location = location
        self.heartbeat_interval = heartbeat_interval
        self.auth_token = auth_token
        self.use_tls = use_tls
        self.tls_verify = tls_verify

        self._socket: socket.socket | None = None
        self._running = False
        self._connected = False
        self._authenticated = False
        self._heartbeat_thread: threading.Thread | None = None
        self._send_queue: Queue = Queue()
        self._send_thread: threading.Thread | None = None

        # Stats
        self._frames_sent = 0
        self._alerts_sent = 0

    def connect(self) -> bool:
        """Connect to the central server."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(10.0)
            self._socket.connect((self.server_host, self.server_port))

            # Wrap in TLS if enabled
            if self.use_tls:
                context = ssl.create_default_context()
                if not self.tls_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                self._socket = context.wrap_socket(
                    self._socket,
                    server_hostname=self.server_host
                )

            self._connected = True
            self._running = True

            # Send registration with auth token
            self._send_message(SensorMessage(
                msg_type='register',
                sensor_id=self.sensor_id,
                payload={
                    'name': self.sensor_name,
                    'interface': self.interface,
                    'location': self.location,
                    'auth_token': self.auth_token,
                }
            ))

            # Start background threads
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self._heartbeat_thread.start()

            self._send_thread = threading.Thread(target=self._send_loop, daemon=True)
            self._send_thread.start()

            logger.info(f"Connected to server {self.server_host}:{self.server_port}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self._connected = False
            return False

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self._running = False
        self._connected = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        logger.info("Disconnected from server")

    def send_frame_data(self, frame_data: dict) -> None:
        """Queue frame data for sending to server."""
        if not self._connected:
            return

        msg = SensorMessage(
            msg_type='frame',
            sensor_id=self.sensor_id,
            payload=frame_data,
        )
        self._send_queue.put(msg)
        self._frames_sent += 1

    def send_alert(self, alert_data: dict) -> None:
        """Queue alert for sending to server."""
        if not self._connected:
            return

        msg = SensorMessage(
            msg_type='alert',
            sensor_id=self.sensor_id,
            payload=alert_data,
        )
        self._send_queue.put(msg)
        self._alerts_sent += 1

    def send_event(self, event_data: dict) -> bool:
        """Queue a curated event for sending to server."""
        if not self._connected:
            return False

        msg = SensorMessage(
            msg_type='event',
            sensor_id=self.sensor_id,
            payload=event_data,
        )
        self._send_queue.put(msg)
        return True

    def _send_message(self, msg: SensorMessage) -> bool:
        """Send a message to the server."""
        if not self._socket or not self._connected:
            return False

        try:
            data = msg.to_json() + '\n'
            self._socket.sendall(data.encode('utf-8'))
            return True
        except Exception as e:
            logger.error(f"Send failed: {e}")
            self._connected = False
            return False

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        while self._running:
            time.sleep(self.heartbeat_interval)
            if self._connected:
                self._send_message(SensorMessage(
                    msg_type='heartbeat',
                    sensor_id=self.sensor_id,
                    payload={
                        'frames_sent': self._frames_sent,
                        'alerts_sent': self._alerts_sent,
                    }
                ))

    def _send_loop(self) -> None:
        """Process send queue."""
        while self._running:
            try:
                msg = self._send_queue.get(timeout=1.0)
                self._send_message(msg)
            except Empty:
                continue

    def get_stats(self) -> dict:
        return {
            'sensor_id': self.sensor_id,
            'connected': self._connected,
            'frames_sent': self._frames_sent,
            'alerts_sent': self._alerts_sent,
        }


class SensorWebSocketClient:
    """
    WebSocket-based client for remote sensors.

    Mirrors SensorClient but uses websockets transport.
    """

    def __init__(
        self,
        server_host: str,
        server_port: int = 9999,
        sensor_name: str = "sensor",
        interface: str = "wlan0",
        location: str | None = None,
        heartbeat_interval: float = 30.0,
        auth_token: str | None = None,
        use_tls: bool = False,
        tls_verify: bool = True,
        path: str = "/ws/sensors",
        sensor_id: str | None = None,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.sensor_id = sensor_id or str(uuid.uuid4())[:8]
        self.sensor_name = sensor_name
        self.interface = interface
        self.location = location
        self.heartbeat_interval = heartbeat_interval
        self.auth_token = auth_token
        self.use_tls = use_tls
        self.tls_verify = tls_verify
        self.path = path

        self._ws = None
        self._running = False
        self._connected = False
        self._heartbeat_thread: threading.Thread | None = None
        self._send_queue: Queue = Queue()
        self._send_thread: threading.Thread | None = None

        # Stats
        self._frames_sent = 0
        self._alerts_sent = 0

    def _build_url(self) -> str:
        scheme = "wss" if self.use_tls else "ws"
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{scheme}://{self.server_host}:{self.server_port}{path}"

    def connect(self) -> bool:
        """Connect to the central server."""
        if ws_connect is None:
            logger.error("websockets is required for WebSocket sensor transport")
            return False
        if self._connected:
            return True

        try:
            ssl_context = None
            if self.use_tls:
                ssl_context = ssl.create_default_context()
                if not self.tls_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            self._ws = ws_connect(
                self._build_url(),
                ssl_context=ssl_context,
                open_timeout=10,
            )

            self._connected = True
            self._running = True

            # Send registration with auth token
            self._send_message(SensorMessage(
                msg_type='register',
                sensor_id=self.sensor_id,
                payload={
                    'name': self.sensor_name,
                    'interface': self.interface,
                    'location': self.location,
                    'auth_token': self.auth_token,
                }
            ))

            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self._heartbeat_thread.start()

            self._send_thread = threading.Thread(target=self._send_loop, daemon=True)
            self._send_thread.start()

            logger.info(f"WebSocket connected to {self._build_url()}")
            return True
        except Exception as e:
            logger.error(f"WebSocket connect failed: {e}")
            self._connected = False
            return False

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self._running = False
        self._connected = False
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
        logger.info("WebSocket sensor disconnected")

    def send_frame_data(self, frame_data: dict) -> None:
        """Queue frame data for sending to server."""
        if not self._connected:
            return

        msg = SensorMessage(
            msg_type='frame',
            sensor_id=self.sensor_id,
            payload=frame_data,
        )
        self._send_queue.put(msg)
        self._frames_sent += 1

    def send_alert(self, alert_data: dict) -> None:
        """Queue alert for sending to server."""
        if not self._connected:
            return

        msg = SensorMessage(
            msg_type='alert',
            sensor_id=self.sensor_id,
            payload=alert_data,
        )
        self._send_queue.put(msg)
        self._alerts_sent += 1

    def send_event(self, event_data: dict) -> bool:
        """Queue a curated event for sending to server."""
        if not self._connected:
            return False

        msg = SensorMessage(
            msg_type='event',
            sensor_id=self.sensor_id,
            payload=event_data,
        )
        self._send_queue.put(msg)
        return True

    def _send_message(self, msg: SensorMessage) -> bool:
        """Send a message to the server."""
        if not self._ws or not self._connected:
            return False

        try:
            self._ws.send(msg.to_json())
            return True
        except Exception as e:
            logger.error(f"WebSocket send failed: {e}")
            self._connected = False
            return False

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        while self._running:
            time.sleep(self.heartbeat_interval)
            if self._connected:
                self._send_message(SensorMessage(
                    msg_type='heartbeat',
                    sensor_id=self.sensor_id,
                    payload={
                        'frames_sent': self._frames_sent,
                        'alerts_sent': self._alerts_sent,
                    }
                ))

    def _send_loop(self) -> None:
        """Process send queue."""
        while self._running:
            try:
                msg = self._send_queue.get(timeout=1.0)
                self._send_message(msg)
            except Empty:
                continue

    def get_stats(self) -> dict:
        return {
            'sensor_id': self.sensor_id,
            'connected': self._connected,
            'frames_sent': self._frames_sent,
            'alerts_sent': self._alerts_sent,
        }


class SensorServer:
    """
    Central server that aggregates data from multiple sensors.

    Provides callbacks for processing incoming frame data, alerts, and events.
    Supports token-based authentication and optional TLS encryption.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9999,
        on_frame: Callable[[str, dict], None] | None = None,
        on_alert: Callable[[str, dict], None] | None = None,
        on_event: Callable[[str, dict], None] | None = None,
        on_register: Callable[[str, SensorInfo, dict], None] | None = None,
        on_heartbeat: Callable[[str, SensorInfo, dict], None] | None = None,
        on_disconnect: Callable[[str, SensorInfo], None] | None = None,
        auth_token: str | None = None,
        tls_cert: str | None = None,
        tls_key: str | None = None,
    ):
        self.host = host
        self.port = port
        self.on_frame = on_frame
        self.on_alert = on_alert
        self.on_event = on_event
        self.on_register = on_register
        self.on_heartbeat = on_heartbeat
        self.on_disconnect = on_disconnect
        self.auth_token = auth_token
        self.tls_cert = tls_cert
        self.tls_key = tls_key

        self._sensors: dict[str, SensorInfo] = {}
        self._authenticated_clients: set = set()  # sensor_ids that passed auth
        self._socket: socket.socket | None = None
        self._ssl_context: ssl.SSLContext | None = None
        self._running = False
        self._accept_thread: threading.Thread | None = None
        self._client_threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    def start(self) -> bool:
        """Start the sensor server."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self.host, self.port))
            self._socket.listen(10)
            self._running = True

            if self.tls_cert and self.tls_key:
                self._ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                self._ssl_context.load_cert_chain(self.tls_cert, self.tls_key)

            self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._accept_thread.start()

            logger.info(f"Sensor server listening on {self.host}:{self.port}")
            return True

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            return False

    def stop(self) -> None:
        """Stop the sensor server."""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        logger.info("Sensor server stopped")

    def get_sensors(self) -> list[SensorInfo]:
        """Get list of connected sensors."""
        with self._lock:
            return list(self._sensors.values())

    def get_stats(self) -> dict:
        """Get server statistics."""
        with self._lock:
            return {
                'sensor_count': len(self._sensors),
                'total_frames': sum(s.frames_received for s in self._sensors.values()),
                'total_alerts': sum(s.alerts_received for s in self._sensors.values()),
                'total_events': sum(s.events_received for s in self._sensors.values()),
            }

    def _accept_loop(self) -> None:
        """Accept incoming connections."""
        while self._running:
            try:
                self._socket.settimeout(1.0)
                client_socket, addr = self._socket.accept()
                logger.info(f"New sensor connection from {addr}")

                if self._ssl_context is not None:
                    try:
                        client_socket = self._ssl_context.wrap_socket(client_socket, server_side=True)
                    except ssl.SSLError as exc:
                        logger.error(f"TLS handshake failed: {exc}")
                        client_socket.close()
                        continue

                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,),
                    daemon=True
                )
                thread.start()
                self._client_threads.append(thread)

            except TimeoutError:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"Accept error: {e}")

    def _handle_client(self, client_socket: socket.socket) -> None:
        """Handle a single client connection."""
        buffer = ""
        sensor_id = None

        try:
            client_socket.settimeout(60.0)

            while self._running:
                try:
                    data = client_socket.recv(4096).decode('utf-8')
                    if not data:
                        break

                    buffer += data

                    # Process complete messages (newline delimited)
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line:
                            msg = SensorMessage.from_json(line)
                            sensor_id = msg.sensor_id
                            self._process_message(msg)

                except TimeoutError:
                    continue

        except Exception as e:
            logger.error(f"Client handler error: {e}")
        finally:
            client_socket.close()
            if sensor_id:
                with self._lock:
                    info = self._sensors.pop(sensor_id, None)
                if info and self.on_disconnect:
                    self.on_disconnect(sensor_id, info)
                logger.info(f"Sensor {sensor_id} disconnected")

    def _process_message(self, msg: SensorMessage) -> bool:
        """
        Process an incoming message.

        Returns True if message was accepted, False if rejected (auth failure).
        """
        with self._lock:
            if msg.msg_type == 'register':
                # Validate auth token if required
                if self.auth_token:
                    client_token = msg.payload.get('auth_token')
                    if client_token != self.auth_token:
                        logger.warning(f"Auth failed for sensor {msg.sensor_id}: invalid token")
                        return False

                self._authenticated_clients.add(msg.sensor_id)
                info = SensorInfo(
                    sensor_id=msg.sensor_id,
                    name=msg.payload.get('name', 'unknown'),
                    interface=msg.payload.get('interface', 'unknown'),
                    location=msg.payload.get('location'),
                )
                self._sensors[msg.sensor_id] = info
                logger.info(f"Sensor registered: {msg.sensor_id}" +
                           (" (authenticated)" if self.auth_token else ""))
                if self.on_register:
                    self.on_register(msg.sensor_id, info, msg.payload)
                return True

            # For non-register messages, check if sensor is authenticated
            if self.auth_token and msg.sensor_id not in self._authenticated_clients:
                logger.warning(f"Rejecting message from unauthenticated sensor {msg.sensor_id}")
                return False

            if msg.msg_type == 'heartbeat':
                if msg.sensor_id in self._sensors:
                    info = self._sensors[msg.sensor_id]
                    info.last_heartbeat = msg.timestamp
                    if self.on_heartbeat:
                        self.on_heartbeat(msg.sensor_id, info, msg.payload)

            elif msg.msg_type == 'frame':
                if msg.sensor_id in self._sensors:
                    self._sensors[msg.sensor_id].frames_received += 1
                if self.on_frame:
                    self.on_frame(msg.sensor_id, msg.payload)

            elif msg.msg_type == 'alert':
                if msg.sensor_id in self._sensors:
                    self._sensors[msg.sensor_id].alerts_received += 1
                if self.on_alert:
                    self.on_alert(msg.sensor_id, msg.payload)

            elif msg.msg_type == 'event':
                if msg.sensor_id in self._sensors:
                    self._sensors[msg.sensor_id].events_received += 1
                if self.on_event:
                    self.on_event(msg.sensor_id, msg.payload)

        return True


class SensorWebSocketServer:
    """
    WebSocket-based sensor server for distributed capture.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9999,
        path: str = "/ws/sensors",
        on_frame: Callable[[str, dict], None] | None = None,
        on_alert: Callable[[str, dict], None] | None = None,
        on_event: Callable[[str, dict], None] | None = None,
        on_register: Callable[[str, SensorInfo, dict], None] | None = None,
        on_heartbeat: Callable[[str, SensorInfo, dict], None] | None = None,
        on_disconnect: Callable[[str, SensorInfo], None] | None = None,
        auth_token: str | None = None,
        tls_cert: str | None = None,
        tls_key: str | None = None,
    ):
        self.host = host
        self.port = port
        self.path = path
        self.on_frame = on_frame
        self.on_alert = on_alert
        self.on_event = on_event
        self.on_register = on_register
        self.on_heartbeat = on_heartbeat
        self.on_disconnect = on_disconnect
        self.auth_token = auth_token
        self.tls_cert = tls_cert
        self.tls_key = tls_key

        self._sensors: dict[str, SensorInfo] = {}
        self._authenticated_clients: set = set()
        self._server = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> bool:
        if ws_serve is None:
            logger.error("websockets is required for WebSocket sensor server")
            return False
        try:
            ssl_context = None
            if self.tls_cert and self.tls_key:
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(self.tls_cert, self.tls_key)

            self._server = ws_serve(
                self._handle_client,
                self.host,
                self.port,
                ssl_context=ssl_context,
                path=self.path,
            )
            if self._server and getattr(self._server, "socket", None):
                self.port = self._server.socket.getsockname()[1]
            self._running = True
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            logger.info(f"Sensor WebSocket server listening on {self.host}:{self.port}{self.path}")
            return True
        except Exception as e:
            logger.error(f"WebSocket server start failed: {e}")
            return False

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass
        logger.info("WebSocket sensor server stopped")

    def get_sensors(self) -> list[SensorInfo]:
        with self._lock:
            return list(self._sensors.values())

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'sensor_count': len(self._sensors),
                'total_frames': sum(s.frames_received for s in self._sensors.values()),
                'total_alerts': sum(s.alerts_received for s in self._sensors.values()),
                'total_events': sum(s.events_received for s in self._sensors.values()),
            }

    def _handle_client(self, websocket) -> None:
        sensor_id = None
        try:
            for message in websocket:
                if not message:
                    continue
                msg = SensorMessage.from_json(message)
                sensor_id = msg.sensor_id
                self._process_message(msg)
        except ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"WebSocket client handler error: {e}")
        finally:
            if sensor_id:
                with self._lock:
                    info = self._sensors.pop(sensor_id, None)
                if info and self.on_disconnect:
                    self.on_disconnect(sensor_id, info)
                logger.info(f"Sensor {sensor_id} disconnected")
            try:
                websocket.close()
            except Exception:
                pass

    def _process_message(self, msg: SensorMessage) -> bool:
        with self._lock:
            if msg.msg_type == 'register':
                if self.auth_token:
                    client_token = msg.payload.get('auth_token')
                    if client_token != self.auth_token:
                        logger.warning(f"Auth failed for sensor {msg.sensor_id}: invalid token")
                        return False

                self._authenticated_clients.add(msg.sensor_id)
                info = SensorInfo(
                    sensor_id=msg.sensor_id,
                    name=msg.payload.get('name', 'unknown'),
                    interface=msg.payload.get('interface', 'unknown'),
                    location=msg.payload.get('location'),
                )
                self._sensors[msg.sensor_id] = info
                logger.info(f"Sensor registered: {msg.sensor_id}" +
                           (" (authenticated)" if self.auth_token else ""))
                if self.on_register:
                    self.on_register(msg.sensor_id, info, msg.payload)
                return True

            if self.auth_token and msg.sensor_id not in self._authenticated_clients:
                logger.warning(f"Rejecting message from unauthenticated sensor {msg.sensor_id}")
                return False

            if msg.msg_type == 'heartbeat':
                if msg.sensor_id in self._sensors:
                    info = self._sensors[msg.sensor_id]
                    info.last_heartbeat = msg.timestamp
                    if self.on_heartbeat:
                        self.on_heartbeat(msg.sensor_id, info, msg.payload)

            elif msg.msg_type == 'frame':
                if msg.sensor_id in self._sensors:
                    self._sensors[msg.sensor_id].frames_received += 1
                if self.on_frame:
                    self.on_frame(msg.sensor_id, msg.payload)

            elif msg.msg_type == 'alert':
                if msg.sensor_id in self._sensors:
                    self._sensors[msg.sensor_id].alerts_received += 1
                if self.on_alert:
                    self.on_alert(msg.sensor_id, msg.payload)

            elif msg.msg_type == 'event':
                if msg.sensor_id in self._sensors:
                    self._sensors[msg.sensor_id].events_received += 1
                if self.on_event:
                    self.on_event(msg.sensor_id, msg.payload)

        return True
