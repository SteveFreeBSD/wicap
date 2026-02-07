#!/usr/bin/env python3
"""
Run the distributed sensor server.

Optional SQL-backed registry persists sensor status and counters.
"""

import argparse
import logging
import os
import signal
import sys
import time

from config import get_scout_config
from event_queue import EventQueueWriter
from nexus.config import get_nexus_config
from nexus.intel.remote_sensor import SensorInfo, SensorServer, SensorWebSocketServer
from nexus.intel.sensor_registry import SensorRegistry

logger = logging.getLogger("scripts.sensor_server")


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(name)s: %(message)s",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run WICAP distributed sensor server")
    parser.add_argument("--host", default=os.getenv("WICAP_SENSOR_HOST", "0.0.0.0"),
                        help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("WICAP_SENSOR_PORT", "9999")),
                        help="Bind port (default: 9999)")
    parser.add_argument("--auth-token", default=os.getenv("WICAP_SENSOR_AUTH_TOKEN"),
                        help="Shared token for sensor auth")
    parser.add_argument("--tls-cert", default=os.getenv("WICAP_SENSOR_TLS_CERT"),
                        help="TLS cert path (optional)")
    parser.add_argument("--tls-key", default=os.getenv("WICAP_SENSOR_TLS_KEY"),
                        help="TLS key path (optional)")
    parser.add_argument("--transport", choices=("tcp", "ws", "wss"),
                        default=os.getenv("WICAP_SENSOR_PROTOCOL", "tcp"),
                        help="Transport protocol (tcp, ws, or wss)")
    parser.add_argument("--ws-path", default=os.getenv("WICAP_SENSOR_WS_PATH", "/ws/sensors"),
                        help="WebSocket path (default: /ws/sensors)")
    parser.add_argument("--no-db", action="store_true", help="Disable SQL registry persistence")
    parser.add_argument("--ingest-events", action="store_true",
                        help="Write incoming event messages into the central queue")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    _configure_logging(args.verbose)

    registry: SensorRegistry | None = None
    if not args.no_db:
        try:
            registry = SensorRegistry(get_nexus_config())
            registry.ensure_schema()
            logger.info("Sensor registry persistence enabled")
        except Exception as exc:
            logger.error(f"Failed to initialize sensor registry: {exc}")
            return 1

    event_queue: EventQueueWriter | None = None
    if args.ingest_events:
        try:
            event_queue = EventQueueWriter(get_scout_config())
            logger.info("Event ingestion enabled (remote sensors -> queue)")
        except Exception as exc:
            logger.error(f"Failed to initialize event queue: {exc}")
            return 1

    def _safe_call(func, *f_args):
        if not func:
            return
        try:
            func(*f_args)
        except Exception as exc:
            logger.error(f"Registry callback failed: {exc}")

    def on_register(sensor_id: str, info: SensorInfo, payload: dict):
        if registry:
            _safe_call(registry.register, info)

    def on_heartbeat(sensor_id: str, info: SensorInfo, payload: dict):
        if registry:
            _safe_call(registry.heartbeat, info, payload)

    def on_disconnect(sensor_id: str, info: SensorInfo):
        if registry:
            _safe_call(registry.disconnect, info)

    def on_event(sensor_id: str, payload: dict):
        if event_queue:
            if "sensor_id" not in payload:
                payload["sensor_id"] = sensor_id
            _safe_call(event_queue.write_event_dict, payload)
        if registry:
            _safe_call(registry.record_event, sensor_id)

    if args.transport == "wss" and not (args.tls_cert and args.tls_key):
        logger.error("wss transport requires --tls-cert and --tls-key")
        return 1

    if args.transport in ("ws", "wss"):
        server = SensorWebSocketServer(
            host=args.host,
            port=args.port,
            path=args.ws_path,
            on_register=on_register,
            on_heartbeat=on_heartbeat,
            on_disconnect=on_disconnect,
            on_event=on_event,
            auth_token=args.auth_token,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )
    else:
        server = SensorServer(
            host=args.host,
            port=args.port,
            on_register=on_register,
            on_heartbeat=on_heartbeat,
            on_disconnect=on_disconnect,
            on_event=on_event,
            auth_token=args.auth_token,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )

    if not server.start():
        return 1

    def _shutdown(signum, _frame):
        logger.info(f"Received signal {signum}, shutting down")
        server.stop()
        if event_queue:
            event_queue.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        server.stop()
        if event_queue:
            event_queue.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
