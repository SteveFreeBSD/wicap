# Remote Sensors

This document explains how to run the distributed sensor server and register
remote capture nodes.

## 1. Sensor Server (Hub)

Run the TCP sensor hub with SQL-backed registry:

```bash
python scripts/run_sensor_server.py --host 0.0.0.0 --port 9999 --auth-token <token>
```

The hub defaults to TCP unless `--transport ws|wss` (or `WICAP_SENSOR_PROTOCOL`)
is provided.

TLS (optional):

```bash
python scripts/run_sensor_server.py --tls-cert /path/server.crt --tls-key /path/server.key
```

WebSocket hub (unified capture protocol) + event ingestion:

```bash
python scripts/run_sensor_server.py --transport ws --ws-path /ws/sensors --ingest-events
```

TLS WebSocket hub:

```bash
python scripts/run_sensor_server.py --transport wss --tls-cert /path/server.crt --tls-key /path/server.key
```

Disable registry persistence (in-memory only):

```bash
python scripts/run_sensor_server.py --no-db
```

## 2. Sensor Client (SDK)

Sensors connect using `SensorClient` or `SensorWebSocketClient`
(see `nexus/intel/remote_sensor.py`).
Example usage inside a capture process:

```python
from nexus.intel.remote_sensor import SensorClient

client = SensorClient(
    server_host="10.0.0.10",
    server_port=9999,
    sensor_name="roof-node-1",
    interface="wlan0",
    location="47.6205,-122.3493",
    auth_token="shared-token",
    sensor_id="roof01",
)
client.connect()

# Send frame metadata or alerts:
client.send_frame_data({"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6})
client.send_alert({"type": "deauth_flood", "severity": 4})
```

Forward curated events from Scout to the hub:

```bash
export WICAP_SENSOR_HUB_HOST=10.0.0.10
export WICAP_SENSOR_HUB_PORT=9999
export WICAP_SENSOR_PROTOCOL=ws
export WICAP_SENSOR_AUTH_TOKEN=shared-token
python scout.py start
```

## 3. UI Visibility

The Sensors page pulls from `sensor_registry`:

- `/sensors` (UI page)
- `/api/sensors` (JSON)

Stale sensors are any online entries with heartbeats older than 120 seconds.

Fan-in metrics:
- `events_received` tracks how many curated events the hub has ingested per sensor.
- `last_event_at` is available in the API payload for latency inspection.

Coverage map:
- The Sensors page renders a coverage map when `location` is a coordinate pair.
- Set `location` as `lat,lon` (decimal degrees), for example: `47.6205,-122.3493`.
- Parsed coordinates are stored as `location_lat`/`location_lon` in `sensor_registry`.
- The UI prefers `location_lat`/`location_lon` when present, and falls back to parsing `location`.
- Sensors without coordinates still appear in the registry table and missing list.

## 4. Configuration

Relevant env vars:

- `WICAP_SQL_*` (for registry persistence)
- `WICAP_SENSOR_HOST`
- `WICAP_SENSOR_PORT`
- `WICAP_SENSOR_AUTH_TOKEN` (shared token, if you wrap this in a launcher)
- `WICAP_SENSOR_HUB_HOST` (for sensors to connect upstream)
- `WICAP_SENSOR_HUB_PORT`
- `WICAP_SENSOR_PROTOCOL` (`ws`, `wss`, or `tcp`)
- `WICAP_SENSOR_WS_PATH` (default `/ws/sensors`)
- `WICAP_SENSOR_TLS_VERIFY` (default `true`)
- `WICAP_SENSOR_ID` (optional stable 8-char sensor ID; defaults to hash of `WICAP_SENSOR_NAME`)

## 5. Next Steps (Planned)

- Sensor health metrics (drop rate, RSSI floor, channel drift)
- Queue health metrics (per-sensor rate, backlog, ingest latency)
