# WICAP Configuration

This document is the single source of truth for configuration knobs.

## Required Secrets (Production)

These should be set via environment variables or a `.env` file (git-ignored).

- `WICAP_SQL_PASSWORD` (required by core/UI when SQL is enabled; minimum length enforced)
- `WICAP_INTERNAL_SECRET` (required for core → UI event push via `/api/internal/emit` and for `/api/admin/*` endpoints)

Related enforcement flags:
- `WICAP_INTERNAL_SECRET_REQUIRED` (default `true`)
- `WICAP_INTERNAL_ALLOWLIST` (default `127.0.0.1,::1`)

Admin UI usage:
- The Admin Console reads `WICAP_INTERNAL_SECRET` from a browser-local setting and sends it
  via the `X-WICAP-SECRET` header for all `/api/admin/*` calls.

## Core (Capture / Scout)

- `WICAP_INTERFACE` (default `wlan0`; Docker uses `.env`/`${WICAP_INTERFACE}` and falls back to `wlan1`)
  - Set to `auto` to resolve by MAC/regex at startup.
- `WICAP_INTERFACE_MAC` (optional; auto-select interface by MAC address)
- `WICAP_INTERFACE_REGEX` (optional; auto-select interface by name regex)
- `WICAP_INTERFACE_EXCLUDE_REGEX` (optional; exclude interfaces from auto-selection)
  - `start_wicap.py` now auto-resolves the interface (prefers `wlan1`) and will abort
    early if no suitable Wi‑Fi interface is detected.
- `WICAP_BANDS` (default `2.4ghz`; options: `2.4ghz`, `5ghz`, `6ghz`, `all`)
- `WICAP_CAPTURE_BACKEND` (default `auto`; options: `auto`, `scapy`, `libpcap`)
- `WICAP_CAPTURES_DIR` (default `./captures`)
- `WICAP_DWELL_THRESHOLD`
- `WICAP_DWELL_DURATION`
- `WICAP_RSSI_STRONG_THRESHOLD` (default `-85`, strict `>` comparison)
- `WICAP_SCORE_DECAY_SECONDS` (default `30`)

Queue / dedup:
- `WICAP_QUEUE_MAX_BYTES` (default `52428800`)
- `WICAP_QUEUE_MAX_FILES` (default `5`)
- `WICAP_QUEUE_BACKPRESSURE_MAX_BYTES` (default: `queue_max_bytes * queue_max_files`)
- `WICAP_QUEUE_BACKPRESSURE_ACTION` (default `drop_pulse`; options: `drop_pulse`, `drop`)
- `WICAP_DEDUP_MAX_ENTRIES` (default `10000`)

Redis (if enabled):
- `WICAP_REDIS_URL` (default `redis://localhost:6380/0`)

Core → UI:
- `WICAP_UI_URL` (default `http://localhost:8080`)

OTLP export (provider-neutral telemetry):
- `WICAP_OTLP_PROFILE` (default `disabled`; options: `disabled`, `self_hosted`, `vendor`, `cloud`)
- `WICAP_OTLP_HTTP_ENDPOINT` (OTLP HTTP endpoint, typically collector `/v1/logs`)
- `WICAP_OTLP_HEADERS` (optional headers as `k=v,k2=v2` or JSON object)
- `WICAP_OTLP_AUTH_BEARER` (optional bearer token for auth profiles)
- `WICAP_OTLP_API_KEY` (optional `x-api-key` auth material)
- `WICAP_OTLP_TIMEOUT_SECONDS` (default `1.5`)
- `WICAP_OTLP_MAX_QUEUE` (default `2000`)
- `WICAP_OTLP_MAX_BATCH` (default `200`)
- `WICAP_OTLP_RETRY_BACKOFF_SECONDS` (default `1.0`)
- `WICAP_OTLP_MAX_BACKOFF_SECONDS` (default `30.0`)

Notes:
- `vendor` and `cloud` profiles require auth and prefer `https` endpoints (non-localhost).
- OTLP failures are fail-open in runtime paths; capture/control pipelines remain primary.

## SQL Server (Shared)

The core and UI both talk to SQL Server.

- `WICAP_SQL_SERVER` / `WICAP_SQL_HOST` (default `192.168.4.25,1433`)
- `WICAP_SQL_DATABASE` (default `WifiInsanityDB`)
- `WICAP_SQL_USER` / `WICAP_SQL_USERNAME` (default `steve_linux`)
- `WICAP_SQL_PASSWORD` (required; minimum length enforced)
- `WICAP_SQL_DRIVER` (default `ODBC Driver 18 for SQL Server`)
- `WICAP_SQL_TRUST_CERT` (default `false`; set to `true` only if you understand the TLS implications)
- `WICAP_LEGACY_SQL_BATCH` (default `false`; opt-in fallback for legacy SQL batch inserts if PersistenceManager init fails)

## Backfill CLI (WiFi + BLE)

Both backfill tools require SQL access and, for BLE, `tshark`. Canonical
commands live in `docs/BACKFILL.md`.

Required env:
- `WICAP_SQL_PASSWORD`
- `WICAP_SQL_TRUST_CERT` (set to `true` if using self-signed certs)

Optional env:
- `WICAP_SQL_SERVER` / `WICAP_SQL_HOST`
- `WICAP_SQL_DATABASE`
- `WICAP_SQL_USER` / `WICAP_SQL_USERNAME`
- `WICAP_SQL_DRIVER`

## UI (wicap-ui)

- `WICAP_SQL_HOST` (UI-side alias for server/host)
- `WICAP_UI_DB_POOL_SIZE` (default `5`)
- `WICAP_CAPTURE_DIR` (default `../captures`) for Admin Captures list
- `WICAP_REPLAY_LOG_DIR` (default `/tmp`) for admin replay logs
- `WICAP_EVIDENCE_BUNDLE_DIR` (default `captures/evidence/bundles`) for evidence bundle ZIPs

## Nexus / Scavenger / Watcher

- `WICAP_DWELL_BASELINE_ON_START` (default `false`; mark existing dwell files as processed on startup)
- `WICAP_SCAVENGER_RAW_READER` (default `false`; enable RawPcapReader/RawPcapNgReader fast path)
- `NEXUS_WORDLISTS_DIR` (default `./captures/wordlists`; external corpus path for password-audit dictionaries)

_Note:_ Large dictionary corpora are intentionally externalized and not tracked
in this repository. Place optional corpora under `NEXUS_WORDLISTS_DIR` or
system paths like `/usr/share/wordlists`.

## Bluetooth (BLE)

- `WICAP_BT_ENABLED` (default `false`)
- `WICAP_BT_INTERFACE` (default `auto`)
  - Set to `auto` to resolve by glob/serial at startup.
- `WICAP_BT_INTERFACE_GLOB` (optional; auto-select by glob, e.g. `/dev/serial/by-id/*nRF*`)
- `WICAP_BT_SERIAL` (optional; auto-select by serial substring in `/dev/serial/by-id/*`)
- `WICAP_BT_CAPTURE_DIR` (default `./captures/bt`)
- `WICAP_BT_EXTCAP_DIR` (default `tools/bluetooth/extcap`)
- `WICAP_BT_COMPANY_IDS_PATH` (optional JSON/CSV company ID map override)
  - Default: `vendor/bluetooth/company_ids.json` (Bluetooth SIG list)
- `WICAP_BT_DEVICE` (legacy alias; prefer `WICAP_BT_INTERFACE`)

_Note:_ When you rely on the Docker soak runner, `scripts/run_docker_soak.sh` now auto-enables Bluetooth capture if it successfully resolves an nRF52840 interface, so you can leave `WICAP_BT_ENABLED` unset in `.env`.
_Note:_ If `WICAP_BT_INTERFACE` points at a stale path (for example a
`/dev/serial/by-id/*` symlink that is not present inside the container), WICAP
falls back to auto-detection (`WICAP_BT_INTERFACE_GLOB`, `WICAP_BT_SERIAL`,
then `/dev/ttyACM*`/`/dev/ttyUSB*`).
_Note:_ BLE capture uses `dumpcap` under the hood, which may drop privileges.
`BluetoothCaptureBackend` now auto-adjusts `captures/bt` permissions when run as
root, but if you run it manually ensure the directory is writable by the
`wireshark`/`dumpcap` user.

## Identity Graph (S3.4)

- `WICAP_IDENTITY_GRAPH_TTL_SEC` (default `300`) cache TTL for the in-memory graph
- `WICAP_IDENTITY_GRAPH_LOOKBACK_DAYS` (default `7`) profile lookback window
- `WICAP_IDENTITY_GRAPH_MIN_SCORE` (default `0.85`) minimum similarity score to link randomized MACs
- `WICAP_IDENTITY_GRAPH_TIME_GAP_SEC` (default `43200`) max time gap for comparisons
- `WICAP_IDENTITY_GRAPH_ALLOW_CROSS_PROTOCOL` (default `false`) allow Wi‑Fi ↔ BLE links on fingerprint matches
- `WICAP_IDENTITY_GRAPH_COMPACT_PROFILES` (default `true`) drop heavy profile fields after graph build to reduce UI memory

## Streaming Feature Engineering (S2.1)

- `WICAP_FEATURE_STREAM_ENABLED` (default `false`)
- `WICAP_FEATURE_WINDOW_SEC` (default `300`)
- `WICAP_FEATURE_MIN_EVENTS` (default `20`)
- `WICAP_FEATURE_RETENTION_SEC` (default `604800` / 7 days)
- `WICAP_FEATURE_STORE` (`redis`, `file`, `memory`, `off`)
- `WICAP_FEATURE_STORE_PATH` (directory for file-backed feature windows)
- `WICAP_FEATURE_GLOBAL_ENABLED` (default `true`)
- `WICAP_FEATURE_BSSID_ENABLED` (default `true`)

## Streaming Baseline (S2.2)

- `WICAP_BASELINE_STREAM_ENABLED` (default `false`)
- `WICAP_BASELINE_HORIZON_SEC` (default `86400`)
- `WICAP_BASELINE_REFRESH_SEC` (default `300`)
- `WICAP_BASELINE_MIN_WINDOWS` (default `20`)
- `WICAP_BASELINE_SCOPE` (default `global`)
- `WICAP_BASELINE_BSSID` (optional; set only if scope is `bssid`)
- `WICAP_BASELINE_STORE_PATH` (directory for baseline snapshots)

## Network Baseline Drift (S3.3)

- `WICAP_NETWORK_BASELINE_PATH` (default `./captures/network_baselines/network_baseline_global.json`)
- `WICAP_NETWORK_BASELINE_ENABLED` (optional; if unset, baseline loads only when the snapshot file exists)

## Streaming Anomaly Scoring (S2.3)

- `WICAP_ANOMALY_STREAM_ENABLED` (default `false`)
- `WICAP_ANOMALY_SCOPE` (defaults to `WICAP_BASELINE_SCOPE` or `global`)
- `WICAP_ANOMALY_BSSID` (optional; set only if scope is `bssid`)
- `WICAP_ANOMALY_SCORE_THRESHOLD` (default `70`)
- `WICAP_ANOMALY_SCORE_SCALE` (default `3.0`)
- `WICAP_ANOMALY_MIN_CONFIDENCE` (default `40`)
- `WICAP_ANOMALY_ATTACK_TYPE` (default `anomaly_stream`)
- `WICAP_ANOMALY_CALIBRATION_ENABLED` (default `false`)
- `WICAP_ANOMALY_CALIBRATION_PATH` (default `./captures/anomaly_calibration`)
- `WICAP_ANOMALY_CALIBRATION_REFRESH_SEC` (default `300`)
- `WICAP_ANOMALY_CALIBRATION_MIN_FEEDBACK` (default `10`)

## Alert Consolidation (S2.5)

- `WICAP_ALERT_CONSOLIDATION_ENABLED` (default `true`)
- `WICAP_ALERT_ML_CONFIDENCE_MIN` (default `80`)
- `WICAP_ALERT_ML_WINDOW_SEC` (default `900`)
- `WICAP_ALERT_SUPPRESSION_ENABLED` (default `true`)
- `WICAP_ALERT_SUPPRESSION_PATH` (default `./captures/alert_suppression.json`)
- `WICAP_ALERT_SUPPRESSION_CACHE_SEC` (default `60`)

## Ghost Hunter (Anomaly Detection)

- `WICAP_GHOST_MODEL_PATH` (default `./models/ghost_hunter/model.joblib`)

## Remote Sensors

- `WICAP_SENSOR_HOST` (default `0.0.0.0`)
- `WICAP_SENSOR_PORT` (default `9999`)
- `WICAP_SENSOR_AUTH_TOKEN` (optional shared token)
- `WICAP_SENSOR_TLS_CERT` (optional server TLS cert)
- `WICAP_SENSOR_TLS_KEY` (optional server TLS key)
- `WICAP_SENSOR_HUB_HOST` (sensor-side hub hostname)
- `WICAP_SENSOR_HUB_PORT` (sensor-side hub port)
- `WICAP_SENSOR_PROTOCOL` (`ws`, `wss`, or `tcp`; default `ws` for sensors, TCP if hub is started without the env or `--transport`)
- `WICAP_SENSOR_WS_PATH` (default `/ws/sensors`)
- `WICAP_SENSOR_TLS_VERIFY` (default `true`)
- `WICAP_SENSOR_NAME` (sensor identity label)
- `WICAP_SENSOR_LOCATION` (optional location tag; use `lat,lon` for coverage map + `location_lat`/`location_lon`)
- `WICAP_SENSOR_ID` (optional stable 8-char ID; defaults to hash of `WICAP_SENSOR_NAME`)

## Optional Dependencies

- `orjson` (faster JSON parse/serialize; optional)
- `xxhash` (faster dedup hashing; optional)
- Rust extension (`native/wicap_rust`) for hot-path helpers; optional
- `tshark` for high-fidelity parsing and fast backfill paths; optional
