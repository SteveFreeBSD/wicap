# Bluetooth Integration Roadmap (Artix + nRF52840)

This roadmap defines a complete, seamless Bluetooth integration for WICAP that
matches the fidelity and UX of the existing 802.11 pipeline (capture → event
queue → processor → SQL → UI → alerts → triangulation).

Date: 2026-02-06
Owner: WICAP core
Status: In Progress
Current slice: **B5 Triangulation** (blocked until sensors are available; B5b complete)

---

## Current State (Reality)

- Capture backend exists but needed wiring fixes.
- BLE parser exists but was not emitting WICAP‑compatible events.
- SQL tables exist but batching + schema creation were incomplete.
- UI endpoint exists but fails if tables are missing.

This document tracks the fixes and the target end state.

---

## Goals

- Full BLE capture (advertisements + connections) using nRF52840 on Artix Linux.
- Unified event ingestion into `curated_events` with a `protocol: "bt"` payload.
- SQL-first device profiles, observations, and triangulation results.
- UI parity with Wi‑Fi: map + dossier + alerts + timeline.
- Cross-protocol identity correlation (BLE ↔ Wi‑Fi) where possible.

## Constraints / Reality Check

- nRF52840 is BLE-only. It cannot sniff Bluetooth Classic (BR/EDR).
- BLE connection capture is limited: one connection can be followed per dongle.
- For Classic BT, plan a later optional backend (e.g., Ubertooth One).
- `WICAP_BT_EXTCAP_DIR` can override the Nordic extcap location if not using the repo copy.

## Troubleshooting (BLE Capture)

- **Missing `pyserial` / `psutil`**:
  - Symptom: `pyserial not found` or `ModuleNotFoundError: No module named 'psutil'` from `nrf_sniffer_ble`.
  - Fix: `python3 -m pip install -r tools/bluetooth/extcap/requirements.txt` (or rebuild the Docker image if using containers).
  - WICAP now validates runtime dependencies before capture start and suspends auto-restarts on fatal extcap errors to avoid crash loops.
- **"Running as user root ... could be dangerous"**:
  - This is a warning from Wireshark/dumpcap when running as root.
  - In Docker (privileged capture), it's expected. To suppress, run as non-root with proper `dumpcap` capabilities.
- **"tshark: There is no device named ..."**:
  - Usually means the extcap interface wasn't resolved or the dongle isn't visible in the container.
  - Run `tshark -D` and set `WICAP_BT_INTERFACE` to the reported interface (e.g., `/dev/ttyACM0-<ver>`).
  - Ensure `/dev/serial/by-id` is mounted and the dongle is present.
  - Use `scripts/bt_preflight.sh` to validate dependencies + device detection.
  - WICAP will also attempt a `/dev/ttyACM*-None` fallback when auto-resolving.
  - Fatal interface errors now trigger a restart cooldown to reduce log spam and stabilize soak runs.
- **Intermittent SQL cast/truncation errors during BT persistence**:
  - WICAP now sanitizes BT/WIDS text fields (invalid Unicode/control chars removed), normalizes bool-like payload fields, and falls back to row-wise SQL inserts when bulk insert fails.
  - Invalid rows are dropped with explicit log context instead of crashing the full flush cycle.
  - Incident grouping is best-effort: on incident allocation SQL errors, grouping is suspended for 300s and alert persistence continues.

---

## Target Architecture (End State)

```
[nRF52840 Sniffer] -> pcapng -> BLE Parser -> event_queue (protocol="bt")
                     |                                   |
                     |                                   v
                 Backfill CLI                      event_processor
                     |                                   |
                     v                                   v
               curated_events  <----- SQL persistence (bt_devices, bt_observations)
                     |
                     v
             Map / Dossier / Alerts / Triangulation
```

**Authoritative data sources**
- Events: `curated_events` + computed columns for BLE fields.
- Profiles: `bt_devices` (first/last seen, vendor, RSSI aggregates, services).
- Observations: `bt_observations` (raw sightings, per sensor).
- Connections: `bt_connections` (when a connection is followed).
- Location: `rf_location_estimates` (shared Wi‑Fi + BLE).

---

## Data Model (SQL)

Add BLE-specific tables and computed columns. Use idempotent SQL Server DDL
patterns (COL_LENGTH/OBJECT_ID checks).

### `bt_devices`
- `addr` (primary key)
- `addr_type` (public/random)
- `vendor`
- `device_type`
- `first_seen`, `last_seen`
- `rssi_avg`, `rssi_max`, `rssi_last`, `rssi_sample_count`, `rssi_last_seen`
- `services` (JSON array of UUIDs)
- `local_name`
- `manufacturer_data_hash`

### `bt_observations`
- `id` identity, `addr`, `sensor_id`, `ts_epoch`, `rssi`, `channel`,
  `adv_type`, `company_id`, `service_uuids`, `local_name`

### `bt_connections`
- `id` identity, `addr`, `peer_addr`, `access_address`, `first_seen`, `last_seen`

### `curated_events` computed columns
- `payload_protocol` (JSON_VALUE `$.protocol`)
- `payload_bt_addr` (JSON_VALUE `$.bt.addr`)
- `payload_bt_rssi` (JSON_VALUE `$.bt.rssi`)
- `payload_bt_company_id` (JSON_VALUE `$.bt.company_id`)
- `payload_bt_local_name` (JSON_VALUE `$.bt.local_name`)
- `payload_bt_adv_type` (JSON_VALUE `$.bt.adv_type`)
- `payload_bt_addr_type` (JSON_VALUE `$.bt.addr_type`)

---

## BLE Event Schema (Normalized)

Each event includes:

```
protocol: "bt"
keys: { sa, da, rssi_dbm, ssid }
channel: int
score: int
bt: {
  addr, addr_type, rssi, adv_type, channel,
  company_id, service_uuids, local_name, manufacturer_data_hash,
  access_address
}
```

Recommended event types:
- `bt_adv_seen`
- `bt_device_new`
- `bt_service_uuid_seen`
- `bt_connection_seen`
- `bt_rssi_strong`
- `bt_name_change`

---

## Roadmap Alignment (Single Source)

Bluetooth work is sequenced to align with the main roadmap:

- **B2 (Parser Enhancements)** must land before **S3.4 Device Identity Graph**
  so BLE devices join identity clusters and dossiers.
- **B4 (UI Parity)** is delivered alongside **S3.4/S3.5** so BLE evidence
  appears in ops outputs and device views.
- **B5 (Triangulation)** aligns with **E1.2 Coverage Estimation** (shared
  `rf_location_estimates`).

See `docs/ROADMAP.md` for the global sequencing.

---

## Work Slices (Roadmap)

Each slice ends with tests + docs update.

### B0. Wiring Fixes (Done)
- Fixed Bluetooth imports and duplicate backend init in `scout.py`.
- Added remote queue support for `write_event_dict`.
- Normalized BLE parser to emit WICAP‑compatible events.
- Fixed BT SQL batching (`executemany`) and added missing tables/indexes.

### B1. Capture Backend Stabilization (Done)
- Split capture/parse paths cleanly (`-w` always, `-T fields` only with callback).
- Validate `WIRESHARK_EXTCAP_DIR` and log errors clearly.
- Ensure the Nordic extcap is discoverable by `tshark` (auto-symlink into the
  system extcap directory when running in Docker).
- Ensure `captures/bt` is writable by `dumpcap` (auto-adjusts permissions on start).
- Add `bt_preflight` script to validate dongle + extcap.
- Configurable extcap path via `WICAP_BT_EXTCAP_DIR` (wired into `scout.py`).
- Auto-detect valid tshark fields to avoid invalid-field crashes; drop malformed lines.
- Soak validation: `docs/reports/soak/ble_soak_2026-01-30.md`.

### B2. Parser Enhancements (Done)
- Extended advertising support with normalized PDU types.
- Service UUID normalization (16/32/128-bit → canonical 128-bit UUIDs).
- Vendor lookup for BLE company IDs (with optional external mapping).
- Connection follow events when access address is present.

### B3. SQL Computed Columns + Indexes (Done)
- Added BLE computed columns to `curated_events`.
- Indexed `payload_protocol` and `payload_bt_addr`.

### B4. UI Parity (Done)
- `/api/devices/bluetooth` now tolerates missing tables and can fall back to `curated_events` for live stats.
- Bluetooth device list renders from `bt_devices` when available; fallback ensures visibility during early capture runs.
- Operational behavior: on database link/query failures, Bluetooth endpoints now return HTTP `503` (explicit failure) instead of silently emitting zeroed stats.
- Map overlay now renders BLE nodes on `/map` with filters + legend support.
- BLE dossier page is available at `/bluetooth/<addr>` with observations + services + RSSI history.

### B5a. Enrichment & Evidence (Done, No Sensors Required)
- Capture and persist `manufacturer_data_hash` for stable BLE fingerprinting.
- Expand vendor enrichment via `WICAP_BT_COMPANY_IDS_PATH` when available.
- Surface `manufacturer_data_hash` in the Bluetooth dossier for investigations.
- Add evidence hooks for identity changes (local name / services / fingerprint) without requiring sensors.
- Emit BLE change alerts into `attack_alerts` so the Alerts UI and dossiers stay consistent:
  - `ble_name_change`
  - `ble_services_change`
  - `ble_fingerprint_change`
- Default company map ships at `vendor/bluetooth/company_ids.json` (Bluetooth SIG list).
- Bluetooth UI includes top-vendor summaries and vendor filtering on the device list.
- Bluetooth dossiers support evidence filtering by type/severity.
Backfill CLI
- Canonical documentation lives in `docs/BACKFILL.md` (WiFi + BLE).
- BLE state file: `captures/bt/bt_backfill.state.json` (default).

### B5b. Analyst Readability + Confidence (Done, No Sensors Required)
- Add BLE attribution confidence scoring and tiering (high/medium/low) for operator triage. ✅
- Surface concise "why this matters" summaries in the device list and BLE dossier. ✅
- Keep unknown/vendor UUIDs summarized while promoting known service labels and stable identity factors. ✅
- Add behavior intelligence metrics (dwell, observation rate, cadence label, rotation-risk score) with UI surfacing. ✅
- Add cross-device address-rotation correlation (cluster size, peer count, suspicion, correlation score) in list + dossier. ✅
- Add timeline anomaly overlays for abrupt BLE behavior/rotation shifts, including recurrence/handoff summaries in dossier + list contracts. ✅
- Harden SQL persistence for noisy/irregular real-world BLE payloads:
  - sanitize odd text/control bytes before SQL writes
  - row-wise fallback for BT/Wi‑Fi/alert staging failures
  - keep flush cycle alive by dropping only invalid rows with diagnostics ✅
- UI readability defaults:
  - Bluetooth list/dossier shows **known service labels only**.
  - Unknown/member UUIDs are hidden as raw values and shown as a **fingerprint UUID count** for correlation context.

### B5. Triangulation (Blocked until sensors are available)
- Propagate `sensor_id` into curated events and `bt_observations` for multi‑sensor joins.
- New triangulation module: `nexus/intel/ble_triangulation.py` (weighted centroid + RSSI distance).
- Schema: `rf_location_estimates` table with protocol + target ID + accuracy + sensor list.
- API: `/api/bluetooth/locations` returns latest BLE estimates when present.
- CLI (manual run):
  - `python -m nexus.intel.ble_triangulation --since-minutes 10 --min-sensors 2`
  - Requires `sensor_registry` lat/lon values (see `docs/REMOTE_SENSORS.md`).

### B6. Classic BT (Optional)
- Ubertooth backend for BR/EDR capture.

---

## Acceptance Criteria (Completion)

- BLE capture runs continuously on Artix with nRF52840 and produces events.
- BLE devices appear in SQL (`bt_devices`) with RSSI aggregates.
- Map and device pages show BLE devices with consistent UX.
- Triangulation yields estimates for multi‑sensor BLE sightings.
- Alerts fire for BLE anomalies with evidence links.

---

## Open Questions

- Do we vendor Nordic sniffer code or depend on system installs?
- How many concurrent BLE connections should we follow (single dongle vs pool)?
- Do we standardize a `protocol` field in all events (Wi‑Fi + BLE)?

---

## Operational Entry Points (Authoritative)

Use these to avoid confusion from one-off experiments:

- **Live capture**: `WICAP_BT_ENABLED=true` + `start_wicap.py` (standard runtime)
  - Preferred device path: `/dev/serial/by-id/*nRF*` (stable across re-plugs)
  - Optional auto-select: `WICAP_BT_INTERFACE_GLOB=/dev/serial/by-id/*nRF*` or `WICAP_BT_SERIAL=<dongle_serial>`
- When using the Docker soak runner, it will now auto-enable Bluetooth capture whenever an nRF52840 interface resolves, so you can skip setting `WICAP_BT_ENABLED` manually.
- **Hardware sanity**: `scripts/bt_preflight.sh` + `scripts/verify_bt_capture.py`
- **Docs of record**: `docs/ROADMAP.md` + this file

Other scripts in `scripts/` are helpers and not canonical unless referenced above.
