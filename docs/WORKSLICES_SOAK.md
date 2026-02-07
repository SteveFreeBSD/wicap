# Live Soak Work Slices

This is the execution plan that turns our current roadmap into a reliable, repeatable live soak gate. It lists every work slice that must land (with documentation and tests) before the system is ready for a professional, uninterrupted soak run. Use this file together with `docs/ROADMAP.md` and `docs/TESTING.md`.

## 1. Why this matters

- A live soak is not just the 30-minute run; it validates the entire capture-service → SQL → UI path under sustained load. Any unaddressed work slice introduces drift or gaps that show up as UI breakage, missing data, or unhandled captures.
- All slices below are sequenced so earlier items complete before the next step starts. Each slice must end with documented verification (playwright soak/resus) and automated tests where possible.

## 2. Required workslices for a solid soak

### S3.4 Device Identity Graph (Maps + Dossier)

- **Goal**: Link Wi‑Fi + BLE fingerprints so the live UI shows combined identities, not just per-protocol fragments.
- **Status**: Completed (graph build + dossier/map integration + export endpoint).
- **Actions**:
  - Implement the `identity_graph` module that merges MACs using fingerprint overlap + shared RSSI windows.
  - Persist graph data in the device dossier API (`/api/devices/{mac}`) and expose node relationships to the map overlay.
  - Add unit tests for fingerprint linking, random MAC resolution, and graph export.
- **Tests**: `pytest tests/test_identity_graph.py`, `pytest -m e2e tests/test_devices_api.py::TestDeviceDossier::test_combined_protocols`.
- **Docs**: Document interaction flow in `docs/map_enhancement_walkthrough.md` and update `docs/ROADMAP.md` status.

### S3.5 Ops Outputs & Evidence Bundles

- **Goal**: Make it easy to export soak-time intelligence plus connect ML outputs to alerts.
- **Status**: Completed (digest CLI, evidence bundle builder, SIEM export).
- **Actions**:
  - Wire webhook/SIEM payloads from the alert engine with evidence pointers (PCAP offsets, event IDs).
  - Build a daily digest CLI that summarizes the last soak run: new devices, alerts, anomalies, drift metrics; store it in `/docs/reports/soak/digest_<date>.md`.
  - Provide JSON + PCAP evidence bundling (zip of curated_events + PCAP) accessible via `/api/evidence/bundles/<date>`.
- **Tests**: Add harness tests for digest generation (`python tests/test_digest.py`) and HTTP contract tests verifying payload structure.
- **Docs**: Update `docs/BACKFILL.md` and `docs/TESTING.md` with new digest + evidence steps.

### B5a Enrichment & Evidence (Bluetooth)

- **Goal**: Finish the BT pipeline so live soak can surface BLE data alongside Wi‑Fi.
- **Status**: Completed (BLE enrichment + evidence alerts wired).
- **Actions**:
  - Populate every BLE event with `manufacturer_data_hash`, `local_name`, and service UUID metadata. Ensure these values persist to `bt_devices` (profile) and `bt_observations` (evidence trail).
  - Expand vendor data via `WICAP_BT_COMPANY_IDS_PATH` (canonical list under `vendor/bluetooth/company_ids.json`).
  - Emit BLE evidence alerts into `attack_alerts` for identity drift:
    - `ble_name_change`
    - `ble_services_change`
    - `ble_fingerprint_change`
- **Tests**: `pytest tests/test_ble_parser.py::test_manufacturer_hash`, `pytest tests/test_ble_alerts.py::test_build_ble_alert_row_basic`, `pytest tests/test_sql_persistence.py::test_add_bt_event_flush`, manual `scripts/bt_preflight.sh` + `scripts/verify_bt_capture.py`.
- **Docs**: Document the evidence alert types in `docs/BLUETOOTH.md` and add a `BLE Evidence` section to `docs/TESTING.md`.

### B5 Triangulation (Sensors + RF Location)

- **Goal**: Ensure soak uses sensors and triangulation by the time we need location-aware alerts.
- **Actions**:
  - Propagate `sensor_id` into every curated BLE and Wi‑Fi observation (`curated_events` + `bt_observations`).
  - Finalize `nexus/intel/ble_triangulation.py` module with `weighted_centroid` calculation and `rf_location_estimates` persistence.
  - Expose `/api/bluetooth/locations` and `/api/devices/{mac}/locations` (combined Wi‑Fi + BLE) for the UI overlays.
- **Tests**: `pytest tests/test_triangulation.py`, integration soak that verifies `/api/system/status` shows `rf_location_estimates` stats.
- **Docs**: Add a new section `docs/REMOTE_SENSORS.md` describing sensor requirements for the soak and how to replay multi-sensor data.

### S3 Live Soak Safety Belt

- **Goal**: Tie every preceding slice into the soak run so nothing slips through.
- **Status**: Completed (preflight + postflight checks wired).
- **Actions**:
  - Update `scripts/run_soak.sh` to call `scripts/soak_preflight.py`, `scripts/verify_capture_paths.sh`, and `scripts/bt_preflight.sh` (when BLE enabled) before starting the run.
  - Extend soak harness (`tests/soak_test.py`) to verify vendor data, identity graph availability, BLE stats, and SIEM export after the run.
  - Confirm `docs/TESTING.md` lists the soak prerequisites, hardware gating, Playwright settings, and new digest/evidence steps.
- **Tests**: `scripts/soak_preflight.py --print-env` (preflight), `tests/soak_test.py` (soak harness). After the run, generate `docs/reports/soak/soak_complete_<date>.md` capturing baseline metrics.

## 3. Sequence & Ownership

1. Finish S3.4 (Device Identity).  ↝ once complete, run core tests + update map docs.  (Owner: Mapping team)  
2. Complete S3.5 (Ops & Evidence). ↝ add digest/evidence tests.  
3. Ship B5a (BLE enrichment) before adding sensors or starting soak; ensures cross-protocol identity.  
4. Wrap B5 (triangulation) to add sensor data that the soak will exercise.  
5. Execute the Live Soak Safety Belt step to validate the entire pipeline in a 30-minute soak.  

## 4. Exit Criteria

- All work slices above have automated coverage + manual verification.  
- `docs/ROADMAP.md`, `docs/BLUETOOTH.md`, and `docs/TESTING.md` explicitly record the soak readiness checklist.  
- Soak harness (`tests/soak_test.py`) saves a new report under `docs/reports/soak/` that shows vendor data, identity graph, evidence metrics, and ble devices for that run.  
- Once the soak passes, stamp `S3 Live Soak` gate in `docs/ROADMAP.md` and confirm the soak release notes mention the new verification steps.  
