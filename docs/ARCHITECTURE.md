# WICAP Architecture

This document describes the current WICAP system boundaries and data flow. It
is intended to prevent “mystery wiring” and reduce accidental regressions.

Start here for navigation: `docs/INDEX.md`

---

## 1. Primary Data Flows

Live:
- `scout.py` captures 802.11 frames, performs lightweight parsing, and emits events
- `event_queue.py` stores events (file-backed and/or Redis-backed depending on configuration)
- `event_processor.py` reads events, deduplicates/enriches, and persists to SQL (`curated_events`)
- `wicap-ui/` reads from SQL and renders dashboards/APIs

Dwell / PCAP intelligence:
- dwell captures land under `captures/` (`dwell_*.pcapng`)
- `nexus/dwell_watcher.py` monitors dwell files and triggers analysis jobs
- `nexus/scavenger/*` extracts offline intelligence (associations/RSSI/etc) and persists to SQL

Ghost Hunter anomaly detection:
- `nexus/intel/ghost_hunter.py` aggregates `curated_events` into windows
- baseline models are trained offline and scored on demand
- streaming baseline scoring runs in `event_processor.py` when enabled
- anomalies persist to `attack_timeline` and operator labels to `attack_feedback`
- feedback calibration snapshots tune streaming thresholds (optional)
- UI consolidates alerts and applies suppression rules for known patterns

Remote sensors:
- `nexus/intel/remote_sensor.py` provides the sensor protocol (client + server)
- `scripts/run_sensor_server.py` runs the hub and persists status to `sensor_registry`
- UI reads sensor status from `sensor_registry` (including `location_lat`/`location_lon` when available)

Map intelligence topology:
- The canonical topology contract, data sources, and API output live in
  `docs/map_enhancement_walkthrough.md`. This file is authoritative for map
  nodes/edges and should be kept in sync with `/api/map/topology`.

---

## 2. Repo Map (Key Files)

Core runtime:
- `start_wicap.py`: orchestrates startup/shutdown and preflight/cleanup
- `scout.py`: capture + hop/governor loop and event emission
- `parser.py`: 802.11 + radiotap parsing utilities used by capture/processing paths
- `event_queue.py`: queue writer (and rotation/backpressure)
- `event_processor.py`: queue consumer; dedup/enrichment; SQL push to `curated_events`
- `schema.sql`: SQL Server schema definitions
- `config.py`: core configuration dataclasses + env resolution

Nexus (intel/forensics):
- `nexus/`: security posture, auditing, watcher/scavenger subsystems
- `nexus/scavenger/`: offline PCAP intelligence extraction agents/pipeline
- `nexus/intel/`: identity lattice, WIDS logic, investigations
- `nexus/intel/remote_sensor.py`: TCP/WS sensor transport + hub ingestion

UI:
- `wicap-ui/app/main.py`: FastAPI app and endpoints
- `wicap-ui/app/templates/`: Jinja templates

---

## 3. Persistence Model (SQL Server)

Event stream:
- `curated_events`: canonical event stream (JSON payload with computed columns for UI queries)

Detections:
- `attack_timeline`: canonical alert/detection sink (severity/confidence/evidence/MITRE mapping)
- `attack_feedback`: operator labels for anomaly retraining
- `attack_alerts`: persisted WIDS alerts (acknowledgements, first/last seen, event_count)
Sensors:
- `sensor_registry`: distributed sensor status + counters (frames/alerts/events + last_event_at + location_lat/location_lon)

Wireless intelligence:
- `handshakes`: extracted WPA(2/3) artifacts
- `security_posture`: per-network posture + risk factors
- `client_profiles`: per-client aggregates and fingerprints
- `client_associations`: client↔BSSID relationship history
- `pcap_index`: capture bookkeeping for backfill/resume and content summaries

---

## 4. Invariants / Guardrails

- Prefer deterministic replay fixtures for parsing/detection changes.
- Use one canonical table per concept; derive secondary views instead of duplicating data.
- Keep active/TX features opt-in and clearly labeled.
- Batch SQL writes safely (NVARCHAR(MAX) + `fast_executemany` requires `setinputsizes()`).
