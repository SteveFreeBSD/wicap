# WICAP Roadmap

This is the single source of truth for:
- what is done
- what is next
- how work is sequenced
If any other roadmap or snapshot disagrees with this file, **this file wins**.

Start here: `docs/INDEX.md`

Last updated: 2026-02-06

---

## 1. Current Status (Reality Check)

| Area | Status | Notes |
|------|--------|-------|
| Core pipeline | Stable | Live capture → queue → processor → SQL → UI working end-to-end. |
| Performance | Optimized | Batch SQL, parallel backfill, fast parsers, Rust hot-path helpers. |
| Forensics | Live | Scavenger extracts intelligence from dwell PCAPs. |
| WIDS | Active | Stateful monitors + alert persistence available. |
| Anomaly detection | Active | Ghost Hunter baseline + attack_timeline integration. |
| Identity | Active | Fingerprinting + identity lattice features exist; ML upgrades are next. |
| UI | Stable | Map, telemetry, alerts, investigations surfaces present. |
| Map intelligence | Complete | S3.1 correctness fixes applied and documented. |
| Bluetooth (BLE) | Experimental | Capture + parser + SQL tables available; B4 UI parity + B5a enrichment done (`docs/BLUETOOTH.md`). |

---

## 2. Next Milestone (What We Do Next)

### Milestone S4: Security + Runtime Hardening [COMPLETED]

Goal: close critical access-control gaps and remove lifecycle/reliability defects
identified in `docs/reports/review_2026-02-06.md` before adding new feature
surface area.

Work slices (sequenced, each slice ends with tests + doc updates):

S4.1 Control-Plane Access Control
- [x] Require admin auth on `/api/system/control`.
- [x] Require admin auth on incident/alert mutation routes (`/api/incidents/*/resolve`, `/api/alerts/ack`, `/api/alerts/feedback`).
- [x] Add negative auth tests for protected mutation endpoints.

S4.2 Realtime Surface Hardening
- [x] Replace wildcard CORS with explicit `WICAP_UI_ALLOWED_ORIGINS`.
- [x] Add auth/secret validation on `/ws/live`.
- [x] Add websocket handshake/reject tests.

S4.3 Scout Lifecycle Correctness
- [x] Remove duplicate `_run_loop()` invocation from `Scout.start()`.
- [x] Consolidate duplicate `_shutdown` definitions into one deterministic teardown path (Wi-Fi + BLE).
- [x] Add startup/shutdown regression tests for scout and BLE backend teardown.

S4.4 Transport Security + Queue Resilience
- [x] Respect `WICAP_SQL_TRUST_CERT` in all SQL connection string builders.
- [x] Latch Redis file fallback after repeated write failure (avoid per-event retry/log storm).
- [x] Add reconnect/backoff to `RemoteEventQueueWriter` after transient hub disconnect.
- [x] Add tests for Redis failure latch and remote reconnect behavior.

S4.5 Time Semantics + Status Correctness
- [x] Normalize status freshness calculations to UTC-aware datetime handling.
- [x] Add tests for offset-bearing ISO timestamps and DST-safe age math.

S4.6 Launcher Safety
- [x] Only register interface cleanup when scout actually owns interface mode changes.
- [x] Add processor-only/watcher-only launcher tests proving no interface mutation.

### Milestone S5: Dead/Legacy Sweep + Public Repo Readiness [IN PROGRESS]

Goal: remove dead code paths, stale docs, and generated artifacts so the public
GitHub source presents a clean, defensible runtime for CTO/investor review.

Work slices (sequenced, each slice ends with tests + doc updates):

S5.1 Dead Code Prune
- [x] Remove unused/deprecated helper methods and stale compatibility shims with no runtime references.
- [x] Add/refresh tests around affected entry points before deletion.

S5.2 Legacy Runtime Path Retirement
- [x] Retire `WICAP_LEGACY_SQL_BATCH`; SQL writes now require `PersistenceManager`.
- [x] Remove legacy SQL batch code paths and update runbooks/config docs.

S5.3 Generated Artifact Hygiene
- [x] Expand `.gitignore` for local runtime artifacts and one-off soak files.
- [x] Ensure no generated baselines, PID markers, or temporary captures are tracked.

S5.4 Wordlist/Dictionary Externalization
- [x] Keep only code-required wordlist references in repo logic.
- [x] Require external corpus paths via `NEXUS_WORDLISTS_DIR` for large dictionaries.
- [x] Validate startup behavior when local corpus folder is absent.

S5.5 Documentation Prune + Archive Discipline
- [x] Mark or move stale docs/runbooks into `docs/archive/` with explicit ARCHIVED banner.
- [x] Remove duplicate instructions that conflict with canonical `docs/ROADMAP.md` and `docs/CONFIGURATION.md`.

S5.6 Public Review Gate
- [x] Run full test suite, docs link check, and grep-based dead-code scan in one gate command.
- [x] Publish a dated cleanup report in `docs/reports/` summarizing removed items and residual risks.

### Milestone S6: Cross-Repo Agentic Integration [IN PROGRESS]

Goal: make WiCAP the canonical runtime intelligence substrate for WICAP Assistant as a network-aware agentic system, with strict policy guardrails and provider-neutral OTLP observability.

Work slices (sequenced, each slice ends with tests + doc updates):

S6.1 Contract Baseline
- [x] Publish/validate `wicap.event.v1` and `wicap.control.v1` contracts consumed by assistant parity tests.
- [x] Add cross-repo fixture exports and drift gates.

S6.2 Policy-Gated Control Intake
- [x] Enforce schema/policy/allowlist checks on incoming control intents.
- [x] Emit accept/reject audit records for every intent.

S6.3 Suricata/Zeek-Compatible Event Semantics
- [x] Export WiCAP-native events with EVE/conn-compatible fields where signal is available.
- [x] Standardize flow correlation keys (`community_id`) and evidence pointers.

S6.4 Anomaly Intelligence Feed
- [x] Publish windowed anomaly features and scored anomaly events (`wicap.anomaly.v1`) for assistant correlation.
- [x] Capture operator feedback labels into exportable artifact stream (`wicap.feedback.v1`) for bounded recalibration loops.

S6.5 Provider-Neutral OTLP Telemetry
- [x] Add optional collector profile + redaction policy baseline tests.
- [x] Ensure telemetry failures do not degrade capture/control paths.

S6.6 Rollout Gates
- [ ] Shadow validation and optional Suricata/Zeek parity runs.
- [ ] Canary -> production promotion based on SLOs.

Detailed workslices and acceptance criteria: `docs/CROSS_REPO_AGENTIC_INTEGRATION.md`.

### Milestone S3: Operational Intelligence + Evidence [COMPLETED]

Goal: make map/alerts/identity outputs accurate, actionable, and exportable before
resuming geo + sensor expansion.

Work slices (sequenced, each slice ends with tests + doc updates):

S3.1 Map Intelligence Correctness
- [x] Build topology edges from `client_associations` (last_seen window), not event types.
- [x] Persist security fields into event payloads (`security.is_open/has_wpa*`) - **Done via security_posture JOIN**.
- [x] Wire RSSI filter + ensure map legend reflects actual thresholds.
- [x] Add topology contract tests and map data fixtures.

S3.2 Incident Consolidation (WIDS -> Incidents)
- [x] Group WIDS bursts into incident records with first/last seen + severity.
- [x] Attach evidence pointers (event_ids, dwell file, pcaps).
- [x] Update alerts UI to show incidents + recommended actions.
- [x] Add unit tests for dedupe window + ordering.

S3.3 Baseline + Drift Detection (30-day) **[DONE]**
- [x] Build a 30-day baseline for SSIDs/BSSIDs/security posture.
- [x] Detect drift (new SSID/BSSID, security downgrade, channel churn).
- [x] Emit WIDS events for drift + add baseline report endpoints.
- Docs: `docs/BASELINE_DRIFT.md`

S3.4 Device Identity Graph **[DONE]**
- [x] Link randomized MACs using fingerprint + PNL/RSSI overlap.
- [x] Expose identity clusters in device dossier + map (API + UI).
- [x] Add graph export for investigations.

S3.5 Ops Outputs + Evidence Bundles **[DONE]**
- [x] Webhook/SIEM export (JSON + evidence pointers).
- [x] Daily digest report (top incidents, drift, new devices).
- [x] Evidence bundle packaging (event IDs + pcaps + metadata).

Parallel Track (E4): Bluetooth Integration (Aligned)
- Canonical plan: `docs/BLUETOOTH.md`
- Current slice: **B5 Triangulation** (blocked until sensors available)
- Gate: **B2 must land before S3.4 Device Identity Graph** so BLE joins identity clusters.

## 3. Completed Milestones (S1-S2)

### Stabilization S1: Codebase Consolidation + Safety [COMPLETED]

Goal: remove duplicated/legacy paths, harden admin surfaces, and make the runtime
path unambiguous before new features.

Inputs:
- `docs/reports/review_2026-01-22.md` (UI refactor, type hints, connection cleanup)
- Internal audit findings (duplicate DwellWatcher, legacy SQL fallback, placeholder admin exec)

Work slices (sequenced, each slice ends with tests + doc updates):

S1.1 Admin Surface Hardening
- [x] Require internal secret + allowlist on all `/api/admin/*` endpoints.
- [x] Remove placeholder exec path or replace with an allowlisted, argument-safe analysis command.
- [x] Add focused tests for admin auth + denial paths.

S1.2 DwellWatcher Consolidation
- [x] Remove or archive legacy `DwellWatcher` in `nexus/password_auditor_enhanced.py`.
- [x] Keep `nexus/dwell_watcher.py` as the single runtime watcher.
- [x] Update tests/imports to reference the canonical watcher only.

S1.3 Persistence + Dedup Cleanup
- [x] Make `PersistenceManager` the required SQL path (legacy SQL batch fallback retired).
- [x] Remove deprecated dedup helpers and update replay driver to call `DedupCache` directly.
- [x] Ensure SQL connections are closed on failure paths (no hidden fallbacks).

S1.4 UI Module Refactor
- [x] Split `wicap-ui/app/main.py` into routes + services modules.
- [x] Preserve URLs, templates, and API contracts.
- [x] Add/adjust UI tests to validate routing + admin auth after the split.

S1.5 Hygiene Pass
- [x] Add return type hints for public methods in core + nexus.
- [x] Extract scoring constants from `scorer.py` into config.
- [x] Standardize logging levels (DEBUG vs INFO) across core entrypoints.

S1.6 Stability Validation (Soak Test Gate)
- [x] Run 30-60 minute live soak (Scout + DwellWatcher + UI).
- [x] Verify ingestion, associations, RSSI aggregates, and UI responsiveness.
- [x] Record EPS, error rates, and any regressions in logs.
- Report: `docs/reports/soak/report_2026-01-22.md`

---

### Milestone S2: Streaming ML Anomaly Detection Pipeline [COMPLETED]

Goal: Transform WICAP from rule-based alerting to adaptive behavioral anomaly detection.
Reduces alert fatigue from 50+/day to 2-3 actionable alerts by learning what's "normal" per deployment.

Gating: Completed after S1; shares foundational work with E2 (Identity ML).

Architecture:
```
Events ──► Feature Extraction ──► Baseline Model (24h) ──► Anomaly Scorer ──► Alert Engine
                                         │                       │
                                         └─── Continuous Learning ┘
```

Work slices (sequenced, each slice ends with tests + doc updates):

S2.1 Feature Engineering Layer
- [x] Build feature extractor for event streams (time-of-day, channel patterns, device behavior).
- [x] Store rolling feature vectors in Redis or lightweight time-series store.
- [x] Add feature export endpoint for model training/debugging.

S2.2 Baseline Model (Online Learning)
- [x] Integrate lightweight streaming baseline for anomaly detection.
- [x] Build 24-hour rolling baseline per-environment (global scope).
- [x] Add baseline persistence and cold-start handling.

S2.3 Anomaly Scoring + Confidence
- [x] Score each event against learned baseline (0-100 anomaly score).
- [x] Add confidence intervals based on baseline maturity.
- [x] Integrate with existing `attack_timeline` and `ghost_hunter` modules.
- [x] Soak test gate: 30-60 minute live run before S2.4.

S2.4 Feedback Loop + Calibration
- [x] Add UI for operator feedback (confirm/dismiss anomalies).
- [x] Calibrate streaming anomaly thresholds from feedback snapshots.
- [x] Track precision/recall proxy metrics via `/api/alerts/metrics`.

S2.5 Alert Consolidation
- [x] Replace rule-based alerts with ML-scored alerts where confidence is high.
- [x] Keep rule-based as fallback for cold-start and edge cases.
- [x] Add alert suppression for known patterns (e.g., daily microwave interference).

---

## 4. Foundations (Completed, Do Not Redo)

- Ghost Hunter anomaly detection (IsolationForest baseline + scoring + feedback UI).
- Distributed grid basics (auth, websocket ingest, sensor registry, coverage map).
- Performance core (batch SQL, fast parsers, Rust helpers, perf smoke guardrail).
- PCAP intelligence (associations, RSSI aggregates, backfill tooling; see `docs/BACKFILL.md` for commands).

## 5. Enhancement Workstreams (2026-2027)

These were consolidated from historical roadmaps in git history. This section is
the only enhancement backlog.

### E1: Geo-Spatial Coverage [PAUSED]
- Resume after S3 completes (S1 → S2 → S3 → E1).

E1.1 Sensor Coordinates + API Exposure
- [x] Add `location_lat`/`location_lon` to `sensor_registry` and registry upserts.
- [x] Expose coordinates in `/api/sensors` and prefer them on the coverage map.
- [x] Document coordinate formatting + storage behavior.

E1.2 Coverage Estimation (Planned)
- [ ] Define a coverage radius heuristic per sensor (config + RSSI).
- [ ] Store `coverage_radius_m` + `last_coverage_update`.
- [ ] Render coverage rings or density overlay on the Sensors page.

E1.3 Spatial Analytics (Future)
- [ ] Add geofence zones for alert routing and escalation.
- [ ] Add geo query helpers (bounding box + proximity search).

### E2: Identity ML Upgrades [PLANNED]
- Classifier for spoofed APs and randomized clients (feature + confidence report).
- Human feedback loop to retrain and calibrate confidence.
- Note: S2.1-S2.3 deliver shared infrastructure; E2 adds specialized classifiers on top.

### E3: Sensor Satellites + Passive Shield [FUTURE]
- Lightweight forwarders (ESP32/Pi) with minimal protocol.
- SDR-only passive shield is optional and gated by hardware.

### E4: Spectrum Expansion [ACTIVE]
- Canonical roadmap: `docs/BLUETOOTH.md` (B0–B6 slices).
- Status: Opt-in (experimental) until B1–B4 complete.
- Current slice: **B5 Triangulation** (blocked until sensors are available; B5b confidence/behavior/rotation/timeline overlays shipped).
- Alignment gates:
  - **B2 → S3.4**: BLE parser/vendor enrichment required before identity graph work.
  - **B4 → S3.4/S3.5**: BLE UI parity ships alongside identity/ops outputs.
  - **B5 → E1.2**: BLE triangulation aligns with geo coverage (`rf_location_estimates`).

---

### E5: Deep Stream (Open Network Protocol Reassembly) [FUTURE]
- HTTP/DNS extraction from open networks for investigation context.

### E6: Visual Spectrum History [FUTURE]
- Waterfall or heatmap history view for signal density over time.

---

## 6. Canonical Operations Entry Points

These are the supported entry points; prefer them over ad-hoc commands.

| Scope | Entry | Purpose |
|------|-------|---------|
| Live operation | `sudo -E python3 start_wicap.py --push-to-sql` | Run core + UI push path on host hardware |
| Verification | `./run_live_verification.sh` | Smoke check services and endpoints |
| Soak test | `./scripts/run_docker_soak.sh <min>` | Multi-worker soak with Playwright checks |
| Deterministic replay | `python3 -m replay_driver --batch tests/fixtures/manifest.json` | Hardware-free regression gate |

Testing details: `docs/TESTING.md`

---

## 7. Performance Roadmap (Completed Phases)

These phases are tracked here to avoid split sources of truth.

Phase 1: DB throughput
- fast batch inserts (`fast_executemany` + `setinputsizes`)
- computed columns + indexes for UI JSON access

Phase 2: Capture backend
- `CaptureBackend` abstraction with Scapy default + optional libpcap backend

Phase 3: Parallel backfill
- worker parallelism + pcap claiming/idempotency guardrails
  - runbooks live in `docs/BACKFILL.md`

Phase 4: Parser upgrades
- raw reader fast path, `xxhash` dedup, MAC cache

Phase 5: Native extensions
- optional Rust extension for hot-path helpers + Python fallback

Research + external references: `docs/research/tool-ecosystem.md`

---

## 8. Known Pitfalls (Do Not Relearn These)

See `docs/CONTRIBUTING.md` for full details and required patterns. Highlights:
- SQL batch truncation with `fast_executemany` unless `setinputsizes()` is used.
- Docker “baking”: code changes require `docker compose build`.
- Schema drift: do not assume runtime auto-migration for column sizes/types.
- Wi‑Fi cleanup: always restore managed mode on exit (preflight + finally/atexit).
- Silent failures: watch data flow counters, not just `/health`.

---

## 9. Documentation Governance (No More Fragmentation)

Rules:
- `docs/INDEX.md` is the entrypoint.
- `docs/ROADMAP.md` is the main WiCAP roadmap; `docs/BLUETOOTH.md` is the BLE roadmap; `docs/CROSS_REPO_AGENTIC_INTEGRATION.md` is the cross-repo integration companion roadmap.
- Research belongs in `docs/research/`.
- Component-specific notes can live in component folders, but must be linked from `docs/INDEX.md`.
- No `PROMPTS/` tree; do not reintroduce it.

History:
- Change history lives in `CHANGELOG.md`.
- Archived/legacy docs go in `docs/archive/` with an ARCHIVED banner.
