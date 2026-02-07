# Changelog

All notable changes to WICAP will be documented in this file.

## [Unreleased]

### Added
- **Redis Queue Integration**: Migrated event pipeline to Redis for horizontal scaling.
- **Network Isolation**: Backend services (Processor, UI, Redis) now operate on a private bridge network.
- **Identity API Optimization**: Refactored `api/devices` to use set-based SQL queries, improving load times by 98%.
- **Pattern-of-Life Caching**: Implemented a 5-minute server-side cache for behavior analysis.
- **UI Filtering**: Added "Hide Randomized" and "High Confidence" toggles to the Device Intelligence page.
- **Log Timezone Fix**: Local timezone synchronization via `/etc/localtime` volume mounting.
- **ML Safety Gates**: explicit gating for experimental ML modules to ensure resource efficiency.

### Fixed
- **Docker Resource Leak**: Resolved PID file collision (`wifiwizard.pid`) which prevented service restarts.
- **Playwright Timeout**: Increased E2E navigation timeouts to 15s for high-latency stress test environments.
- **N+1 SQL Queries**: Eliminated hundreds of redundant database calls in the Identity Lattice implementation.
- **Telemetry Stream Churn**: Packet stream now defaults to Wi-Fi-focused rows, batches live inserts, and suppresses repetitive BLE bursts to prevent visual strobing.
- **Bluetooth Readability**: Sanitized malformed BLE local names and converted verbose UUIDs into concise service labels for production-friendly UI display.
- **Bluetooth Service Clarity**: Unknown/vendor UUIDs are now hidden by default and summarized as counts to reduce redundant, low-actionability UI noise.
- **Bluetooth Analyst Context**: Added BLE device confidence scoring and "why this matters" summaries to both the Bluetooth device list API and dossier view for triage-ready readability.
- **Bluetooth Behavior Intelligence**: Added cadence/dwell/activity/rotation-risk metrics with behavior summaries in BLE API + UI surfaces, including sortable list controls and dossier behavior panel.
- **Bluetooth Rotation Correlation**: Added cross-device address-rotation clustering (cluster size, peer count, suspicion flag, correlation score, summary) to BLE API and dossier correlation evidence.
- **Bluetooth Timeline Overlays**: Added recurrence scoring and timeline anomaly overlays (handoff/spike/gap detection) to BLE dossier views, with recurrence contract fields in BLE list API payloads.

### Changed
- **Documentation**: Unified docs under `docs/` with `docs/INDEX.md` entrypoint; added canonical `docs/CONFIGURATION.md`, `docs/TESTING.md`, `docs/ARCHITECTURE.md`; simplified README; archived legacy roadmap docs.
- **Validation Harness**: Extended UI smoke + Docker soak gates to include Bluetooth endpoints and Playwright Bluetooth suite coverage (`test_bluetooth_ui.py`), including confidence/readability assertions.
- **Offline Docker Contract Checks**: `run_docker_soak.sh` now validates BLE behavior field contracts (`behavior_label`, dwell/rate, rotation risk) before e2e loops.
- **Rotation Contract Validation**: Offline Docker soak now validates BLE rotation correlation fields (`rotation_cluster_size`, `rotation_suspected`, `rotation_correlation_score`, `rotation_summary`) before e2e loops.
- **Recurrence Contract Validation**: Offline Docker soak now validates BLE recurrence fields (`recurrence_label`, `recurrence_score`, `recurrence_summary`, `recurrence_handoff_count`, `recurrence_peer_presence_ratio`) before e2e loops.

---

## [2026-01-18] - Documentation Consolidation

### Added
- Created `docs/` structure.
- Archived `AGENTS_SYNC.md` to `logs/archive/`.
- Moved research docs to `docs/research/`.

---

## [2026-01-16] - Soak Test & Polish

### Added
- **Live Soak Report**: Validated system stability over 30 mins.
- **UI Polish**: Fixed map icons and telemetry spacing.
- **Replay Determinism**: Full replay pipeline with deterministic fixtures.

### Fixed
- **Handshake Dedup**: Logic now handles duplicate handshakes correctly.
- **Watcher Backlog**: Added `--baseline` flag to manage existing capture files.
