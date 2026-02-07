# Dead/Legacy Sweep Report: WICAP

Date: 2026-02-06  
Reviewer: Codex (GPT-5)

## Scope

Targeted for CTO/investor-facing repository readiness:
- runtime lifecycle and control-plane security
- dead/deprecated code paths
- generated artifact hygiene
- stale/legacy documentation surface

Validation executed:
- `pytest -q` (full suite): **418 passed, 24 skipped, 1 xfailed**
- `./scripts/review_gate.sh`: **PASS** (full pytest + docs reference check + dead/legacy marker scan + repository hygiene check)
- `pip-audit` (all manifests): **PASS** (`requirements.txt`, `wicap-ui/requirements.txt`, `tools/bluetooth/requirements.txt`, `tools/bluetooth/extcap/requirements.txt`)

## Completed In This Sweep

1. Protected privileged mutation/control endpoints with admin dependency:
   - `/api/system/control`
   - `/api/incidents/{incident_id}/resolve`
   - `/api/alerts/ack`
   - `/api/alerts/feedback`
2. Fixed UTC-safe `last_insert_age_sec` parsing in system status route.
3. Removed duplicate scout run loop invocation in `Scout.start()`.
4. Consolidated scout shutdown path and ensured Bluetooth backend teardown.
5. Made launcher interface cleanup registration scout-only.
6. Honored `WICAP_SQL_TRUST_CERT` in processor SQL connection builders.
7. Latched Redis queue fallback after repeated failures.
8. Added reconnect/backoff logic for remote sensor queue writer.
9. Removed unused deprecated scout helper methods (`_get_next_channel`, `_set_channel`).
10. Extended git hygiene for local artifacts (`.soak_pid`, soak baseline JSON).
11. Hardened realtime surfaces: `/ws/live` now enforces origin + secret checks and Socket.IO CORS is origin allowlist-based.
12. Removed legacy integration fallback from `wicap_test_suite.py` (`inject_live_test.py` is no longer an implicit execution path).
13. Added regression tests for integration-runner selection and skip behavior (`tests/test_wicap_test_suite_runner.py`).
14. Moved NEXUS wordlist runtime default to git-ignored `captures/wordlists`, with explicit `NEXUS_WORDLISTS_DIR` override docs and tests.
15. Hardened wordlist startup behavior when local corpus folders are absent and normalized archive bannering for `docs/archive/6GHZ_IMPLEMENTATION.md`.
16. Added a single-command public review gate (`scripts/review_gate.sh`) that runs full tests, docs reference checks, dead/legacy marker scans, and repository hygiene checks.
17. Retired `WICAP_LEGACY_SQL_BATCH` and removed legacy SQL batch fallback code in `event_processor.py`; SQL writes now require `PersistenceManager`.
18. Archived duplicate soak planning content in `docs/WORKSLICES_SOAK.md` and pointed documentation entrypoints to canonical roadmap/testing docs.
19. Pruned one-off legacy test utilities (`tests/final_proof.py`, `tests/generate_and_crack.py`, `tests/trigger_audit.py`, `tests/inject_live_test.py`, `tests/verify_endpoints.py`) and separated hardware BT sanity into `scripts/verify_bt_capture.py`.
20. Added `tests/README.md` to define canonical automated vs manual test surfaces.
21. Removed stale test/runtime artifacts that were not referenced by code paths (`test_sample.pcap`, `wpa-sample.pcap.gz`, `tests/triangulation_report.html`, `tests/mock_cracks.pot`, `tests/mock_hash.22000`).
22. Added `scripts/check_repo_hygiene.py` and wired it into `scripts/review_gate.sh` to block tracked runtime artifacts (captures/logs/wordlists/soak markers).
23. Promoted GitHub CI to a single required `review-gate` job that runs lint + `scripts/review_gate.sh`; documented branch-protection check naming in `docs/CONTRIBUTING.md`.
24. Removed tracked runtime artifacts `SOAK_ERRORS.txt` and `processor.state.json`; expanded repo hygiene checks to forbid tracked `*.log`/`*.state.json` artifacts.
25. Added root `SECURITY.md` with disclosure workflow, response SLAs, and hardening baseline.
26. Added CI dependency vulnerability auditing (`pip-audit`) across all maintained Python requirement manifests.
27. Added weekly `Dependabot` automation for pip and GitHub Actions updates (`.github/dependabot.yml`).
28. Added repository ownership rules in `.github/CODEOWNERS` and documented required Code Owner review in contribution governance.
29. Added top-level `LICENSE` (source-available, all-rights-reserved) and linked it from `README.md`.
30. Fixed Docker startup race causing stale UI telemetry by adding Redis health-gating in `docker-compose.yml` and processor-side Redis init retry logic for transient `LOADING` states.
31. Added regression tests for Redis init retry/fallback behavior (`tests/test_event_processor_redis_init_retry.py`).
32. Fixed `last_insert_age_sec` skew for timezone-naive SQL timestamps in UI system status and added regression coverage (`tests/test_system_status_route.py`).
33. Stabilized Telemetry packet stream UX: added Wi-Fi-first default rendering, Bluetooth visibility toggle, pause control, batched row flush, and BLE burst dedupe to eliminate UI strobing under high BT advertisement rates.
34. Improved Bluetooth presentation quality by sanitizing malformed local names and converting raw service UUIDs into concise labels for the UI and BLE dossier pages.
35. Reduced Bluetooth service noise by hiding unknown/vendor UUIDs from default display and surfacing only actionable mapped services with an unknown-count summary.
36. Added BLE analyst-confidence scoring with tiered "why this matters" summaries in `/api/devices/bluetooth` and BLE dossier pages to improve triage readability and operator decision quality.
37. Extended test harness + offline Docker soak to include Bluetooth endpoint smoke checks, Bluetooth Playwright coverage, and API contract validation for confidence/readability fields.
38. Added BLE behavior intelligence (cadence label, dwell, activity rate, rotation risk, interval metrics) to API/UI with Playwright coverage and offline Docker contract checks.
39. Added BLE address-rotation correlation clustering and dossier evidence (related addresses) with full contract validation in offline Docker soak and Playwright UI coverage.
40. Added BLE timeline anomaly overlays and recurrence/handoff scoring to dossier views, plus recurrence field contract validation in BLE API soak checks.

## Legacy/Dead-Code And Doc Risk Areas (Next)

1. Optional: add a local pre-commit hook that shells out to `scripts/review_gate.sh` (CI is already wired).

## Roadmap Mapping

Integrated into canonical roadmap (not a separate roadmap):
- `docs/ROADMAP.md` S4 moved to **COMPLETED**.
- `docs/ROADMAP.md` S5 is active and tracked as **IN PROGRESS**.
