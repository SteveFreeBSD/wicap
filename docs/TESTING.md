# WICAP Testing

This document is the single source of truth for how to validate changes.

## 1. Fast Local Gate (Default)

Run unit and component tests (skips Playwright e2e by default):

```bash
pytest -m "not e2e" -v
```

If you only want the fastest subset:

```bash
pytest -m "unit and not e2e" -v
```

## 1.1 Redis Streams Integration Test

Validate at-least-once delivery (no loss/dupes after consumer crash) for the
Redis Streams queue. Requires a reachable Redis/Valkey instance.

```bash
WICAP_REDIS_URL=redis://localhost:6380/0 pytest -q tests/test_redis_stream_queue_integration.py
```

## 1.2 Public Review Gate (CTO/Investor Readiness)

Run the unified gate command:

```bash
./scripts/review_gate.sh
```

This runs:
- `pytest -q` (full suite)
- `python3 scripts/check_docs_links.py` (canonical docs reference integrity)
- `python3 scripts/check_dead_markers.py` (dead/legacy marker guardrails)
- `python3 scripts/check_repo_hygiene.py` (tracked artifact hygiene guardrails)

GitHub Actions enforces this via the required status check `review-gate`.

## 1.3 Dependency Vulnerability Audit

Run dependency vulnerability scanning across all maintained Python manifests:

```bash
.venv/bin/pip-audit -r requirements.txt
.venv/bin/pip-audit -r wicap-ui/requirements.txt
.venv/bin/pip-audit -r tools/bluetooth/requirements.txt
.venv/bin/pip-audit -r tools/bluetooth/extcap/requirements.txt
```

## 2. Deterministic Replay (No Hardware Required)

Run the replay fixture batch:

```bash
python3 -m replay_driver --batch tests/fixtures/manifest.json
```

Regenerate a golden snapshot after fixture changes:

```bash
python3 -m replay_driver --pcap tests/fixtures/pcap/mixed_traffic_ch2.pcapng --snapshot
```

## 3. UI E2E (Playwright)

These are marked `e2e` and may require Playwright + a running UI:

```bash
pytest -m e2e -v
```

If `WICAP_UI_URL` is not set, the test harness will auto-start a local
FastAPI UI instance on a free port and run in `WICAP_UI_TEST_MODE=true`
(no SQL Server required). To target an existing UI instance, set
`WICAP_UI_URL` explicitly and disable test mode.

Admin UI checks require `WICAP_E2E_ADMIN_SECRET` to match the UI's
`WICAP_INTERNAL_SECRET`. If unset, admin-specific tests are skipped.

Bluetooth UI coverage is included in the `e2e` marker and runs alongside the
main UI suite. BLE-specific assertions now include confidence badges and
service-UUID summary readability checks plus behavior/recurrence rendering checks
(`tests/test_bluetooth_ui.py`).

## 4. Soak Tests

### Quick Soak (30 min, attached)

```bash
sudo ./scripts/run_soak.sh 30
```

Direct invocation (no wrapper) is also supported:

```bash
python tests/soak_test.py --duration-minutes 30 --playwright-interval-minutes 15
```

Default behavior for direct `tests/soak_test.py` runs is to execute a
post-soak shutdown sequence. To keep services running after the soak:

```bash
python tests/soak_test.py --duration-minutes 30 --no-shutdown-on-complete
```

For Docker full-stack soak (core + Bluetooth Playwright):

```bash
./scripts/run_docker_soak.sh 30
```

For the Python live runner, duration/interval flags are available directly:

```bash
python scripts/run_live_soak.py --duration-minutes 30 --playwright-interval-minutes 15
```

The Docker soak now validates `/api/devices/bluetooth` contract keys and runs:
- `tests/test_e2e_ui.py`
- `tests/test_bluetooth_ui.py`
- Soak fails immediately if `/api/stats` or `/api/devices/bluetooth` return non-200 responses.
- Soak fails after consecutive e2e failures (default limit: `E2E_FAIL_LIMIT=2`).
- When Bluetooth is enabled, soak enforces non-zero BLE observations after a grace period (`BT_ACTIVITY_GRACE_MINUTES`, default `15`).

Contract validation includes confidence and behavior fields used by the BLE UI
(`confidence_*`, `why_matters`, `behavior_label`, `dwell_minutes`,
`observation_rate_per_hour`, `rotation_risk_score`, `rotation_cluster_size`,
`rotation_peer_count`, `rotation_suspected`, `rotation_correlation_score`,
`rotation_summary`, `recurrence_label`, `recurrence_score`,
`recurrence_summary`, `recurrence_handoff_count`,
`recurrence_peer_presence_ratio`).

### Long Soak (8 hours, detached)

Use `--detach` (or `-d`) to run unattended. The soak will survive terminal closure:

```bash
sudo ./scripts/run_soak.sh 480 --detach
```

Output:
```
✅ Soak started in background (PID: 12345)
📝 Log file: logs/soak/soak_480m_20260202_071500.log
   To monitor:  tail -f logs/soak/soak_480m_20260202_071500.log
   Expected completion: 2026-02-02 15:15
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WICAP_SOAK_DURATION_MINUTES` | 30 | Total soak duration |
| `WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES` | 15 | Minutes between UI checks |
| `PLAYWRIGHT_TIMEOUT_SECONDS` | 120 | Default per-page Playwright timeout (seconds) |
| `PLAYWRIGHT_PAGE_TIMEOUT_MS` | (derived) | Default Playwright page/navigation timeout |
| `SOAK_PYTEST_TIMEOUT_SECONDS` | 600 | Timeout for a full pytest UI check (seconds) |
| `WICAP_SOAK_SKIP_SLOW` | 1 | Skip slow UI tests (e.g., `/map`, `/scavenger`) during soak |
| `WICAP_SOAK_BASELINE_PATH` | `docs/reports/soak/baseline.json` | Baseline JSON used for soak regression checks |
| `WICAP_SOAK_BASELINE_ENFORCE` | 0 | Fail soak on regressions (1 = error, 0 = warning) |
| `WICAP_SOAK_BASELINE_UPDATE` | 0 | Overwrite baseline with current run |
| `WICAP_SOAK_BASELINE_MAX_RSS_GROWTH_PCT` | 30 | Max allowed RSS end growth vs baseline |
| `WICAP_SOAK_BASELINE_MAX_EPS_DROP_PCT` | 25 | Max allowed EPS drop vs baseline |
| `WICAP_SOAK_BASELINE_MIN_UI_PASS_RATE` | 1.0 | Minimum acceptable UI check pass rate |
| `WICAP_SOAK_SHUTDOWN_ON_COMPLETE` | 1 | Auto-run shutdown sequence after direct `tests/soak_test.py` |
| `WICAP_UI_URL` | (auto) | Base URL for UI E2E tests (auto-started if unset) |
| `WICAP_UI_TEST_MODE` | true (tests) | Use no-op DB pool for UI test runs |
| `PYTEST_ARGS` | (none) | Extra pytest args, e.g. `-m "e2e and not slow"` |

### Preflight (Automatic)

Preflight runs automatically and will:
- Resolve Wi‑Fi (`WICAP_INTERFACE`) and BLE interfaces (nRF52840)
- Validate capture paths (`scripts/verify_capture_paths.sh`)
- Run `scripts/bt_preflight.sh` when BLE is enabled

### Memory Profiling (UI)

- Track baseline vs end-of-soak memory with `docker stats` or the soak report.
- **Memory checkpoints**: Soak captures snapshots at minute 10, 30, 60, 120 to show steady-state.
- **Identity graph cache**: Check `/api/system/status` for `identity_graph_cache` metrics.
- Prefer WICAP’s built-in memprof (safe for Docker healthchecks):
  - `WICAP_UI_MEMPROF=on-demand` to avoid startup overhead.
  - Optional: `WICAP_UI_MEMPROF_DEFER_SECONDS=60` to delay tracing.
  - `curl http://localhost:8080/api/system/memory` to start tracing on demand.
- Avoid `PYTHONTRACEMALLOC` in Docker startup (can stall imports and fail healthchecks).
- Optional (if installed): `py-spy top --pid $(pgrep -f uvicorn)` for live alloc pressure.

### Soak Telemetry (Auto-Collected)

The soak runner now captures extra telemetry every Playwright interval:

- **EPS trend** (`telemetry.eps_samples[]`)
- **Container restart signals** (`telemetry.container_starts`, based on container ID/start time/restart count)
- **Capture dir disk usage** (`telemetry.disk_usage[]`)
- **API latency samples** (`telemetry.latency_samples[]`)

The final memory snapshot uses retries and falls back to Docker stats if the
memory endpoint fails, so the soak report always contains end-state RSS.

### Baseline Regression Gate

Each soak compares its end-state metrics to a stored baseline. If the baseline
file does not exist, the soak writes one automatically. Regressions are added
to warnings by default or errors when enforcement is enabled.

Baseline metrics include:
- UI RSS start/end (MiB)
- EPS average
- UI check pass rate

Override path or enforcement with:

```bash
WICAP_SOAK_BASELINE_PATH=docs/reports/soak/baseline.json
WICAP_SOAK_BASELINE_ENFORCE=1
WICAP_SOAK_BASELINE_UPDATE=1
```

### Playwright Timeout Scaling

When `SOAK_PYTEST_TIMEOUT_SECONDS` is not set, the soak runner scales the
pytest timeout based on an estimated test count:

```
timeout = 120s + (test_count × 30s) + 60s buffer
```

### Monitoring a Detached Soak

```bash
# Check if soak is running
cat .soak.pid && ps -p $(cat .soak.pid)

# Follow the log
tail -f logs/soak/soak_*.log

# Check Docker health
docker ps | grep wicap

# API health
curl -s http://localhost:8080/api/system/status | python3 -m json.tool

# Live status (updates each Playwright interval)
cat .soak_status.json
watch -n 30 cat .soak_status.json
```

The status file is written atomically and updated every 30 seconds during the soak,
so it stays current even if UI checks are disabled.

### Pipeline Health Signals

- `/api/system/status` includes `last_insert_age_sec`, `queue_backlog_bytes`, `queue_last_event_age_sec`,
  `last_updated_age_sec`, and `status_stale`
- During a healthy run, `last_insert_age_sec` should stay low (typically <120s)
- `queue_backlog_bytes` should not grow without bound

Record soak results in `docs/reports/soak/` with a date-stamped report.

### Playwright Timeouts for Heavy Pages

The `/map` and `/scavenger` pages can exceed 120s on large datasets. For long soaks,
use a higher per-page timeout (e.g., 180s) or mark those tests as slow and exclude
them from quick checks:

```bash
PLAYWRIGHT_TIMEOUT_SECONDS=180 pytest -m "e2e and not slow" -v
```

## 4.4 Identity Graph Export (S3.4)

Generate a graph export for investigations (from cache or via SQL refresh):

```bash
python scripts/identity_graph_refresh.py --export docs/reports/soak/identity_graph_export.json
```

Or via the UI API (JSON download):

```bash
curl -s http://localhost:8080/api/identity/graph/export -o identity_graph_export.json
```

For soak postflight checks, a lightweight summary endpoint avoids expensive rebuilds:

```bash
curl -s http://localhost:8080/api/identity/graph/summary | python3 -m json.tool
```

## 4.5 Ops Digest + Evidence Bundles (S3.5)

Generate a daily digest (last 24h by default):

```bash
python scripts/daily_digest.py --since-hours 24
```

Generate an evidence bundle zip for a time range:

```bash
python scripts/evidence_bundle.py --start-ts 1700000000 --end-ts 1700003600
```

Or via the UI API (date-based bundle):

```bash
curl -O http://localhost:8080/api/evidence/bundles/2026-02-01
```

SIEM/Webhook export (JSON payload):

```bash
curl -s http://localhost:8080/api/ops/siem?since_hours=24 | jq '.alerts | length'
```

## 4.1 BLE Evidence (Unit)

Verify BLE enrichment and evidence alerts without hardware:

```bash
pytest tests/test_ble_parser.py::test_manufacturer_hash -v
pytest tests/test_ble_alerts.py::test_build_ble_alert_row_basic -v
pytest tests/test_sql_persistence.py::test_add_bt_event_flush -v
pytest tests/test_bt_persistence_sanitize.py -v
pytest tests/test_persistence_resilience.py -v
```

Expected: manufacturer hash is present, BLE alert rows are well-formed, and BT
flush writes to `bt_devices` + `bt_observations`. Persistence resilience tests
also verify row-wise fallback and sanitization under malformed inputs.

## 4.2 Bluetooth Capture Sanity (Hardware)

These checks require an nRF52840 dongle and BLE traffic in range:

```bash
scripts/bt_preflight.sh
PYTHONPATH=. python scripts/verify_bt_capture.py
```

Expected: events print to stdout and a `.pcapng` file is created in
`captures_verify/bt`.

## 4.3 Backfill CLI (WiFi + BLE)

All offline backfill commands and flags live in `docs/BACKFILL.md`.

Dev-only: `python scripts/mock_bt_traffic.py` injects synthetic BLE rows for UI demos.

## 4.4 Clean Shutdown (Reset Interfaces)

Use the canonical shutdown script to stop services, reset Wi‑Fi to managed mode,
and release any BLE capture device:

```bash
python scripts/stop_wicap.py
```

## 5. Performance Smoke

```bash
pytest -m perf_smoke -v
```

Perf smoke tests are fixture-based (no live capture or SQL required). They
enforce a generous ceiling to catch pathological slowdowns, not tight budgets.

Benchmarks:

```bash
python3 scripts/perf_bench.py --pcap tests/fixtures/pcap/mixed_traffic_ch2.pcapng --parser tshark
python3 scripts/perf_bench.py --db --rows 10000
```

## 6. Ghost Hunter Sanity Check

Requires SQL + curated_events.

```bash
python -m nexus.intel.ghost_hunter train --since 7d --window-min 5
python -m nexus.intel.ghost_hunter score --since 1d --window-min 5 --dry-run
```

## 7. Remote Sensor Smoke

Run the sensor hub (requires SQL credentials if registry enabled):

```bash
python scripts/run_sensor_server.py --no-db
```

WebSocket transport + event ingestion:

```bash
python scripts/run_sensor_server.py --transport ws --no-db --ingest-events
```

Confirm fan-in metrics:
- Start a sensor with `WICAP_SENSOR_HUB_HOST` and generate traffic.
- Verify `sensor_registry.events_received` increases or check `/api/sensors`.

## 8. Environment Notes

Some modules require SQL and internal secret configuration in real operation.
See `docs/CONFIGURATION.md` for required secrets and defaults.

## 9. Alerts Sanity (Manual)

- Confirm WIDS alerts populate `attack_alerts` and appear in `/api/alerts`.
- Toggle acknowledgement via `POST /api/alerts/ack` and verify the alert hides by default.
