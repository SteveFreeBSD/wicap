# Ghost Hunter Anomaly Detection

Ghost Hunter detects baseline drift that slips past signature-based WIDS.
It is offline-first and operates on windowed aggregates from `curated_events`.

## 1. Data Flow

1. Read `curated_events` for a time range.
2. Aggregate per BSSID per window (default 5 minutes).
3. Train an IsolationForest baseline (manual trigger).
4. Score new windows against the baseline.
5. Persist anomalies to `attack_timeline` with explanations.
6. Optional operator feedback is stored in `attack_feedback`.

## 2. Feature Set (per BSSID, per window)

- `event_count`: total events in the window
- `unique_clients`: unique source MACs (client churn proxy)
- `unique_ssids`: SSIDs seen for the BSSID
- `deauth_rate`: deauth/disassoc frames per second
- `assoc_rate`: association requests per second
- `channel_count`: number of channels observed (drift)
- `seq_jitter_avg`: average sequence delta (wrap-aware)
- `seq_jitter_max`: max sequence delta
- `beacon_interval_avg`: mean beacon interval (TU)
- `beacon_interval_jitter`: stddev of beacon interval

## 3. Training

Train a baseline model (30 days is a good start):

```bash
python -m nexus.intel.ghost_hunter train --since 30d --window-min 5
```

Model path default: `./models/ghost_hunter/model.joblib`
Override with `WICAP_GHOST_MODEL_PATH`.

## 4. Scoring

Score recent windows and persist anomalies:

```bash
python -m nexus.intel.ghost_hunter score --since 1d --window-min 5
```

Dry run (no DB writes):

```bash
python -m nexus.intel.ghost_hunter score --since 1d --window-min 5 --dry-run
```

## 5. Persistence

- `attack_timeline`:
  - `attack_type`: `anomaly_drift`
  - `description`: top feature deviations
  - `ioc_summary`: JSON with feature values + score
- `attack_feedback`:
  - operator labels: `benign`, `confirmed`, `noisy`

## 6. Feedback Loop

The alerts UI allows labeling anomalies:
- Confirmed: likely malicious or meaningful drift
- Benign: expected environmental change

Feedback is stored in `attack_feedback` for future retraining.

## 7. Guardrails

- Offline-first: no automatic training in live pipeline.
- Minimum events per window (default 20) to reduce noise.
- Idempotent persistence via merge on (attack_type, bssid, window).
- Keep model changes explicit and versioned.

## 8. Streaming Feature Engineering (S2.1)

The S2.1 layer derives rolling feature windows from the live event stream and
stores them for online models and debugging. It runs inside the event processor
when enabled and produces windows for both:

- `scope=global` (environment baseline)
- `scope=bssid` (per-BSSID behavior)

Feature vector (per window):
- `event_count`, `unique_clients`, `unique_ssids`
- `deauth_rate`, `assoc_rate`
- `channel_count`, `channel_top_ratio`
- `seq_jitter_avg`, `seq_jitter_max`
- `beacon_interval_avg`, `beacon_interval_jitter`
- `hour_sin`, `hour_cos`

Storage:
- Redis sorted set (default when `WICAP_REDIS_URL` is set), or
- JSONL files under `captures/feature_windows/`

Export:
- `GET /api/admin/features` (requires `WICAP_INTERNAL_SECRET`)
- Parameters: `since`, `until`, `limit`, `scope`, `bssid`

## 9. Streaming Baseline (S2.2)

The streaming baseline builds a rolling 24-hour reference from feature windows.
Snapshots are persisted for downstream scoring and cold-start visibility.

Defaults:
- Horizon: 24 hours
- Refresh: every 5 minutes
- Scope: `global` (per-environment baseline)

Snapshot storage:
- `captures/feature_baselines/baseline_<scope>_<bssid>.json`

Manual refresh:

```bash
python -m nexus.intel.stream_baseline refresh --since 24h --min-windows 20
```

## 10. Streaming Anomaly Scoring (S2.3)

Live scoring runs inside `event_processor.py` when enabled. It reads the latest
baseline snapshot and scores feature windows with a z-score RMS metric:

- `score`: 0-100 anomaly score (higher = more anomalous)
- `confidence`: `score * baseline_maturity`
- `baseline_maturity`: sample_count / min_windows (recency-adjusted)

Anomalies are persisted to `attack_timeline` when:
- baseline snapshot is `ready`
- `score >= WICAP_ANOMALY_SCORE_THRESHOLD`
- `confidence >= WICAP_ANOMALY_MIN_CONFIDENCE`

Attack type defaults to `anomaly_stream` (override with `WICAP_ANOMALY_ATTACK_TYPE`).

Config:
- `WICAP_ANOMALY_STREAM_ENABLED` (default `false`)
- `WICAP_ANOMALY_SCOPE` (defaults to `WICAP_BASELINE_SCOPE` or `global`)
- `WICAP_ANOMALY_SCORE_THRESHOLD` (default `70`)
- `WICAP_ANOMALY_SCORE_SCALE` (default `3.0`)
- `WICAP_ANOMALY_MIN_CONFIDENCE` (default `40`)

## 11. Feedback Loop + Calibration (S2.4)

Operator feedback is captured from the Alerts UI (attack_timeline rows) and
stored in `attack_feedback`.

API:
- `POST /api/alerts/feedback` with `label: confirmed|benign|noisy`
- `GET /api/alerts/metrics` returns precision/recall proxy + threshold guidance

Calibration CLI (writes snapshot files under `captures/anomaly_calibration/`):

```bash
python -m nexus.intel.feedback_calibration refresh --since 24h --attack-type anomaly_stream
```

When `WICAP_ANOMALY_CALIBRATION_ENABLED=true`, the live stream scorer reads
the latest snapshot and adjusts the anomaly score threshold accordingly.

## 12. Alert Consolidation (S2.5)

Alert consolidation runs in the UI API layer to reduce duplicate noise:

- High-confidence anomaly alerts replace overlapping rule-based WIDS alerts.
- Rule-based alerts remain as fallback when no high-confidence anomalies exist.
- Optional suppression rules filter known recurring patterns (e.g., daily microwave noise).

Suppression rules are read from `WICAP_ALERT_SUPPRESSION_PATH` when enabled.
See `docs/CONFIGURATION.md` for defaults and flags.

Example suppression file:

```json
[
  {
    "id": "microwave_evening",
    "alert_type": "deauth_flood",
    "start_hour": 17,
    "end_hour": 19,
    "days": ["mon", "tue", "wed", "thu", "fri"],
    "reason": "Known microwave interference window"
  }
]
```

## 13. WIDS Alert Persistence

Rule-based WIDS detections are persisted to `attack_alerts` for the Alerts UI.
Acknowledgements are stored in the same table.

API:
- `POST /api/alerts/ack` with `acknowledged: true|false`
