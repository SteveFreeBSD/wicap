# Network Baseline Drift (S3.3)

This document describes the 30‑day network baseline and drift detection
introduced in S3.3. The goal is to detect environmental changes that matter
operationally (new SSIDs/BSSIDs, security downgrades, channel churn) without
breaking the live pipeline.

## What It Does

- Builds a 30‑day baseline from SQL (`curated_events` + `security_posture`).
- Loads the baseline at Scout startup (if present).
- Emits WIDS alerts when observed traffic deviates from the baseline.

## Baseline Snapshot

Stored as JSON at:
`captures/network_baselines/network_baseline_global.json`

Contains:
- `ssid_bssids`: known BSSIDs per SSID (30‑day history)
- `bssid_security`: baseline security posture per BSSID
- `bssid_channel`: primary channel per BSSID (most common in 30 days)

## Drift Alert Types

- `wids_baseline_new_ssid` — SSID not seen in 30 days
- `wids_baseline_new_bssid` — New BSSID for existing SSID
- `wids_baseline_security_downgrade` — Security posture dropped vs baseline
- `wids_baseline_channel_drift` — Channel changed vs baseline

These alerts flow through the existing WIDS alert pipeline and appear in the
Alerts UI and `/api/alerts`.

## Building the Baseline

Run the baseline refresh command (uses SQL Server via `pyodbc`):

```bash
python -m nexus.intel.network_baseline refresh --since 30d
```

To inspect the current snapshot:

```bash
python -m nexus.intel.network_baseline report
```

## API Endpoints

- `GET /api/baseline/network` — baseline summary
- `GET /api/baseline/network?include_maps=true` — full snapshot maps
- `GET /api/baseline/drift` — recent drift alerts (`wids_baseline_*`)

## Configuration

- `WICAP_NETWORK_BASELINE_PATH` — baseline JSON path
- `WICAP_NETWORK_BASELINE_ENABLED` — when set to true, forces baseline load

If `WICAP_NETWORK_BASELINE_ENABLED` is unset, WICAP loads the baseline only if
the snapshot file exists. This avoids errors during early deployments.
