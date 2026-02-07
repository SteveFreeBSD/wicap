# WICAP Backfill CLI (WiFi + BLE)

This is the single source of truth for offline backfill commands and flags.
Use it to replay historical captures into SQL without running live capture.

---

## WiFi Backfill (PCAP Intelligence)

Script: `scripts/mine_pcaps.py`

Purpose:
- Populate associations + RSSI aggregates from Wi‑Fi captures.
- Uses `pcap_index.processing_status` for idempotency and resume.

Common runs:
- 30-day backfill: `python scripts/mine_pcaps.py --since 30d --resume --batch 100`
- Full backfill: `python scripts/mine_pcaps.py --all --resume --batch 100`
- Retry errors only: `python scripts/mine_pcaps.py --retry-errors --batch 50`
- Dry run: `python scripts/mine_pcaps.py --since 30d --dry-run`

Key flags:
- `--since 30d` (default) or `YYYY-MM-DD`
- `--all` (ignore `--since`)
- `--resume` (process `pending`, `error`, `processing`)
- `--retry-errors` (process only `error`)
- `--batch 100` (max files per run)
- `--workers 1` (parallel parse workers; main process persists)
- `--parser scapy|tshark` (default `scapy`)
- `--tshark-path /path/to/tshark`
- `--no-dedupe` (disable packet dedup)
- `--progress-every 10`
- `--dry-run` (parse only, no SQL writes)

State:
- `pcap_index.processing_status` tracks `pending → processing → complete/error`.

---

## BLE Backfill (Bluetooth PCAPs)

Script: `scripts/mine_bt_pcaps.py`

Purpose:
- Populate `bt_devices`, `bt_observations`, and `curated_events` (unless skipped).
- Uses a local state file for resume semantics.

Common runs:
- 30-day backfill: `python scripts/mine_bt_pcaps.py --pcap-dir captures/bt --since 30d --resume --workers 4 --batch 200`
- Full backfill: `python scripts/mine_bt_pcaps.py --pcap-dir captures/bt --all --resume --workers 4 --batch 200`
- Retry errors only: `python scripts/mine_bt_pcaps.py --pcap-dir captures/bt --retry-errors --workers 4 --batch 200`
- Dry run: `python scripts/mine_bt_pcaps.py --pcap-dir captures/bt --since 30d --dry-run`

Key flags:
- `--since 30d` (default) or `YYYY-MM-DD`
- `--all` (ignore `--since`)
- `--resume` (process `pending`, `error`, `processing`)
- `--retry-errors` (process only `error`)
- `--limit N` (max files) or `--batch N` (alias)
- `--workers 1` (parallel parse workers)
- `--batch-size 200` (SQL insert batch size)
- `--skip-curated` (write only BLE tables)
- `--tshark-path /path/to/tshark`
- `--progress-every 10`
- `--dry-run` (parse only, no SQL writes)

State:
- Default: `captures/bt/bt_backfill.state.json`
- Per‑file statuses: `pending`, `processing`, `complete`, `error`

---

## Troubleshooting

- `tshark` missing: install Wireshark or provide `--tshark-path`.
- SQL auth: set `WICAP_SQL_PASSWORD` (and `WICAP_SQL_TRUST_CERT=yes` if needed).
- BLE backfill does **not** require a dongle; it only needs existing PCAPs.

---

## Logging Parity

Both backfills emit progress every `--progress-every` files and log total events.

---

## Post‑Backfill Verification Checklist

Use this after any sizeable replay to validate correctness before longer soaks.

WiFi:
- Count recent associations and RSSI updates:
  - `SELECT COUNT(*) FROM client_associations WHERE last_seen > DATEADD(day, -7, SYSDATETIME());`
  - `SELECT COUNT(*) FROM client_profiles WHERE rssi_sample_count > 0;`
- Spot‑check a known BSSID in `client_associations` and ensure `association_count` increments.
- If you rerun one file, counts should not double (idempotent MERGE).

BLE:
- Count recent observations:
  - `SELECT COUNT(*) FROM bt_observations WHERE inserted_at > DATEADD(day, -7, SYSDATETIME());`
- Spot‑check a device in `bt_devices` and ensure `last_seen` advances.
- If you rerun one file, `bt_devices` should update `last_seen` without duplicates.

Both:
- Rerun with `--retry-errors` and confirm no new errors.

---

## Ops Outputs After Backfill (Optional, S3.5)

Once backfill is complete, generate ops outputs to verify evidence paths:

- Daily digest:
  - `python scripts/daily_digest.py --since-hours 24`
- Evidence bundle (time range):
  - `python scripts/evidence_bundle.py --start-ts <epoch> --end-ts <epoch>`
