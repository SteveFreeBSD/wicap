#!/usr/bin/env python3
"""
Backfill Bluetooth (BLE) PCAPs into SQL.

Parses BLE pcap/pcapng files with tshark and replays events through the
PersistenceManager so both curated_events and bt_* tables are populated.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import time
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

from nexus.config import NexusConfig
from src.wicap.core.capture.bluetooth_backend import BluetoothCaptureBackend
from src.wicap.core.processing.ble_parser import BLEParser
from src.wicap.core.processing.persistence import PersistenceManager


def _parse_since(value: str) -> datetime | None:
    token = value.strip().lower()
    if not token:
        return None
    if token.endswith("d"):
        try:
            days = int(token[:-1])
        except ValueError as exc:
            raise ValueError(f"Invalid --since value: {value}") from exc
        return datetime.now() - timedelta(days=days)
    if token.endswith("h"):
        try:
            hours = int(token[:-1])
        except ValueError as exc:
            raise ValueError(f"Invalid --since value: {value}") from exc
        return datetime.now() - timedelta(hours=hours)
    if token.endswith("m"):
        try:
            minutes = int(token[:-1])
        except ValueError as exc:
            raise ValueError(f"Invalid --since value: {value}") from exc
        return datetime.now() - timedelta(minutes=minutes)
    if token.endswith("s"):
        try:
            seconds = int(token[:-1])
        except ValueError as exc:
            raise ValueError(f"Invalid --since value: {value}") from exc
        return datetime.now() - timedelta(seconds=seconds)
    try:
        return datetime.fromisoformat(token)
    except ValueError as exc:
        raise ValueError(f"Invalid --since value: {value}") from exc


def _load_state(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data.get("files", {})
    except Exception:
        return {}

def _save_state(path: Path, files: dict[str, dict[str, str]]) -> None:
    payload = {"files": files, "updated_at": time.time()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def _get_status(files: dict[str, dict[str, str]], name: str) -> str:
    entry = files.get(name, {})
    return entry.get("status", "pending")


def _set_status(
    files: dict[str, dict[str, str]],
    name: str,
    status: str,
    error: str | None = None,
) -> None:
    entry = files.get(name, {})
    entry["status"] = status
    entry["updated_at"] = time.time()
    if error:
        entry["error"] = error
    elif "error" in entry:
        entry.pop("error", None)
    files[name] = entry


def _iter_pcaps(pcap_dir: Path, since: datetime | None) -> list[Path]:
    candidates = []
    for ext in ("*.pcapng", "*.pcap"):
        candidates.extend(pcap_dir.glob(ext))
    if since:
        candidates = [
            p
            for p in candidates
            if datetime.fromtimestamp(p.stat().st_mtime) >= since
        ]
    return sorted(candidates, key=lambda p: p.stat().st_mtime)


def _build_tshark_cmd(tshark_path: str, pcap: Path, fields: Iterable[str]) -> list[str]:
    cmd = [
        tshark_path,
        "-r", str(pcap),
        "-T", "fields",
        "-E", "separator=|",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]
    for field in fields:
        cmd.extend(["-e", field])
    return cmd


def _get_field_list() -> list[str]:
    backend = BluetoothCaptureBackend("offline", Path("captures/bt"))
    return backend._resolve_field_list()


def _parse_pcap_file(
    pcap: Path,
    fields: list[str],
    sensor_id: str | None,
    tshark_path: str,
) -> tuple[str, list[dict]]:
    parser_ble = BLEParser()
    cmd = _build_tshark_cmd(tshark_path, pcap, fields)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    events: list[dict] = []
    try:
        for line in proc.stdout or []:
            event = parser_ble.parse_line(line, field_names=fields)
            if not event:
                continue
            if sensor_id and not event.get("sensor_id"):
                event["sensor_id"] = sensor_id
            events.append(event)
        proc.wait()
    finally:
        if proc.poll() is None:
            proc.terminate()
    if proc.returncode not in (0, None):
        err = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"tshark failed on {pcap}: {err}")
    return pcap.name, events


def _worker_parse_only(args: tuple[str, list[str], str | None, str]) -> tuple[str, list[dict]]:
    path_str, fields, sensor_id, tshark_path = args
    return _parse_pcap_file(Path(path_str), fields, sensor_id, tshark_path)


def _persist_events(
    persistence: PersistenceManager,
    events: Iterable[dict],
    skip_curated: bool,
) -> int:
    count = 0
    for event in events:
        if not skip_curated:
            persistence.add_event(event)
        persistence.add_bt_event(event)
        count += 1
    return count


def _log_progress(
    logger: logging.Logger,
    label: str,
    current: int,
    total: int,
    total_events: int,
) -> None:
    if total:
        logger.info("%s: %s/%s files | events=%s", label, current, total, total_events)


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill BLE PCAPs into SQL")
    parser.add_argument("--pcap-dir", default="captures/bt", help="Directory with BLE pcaps")
    parser.add_argument("--since", default="30d", help="Date (YYYY-MM-DD) or window (e.g. 7d, 12h)")
    parser.add_argument("--all", action="store_true", help="Process all captures (ignore --since)")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of files processed")
    parser.add_argument("--batch", type=int, default=0, help="Alias for --limit (max files to process)")
    parser.add_argument("--resume", action="store_true", help="Skip files already recorded in state file")
    parser.add_argument("--reset", action="store_true", help="Ignore previous state")
    parser.add_argument("--retry-errors", action="store_true", help="Only retry files marked error")
    parser.add_argument("--state-file", default="captures/bt/bt_backfill.state.json", help="State file path")
    parser.add_argument("--batch-size", type=int, default=200, help="Batch size for SQL inserts")
    parser.add_argument("--workers", type=int, default=1, help="Number of parallel workers")
    parser.add_argument("--dry-run", action="store_true", help="Parse only, do not write to SQL")
    parser.add_argument("--skip-curated", action="store_true", help="Skip curated_events inserts")
    parser.add_argument("--tshark-path", default="tshark", help="Path to tshark")
    parser.add_argument("--progress-every", type=int, default=10, help="Log progress every N files")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logger = logging.getLogger("scripts.mine_bt_pcaps")

    if not shutil.which(args.tshark_path):
        logger.error("tshark not found at %s. Install Wireshark/tshark first.", args.tshark_path)
        return 1

    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.exists():
        logger.error("PCAP directory not found: %s", pcap_dir)
        return 1

    since = None
    if args.since and not args.all:
        since = _parse_since(args.since)
    state_file = Path(args.state_file)
    files_state: dict[str, dict[str, str]] = {}
    if args.resume and not args.reset:
        files_state = _load_state(state_file)

    files = _iter_pcaps(pcap_dir, since)
    limit = args.limit
    if args.batch and args.batch > 0:
        limit = args.batch
    if limit and limit > 0:
        files = files[: limit]

    if not files:
        logger.info("No BLE pcaps found to process.")
        return 0

    fields = _get_field_list()
    sensor_id = os.environ.get("WICAP_SENSOR_ID")
    workers = max(1, args.workers)

    statuses = {"pending"}
    if args.retry_errors:
        statuses = {"error"}
    elif args.resume:
        statuses = {"pending", "error", "processing"}

    filtered: list[Path] = []
    for pcap in files:
        status = _get_status(files_state, pcap.name)
        if status in statuses:
            filtered.append(pcap)

    if not filtered:
        logger.info("No files matched filter criteria")
        return 0

    if args.dry_run:
        logger.info("[dry-run] Would process %s file(s) with %s worker(s).", len(filtered), workers)
        return 0

    config = NexusConfig.from_env()
    persistence = PersistenceManager(config.get_sql_connection_string(), batch_size=args.batch_size)

    total_events = 0
    if workers == 1:
        for idx, pcap in enumerate(filtered, start=1):
            _set_status(files_state, pcap.name, "processing")
            _save_state(state_file, files_state)
            try:
                _, events = _parse_pcap_file(pcap, fields, sensor_id, args.tshark_path)
            except Exception as exc:
                logger.error("%s", exc)
                _set_status(files_state, pcap.name, "error", str(exc))
                _save_state(state_file, files_state)
                return 1
            total_events += _persist_events(persistence, events, args.skip_curated)
            persistence.flush()
            _set_status(files_state, pcap.name, "complete")
            _save_state(state_file, files_state)
            if args.progress_every and idx % args.progress_every == 0:
                _log_progress(logger, "progress", idx, len(filtered), total_events)
    else:
        for pcap in filtered:
            _set_status(files_state, pcap.name, "processing")
        _save_state(state_file, files_state)
        pending: list[tuple[str, list[dict]]] = []
        completed = 0
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(_worker_parse_only, (str(pcap), fields, sensor_id, args.tshark_path))
                for pcap in filtered
            ]
            total = len(futures)
            for future in as_completed(futures):
                completed += 1
                try:
                    name, events = future.result()
                except Exception as exc:
                    logger.error("Worker failed: %s", exc)
                    _set_status(files_state, name, "error", str(exc))
                    _save_state(state_file, files_state)
                    return 1
                pending.append((name, events))
                if len(pending) >= 25 or completed == total:
                    for name, events in pending:
                        total_events += _persist_events(persistence, events, args.skip_curated)
                        _set_status(files_state, name, "complete")
                    persistence.flush()
                    _save_state(state_file, files_state)
                    if args.progress_every and completed % args.progress_every == 0:
                        _log_progress(logger, "persisted", completed, total, total_events)
                    pending = []

    persistence.flush()
    persistence.disconnect()
    logger.info("Completed BLE backfill. Total events: %s", total_events)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
