#!/usr/bin/env python3
"""
Backfill PCAP intelligence into SQL (associations + RSSI aggregates).
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
from collections.abc import Iterator, Sequence
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

# Allow running as a script from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import pyodbc
except ImportError as exc:
    raise SystemExit("pyodbc is required for backfill") from exc

from nexus.config import get_nexus_config
from nexus.scavenger.agents import SCAPY_AVAILABLE
from nexus.scavenger.persistence import ScavengerDAO
from nexus.scavenger.pipeline import ScavengerPipeline

logger = logging.getLogger("scripts.mine_pcaps")


def _parse_since(value: str) -> datetime:
    value = value.strip().lower()
    if value.endswith("d"):
        days = int(value[:-1])
        return datetime.now() - timedelta(days=days)
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid --since value: {value}") from exc


def _list_candidates(captures_dir: Path, since: datetime | None, include_all: bool) -> list[Path]:
    patterns = ("*.pcapng", "*.pcap", "*.cap")
    files: list[Path] = []
    for pattern in patterns:
        files.extend(captures_dir.glob(pattern))
    files = [p for p in files if p.is_file()]
    if since and not include_all:
        files = [p for p in files if datetime.fromtimestamp(p.stat().st_mtime) >= since]
    files.sort(key=lambda p: p.stat().st_mtime)
    return files


def _ensure_pcap_index(conn: pyodbc.Connection, files: Sequence[Path]) -> None:
    if not files:
        return
    cursor = conn.cursor()
    cursor.fast_executemany = True
    rows = []
    for path in files:
        stat = path.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime)
        rows.append((str(path), path.name, stat.st_size, mtime, mtime))
    cursor.executemany(
        """
        MERGE pcap_index AS target
        USING (SELECT ? AS filepath, ? AS filename, ? AS file_size, ? AS capture_start, ? AS capture_end) AS source
        ON target.filepath = source.filepath
        WHEN MATCHED THEN
            UPDATE SET
                filename = COALESCE(target.filename, source.filename),
                file_size = COALESCE(target.file_size, source.file_size),
                capture_start = COALESCE(target.capture_start, source.capture_start),
                capture_end = COALESCE(target.capture_end, source.capture_end)
        WHEN NOT MATCHED THEN
            INSERT (filename, filepath, file_size, capture_start, capture_end, processing_status)
            VALUES (source.filename, source.filepath, source.file_size, source.capture_start, source.capture_end, 'pending');
        """,
        rows,
    )
    conn.commit()


def _fetch_status_map(conn: pyodbc.Connection) -> dict[str, str]:
    cursor = conn.cursor()
    cursor.execute("SELECT filepath, processing_status FROM pcap_index")
    return {row[0]: row[1] for row in cursor.fetchall()}


def _update_status(
    conn: pyodbc.Connection,
    filepath: str,
    status: str,
    error: str | None = None,
) -> None:
    cursor = conn.cursor()
    if status == "processing":
        cursor.execute(
            """
            UPDATE pcap_index
            SET processing_status = ?, processing_error = NULL, processed_at = NULL
            WHERE filepath = ?
            """,
            (status, filepath),
        )
    elif status == "complete":
        cursor.execute(
            """
            UPDATE pcap_index
            SET processing_status = ?, processing_error = NULL, processed_at = SYSDATETIME()
            WHERE filepath = ?
            """,
            (status, filepath),
        )
    elif status == "error":
        cursor.execute(
            """
            UPDATE pcap_index
            SET processing_status = ?, processing_error = ?, processed_at = SYSDATETIME()
            WHERE filepath = ?
            """,
            (status, error, filepath),
        )
    else:
        cursor.execute(
            "UPDATE pcap_index SET processing_status = ? WHERE filepath = ?",
            (status, filepath),
        )


def _claim_file(
    conn: pyodbc.Connection,
    filepath: str,
    allowed_statuses: Sequence[str],
) -> bool:
    if not allowed_statuses:
        return False
    placeholders = ", ".join("?" for _ in allowed_statuses)
    cursor = conn.cursor()
    cursor.execute(
        f"""
        UPDATE pcap_index
        SET processing_status = ?, processing_error = NULL, processed_at = NULL
        WHERE filepath = ? AND processing_status IN ({placeholders})
        """,
        ("processing", filepath, *allowed_statuses),
    )
    return cursor.rowcount == 1


def _is_randomized_mac(mac: str) -> bool:
    mac = mac.lower()
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _is_broadcast_or_multicast(mac: str | None) -> bool:
    if not mac:
        return True
    mac = mac.lower()
    if mac == "ff:ff:ff:ff:ff:ff":
        return True
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return True
    return bool(first_octet & 0x01)


@dataclass
class _AssocAgg:
    client_mac: str
    bssid: str
    ssid: str | None = None
    first_ts: float | None = None
    last_ts: float | None = None
    association_count: int = 0
    last_assoc_type: str | None = None
    has_mgmt: bool = False

    def update(self, ts: float, assoc_type: str, ssid: str | None, trust: str) -> None:
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts
        if self.ssid is None and ssid:
            self.ssid = ssid
        self.association_count += 1
        self.last_assoc_type = assoc_type
        if trust == "mgmt":
            self.has_mgmt = True


def _tshark_available(path: str) -> bool:
    return shutil.which(path) is not None


def _select_tshark_fields(tshark_path: str) -> tuple[str, str]:
    """Pick ToDS/FromDS field names supported by installed tshark."""
    try:
        output = subprocess.check_output(
            [tshark_path, "-G", "fields"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return ("wlan.fc.tods", "wlan.fc.fromds")

    if "wlan.fc.tods" in output and "wlan.fc.fromds" in output:
        return ("wlan.fc.tods", "wlan.fc.fromds")
    if "wlan.fc.to_ds" in output and "wlan.fc.from_ds" in output:
        return ("wlan.fc.to_ds", "wlan.fc.from_ds")
    if "wlan.fc.tods" in output and "wlan.fc.from_ds" in output:
        return ("wlan.fc.tods", "wlan.fc.from_ds")
    return ("wlan.fc.tods", "wlan.fc.fromds")


def _iter_tshark_rows(
    pcap_path: Path,
    tshark_path: str,
    to_ds_field: str,
    from_ds_field: str,
) -> Iterator[list[str]]:
    fields = [
        "frame.time_epoch",
        "wlan.fc.type",
        "wlan.fc.subtype",
        to_ds_field,
        from_ds_field,
        "wlan.sa",
        "wlan.da",
        "wlan.ta",
        "wlan.ra",
        "wlan.bssid",
        "wlan.ssid",
        "radiotap.dbm_antsignal",
    ]
    cmd = [
        tshark_path,
        "-n",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-E",
        "header=n",
        "-E",
        "quote=n",
        "-Y",
        "wlan.fc.type == 0 || wlan.fc.type == 2",
    ]
    for field in fields:
        cmd.extend(["-e", field])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if not proc.stdout or not proc.stderr:
        proc.kill()
        raise RuntimeError("Failed to open tshark output streams")

    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            parts = line.split("\t") if line else []
            if len(parts) < len(fields):
                parts.extend([""] * (len(fields) - len(parts)))
            yield parts
    finally:
        stderr = proc.stderr.read()
        ret = proc.wait()
        if ret != 0:
            raise RuntimeError(f"tshark failed for {pcap_path.name}: {stderr.strip()}")


def _parse_int(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _parse_float(value: str) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _parse_bool(value: str) -> bool:
    if not value:
        return False
    value = value.strip().lower()
    return value in {"1", "true", "yes"}


def _process_tshark_file(
    pcap_path: Path,
    tshark_path: str,
    to_ds_field: str,
    from_ds_field: str,
) -> tuple[list[dict[str, object]], list[tuple[str, list[int], datetime | None]], list[tuple[str, datetime, datetime, int]]]:
    idx_ts = 0
    idx_type = 1
    idx_subtype = 2
    idx_to_ds = 3
    idx_from_ds = 4
    idx_sa = 5
    idx_da = 6
    idx_ta = 7
    idx_ra = 8
    idx_bssid = 9
    idx_ssid = 10
    idx_rssi = 11

    associations: dict[tuple[str, str], _AssocAgg] = {}
    rssi_samples: dict[str, list[int]] = {}
    rssi_first_last: dict[str, tuple[float, float]] = {}

    for parts in _iter_tshark_rows(pcap_path, tshark_path, to_ds_field, from_ds_field):
        ts = _parse_float(parts[idx_ts])
        if ts is None:
            continue
        frame_type = _parse_int(parts[idx_type])
        if frame_type is None:
            continue
        subtype = _parse_int(parts[idx_subtype]) or 0
        to_ds = _parse_bool(parts[idx_to_ds])
        from_ds = _parse_bool(parts[idx_from_ds])

        sa = parts[idx_sa].lower() if parts[idx_sa] else None
        da = parts[idx_da].lower() if parts[idx_da] else None
        ta = parts[idx_ta].lower() if parts[idx_ta] else None
        ra = parts[idx_ra].lower() if parts[idx_ra] else None
        bssid = parts[idx_bssid].lower() if parts[idx_bssid] else None
        ssid = parts[idx_ssid] or None

        # RSSI for probe requests only (match AgentShadow behavior)
        if frame_type == 0 and subtype == 4 and sa and not _is_broadcast_or_multicast(sa):
            rssi = _parse_int(parts[idx_rssi])
            if rssi is not None:
                rssi_samples.setdefault(sa, []).append(rssi)
                first_last = rssi_first_last.get(sa)
                if first_last is None:
                    rssi_first_last[sa] = (ts, ts)
                else:
                    rssi_first_last[sa] = (min(first_last[0], ts), max(first_last[1], ts))

        client_mac = None
        assoc_type = None
        trust = None

        if frame_type == 0:
            if subtype in (0, 2):  # AssocReq, ReassocReq
                client_mac = sa
                assoc_type = "assoc_req"
            elif subtype in (1, 3):  # AssocResp, ReassocResp
                client_mac = da or ra
                assoc_type = "assoc_resp"
            elif subtype == 11:  # Auth
                client_mac = sa
                assoc_type = "auth"
            else:
                client_mac = None

            if client_mac and not bssid:
                bssid = ra
            trust = "mgmt" if client_mac else None

        elif frame_type == 2:
            if to_ds and not from_ds:
                bssid = ra or bssid
                client_mac = ta or sa
            elif from_ds and not to_ds:
                bssid = ta or bssid
                client_mac = ra or da
            else:
                client_mac = None
            assoc_type = "data" if client_mac else None
            trust = "data" if client_mac else None

        if not client_mac or not bssid:
            continue
        if _is_broadcast_or_multicast(client_mac) or _is_broadcast_or_multicast(bssid):
            continue

        key = (client_mac, bssid)
        record = associations.get(key)
        if record is None:
            record = _AssocAgg(client_mac=client_mac, bssid=bssid)
            associations[key] = record

        if assoc_type == "data" and record.has_mgmt:
            continue
        record.update(ts, assoc_type or "data", ssid, trust or "data")

    assoc_rows = []
    for record in associations.values():
        if record.first_ts is None or record.last_ts is None:
            continue
        assoc_rows.append(
            {
                "client_mac": record.client_mac,
                "bssid": record.bssid,
                "ssid": record.ssid,
                "first_seen": datetime.fromtimestamp(record.first_ts),
                "last_seen": datetime.fromtimestamp(record.last_ts),
                "association_count": record.association_count,
                "assoc_type": record.last_assoc_type,
            }
        )

    rssi_batches = []
    ensure_rows = []
    for mac, samples in rssi_samples.items():
        first_last = rssi_first_last.get(mac)
        if not first_last:
            continue
        first_seen = datetime.fromtimestamp(first_last[0])
        last_seen = datetime.fromtimestamp(first_last[1])
        ensure_rows.append((mac, first_seen, last_seen, 1 if _is_randomized_mac(mac) else 0))
        rssi_batches.append((mac, samples, last_seen))

    return assoc_rows, rssi_batches, ensure_rows


def _ensure_client_profiles(
    cursor: pyodbc.Cursor,
    client_rows: Sequence[tuple[str, datetime, datetime, int]],
) -> None:
    if not client_rows:
        return
    cursor.fast_executemany = True
    cursor.executemany(
        """
        MERGE client_profiles AS target
        USING (SELECT ? AS mac_addr, ? AS first_seen, ? AS last_seen, ? AS is_randomized) AS source
        ON target.mac_addr = source.mac_addr
        WHEN MATCHED THEN
            UPDATE SET
                first_seen = CASE
                    WHEN target.first_seen IS NULL OR source.first_seen < target.first_seen
                        THEN source.first_seen
                    ELSE target.first_seen
                END,
                last_seen = CASE
                    WHEN target.last_seen IS NULL OR source.last_seen > target.last_seen
                        THEN source.last_seen
                    ELSE target.last_seen
                END,
                updated_at = SYSDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (mac_addr, vendor, device_type, first_seen, last_seen, probe_count, is_randomized, threat_score)
            VALUES (source.mac_addr, 'Unknown', NULL, source.first_seen, source.last_seen, 0, source.is_randomized, 0);
        """,
        client_rows,
    )


def _persist_associations(
    cursor: pyodbc.Cursor,
    associations: Sequence[dict[str, object]],
) -> None:
    if not associations:
        return
    cursor.fast_executemany = True
    rows = []
    for assoc in associations:
        rows.append(
            (
                assoc["client_mac"],
                assoc["bssid"],
                assoc.get("ssid"),
                assoc["first_seen"],
                assoc["last_seen"],
                assoc.get("association_count", 1),
                assoc.get("assoc_type"),
            )
        )
    cursor.executemany(
        """
        MERGE client_associations AS target
        USING (
            SELECT ? AS client_mac, ? AS bssid, ? AS ssid, ? AS first_seen,
                   ? AS last_seen, ? AS association_count, ? AS assoc_type
        ) AS source
        ON target.client_mac = source.client_mac AND target.bssid = source.bssid
        WHEN MATCHED THEN
            UPDATE SET
                ssid = COALESCE(target.ssid, source.ssid),
                first_seen = CASE
                    WHEN target.first_seen IS NULL OR source.first_seen < target.first_seen
                        THEN source.first_seen
                    ELSE target.first_seen
                END,
                last_seen = CASE
                    WHEN target.last_seen IS NULL OR source.last_seen > target.last_seen
                        THEN source.last_seen
                    ELSE target.last_seen
                END,
                association_count = target.association_count + source.association_count,
                last_assoc_type = source.assoc_type
        WHEN NOT MATCHED THEN
            INSERT (client_mac, bssid, ssid, first_seen, last_seen, association_count, last_assoc_type)
            VALUES (source.client_mac, source.bssid, source.ssid, source.first_seen,
                    source.last_seen, source.association_count, source.assoc_type);
        """,
        rows,
    )


def _update_associated_bssids(cursor: pyodbc.Cursor, mac_to_bssids: dict[str, list[str]]) -> None:
    if not mac_to_bssids:
        return
    updates = []
    for mac, bssids in mac_to_bssids.items():
        updates.append((bssids, mac))

    # setinputsizes for NVARCHAR(MAX) associated_bssids column
    cursor.fast_executemany = True
    cursor.setinputsizes([
        (pyodbc.SQL_WVARCHAR, 0, 0),  # associated_bssids NVARCHAR(MAX)
        (pyodbc.SQL_CHAR, 17, 0),     # mac_addr
    ])
    cursor.executemany(
        """
        UPDATE client_profiles
        SET associated_bssids = ?, updated_at = SYSDATETIME()
        WHERE mac_addr = ?
        """,
        updates,
    )


def _build_association_updates(
    cursor: pyodbc.Cursor,
    associations: Sequence[dict[str, object]],
) -> tuple[list[tuple[str, datetime, datetime, int]], dict[str, list[str]]]:
    if not associations:
        return [], {}

    mac_to_bssids: dict[str, set] = {}
    mac_first_last: dict[str, tuple[datetime, datetime]] = {}

    for assoc in associations:
        client = assoc["client_mac"]
        bssid = assoc["bssid"]
        mac_to_bssids.setdefault(client, set()).add(bssid)
        first_seen = assoc["first_seen"]
        last_seen = assoc["last_seen"]
        existing = mac_first_last.get(client)
        if existing is None:
            mac_first_last[client] = (first_seen, last_seen)
        else:
            mac_first_last[client] = (
                min(existing[0], first_seen),
                max(existing[1], last_seen),
            )

    macs = list(mac_to_bssids.keys())
    existing: dict[str, list[str]] = {}
    if macs:
        chunk_size = 900
        for i in range(0, len(macs), chunk_size):
            chunk = macs[i : i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            cursor.execute(
                f"SELECT mac_addr, associated_bssids FROM client_profiles WHERE mac_addr IN ({placeholders})",
                chunk,
            )
            for row in cursor.fetchall():
                existing[row[0].lower()] = (
                    json.loads(row[1]) if row[1] else []
                )

    updated_json: dict[str, list[str]] = {}
    for mac, bssids in mac_to_bssids.items():
        merged = set(existing.get(mac, []))
        merged.update(bssids)
        final = list(merged)[:1000]
        updated_json[mac] = json.dumps(final)

    ensure_rows = []
    for mac, (first_seen, last_seen) in mac_first_last.items():
        ensure_rows.append((mac, first_seen, last_seen, 1 if _is_randomized_mac(mac) else 0))

    return ensure_rows, updated_json


def _process_one_tshark(
    path: Path,
    config,
    conn: pyodbc.Connection | None,
    dry_run: bool,
    tshark_path: str,
    claim_statuses: Sequence[str],
    to_ds_field: str | None = None,
    from_ds_field: str | None = None,
    persist: bool = True,
) -> tuple[str, str | None, tuple | None]:
    if dry_run:
        if to_ds_field is None or from_ds_field is None:
            to_ds_field, from_ds_field = _select_tshark_fields(tshark_path)
        _process_tshark_file(path, tshark_path, to_ds_field, from_ds_field)
        return ("dry-run", None, None)

    if persist:
        if conn is None:
            raise RuntimeError("DB connection required for tshark backfill")

        if not _claim_file(conn, str(path), claim_statuses):
            logger.info("Skipping %s (already claimed)", path)
            return ("skipped", None, None)
        conn.commit()

    if to_ds_field is None or from_ds_field is None:
        to_ds_field, from_ds_field = _select_tshark_fields(tshark_path)

    dao = ScavengerDAO(config)
    try:
        associations, rssi_batches, ensure_rows = _process_tshark_file(
            path,
            tshark_path,
            to_ds_field,
            from_ds_field,
        )

        if not persist:
            return ("parsed", None, (associations, rssi_batches, ensure_rows))

        cursor = conn.cursor()
        if ensure_rows:
            _ensure_client_profiles(cursor, ensure_rows)
        if rssi_batches:
            dao.merge_rssi_aggregates(rssi_batches, conn=conn, commit=False)
        if associations:
            dao.merge_associations_batch(associations, conn=conn, commit=False)

        _update_status(conn, str(path), "complete")
        conn.commit()
        return ("complete", None, None)
    except Exception as exc:
        logger.error("Failed %s: %s", path, exc)
        if persist:
            try:
                conn.rollback()
            except Exception:
                pass
            _update_status(conn, str(path), "error", str(exc))
            conn.commit()
        return ("error", str(exc), None)


def _process_one_scapy(
    path: Path,
    config,
    conn: pyodbc.Connection | None,
    dry_run: bool,
    deduplicate: bool,
    claim_statuses: Sequence[str],
    persist: bool = True,
) -> tuple[str, str | None, tuple | None]:
    if dry_run:
        pipeline = ScavengerPipeline(
            capture_dir=path.parent,
            config=None,
            agents=["shadow", "cartographer"],
        )
        pipeline.run(pcap_files=[path], deduplicate=deduplicate)
        return ("dry-run", None)

    if conn is None:
        raise RuntimeError("DB connection required for scapy backfill")

    if not _claim_file(conn, str(path), claim_statuses):
        logger.info("Skipping %s (already claimed)", path)
        return ("skipped", None)
    conn.commit()

    try:
        pipeline = ScavengerPipeline(
            capture_dir=path.parent,
            config=config,
            agents=["shadow", "cartographer"],
        )
        pipeline.run(pcap_files=[path], deduplicate=deduplicate, db_conn=conn)

        cart = pipeline.agents.get("cartographer")
        associations = cart.export_associations() if cart else []

        if associations:
            cursor = conn.cursor()
            ensure_rows, updated_json = _build_association_updates(cursor, associations)
            if ensure_rows:
                _ensure_client_profiles(cursor, ensure_rows)
            _persist_associations(cursor, associations)
            if updated_json:
                _update_associated_bssids(cursor, updated_json)

        _update_status(conn, str(path), "complete")
        conn.commit()
        return ("complete", None, None)
    except Exception as exc:
        logger.error("Failed %s: %s", path, exc)
        if persist:
            try:
                conn.rollback()
            except Exception:
                pass
            _update_status(conn, str(path), "error", str(exc))
            conn.commit()
        return ("error", str(exc), None)


def _worker_parse_only(
    path_str: str,
    parser_backend: str,
    deduplicate: bool,
    dry_run: bool,
    claim_statuses: Sequence[str],
    tshark_path: str,
) -> tuple[str, str, str | None, tuple | None]:
    config = get_nexus_config()
    path = Path(path_str)

    # Note: No DB connection created here!
    # We call process functions with persist=False

    conn = None # No DB connection in worker

    if parser_backend == "tshark":
        status, error, data = _process_one_tshark(
            path,
            config,
            conn,
            dry_run,
            tshark_path,
            claim_statuses,
            persist=False,
        )
    else:
        # Scapy path currently requires persist=True due to heavy pipeline coupling
        # For now, we return skipped
        return (path_str, "skipped", "Scapy parallel parse-only not supported", None)

    return (path_str, status, error, data)


def _run_backfill_tshark(
    files: Sequence[Path],
    config,
    conn: pyodbc.Connection | None,
    dry_run: bool,
    progress_every: int,
    tshark_path: str,
    claim_statuses: Sequence[str],
) -> None:
    total = len(files)
    to_ds_field, from_ds_field = _select_tshark_fields(tshark_path)

    for idx, path in enumerate(files, start=1):
        if progress_every and idx % progress_every == 0:
            logger.info("Progress: %s/%s files", idx, total)

        _process_one_tshark(
            path,
            config,
            conn,
            dry_run,
            tshark_path,
            claim_statuses,
            to_ds_field=to_ds_field,
            from_ds_field=from_ds_field,
            persist=True,
        )


def _run_backfill(
    files: Sequence[Path],
    config,
    conn: pyodbc.Connection | None,
    dry_run: bool,
    progress_every: int,
    deduplicate: bool,
    claim_statuses: Sequence[str],
) -> None:
    total = len(files)
    for idx, path in enumerate(files, start=1):
        if progress_every and idx % progress_every == 0:
            logger.info("Progress: %s/%s files", idx, total)

        _process_one_scapy(
            path,
            config,
            conn,
            dry_run,
            deduplicate,
            claim_statuses,
            persist=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill PCAP intelligence into SQL")
    parser.add_argument("--since", default="30d", help="Date (YYYY-MM-DD) or Nd (e.g., 30d)")
    parser.add_argument("--all", action="store_true", help="Process all captures (ignore --since)")
    parser.add_argument("--resume", action="store_true", help="Resume pending/error/processing files")
    parser.add_argument("--retry-errors", action="store_true", help="Only retry files marked error")
    parser.add_argument("--batch", type=int, default=100, help="Max files to process per run")
    parser.add_argument("--workers", type=int, default=1, help="Number of parallel workers")
    parser.add_argument("--dry-run", action="store_true", help="Parse PCAPs without DB writes")
    parser.add_argument("--no-dedupe", action="store_true", help="Disable packet deduplication")
    parser.add_argument(
        "--parser",
        choices=["scapy", "tshark"],
        default="scapy",
        help="Parser backend (scapy or tshark)",
    )
    parser.add_argument("--tshark-path", default="tshark", help="Path to tshark")
    parser.add_argument("--progress-every", type=int, default=10, help="Log progress every N files")
    args = parser.parse_args()
    deduplicate = not args.no_dedupe

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    since = None
    if args.since and not args.all:
        since = _parse_since(args.since)

    config = get_nexus_config()
    captures_dir = config.captures_dir
    files = _list_candidates(captures_dir, since, args.all)
    if not files:
        logger.info("No capture files found")
        return 0

    conn = None
    status_map: dict[str, str] = {}
    if not args.dry_run:
        conn = pyodbc.connect(config.get_sql_connection_string(), autocommit=False)
        _ensure_pcap_index(conn, files)
        status_map = _fetch_status_map(conn)
    else:
        try:
            conn = pyodbc.connect(config.get_sql_connection_string(), autocommit=True)
            status_map = _fetch_status_map(conn)
            conn.close()
        except Exception:
            status_map = {}
            conn = None

    statuses = set()
    if args.retry_errors:
        statuses = {"error"}
    elif args.resume:
        statuses = {"pending", "error", "processing"}
    else:
        statuses = {"pending"}

    filtered: list[Path] = []
    for path in files:
        status = status_map.get(str(path), "pending")
        if status in statuses:
            filtered.append(path)

    if args.batch and args.batch > 0:
        filtered = filtered[: args.batch]

    if not filtered:
        logger.info("No files matched filter criteria")
        if conn:
            conn.close()
        return 0

    logger.info("Processing %s files", len(filtered))
    parser_backend = args.parser
    if parser_backend == "tshark" and not _tshark_available(args.tshark_path):
        logger.warning("tshark not found; falling back to scapy parser")
        parser_backend = "scapy"
    if parser_backend == "scapy" and not SCAPY_AVAILABLE:
        logger.error("scapy not available; cannot parse PCAPs")
        return 1
    workers = max(1, args.workers)

    if args.dry_run:
        if workers > 1:
            logger.info("Processing %s files with %s workers (dry-run)", len(filtered), workers)
            claim_statuses = tuple(sorted(statuses))
            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(
                        _worker_parse_only,
                        str(path),
                        parser_backend,
                        deduplicate,
                        True,
                        claim_statuses,
                        args.tshark_path,
                    )
                    for path in filtered
                ]
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    if args.progress_every and completed % args.progress_every == 0:
                        logger.info("Progress: %s/%s files", completed, len(filtered))
                    try:
                        _, status, error, _ = future.result()
                        if status == "error":
                            logger.error("Worker error: %s", error)
                    except Exception as exc:
                        logger.error("Worker failed: %s", exc)
            return 0

        if parser_backend == "tshark":
            _run_backfill_tshark(
                filtered,
                config,
                None,
                True,
                args.progress_every,
                args.tshark_path,
                tuple(sorted(statuses)),
            )
        else:
            _run_backfill(
                filtered,
                config,
                None,
                True,
                args.progress_every,
                deduplicate,
                tuple(sorted(statuses)),
            )
        return 0

    if conn is None:
        logger.error("DB connection unavailable")
        return 1

    claim_statuses = tuple(sorted(statuses))
    if workers > 1:
        logger.info("Processing %s files with %s workers (Map-Reduce)", len(filtered), workers)
        # Main process handles DB
        dao = ScavengerDAO(config)

        with ProcessPoolExecutor(max_workers=workers) as executor:
            # Dispatch all parse jobs
            futures = [
                executor.submit(
                    _worker_parse_only,
                    str(path),
                    parser_backend,
                    deduplicate,
                    False,
                    claim_statuses,
                    args.tshark_path,
                )
                for path in filtered
            ]

            completed = 0
            pending_batch = []

            for future in as_completed(futures):
                try:
                    path_str, status, error, data = future.result()
                    completed += 1

                    if status == "parsed" and data:
                        # Add to batch for persistence
                        # data is (associations, rssi_batches, ensure_rows)
                        pending_batch.append((path_str, data))
                    elif status == "error":
                        logger.error("Failed %s: %s", path_str, error)
                        _update_status(conn, path_str, "error", error)
                        conn.commit()
                    elif status == "skipped":
                        # Should not happen if logic is correct, but safe to ignore
                        pass
                except Exception as exc:
                    logger.error("Worker failed: %s", exc)

                # Persist batch if size reached or done
                if len(pending_batch) >= 50 or completed == len(filtered):
                    if pending_batch:
                        logger.info("Persisting batch of %s files...", len(pending_batch))
                        try:
                            # 1. Claim files (mark as processing -> updating)
                            # Actually, we can just update to complete, but let's be safe

                            # 2. Merge all data
                            batch_associations = []
                            batch_rssi = []
                            batch_ensure = []

                            for _, (assoc, rssi, ensure) in pending_batch:
                                batch_associations.extend(assoc)
                                batch_rssi.extend(rssi)
                                batch_ensure.extend(ensure)

                            cursor = conn.cursor()
                            if batch_ensure:
                                _ensure_client_profiles(cursor, batch_ensure)
                            if batch_rssi:
                                dao.merge_rssi_aggregates(batch_rssi, conn=conn, commit=False)
                            if batch_associations:
                                dao.merge_associations_batch(batch_associations, conn=conn, commit=False)

                            # 3. Mark complete
                            for p_str, _ in pending_batch:
                                _update_status(conn, p_str, "complete")

                            conn.commit()
                            pending_batch = []
                        except Exception as exc:
                            logger.error("Batch persistence failed: %s", exc)
                            conn.rollback()
                            # Mark individual errors?
                            for p_str, _ in pending_batch:
                                _update_status(conn, p_str, "error", f"Batch write failed: {exc}")
                            conn.commit()
                            pending_batch = []

                if args.progress_every and completed % args.progress_every == 0:
                    logger.info("Progress: %s/%s files", completed, len(filtered))

        return 0

    if parser_backend == "tshark":
        _run_backfill_tshark(
            filtered,
            config,
            conn,
            False,
            args.progress_every,
            args.tshark_path,
            claim_statuses,
        )
    else:
        _run_backfill(
            filtered,
            config,
            conn,
            False,
            args.progress_every,
            deduplicate,
            claim_statuses,
        )
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
