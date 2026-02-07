"""
Network baseline + drift detection support.

Builds a 30-day baseline for SSIDs/BSSIDs/security posture and persists a
snapshot for WIDS to compare against during live capture.
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from nexus.config import NexusConfig, get_nexus_config
from nexus.utils import json_compat

logger = logging.getLogger("nexus.intel.network_baseline")


def _default_baseline_path() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    default_dir = repo_root / "captures" / "network_baselines"
    default_path = default_dir / "network_baseline_global.json"
    env_path = os.getenv("WICAP_NETWORK_BASELINE_PATH")
    return Path(env_path) if env_path else default_path


def _normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().upper()


def _encryption_label(
    *,
    is_open: bool | None = None,
    has_wep: bool | None = None,
    has_wpa: bool | None = None,
    has_wpa2: bool | None = None,
    has_wpa3: bool | None = None,
) -> str:
    if has_wpa3:
        return "WPA3"
    if has_wpa2:
        return "WPA2"
    if has_wpa:
        return "WPA"
    if has_wep:
        return "WEP"
    if is_open:
        return "Open"
    return "Unknown"


@dataclass
class NetworkBaselineSnapshot:
    scope: str
    horizon_days: int
    since_ts: float
    until_ts: float
    updated_at: float
    ssid_bssids: dict[str, list[str]]
    bssid_security: dict[str, str]
    bssid_channel: dict[str, int]
    bssid_ssid: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "horizon_days": self.horizon_days,
            "since_ts": self.since_ts,
            "until_ts": self.until_ts,
            "updated_at": self.updated_at,
            "ssid_bssids": self.ssid_bssids,
            "bssid_security": self.bssid_security,
            "bssid_channel": self.bssid_channel,
            "bssid_ssid": self.bssid_ssid,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkBaselineSnapshot:
        return cls(
            scope=data.get("scope", "global"),
            horizon_days=int(data.get("horizon_days", 30)),
            since_ts=float(data.get("since_ts", 0.0)),
            until_ts=float(data.get("until_ts", 0.0)),
            updated_at=float(data.get("updated_at", 0.0)),
            ssid_bssids=dict(data.get("ssid_bssids", {})),
            bssid_security=dict(data.get("bssid_security", {})),
            bssid_channel={k: int(v) for k, v in (data.get("bssid_channel", {}) or {}).items()},
            bssid_ssid=dict(data.get("bssid_ssid", {})),
        )

    @property
    def total_ssids(self) -> int:
        return len(self.ssid_bssids)

    @property
    def total_bssids(self) -> int:
        return len(self.bssid_security) or len(self.bssid_channel) or len(self.bssid_ssid)


class NetworkBaselineStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else _default_baseline_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, snapshot: NetworkBaselineSnapshot) -> Path:
        with open(self.path, "w") as handle:
            handle.write(json_compat.dumps(snapshot.to_dict(), separators=(",", ":")))
        return self.path

    def load(self) -> NetworkBaselineSnapshot | None:
        if not self.path.exists():
            return None
        try:
            with open(self.path) as handle:
                return NetworkBaselineSnapshot.from_dict(json_compat.loads(handle.read()))
        except Exception as exc:
            logger.warning(f"Failed to load network baseline: {exc}")
            return None


def load_network_baseline(path: Path | None = None) -> NetworkBaselineSnapshot | None:
    return NetworkBaselineStore(path).load()


def build_network_baseline(
    config: NexusConfig | None = None,
    *,
    horizon_days: int = 30,
) -> NetworkBaselineSnapshot:
    config = config or get_nexus_config()
    try:
        import pyodbc
    except Exception as exc:
        raise RuntimeError("pyodbc is required to build network baselines") from exc

    now_ts = time.time()
    since_ts = now_ts - (horizon_days * 86400.0)
    since_dt = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=horizon_days)

    ssid_bssids: dict[str, set[str]] = {}
    bssid_ssid: dict[str, str] = {}

    conn = pyodbc.connect(config.get_sql_connection_string())
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT payload_effective_ssid, payload_effective_bssid
            FROM curated_events
            WHERE ts_epoch >= ?
              AND payload_effective_ssid IS NOT NULL
              AND payload_effective_bssid IS NOT NULL
            """,
            (since_ts,),
        )
        for row in cursor.fetchall():
            ssid = row[0]
            bssid = _normalize_mac(row[1])
            if not ssid or not bssid:
                continue
            ssid_bssids.setdefault(ssid, set()).add(bssid)
            if bssid not in bssid_ssid:
                bssid_ssid[bssid] = ssid

        bssid_security: dict[str, str] = {}
        bssid_channel: dict[str, int] = {}

        cursor.execute(
            """
            SELECT bssid, ssid, is_open, has_wep, has_wpa, has_wpa2, has_wpa3, channel
            FROM security_posture
            WHERE last_seen >= ?
            """,
            (since_dt,),
        )
        for row in cursor.fetchall():
            bssid = _normalize_mac(row[0])
            if not bssid:
                continue
            enc = _encryption_label(
                is_open=bool(row[2]) if row[2] is not None else None,
                has_wep=bool(row[3]) if row[3] is not None else None,
                has_wpa=bool(row[4]) if row[4] is not None else None,
                has_wpa2=bool(row[5]) if row[5] is not None else None,
                has_wpa3=bool(row[6]) if row[6] is not None else None,
            )
            bssid_security[bssid] = enc
            channel = row[7]
            if channel is not None:
                try:
                    bssid_channel[bssid] = int(channel)
                except (TypeError, ValueError):
                    pass
            ssid = row[1]
            if ssid and bssid not in bssid_ssid:
                bssid_ssid[bssid] = ssid

        cursor.execute(
            """
            SELECT payload_effective_bssid, channel, COUNT(*) as cnt
            FROM curated_events
            WHERE ts_epoch >= ?
              AND payload_effective_bssid IS NOT NULL
              AND channel IS NOT NULL
            GROUP BY payload_effective_bssid, channel
            """,
            (since_ts,),
        )
        channel_counts: dict[str, dict[int, int]] = {}
        for row in cursor.fetchall():
            bssid = _normalize_mac(row[0])
            if not bssid:
                continue
            try:
                channel = int(row[1])
            except (TypeError, ValueError):
                continue
            count = int(row[2] or 0)
            channel_counts.setdefault(bssid, {})[channel] = count

        for bssid, channels in channel_counts.items():
            if bssid in bssid_channel:
                continue
            if channels:
                best_channel = max(channels.items(), key=lambda item: item[1])[0]
                bssid_channel[bssid] = int(best_channel)

        snapshot = NetworkBaselineSnapshot(
            scope="global",
            horizon_days=horizon_days,
            since_ts=since_ts,
            until_ts=now_ts,
            updated_at=now_ts,
            ssid_bssids={k: sorted(v) for k, v in ssid_bssids.items()},
            bssid_security=bssid_security,
            bssid_channel=bssid_channel,
            bssid_ssid=bssid_ssid,
        )
        return snapshot
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _parse_days(value: str) -> int:
    value = value.strip().lower()
    if value.endswith("d"):
        value = value[:-1]
    return int(float(value))


def _cmd_refresh(args: argparse.Namespace) -> int:
    horizon_days = _parse_days(args.since)
    snapshot = build_network_baseline(horizon_days=horizon_days)
    store = NetworkBaselineStore(Path(args.output) if args.output else None)
    path = store.save(snapshot)
    logger.info(
        "Network baseline saved: %s (ssids=%d, bssids=%d, horizon=%dd)",
        path,
        snapshot.total_ssids,
        snapshot.total_bssids,
        snapshot.horizon_days,
    )
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    store = NetworkBaselineStore(Path(args.path) if args.path else None)
    snapshot = store.load()
    if not snapshot:
        raise SystemExit("No baseline snapshot found.")
    print("Network baseline report")
    print(f"  Path: {store.path}")
    print(f"  Horizon: {snapshot.horizon_days}d")
    print(f"  SSIDs: {snapshot.total_ssids}")
    print(f"  BSSIDs: {snapshot.total_bssids}")
    print(f"  Updated: {datetime.fromtimestamp(snapshot.updated_at, tz=timezone.utc)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Network baseline builder")
    subparsers = parser.add_subparsers(dest="command")

    refresh = subparsers.add_parser("refresh", help="Refresh baseline snapshot from SQL")
    refresh.add_argument("--since", default="30d", help="Baseline window (e.g., 30d)")
    refresh.add_argument("--output", help="Override output path")
    refresh.set_defaults(func=_cmd_refresh)

    report = subparsers.add_parser("report", help="Report current baseline snapshot")
    report.add_argument("--path", help="Baseline snapshot path")
    report.set_defaults(func=_cmd_report)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
