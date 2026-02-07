#!/usr/bin/env python3
"""
Lightweight performance benchmarks for WICAP.

Usage examples:
  python3 scripts/perf_bench.py --pcap captures/dwell_*.pcapng --parser tshark
  python3 scripts/perf_bench.py --pcap tests/fixtures/pcap/mixed_traffic_ch2.pcapng --parser scapy
  python3 scripts/perf_bench.py --db --rows 10000
"""

import argparse
import shutil
import subprocess
import time
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WICAP performance benchmark tool")
    parser.add_argument("--pcap", type=Path, help="PCAP/PCAPNG file to parse")
    parser.add_argument("--parser", choices=("tshark", "scapy"), default="tshark")
    parser.add_argument("--tshark-path", default="tshark", help="Path to tshark binary")
    parser.add_argument("--db", action="store_true", help="Run DB insert benchmark")
    parser.add_argument("--rows", type=int, default=10000, help="Row count for DB benchmark")
    parser.add_argument("--repeat", type=int, default=1, help="Number of times to repeat benchmarks")
    return parser.parse_args()


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


def _bench_tshark(pcap_path: Path, tshark_path: str) -> dict | None:
    if shutil.which(tshark_path) is None:
        print("tshark not found; skipping tshark benchmark")
        return None

    to_ds_field, from_ds_field = _select_tshark_fields(tshark_path)
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

    start = time.perf_counter()
    line_count = 0
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if not proc.stdout or not proc.stderr:
        proc.kill()
        print("Failed to open tshark output streams")
        return None
    try:
        for _ in proc.stdout:
            line_count += 1
    finally:
        stderr = proc.stderr.read()
        ret = proc.wait()
    if ret != 0:
        print(f"tshark failed: {stderr.strip()}")
        return None

    elapsed = time.perf_counter() - start
    return {
        "backend": "tshark",
        "lines": line_count,
        "elapsed_sec": elapsed,
        "lines_per_sec": line_count / elapsed if elapsed > 0 else 0,
    }


def _bench_scapy(pcap_path: Path) -> dict | None:
    try:
        from scapy.utils import PcapNgReader, PcapReader
    except Exception:
        print("Scapy not available; skipping scapy benchmark")
        return None

    reader_cls = PcapNgReader if pcap_path.suffix.lower() == ".pcapng" else PcapReader
    start = time.perf_counter()
    packet_count = 0
    with reader_cls(str(pcap_path)) as reader:
        for _ in reader:
            packet_count += 1
    elapsed = time.perf_counter() - start
    return {
        "backend": "scapy",
        "packets": packet_count,
        "elapsed_sec": elapsed,
        "packets_per_sec": packet_count / elapsed if elapsed > 0 else 0,
    }


def _bench_db(rows: int) -> dict | None:
    try:
        import pyodbc
    except ImportError:
        print("pyodbc not available; skipping DB benchmark")
        return None

    from nexus.config import get_nexus_config

    cfg = get_nexus_config()
    conn = pyodbc.connect(cfg.get_sql_connection_string())
    cursor = conn.cursor()
    cursor.execute("IF OBJECT_ID('tempdb..#PerfBench') IS NOT NULL DROP TABLE #PerfBench;")
    cursor.execute("CREATE TABLE #PerfBench (id INT NOT NULL, value NVARCHAR(64) NOT NULL);")
    conn.commit()

    payload = [(i, f"value_{i}") for i in range(rows)]
    cursor.fast_executemany = True

    start = time.perf_counter()
    cursor.executemany("INSERT INTO #PerfBench (id, value) VALUES (?, ?)", payload)
    conn.commit()
    elapsed = time.perf_counter() - start

    return {
        "backend": "db",
        "rows": rows,
        "elapsed_sec": elapsed,
        "rows_per_sec": rows / elapsed if elapsed > 0 else 0,
    }


def _print_result(result: dict) -> None:
    if result["backend"] == "tshark":
        print(
            f"tshark: {result['lines']} lines in {result['elapsed_sec']:.2f}s "
            f"({result['lines_per_sec']:.0f} lines/sec)"
        )
    elif result["backend"] == "scapy":
        print(
            f"scapy: {result['packets']} packets in {result['elapsed_sec']:.2f}s "
            f"({result['packets_per_sec']:.0f} pkt/sec)"
        )
    elif result["backend"] == "db":
        print(
            f"db: {result['rows']} rows in {result['elapsed_sec']:.2f}s "
            f"({result['rows_per_sec']:.0f} rows/sec)"
        )


def main() -> int:
    args = _parse_args()

    if not args.pcap and not args.db:
        print("Nothing to do. Provide --pcap and/or --db.")
        return 1

    for _ in range(args.repeat):
        if args.pcap:
            if not args.pcap.exists():
                print(f"PCAP not found: {args.pcap}")
                return 1
            if args.parser == "tshark":
                result = _bench_tshark(args.pcap, args.tshark_path)
            else:
                result = _bench_scapy(args.pcap)
            if result:
                _print_result(result)
        if args.db:
            result = _bench_db(args.rows)
            if result:
                _print_result(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
