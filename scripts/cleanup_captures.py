#!/usr/bin/env python3
"""
Retention script for WiFiWizard PCAP captures.

- Deletes oldest files when total size exceeds the cap or files exceed max age.
- Optionally gzip-compresses files before removal.
"""

import argparse
import gzip
import shutil
import time
from pathlib import Path

# ---- Configuration ----
MAX_GB = 5          # total size limit for captures directory
MAX_DAYS = 7        # maximum age of a PCAP before forced removal
COMPRESS = False    # set True to gzip-compress before deletion
# -----------------------

def _size_bytes(paths):
    total = 0
    for p in paths:
        try:
            total += p.stat().st_size
        except FileNotFoundError:
            continue
    return total

def _remove(p: Path, compress: bool, dry_run: bool) -> None:
    if dry_run:
        print(f"Would remove {p.name}")
        return
    if compress:
        gz = p.with_suffix(p.suffix + ".gz")
        with p.open("rb") as f_in, gzip.open(gz, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        p.unlink()
        print(f"Compressed & removed {p.name}")
    else:
        p.unlink()
        print(f"Removed {p.name}")

def _list_pcaps(capt_dir: Path):
    pcaps = [p for p in capt_dir.glob("dwell_*.pcapng") if p.is_file()]
    pcaps.sort(key=lambda p: p.stat().st_mtime)
    return pcaps

def _prune(capt_dir: Path, max_gb: float, max_days: int, compress: bool, dry_run: bool):
    pcaps = _list_pcaps(capt_dir)
    if not pcaps:
        return
    # Age-based removal
    cutoff = time.time() - max_days * 86400
    kept = []
    for p in pcaps:
        if p.stat().st_mtime < cutoff:
            _remove(p, compress, dry_run)
        else:
            kept.append(p)
    pcaps = kept
    # Size-based removal (oldest first)
    max_bytes = int(max_gb * 1024 ** 3)
    while _size_bytes(pcaps) > max_bytes and pcaps:
        _remove(pcaps.pop(0), compress, dry_run)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prune dwell PCAPs in captures/ by age and size")
    parser.add_argument("--dir", default="captures", help="Capture directory to prune")
    parser.add_argument("--max-gb", type=float, default=MAX_GB, help="Total size cap in GB")
    parser.add_argument("--max-days", type=int, default=MAX_DAYS, help="Max file age in days")
    parser.add_argument("--compress", action="store_true", default=COMPRESS, help="Gzip before removal")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without deleting")
    args = parser.parse_args()
    _prune(Path(args.dir), args.max_gb, args.max_days, args.compress, args.dry_run)
