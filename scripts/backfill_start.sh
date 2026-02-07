#!/bin/bash
# =============================================================================
# WICAP Full Historical Backfill - Overnight Run
# =============================================================================
# Duration: ~2-4 hours for ~7,900 PCAPs (with optimizations)
# Best run overnight or during low-activity periods
#
# Prerequisites:
# - Commit 70062c9 or later (batch persistence + --no-dedupe)
# - SQL Server accessible
# - No active Scout/DwellWatcher processes

set -e
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

# =============================================================================
# STEP 1: Pre-flight checks
# =============================================================================
echo "=== Pre-flight Checks ==="

# Ensure no capture processes running
pkill -f start_wicap 2>/dev/null || true
pkill -f "nexus.watcher" 2>/dev/null || true
echo "✓ Capture processes stopped"

# Check pending file count
python3 - <<'PY'
import pyodbc
from nexus.config import get_nexus_config
cfg = get_nexus_config()
conn = pyodbc.connect(cfg.get_sql_connection_string())
cur = conn.cursor()

cur.execute("SELECT processing_status, COUNT(*) FROM pcap_index GROUP BY processing_status")
print("\n=== pcap_index Status ===")
for row in cur.fetchall():
    print(f"  {row[0] or 'NULL'}: {row[1]}")

cur.execute("SELECT COUNT(*) FROM pcap_index WHERE processing_status IS NULL OR processing_status = 'pending'")
pending = cur.fetchone()[0]
print(f"\nTotal pending: {pending}")
print(f"Estimated time: {pending * 5.6 / 60:.1f} minutes ({pending * 5.6 / 3600:.1f} hours)")
PY

# =============================================================================
# STEP 2: Start backfill (nohup for overnight)
# =============================================================================
echo ""
echo "=== Starting Backfill ==="
echo "Log: logs/backfill_full.log"
echo "Start time: $(date)"

nohup python scripts/mine_pcaps.py \
    --all \
    --resume \
    --batch 100 \
    --no-dedupe \
    > logs/backfill_full.log 2>&1 &

BACKFILL_PID=$!
echo "Backfill PID: $BACKFILL_PID"
echo $BACKFILL_PID > logs/backfill.pid

echo ""
echo "=== Backfill Running ==="
echo "Monitor with: tail -f logs/backfill_full.log"
echo "Check status: ps aux | grep mine_pcaps"
echo ""
echo "Run 'bash scripts/backfill_validate.sh' after completion to verify results."
