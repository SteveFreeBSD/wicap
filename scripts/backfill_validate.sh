#!/bin/bash
# =============================================================================
# WICAP Backfill Validation - Run After Completion
# =============================================================================

set -e
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

echo "=== Backfill Validation ==="
echo "Time: $(date)"
echo ""

python3 - <<'PY'
import pyodbc
from nexus.config import get_nexus_config

cfg = get_nexus_config()
conn = pyodbc.connect(cfg.get_sql_connection_string())
cur = conn.cursor()

print("=== pcap_index Status ===")
cur.execute("SELECT processing_status, COUNT(*) FROM pcap_index GROUP BY processing_status")
for row in cur.fetchall():
    print(f"  {row[0] or 'NULL'}: {row[1]}")

print("\n=== Error Summary ===")
cur.execute("""
    SELECT TOP 5 processing_error, COUNT(*) as cnt
    FROM pcap_index
    WHERE processing_status = 'error'
    GROUP BY processing_error
    ORDER BY cnt DESC
""")
errors = cur.fetchall()
if errors:
    for row in errors:
        print(f"  [{row[1]}x] {row[0][:80] if row[0] else 'NULL'}...")
else:
    print("  No errors!")

print("\n=== Association Stats ===")
cur.execute("SELECT COUNT(*) FROM client_associations")
print(f"  Total associations: {cur.fetchone()[0]}")

cur.execute("SELECT COUNT(DISTINCT client_mac) FROM client_associations")
print(f"  Unique clients: {cur.fetchone()[0]}")

cur.execute("SELECT COUNT(DISTINCT bssid) FROM client_associations")
print(f"  Unique BSSIDs: {cur.fetchone()[0]}")

print("\n=== RSSI Stats ===")
cur.execute("SELECT COUNT(*) FROM client_profiles WHERE rssi_sample_count > 0")
print(f"  Profiles with RSSI: {cur.fetchone()[0]}")

cur.execute("SELECT AVG(rssi_sample_count), MAX(rssi_sample_count) FROM client_profiles WHERE rssi_sample_count > 0")
row = cur.fetchone()
print(f"  Avg samples/profile: {row[0]:.1f}" if row[0] else "  Avg samples/profile: N/A")
print(f"  Max samples: {row[1]}" if row[1] else "  Max samples: N/A")

print("\n=== Top Associations by Count ===")
cur.execute("""
    SELECT TOP 5 client_mac, bssid, association_count
    FROM client_associations
    ORDER BY association_count DESC
""")
for row in cur.fetchall():
    print(f"  {row[0]} → {row[1]}: {row[2]}")

print("\n=== Validation Complete ===")
PY
