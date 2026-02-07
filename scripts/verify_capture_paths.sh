#!/bin/bash
set -euo pipefail

CAP_DIR="${WICAP_CAPTURES_DIR:-./captures}"
BT_DIR="${WICAP_BT_CAPTURE_DIR:-./captures/bt}"

echo "🔍 Verifying capture paths..."

mkdir -p "$CAP_DIR" "$BT_DIR"

touch "$CAP_DIR/.wicap_write_test" 2>/dev/null || {
  echo "❌ Cannot write to capture dir: $CAP_DIR"
  exit 1
}
rm -f "$CAP_DIR/.wicap_write_test"

touch "$BT_DIR/.wicap_write_test" 2>/dev/null || {
  echo "❌ Cannot write to BLE capture dir: $BT_DIR"
  exit 1
}
rm -f "$BT_DIR/.wicap_write_test"

echo "✅ Capture paths OK: $CAP_DIR, $BT_DIR"
