#!/bin/bash
set -e

# Configuration
DURATION_MINUTES=${1:-60}  # Default 60 minutes
INTERVAL_SECONDS=300       # 5 minutes
LOG_DIR="logs_soak_$(date +%s)"
E2E_FAIL_LIMIT=${E2E_FAIL_LIMIT:-2}
BT_ACTIVITY_GRACE_MINUTES=${BT_ACTIVITY_GRACE_MINUTES:-15}

read_env_var() {
    local key="$1"
    if [ -f ".env" ]; then
        local line
        line=$(grep -E "^${key}=" .env | tail -n1)
        if [ -n "$line" ]; then
            echo "${line#${key}=}"
        fi
    fi
}

INTERFACE="${WICAP_INTERFACE:-$(read_env_var WICAP_INTERFACE)}"
INTERFACE_MAC="${WICAP_INTERFACE_MAC:-$(read_env_var WICAP_INTERFACE_MAC)}"
INTERFACE_REGEX="${WICAP_INTERFACE_REGEX:-$(read_env_var WICAP_INTERFACE_REGEX)}"
INTERFACE_EXCLUDE_REGEX="${WICAP_INTERFACE_EXCLUDE_REGEX:-$(read_env_var WICAP_INTERFACE_EXCLUDE_REGEX)}"

BT_ENABLED="${WICAP_BT_ENABLED:-$(read_env_var WICAP_BT_ENABLED)}"
BT_INTERFACE="${WICAP_BT_INTERFACE:-$(read_env_var WICAP_BT_INTERFACE)}"
BT_INTERFACE_GLOB="${WICAP_BT_INTERFACE_GLOB:-$(read_env_var WICAP_BT_INTERFACE_GLOB)}"
BT_SERIAL="${WICAP_BT_SERIAL:-$(read_env_var WICAP_BT_SERIAL)}"

is_truthy() {
    case "$1" in
        true|TRUE|1|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

resolve_wifi_interface() {
    local iface="$INTERFACE"
    local candidates=()
    local all_ifaces=()
    local addr

    if [ -n "$iface" ] && [ "$iface" != "auto" ]; then
        echo "$iface"
        return
    fi

    for path in /sys/class/net/*; do
        local name
        name=$(basename "$path")
        [ "$name" = "lo" ] && continue
        [ -n "$INTERFACE_EXCLUDE_REGEX" ] && echo "$name" | grep -Eq "$INTERFACE_EXCLUDE_REGEX" && continue
        all_ifaces+=("$name")
        if [ -d "$path/wireless" ]; then
            candidates+=("$name")
        fi
    done

    # Prefer wireless candidates
    if [ ${#candidates[@]} -eq 0 ]; then
        candidates=("${all_ifaces[@]}")
    fi

    if [ -n "$INTERFACE_MAC" ]; then
        local target
        target=$(echo "$INTERFACE_MAC" | tr '[:upper:]' '[:lower:]')
        for name in "${candidates[@]}"; do
            addr=$(cat "/sys/class/net/$name/address" 2>/dev/null | tr '[:upper:]' '[:lower:]')
            if [ "$addr" = "$target" ]; then
                echo "$name"
                return
            fi
        done
        echo ""
        return
    fi

    if [ -n "$INTERFACE_REGEX" ]; then
        for name in "${candidates[@]}"; do
            if echo "$name" | grep -Eq "$INTERFACE_REGEX"; then
                echo "$name"
                return
            fi
        done
        echo ""
        return
    fi

    if [ ${#candidates[@]} -eq 1 ]; then
        echo "${candidates[0]}"
        return
    fi

    echo ""
}

resolve_bt_interface() {
    local iface="$BT_INTERFACE"

    if [ -n "$iface" ] && [ "$iface" != "auto" ]; then
        echo "$iface"
        return
    fi

    shopt -s nullglob

    if [ -n "$BT_INTERFACE_GLOB" ]; then
        local matches=($BT_INTERFACE_GLOB)
        if [ ${#matches[@]} -eq 1 ]; then
            echo "${matches[0]}"
            return
        fi
        echo ""
        return
    fi

    if [ -n "$BT_SERIAL" ]; then
        local matches=(/dev/serial/by-id/*"$BT_SERIAL"*)
        if [ ${#matches[@]} -eq 1 ]; then
            echo "${matches[0]}"
            return
        fi
        echo ""
        return
    fi

    local nrf_matches=()
    for path in /dev/serial/by-id/*; do
        if echo "$path" | grep -Ei -q "nrf|nordic"; then
            nrf_matches+=("$path")
        fi
    done
    if [ ${#nrf_matches[@]} -eq 1 ]; then
        echo "${nrf_matches[0]}"
        return
    fi

    local by_id_matches=(/dev/serial/by-id/*)
    if [ ${#by_id_matches[@]} -eq 1 ]; then
        echo "${by_id_matches[0]}"
        return
    fi

    local acm_matches=(/dev/ttyACM*)
    if [ ${#acm_matches[@]} -eq 1 ]; then
        echo "${acm_matches[0]}"
        return
    fi

    echo ""
}

WIFI_AUTO_REQUESTED=false
if [ -z "$INTERFACE" ] || [ "$INTERFACE" = "auto" ] || [ -n "$INTERFACE_MAC" ] || [ -n "$INTERFACE_REGEX" ]; then
    WIFI_AUTO_REQUESTED=true
fi

BT_AUTO_REQUESTED=false
if [ -z "$BT_INTERFACE" ] || [ "$BT_INTERFACE" = "auto" ] || [ -n "$BT_INTERFACE_GLOB" ] || [ -n "$BT_SERIAL" ]; then
    BT_AUTO_REQUESTED=true
fi

INTERFACE=$(resolve_wifi_interface)
BT_INTERFACE=$(resolve_bt_interface)

if [ -z "$BT_ENABLED" ] && [ -n "$BT_INTERFACE" ] && [ "$BT_AUTO_REQUESTED" = "true" ]; then
    BT_ENABLED="true"
    echo "Auto-enabling Bluetooth capture because interface ${BT_INTERFACE} resolved."
fi

if [ "$WIFI_AUTO_REQUESTED" = "true" ] && [ -z "$INTERFACE" ]; then
    echo "❌ Unable to resolve Wi-Fi interface. Set WICAP_INTERFACE or WICAP_INTERFACE_MAC/REGEX."
    exit 1
fi

if [ "$BT_AUTO_REQUESTED" = "true" ] && [ -z "$BT_INTERFACE" ] && is_truthy "$BT_ENABLED"; then
    echo "❌ Unable to resolve Bluetooth device. Set WICAP_BT_INTERFACE or WICAP_BT_INTERFACE_GLOB/SERIAL."
    exit 1
fi

# Defaults (only when auto not requested)
INTERFACE="${INTERFACE:-wlan1}"
BT_INTERFACE="${BT_INTERFACE:-/dev/ttyACM0}"
mkdir -p "$LOG_DIR"
E2E_FAIL_COUNT=0

echo "========================================================"
echo "Starting WICAP Docker Soak Test"
echo "Duration: $DURATION_MINUTES minutes"
echo "Queue:    Redis (wicap-redis)"
echo "Workers:  2 (Replicas)"
echo "Interface: $INTERFACE"
echo "Bluetooth: ${BT_ENABLED:-false} (${BT_INTERFACE})"
echo "Logs:     $LOG_DIR"
echo "========================================================"

# Validate interface exists early
if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "❌ Interface '$INTERFACE' not found. Set WICAP_INTERFACE in .env."
    exit 1
fi

# Validate Bluetooth device if enabled
if is_truthy "$BT_ENABLED"; then
    if [ ! -e "$BT_INTERFACE" ]; then
        echo "❌ Bluetooth device '$BT_INTERFACE' not found. Set WICAP_BT_INTERFACE in .env."
        exit 1
    fi
fi

# Export resolved values for docker compose substitution
export WICAP_INTERFACE="$INTERFACE"
export WICAP_BT_ENABLED="${BT_ENABLED:-false}"
export WICAP_BT_INTERFACE="$BT_INTERFACE"

# Cleanup Function
cleanup() {
    echo "Stopping Docker stack..."
    docker compose down || true
    
    # Cleanup Interface (Force reset to managed mode)
    echo "Resetting WiFi interface ${INTERFACE}..."
    if sudo -n true 2>/dev/null; then
        sudo -n ip link set "${INTERFACE}" down 2>/dev/null || true
        sudo -n iw dev "${INTERFACE}" set type managed 2>/dev/null || true
        sudo -n ip link set "${INTERFACE}" up 2>/dev/null || true
    else
        echo "⚠️  Skipping WiFi reset (sudo requires a password in this environment)."
    fi
    
    echo "Soak test finished."
}
trap cleanup EXIT

# 1. Build and Start
echo "[1/4] Pre-cleanup and Build..."
# Force remove potential conflicting containers
docker rm -f wicap-ui wicap-scout wicap-processor-1 wicap-processor-2 2>/dev/null || true
docker compose down --remove-orphans 2>/dev/null || true
rm -f captures/wifiwizard.pid 2>/dev/null || true

# Ensure wicap-base is available if needed (skip if present)
# docker build -t wicap-base:latest -f docker/base.Dockerfile . 

docker compose up -d --build

echo "Waiting 10s for services to stabilize..."
sleep 10

# 2. Check Health
echo "[2/4] Verifying initial health..."
READY=0
for _ in $(seq 1 24); do
    if curl -sSf http://localhost:8080/api/system/status > /dev/null; then
        READY=1
        break
    fi
    sleep 5
done

if [ "$READY" -ne 1 ]; then
    echo "ERROR: UI not reachable at start (after readiness retries)."
    docker compose logs
    exit 1
fi

echo "Validating Bluetooth API contract..."
BT_PAYLOAD=$(curl -sS http://localhost:8080/api/devices/bluetooth || true)
if [ -z "$BT_PAYLOAD" ]; then
    echo "ERROR: /api/devices/bluetooth returned an empty payload."
    docker compose logs --tail 80
    exit 1
fi

if is_truthy "$WICAP_BT_ENABLED"; then
    echo "Bluetooth capture is enabled; soak will require non-zero BT observations after ${BT_ACTIVITY_GRACE_MINUTES}m grace period."
fi
if ! python3 - "$BT_PAYLOAD" <<'PY'
import json
import sys

try:
    payload = json.loads(sys.argv[1])
except Exception as exc:  # pragma: no cover - shell contract check
    raise SystemExit(f"invalid JSON payload: {exc}") from exc

if not isinstance(payload, dict):
    raise SystemExit("payload must be an object")

for key in ("stats", "devices"):
    if key not in payload:
        raise SystemExit(f"missing top-level key: {key}")

devices = payload.get("devices")
if not isinstance(devices, list):
    raise SystemExit("'devices' must be a list")

if devices:
    required = {
        "confidence_score",
        "confidence_tier",
        "why_matters",
        "is_randomized",
        "service_unknown_count",
        "behavior_label",
        "behavior_summary",
        "dwell_minutes",
        "observation_rate_per_hour",
        "rotation_risk_score",
        "rotation_cluster_size",
        "rotation_peer_count",
        "rotation_suspected",
        "rotation_correlation_score",
        "rotation_summary",
        "recurrence_label",
        "recurrence_score",
        "recurrence_summary",
        "recurrence_handoff_count",
        "recurrence_peer_presence_ratio",
    }
    sample = devices[0]
    missing = sorted(k for k in required if k not in sample)
    if missing:
        raise SystemExit("missing Bluetooth contract keys: " + ", ".join(missing))

print("Bluetooth API contract check passed.")
PY
then
    echo "ERROR: Bluetooth API contract validation failed."
    docker compose logs --tail 80
    exit 1
fi

echo "System reachable. Workers running:"
docker compose ps

# 3. Soak Loop
START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION_MINUTES * 60))

echo "[3/4] Entering soak loop..."
ITERATION=1

while [ $(date +%s) -lt $END_TIME ]; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    REMAINING=$((END_TIME - CURRENT_TIME))
    
    echo "--- Iteration $ITERATION (Elapsed: ${ELAPSED}s, Remaining: ${REMAINING}s) ---"
    
    # Run Playwright E2E Tests
    echo "Running Playwright E2E check (core + bluetooth)..."
    if WICAP_UI_URL=http://localhost:8080 pytest tests/test_e2e_ui.py tests/test_bluetooth_ui.py -m e2e -v > "$LOG_DIR/pytest_iter_${ITERATION}.log" 2>&1; then
        echo "✅ E2E Tests Passed"
        E2E_FAIL_COUNT=0
    else
        echo "❌ E2E Tests Failed! See $LOG_DIR/pytest_iter_${ITERATION}.log"
        E2E_FAIL_COUNT=$((E2E_FAIL_COUNT + 1))
        # Optional: capture logs on failure
        docker compose logs --tail 50 > "$LOG_DIR/docker_fail_iter_${ITERATION}.log"
        if [ "$E2E_FAIL_COUNT" -ge "$E2E_FAIL_LIMIT" ]; then
            echo "ERROR: E2E failed ${E2E_FAIL_COUNT} consecutive iterations (limit=${E2E_FAIL_LIMIT}). Aborting soak."
            exit 1
        fi
    fi
    
    # Check for container errors
    ERROR_COUNT=$(docker compose logs --since 5m | grep "ERROR" | wc -l)
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "⚠️  WARNING: $ERROR_COUNT errors detected in Docker logs in last 5m."
    else
        echo "✅ Logs clean (no new errors)."
    fi

    # API Status Check
    STATUS=$(curl -s http://localhost:8080/api/system/status)
    CURRENT_EPS=$(echo "$STATUS" | grep -o '"eps":\s*[0-9.]*' | sed 's/.*://' | tr -d ' ' || echo "N/A")
    echo "Current EPS: $CURRENT_EPS"

    STATS_BODY="$LOG_DIR/stats_iter_${ITERATION}.json"
    STATS_HTTP=$(curl -sS -o "$STATS_BODY" -w "%{http_code}" http://localhost:8080/api/stats || true)
    if [ "$STATS_HTTP" != "200" ]; then
        echo "ERROR: /api/stats returned HTTP ${STATS_HTTP}."
        docker compose logs --tail 80 > "$LOG_DIR/docker_stats_error_iter_${ITERATION}.log"
        exit 1
    fi

    if is_truthy "$WICAP_BT_ENABLED"; then
        BT_BODY="$LOG_DIR/bluetooth_iter_${ITERATION}.json"
        BT_HTTP=$(curl -sS -o "$BT_BODY" -w "%{http_code}" http://localhost:8080/api/devices/bluetooth || true)
        if [ "$BT_HTTP" != "200" ]; then
            echo "ERROR: /api/devices/bluetooth returned HTTP ${BT_HTTP}."
            docker compose logs --tail 120 > "$LOG_DIR/docker_bluetooth_error_iter_${ITERATION}.log"
            exit 1
        fi
        BT_PAYLOAD=$(cat "$BT_BODY")
        BT_COUNTS=$(python3 - "$BT_PAYLOAD" <<'PY'
import json
import sys

payload = {}
try:
    payload = json.loads(sys.argv[1] if len(sys.argv) > 1 else "{}")
except Exception:
    print("-1 -1")
    raise SystemExit(0)

stats = payload.get("stats") or {}
devices = stats.get("total_devices", 0)
obs = stats.get("total_observations", 0)
try:
    print(f"{int(devices)} {int(obs)}")
except Exception:
    print("-1 -1")
PY
)
        BT_DEVICE_COUNT=$(echo "$BT_COUNTS" | awk '{print $1}')
        BT_OBS_COUNT=$(echo "$BT_COUNTS" | awk '{print $2}')
        echo "Bluetooth stats: devices=${BT_DEVICE_COUNT} observations=${BT_OBS_COUNT}"
        if [ "$BT_DEVICE_COUNT" -lt 0 ] || [ "$BT_OBS_COUNT" -lt 0 ]; then
            echo "ERROR: /api/devices/bluetooth returned invalid JSON."
            echo "$BT_PAYLOAD" > "$LOG_DIR/bluetooth_error_iter_${ITERATION}.json"
            exit 1
        fi
        if [ "$ELAPSED" -ge $((BT_ACTIVITY_GRACE_MINUTES * 60)) ] && [ "$BT_OBS_COUNT" -eq 0 ]; then
            echo "ERROR: Bluetooth observations still zero after grace period."
            echo "$BT_PAYLOAD" > "$LOG_DIR/bluetooth_zero_iter_${ITERATION}.json"
            docker compose logs --tail 120 > "$LOG_DIR/docker_bluetooth_zero_iter_${ITERATION}.log"
            exit 1
        fi
    fi

    ITERATION=$((ITERATION+1))
    
    # Wait for interval or end
    if [ "$REMAINING" -gt "$INTERVAL_SECONDS" ]; then
        echo "Sleeping for $INTERVAL_SECONDS seconds..."
        sleep "$INTERVAL_SECONDS"
    else
        echo "Final sleep for remaining $REMAINING seconds..."
        sleep "$REMAINING"
    fi
done

echo "[4/4] Soak test completed."
