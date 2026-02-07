#!/bin/bash
set -e

# WICAP One-Click Live Soak Runner
# Usage: sudo ./scripts/run_soak.sh [DURATION_MINUTES] [--detach]
#
# Examples:
#   sudo ./scripts/run_soak.sh 30           # 30-min soak, attached
#   sudo ./scripts/run_soak.sh 480 --detach # 8-hour soak, detached (nohup)

# 1. Parse arguments
DETACH=false
DURATION=30

for arg in "$@"; do
    case $arg in
        --detach|-d)
            DETACH=true
            ;;
        [0-9]*)
            DURATION=$arg
            ;;
    esac
done

# 2. Check for Root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (needed for Docker & WiFi control):"
  echo "   sudo $0 $@"
  exit 1
fi

# 3. Configuration - export explicitly
export WICAP_SOAK_DURATION_MINUTES="$DURATION"
export WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES="${WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES:-15}"

# Calculate expected end time
END_TIME=$(date -d "+${DURATION} minutes" "+%Y-%m-%d %H:%M")

echo "============================================================"
echo "🌊 WICAP Live Soak Launcher"
echo "============================================================"
echo "Duration:       ${WICAP_SOAK_DURATION_MINUTES} min"
echo "UI Check Interval: ${WICAP_SOAK_PLAYWRIGHT_INTERVAL_MINUTES} min"
echo "Expected End:   ${END_TIME}"
echo "Detached Mode:  ${DETACH}"
echo "User:           ${SUDO_USER:-root}"
echo "============================================================"

# 4. Detect Playwright Browser Cache (Offline Support)
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    CANDIDATE_PATH="$USER_HOME/.cache/ms-playwright"
    if [ -d "$CANDIDATE_PATH" ]; then
        echo "✅ Detected user browser cache: $CANDIDATE_PATH"
        export PLAYWRIGHT_BROWSERS_PATH="$CANDIDATE_PATH"
    fi
fi

# 5. Locate venv
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "⚠️ Virtualenv not found at $VENV_PYTHON"
    echo "🛠️ Auto-fixing: Creating venv and installing dependencies..."
    
    if [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" python3 -m venv "$PROJECT_ROOT/.venv"
        sudo -u "$SUDO_USER" "$VENV_PYTHON" -m pip install -r "$PROJECT_ROOT/requirements.txt"
        sudo -u "$SUDO_USER" "$VENV_PYTHON" -m pip install -r "$PROJECT_ROOT/wicap-ui/requirements.txt"
    else
        python3 -m venv "$PROJECT_ROOT/.venv"
        "$VENV_PYTHON" -m pip install -r "$PROJECT_ROOT/requirements.txt"
        "$VENV_PYTHON" -m pip install -r "$PROJECT_ROOT/wicap-ui/requirements.txt"
    fi
    echo "✅ Environment created."
fi

cd "$PROJECT_ROOT"

# 6. Preflight
echo "🧭 Running soak preflight..."
SOAK_ENV="$("$VENV_PYTHON" scripts/soak_preflight.py --print-env)"
if [ -z "$SOAK_ENV" ]; then
    echo "❌ Soak preflight failed (no env overrides)."
    exit 1
fi
eval "$SOAK_ENV"
export WICAP_SOAK_PREFLIGHT_DONE=1

"$PROJECT_ROOT/scripts/verify_capture_paths.sh"
if [ "${WICAP_BT_ENABLED:-false}" = "true" ]; then
    "$PROJECT_ROOT/scripts/bt_preflight.sh"
fi

# 7. Define log file
LOG_DIR="$PROJECT_ROOT/logs/soak"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/soak_${DURATION}m_${TIMESTAMP}.log"

# 8. Run the soak
echo "🚀 Launching soak test runner..."
echo "📝 Log file: $LOG_FILE"

if [ "$DETACH" = true ]; then
    echo ""
    echo "🔓 DETACHED MODE: Soak will run in background."
    echo "   To monitor:  tail -f $LOG_FILE"
    echo "   To check:    docker ps | grep wicap"
    echo "   Expected completion: $END_TIME"
    echo ""
    
    # Use nohup to detach from terminal
    nohup "$VENV_PYTHON" scripts/run_live_soak.py > "$LOG_FILE" 2>&1 &
    SOAK_PID=$!
    echo "$SOAK_PID" > "$PROJECT_ROOT/.soak.pid"
    echo "✅ Soak started in background (PID: $SOAK_PID)"
    echo "   PID file: $PROJECT_ROOT/.soak.pid"
else
    # Run attached, output to both console and log
    exec "$VENV_PYTHON" scripts/run_live_soak.py 2>&1 | tee "$LOG_FILE"
fi
