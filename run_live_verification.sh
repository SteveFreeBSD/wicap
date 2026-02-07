#!/bin/bash
set -e

# Configuration
LOG_DIR="logs_verification_$(date +%s)"
mkdir -p "$LOG_DIR"
echo "Starting Live Verification Run. Logs in $LOG_DIR"

# Cleanup function
cleanup() {
    echo "Stopping services..."
    # Intentionally ignoring errors during cleanup
    sudo pkill -f start_wicap.py >/dev/null 2>&1 || true
    sudo pkill -f scout.py >/dev/null 2>&1 || true
    sudo pkill -f "uvicorn wicap-ui.app.main:app" >/dev/null 2>&1 || true
    echo "Services stopped."
}
trap cleanup EXIT

# 0. Pre-flight sudo check
echo "Refreshing sudo credentials..."
# Assumes sudo is already cached by interactive check
sudo -v 

# 1. Start UI
echo "Starting UI..."
PYTHONPATH=$PYTHONPATH:$(pwd) nohup python3 -m uvicorn wicap-ui.app.main:app --host 127.0.0.1 --port 8080 > "$LOG_DIR/ui.log" 2>&1 &
UI_PID=$!
echo "UI started (PID $UI_PID). Waiting for it to settle..."
sleep 5

# Check UI health
if ! curl -s http://127.0.0.1:8080/ > /dev/null; then
    echo "ERROR: UI failed to start. Check $LOG_DIR/ui.log"
    cat "$LOG_DIR/ui.log"
    exit 1
fi
echo "UI is reachable."

# 2. Start Backend
echo "Starting Backend Suite..."
# Using sudo (cached), run in background via shell & 
sudo python3 start_wicap.py --push-to-sql > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

echo "Backend started (PID $BACKEND_PID). Monitoring (CTRL+C to stop)..."

# 3. Monitor Loop
END=$((SECONDS+300)) # Run for 5 minutes
while [ $SECONDS -lt $END ]; do
    echo "--- Status at $(date) ---"
    
    # Check System Status API
    STATUS_JSON=$(curl -s http://127.0.0.1:8080/api/system/status)
    EPS=$(echo "$STATUS_JSON" | grep -o '"eps": [0-9.]*' | cut -d' ' -f2)
    SERVICE_STATUS=$(echo "$STATUS_JSON" | grep -o '"service_status": "[^"]*"' | cut -d'"' -f4)
    
    echo "UI Service Status: $SERVICE_STATUS"
    echo "Events Per Second: $EPS"
    
    # Check Backend Log for specific success/error markers
    tail -n 3 "$LOG_DIR/backend.log"
    
    sleep 10
done

echo "Verification run complete."
