#!/bin/bash

# bt_preflight.sh
# Validates the environment for WICAP Bluetooth capture (Slice B0)

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "Starting Bluetooth Preflight Check..."

# 1. Check for tshark
if command -v tshark &> /dev/null; then
    echo -e "[${GREEN}OK${NC}] tshark is installed"
else
    echo -e "[${RED}FAIL${NC}] tshark is NOT installed. Please install wireshark-cli / tshark."
    exit 1
fi

# 2. Check python3
if command -v python3 &> /dev/null; then
    echo -e "[${GREEN}OK${NC}] python3 is installed"
else
    echo -e "[${RED}FAIL${NC}] python3 is NOT installed."
    exit 1
fi

# 3. Check pyserial
if python3 -c "import serial" &> /dev/null; then
    echo -e "[${GREEN}OK${NC}] python module 'pyserial' is installed"
else
    echo -e "[${RED}FAIL${NC}] python module 'pyserial' is missing. Run: pip install pyserial"
    exit 1
fi

# 4. Check for Nordic Sniffer tools
EXTCAP_DIR="${WICAP_BT_EXTCAP_DIR:-tools/bluetooth/extcap}"
SNIFFER_PATH="${EXTCAP_DIR}/nrf_sniffer_ble.py"
if [ -f "$SNIFFER_PATH" ]; then
    echo -e "[${GREEN}OK${NC}] Nordic nrf_sniffer_ble.py found at $SNIFFER_PATH"
else
    echo -e "[${RED}FAIL${NC}] Nordic nrf_sniffer_ble.py NOT found at $SNIFFER_PATH"
    echo -e "${YELLOW}ACTION REQUIRED: Set WICAP_BT_EXTCAP_DIR or extract Nordic extcap to tools/bluetooth/extcap${NC}"
fi

# 5. Check for dongle access
DEVICE="${WICAP_BT_INTERFACE:-}"
BT_GLOB="${WICAP_BT_INTERFACE_GLOB:-}"
BT_SERIAL="${WICAP_BT_SERIAL:-}"

# Backward compat
if [ -z "$DEVICE" ] && [ ! -z "$WICAP_BT_DEVICE" ]; then
    DEVICE="$WICAP_BT_DEVICE"
    echo -e "${YELLOW}WARN${NC}: WICAP_BT_DEVICE is deprecated; use WICAP_BT_INTERFACE instead."
fi

resolve_device() {
    local iface="$DEVICE"
    if [ -n "$iface" ] && [ "$iface" != "auto" ]; then
        echo "$iface"
        return
    fi

    shopt -s nullglob

    if [ -n "$BT_GLOB" ]; then
        local matches=($BT_GLOB)
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

DEVICE=$(resolve_device)

# Default to Nordic Sniffer CDC ACM path
DEVICE="${DEVICE:-/dev/ttyACM0-4.6}"

if [ -e "$DEVICE" ]; then
    echo -e "[${GREEN}OK${NC}] Device $DEVICE found"
    if [ -r "$DEVICE" ] && [ -w "$DEVICE" ]; then
        echo -e "[${GREEN}OK${NC}] Device $DEVICE is read/write accessible"
    else
        echo -e "[${RED}FAIL${NC}] Device $DEVICE exists but is NOT accessible."
        echo -e "${YELLOW}HINT: Add your user to 'dialout' or 'uucp' group: sudo usermod -aG dialout $USER${NC}"
    fi
else
    echo -e "[${YELLOW}WARN${NC}] Device $DEVICE not found. Is the dongle plugged in?"
fi

echo "Preflight check complete."
