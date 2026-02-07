"""
WiFi Capabilities Discovery Utility.

Uses `iw` command to auto-detect supported channels and bands for a given interface.
"""

import logging
import shutil
import subprocess

logger = logging.getLogger('wicap.wifi_capabilities')

def get_supported_channels(interface: str, bands: list[str] | None = None) -> list[dict]:
    """
    Get list of supported channels for the given interface.

    Args:
        interface: Name of the wireless interface (e.g., 'wlan0').
        bands: List of bands to include. Allowed: ['2.4ghz', '5ghz', '6ghz'].
               If None or empty, all supported bands are returned.

    Returns:
        List of dicts: {'channel': int, 'freq': int, 'band': str}
    """
    defaults = [
        {'channel': 1, 'freq': 2412, 'band': '2.4ghz'},
        {'channel': 6, 'freq': 2437, 'band': '2.4ghz'},
        {'channel': 11, 'freq': 2462, 'band': '2.4ghz'}
    ]

    if not shutil.which("iw"):
        logger.warning("`iw` command not found. Cannot auto-detect channels. Returning 2.4GHz defaults.")
        return defaults

    # Normalize bands
    if bands:
        bands = [b.lower() for b in bands]
        if "all" in bands:
            bands = ['2.4ghz', '5ghz', '6ghz']
    else:
        bands = ['2.4ghz', '5ghz', '6ghz']

    # We need to find the PHY associated with the interface first
    phy = _get_phy_for_interface(interface)
    if not phy:
        logger.warning(f"Could not determine PHY for {interface}. Returning 2.4GHz defaults.")
        return defaults

    return _get_channels_from_iw_list(phy, bands)

def _get_phy_for_interface(interface: str) -> str | None:
    """Resolve interface name (wlan0) to PHY name (phy0)."""
    try:
        output = subprocess.check_output(["iw", "dev", interface, "info"], text=True)
        for line in output.splitlines():
            if "wiphy" in line:
                # Example: wiphy 0
                parts = line.split()
                if len(parts) >= 2:
                    return f"phy{parts[1]}"
    except subprocess.CalledProcessError:
        pass

    # Fallback: try parsing `iw dev` full output if the specific command failed or interface mismatch
    try:
        output = subprocess.check_output(["iw", "dev"], text=True)
        current_phy = None
        for line in output.splitlines():
            if line.startswith("phy#"):
                current_phy = f"phy{line.split('#')[1]}"
            if f"Interface {interface}" in line and current_phy:
                return current_phy
    except Exception as e:
        logger.error(f"Error resolving PHY for {interface}: {e}")

    return None

def _get_channels_from_iw_list(phy: str, target_bands: list[str]) -> list[dict]:
    """Parse `iw phy <phy> info` to find supported channels."""
    supported_channels: list[dict] = []
    seen_combinations = set()

    try:
        # We use `iw list` usually, or `iw phy <phy> info`
        # `iw list` returns all phys, so we need to filter for our specific phy section
        # simpler to just run `iw phy <phy> info`
        output = subprocess.check_output(["iw", "phy", phy, "info"], text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to query capabilities for {phy}: {e}")
        return [
            {'channel': 1, 'freq': 2412, 'band': '2.4ghz'},
            {'channel': 6, 'freq': 2437, 'band': '2.4ghz'},
            {'channel': 11, 'freq': 2462, 'band': '2.4ghz'}
        ]


    # Parsing logic for `iw` output
    # Band 1:
    #    Frequencies:
    #       * 2412 MHz [1] (20.0 dBm)
    # Band 2:
    #    Frequencies:
    #       * 5180 MHz [36] (20.0 dBm)

    lines = output.splitlines()
    for line in lines:
        line = line.strip()

        if line.startswith("Band"):
            continue

        if "* " in line and "MHz" in line and "[" in line:
            # * 2412 MHz [1] ...
            try:
                parts = line.split()
                freq_mhz = int(float(parts[1]))
                channel_part = line.split('[')[1].split(']')[0]
                channel = int(channel_part)

                # Determine band from frequency
                if 2400 <= freq_mhz <= 2500:
                    band = "2.4ghz"
                elif 5000 <= freq_mhz <= 5900:
                    band = "5ghz"
                elif 5925 <= freq_mhz <= 7125:
                    band = "6ghz"
                else:
                    band = "other"

                # Check disabled/no-IR (No Initiate Radiation)
                # If "disabled" or "no IR" is in the line, we might want to skip it for *active* scanning/injection
                # depending on region. For passive monitoring (monitor mode), we can technically listen.
                # safely, let's include unless explicitly disabled by hardware
                if "disabled" in line.lower():
                    continue

                if band in target_bands:
                    # Deduplicate based on channel+band (freq usually implies both)
                    key = (channel, band)
                    if key not in seen_combinations:
                        supported_channels.append({
                            'channel': channel,
                            'freq': freq_mhz,
                            'band': band
                        })
                        seen_combinations.add(key)

            except (ValueError, IndexError):
                continue

    return sorted(supported_channels, key=lambda x: x['freq'])
