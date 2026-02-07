"""
WiFiWizard Phase 3 - Scout/Dwell Configuration

Single-process scout with integrated dwell capture mode.
All paths are repo-relative by default.

Note: For NEXUS security audit configuration (SQL, hashcat, password auditing),
see nexus/config.py which contains NexusConfig.
"""

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

# Global Constants
DEFAULT_INTERFACE = "wlan0"
WICAP_INTERFACE_ENV_VAR = "WICAP_INTERFACE"

# Event Bus Configuration (Single Source of Truth)
REDIS_QUEUE_KEY = "wicap:events"


def _get_env(*names: str, default: str = "") -> str:
    """Return the first non-empty env var from names, else default."""
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _get_env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _derive_sensor_id(name: str) -> str:
    token = (name or "sensor").encode("utf-8")
    return hashlib.sha1(token).hexdigest()[:8]

def _get_default_captures_dir() -> Path:
    """Get default captures directory (repo-relative)."""
    # Default to ./captures relative to working directory
    return Path("./captures")


def _get_sql_password() -> str:
    """Get SQL password from environment, fail if not set.

    SECURITY: No default passwords allowed. This ensures credentials
    must be explicitly provided via environment variables.

    Raises:
        ValueError: If WICAP_SQL_PASSWORD is not set or is too short.
    """
    password = os.getenv("WICAP_SQL_PASSWORD")
    if not password:
        raise ValueError(
            "WICAP_SQL_PASSWORD environment variable is required. "
            "No default passwords are allowed for security. "
            "Please set WICAP_SQL_PASSWORD in your environment or .env file."
        )
    if len(password) < 12:
        raise ValueError(
            f"WICAP_SQL_PASSWORD must be at least 12 characters long "
            f"(current length: {len(password)}). This is a security requirement."
        )
    return password


@dataclass
class ScoutConfig:
    """Configuration for scout-dwell mode."""

    # Interface
    interface: str = field(default_factory=lambda: os.getenv(WICAP_INTERFACE_ENV_VAR, DEFAULT_INTERFACE))

    # Bluetooth Configuration
    bt_enabled: bool = field(default_factory=lambda: _get_env_bool("WICAP_BT_ENABLED", False))
    bt_interface: str = field(default_factory=lambda: _get_env("WICAP_BT_INTERFACE", default="auto"))
    bt_capture_dir: Path = field(default_factory=lambda: Path(_get_env("WICAP_BT_CAPTURE_DIR", default="./captures/bt")))
    bt_extcap_dir: str | None = field(
        default_factory=lambda: _get_env("WICAP_BT_EXTCAP_DIR", default="tools/bluetooth/extcap")
    )

    # Channel hopping
    # If None, will auto-detect based on bands.
    # List of simple ints (legacy) or dicts {'channel': int, 'freq': int, 'band': str}
    channels: list[dict] | None = None
    bands: list[str] = field(default_factory=lambda: ["2.4ghz"]) # Default to safe 2.4 only unless enabled
    priority_channels: list[int] = field(default_factory=lambda: [1, 6, 11])
    scout_dwell_ms: int = 400  # 300-500ms per channel during scout

    # Dwell mode
    dwell_threshold: int = 1  # Score threshold to trigger dwell
    dwell_duration_sec: int = 30  # How long to dwell on interesting channel

    # Scoring weights (simple rule-based)
    score_new_ssid: int = 1
    score_new_bssid: int = 1
    score_hidden_ssid: int = 2
    score_open_network: int = 2
    score_probe_nonbroadcast: int = 1
    score_deauth_spike: int = 3  # >5 deauths in 10s
    score_strong_rssi: int = 1  # Points for RSSI above configured threshold
    rssi_strong_threshold: int = -85  # dBm threshold (higher/less negative is stronger)
    score_decay_seconds: float = 30.0
    deauth_spike_count: int = 5
    deauth_spike_window_sec: int = 10

    # Output paths (repo-relative by default)
    captures_dir: Path = field(default_factory=_get_default_captures_dir)

    # PCAP settings during dwell (no rotation in Phase 1 - one file per dwell)
    pcap_max_packets: int = 100000  # Max packets per dwell PCAP

    # Event queue rotation (0 disables)
    queue_max_bytes: int = 50 * 1024 * 1024  # 50MB
    queue_max_files: int = 5  # Retain latest N rotated queue files
    queue_backpressure_max_bytes: int = 0  # Computed default in get_scout_config
    queue_backpressure_action: str = "drop_pulse"  # drop_pulse|drop

    # Processor dedup cache limit (bounded memory)
    dedup_max_entries: int = 10000

    # Redis Configuration
    redis_url: str | None = field(default_factory=lambda: os.getenv("WICAP_REDIS_URL"))

    # Remote Sensor Hub (optional)
    sensor_hub_host: str | None = field(default_factory=lambda: os.getenv("WICAP_SENSOR_HUB_HOST"))
    sensor_hub_port: int = field(
        default_factory=lambda: int(os.getenv("WICAP_SENSOR_HUB_PORT", os.getenv("WICAP_SENSOR_PORT", "9999")))
    )
    sensor_protocol: str = field(default_factory=lambda: os.getenv("WICAP_SENSOR_PROTOCOL", "ws"))
    sensor_auth_token: str | None = field(default_factory=lambda: os.getenv("WICAP_SENSOR_AUTH_TOKEN"))
    sensor_tls_verify: bool = field(default_factory=lambda: _get_env_bool("WICAP_SENSOR_TLS_VERIFY", True))
    sensor_ws_path: str = field(default_factory=lambda: os.getenv("WICAP_SENSOR_WS_PATH", "/ws/sensors"))
    sensor_name: str = field(default_factory=lambda: os.getenv("WICAP_SENSOR_NAME", "sensor"))
    sensor_location: str | None = field(default_factory=lambda: os.getenv("WICAP_SENSOR_LOCATION"))
    sensor_id: str = field(
        default_factory=lambda: _get_env("WICAP_SENSOR_ID", default="") or _derive_sensor_id(os.getenv("WICAP_SENSOR_NAME", "sensor"))
    )

    def __post_init__(self):
        """Ensure directories exist and compute derived paths."""
        self.captures_dir = Path(self.captures_dir)
        self.captures_dir.mkdir(parents=True, exist_ok=True)

        if self.bt_enabled:
            self.bt_capture_dir = Path(self.bt_capture_dir)
            self.bt_capture_dir.mkdir(parents=True, exist_ok=True)

        # Channel Auto-Discovery
        if self.channels is None:
            try:
                # Lazy import to avoid circular dependencies or import errors config-time
                from utils.wifi_capabilities import get_supported_channels
                detected = get_supported_channels(self.interface, self.bands)
                if detected:
                    self.channels = detected
                    # Add common 5GHz priority channels if in use
                    if "5ghz" in self.bands or "all" in self.bands:
                        # Append common 5GHz non-DFS channels to priority if present in detected
                        common_5g = [36, 40, 44, 48, 149, 153, 157, 161]
                        # For priority logic, we need to check if these channels are in the valid list
                        # Since channels is now a list of dicts, we check 'channel' key
                        valid_nums = {d['channel'] for d in self.channels}
                        self.priority_channels.extend([c for c in common_5g if c in valid_nums and c not in self.priority_channels])
                else:
                    # Fallback defaults (2.4GHz)
                    self.channels = [
                        {'channel': 1, 'freq': 2412, 'band': '2.4ghz'},
                        {'channel': 6, 'freq': 2437, 'band': '2.4ghz'},
                        {'channel': 11, 'freq': 2462, 'band': '2.4ghz'}
                    ]
            except ImportError:
                # Fallback
                self.channels = [
                    {'channel': 1, 'freq': 2412, 'band': '2.4ghz'},
                    {'channel': 6, 'freq': 2437, 'band': '2.4ghz'},
                    {'channel': 11, 'freq': 2462, 'band': '2.4ghz'}
                ]

        # Ensure priority channels are in the scrape list
        try:
            valid_nums = {d.get("channel") for d in (self.channels or []) if isinstance(d, dict)}
            self.priority_channels = [p for p in self.priority_channels if p in valid_nums]
        except Exception:
            # Keep user-provided priority list if channel parsing fails.
            pass

    @property
    def events_log(self) -> Path:
        """Path to events log file."""
        return self.captures_dir / "events.log"

    @property
    def pidfile(self) -> Path:
        """Path to PID file for daemon control."""
        return self.captures_dir / "wifiwizard.pid"


@dataclass
class SQLConfig:
    """Configuration for SQL Server connection."""
    server: str = field(
        default_factory=lambda: _get_env(
            "WICAP_SQL_SERVER",
            "WICAP_SQL_HOST",
            default="192.168.4.25,1433",
        )
    )
    database: str = field(default_factory=lambda: os.getenv("WICAP_SQL_DATABASE", "WifiInsanityDB"))
    username: str = field(
        default_factory=lambda: _get_env(
            "WICAP_SQL_USER",
            "WICAP_SQL_USERNAME",
            default="steve_linux",
        )
    )
    password: str = field(default_factory=lambda: _get_sql_password())
    driver: str = field(default_factory=lambda: os.getenv("WICAP_SQL_DRIVER", "ODBC Driver 18 for SQL Server"))


def get_scout_config() -> ScoutConfig:
    """Get scout configuration with environment overrides."""
    kwargs = {}

    # Environment overrides
    if os.environ.get("WICAP_INTERFACE"):
        kwargs['interface'] = os.environ["WICAP_INTERFACE"]
    if os.environ.get("WICAP_DWELL_THRESHOLD"):
        kwargs['dwell_threshold'] = int(os.environ["WICAP_DWELL_THRESHOLD"])
    if os.environ.get("WICAP_DWELL_DURATION"):
        kwargs['dwell_duration_sec'] = int(os.environ["WICAP_DWELL_DURATION"])
    if os.environ.get("WICAP_CAPTURES_DIR"):
        kwargs['captures_dir'] = Path(os.environ["WICAP_CAPTURES_DIR"])
    if os.environ.get("WICAP_RSSI_STRONG_THRESHOLD"):
        kwargs['rssi_strong_threshold'] = int(os.environ["WICAP_RSSI_STRONG_THRESHOLD"])
    if os.environ.get("WICAP_SCORE_DECAY_SECONDS"):
        kwargs['score_decay_seconds'] = float(os.environ["WICAP_SCORE_DECAY_SECONDS"])
    if os.environ.get("WICAP_QUEUE_MAX_BYTES"):
        kwargs['queue_max_bytes'] = int(os.environ["WICAP_QUEUE_MAX_BYTES"])
    if os.environ.get("WICAP_QUEUE_MAX_FILES"):
        kwargs['queue_max_files'] = int(os.environ["WICAP_QUEUE_MAX_FILES"])
    if "WICAP_QUEUE_BACKPRESSURE_MAX_BYTES" in os.environ:
        kwargs['queue_backpressure_max_bytes'] = int(os.environ["WICAP_QUEUE_BACKPRESSURE_MAX_BYTES"])
    if os.environ.get("WICAP_QUEUE_BACKPRESSURE_ACTION"):
        kwargs['queue_backpressure_action'] = os.environ["WICAP_QUEUE_BACKPRESSURE_ACTION"]
    if os.environ.get("WICAP_DEDUP_MAX_ENTRIES"):
        kwargs['dedup_max_entries'] = int(os.environ["WICAP_DEDUP_MAX_ENTRIES"])

    if os.environ.get("WICAP_BANDS"):
        kwargs['bands'] = [b.strip().lower() for b in os.environ["WICAP_BANDS"].split(",")]

    if os.environ.get("WICAP_BT_ENABLED"):
        kwargs['bt_enabled'] = _get_env_bool("WICAP_BT_ENABLED")
    if os.environ.get("WICAP_BT_INTERFACE"):
        kwargs['bt_interface'] = os.environ["WICAP_BT_INTERFACE"]
    if os.environ.get("WICAP_BT_CAPTURE_DIR"):
        kwargs['bt_capture_dir'] = Path(os.environ["WICAP_BT_CAPTURE_DIR"])
    if os.environ.get("WICAP_BT_EXTCAP_DIR"):
        kwargs['bt_extcap_dir'] = os.environ["WICAP_BT_EXTCAP_DIR"]
    if os.environ.get("WICAP_SENSOR_ID"):
        kwargs['sensor_id'] = os.environ["WICAP_SENSOR_ID"]

    config = ScoutConfig(**kwargs)

    # Default behavior: apply backpressure once the rotated queue set reaches its max size.
    # A value of 0 means "not explicitly set".
    if getattr(config, "queue_backpressure_max_bytes", 0) <= 0:
        config.queue_backpressure_max_bytes = config.queue_max_bytes * max(1, config.queue_max_files)

    return config


def get_sql_config() -> SQLConfig:
    """Get SQL configuration with environment overrides."""
    return SQLConfig()
