"""
NEXUS Configuration Module

Centralized configuration for the security audit system (SQL, hashcat,
password auditing, risk scoring).

Note: For WiFi scanning/dwell configuration (ScoutConfig), see the root
config.py which contains ScoutConfig for channel hopping and capture settings.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NexusConfig:
    """Configuration for NEXUS security audit system."""

    # Base paths
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    captures_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "captures")
    wordlists_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "captures" / "wordlists")
    reports_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "reports")

    # Hashcat settings
    hashcat_binary: str = "/usr/bin/hashcat"
    hashcat_potfile: Path = field(default_factory=lambda: Path.home() / ".local/share/hashcat/hashcat.potfile")
    hashcat_rules_dir: Path = field(default_factory=lambda: Path("/usr/share/hashcat/rules"))

    # SQL Server connection (reuse from main config)
    sql_server: str = field(
        default_factory=lambda: _get_env(
            "WICAP_SQL_SERVER",
            "WICAP_SQL_HOST",
            default="192.168.4.25,1433",
        )
    )
    sql_database: str = field(default_factory=lambda: os.getenv('WICAP_SQL_DATABASE', 'WifiInsanityDB'))
    sql_username: str = field(
        default_factory=lambda: _get_env(
            "WICAP_SQL_USER",
            "WICAP_SQL_USERNAME",
            default="steve_linux",
        )
    )
    sql_password: str = field(default_factory=lambda: _get_sql_password())
    sql_driver: str = field(default_factory=lambda: os.getenv('WICAP_SQL_DRIVER', 'ODBC Driver 18 for SQL Server'))

    # Risk scoring thresholds
    risk_threshold_critical: int = 80
    risk_threshold_high: int = 60
    risk_threshold_medium: int = 40

    # Processing settings
    batch_size: int = 50
    max_pcap_queue: int = 100

    # Password auditing
    default_audit_strategy: str = "quick"
    enable_auto_crack: bool = False

    # Retention
    retention_days_pcap: int = 30
    retention_days_events: int = 90

    # Dwell watcher
    dwell_baseline_on_start: bool = field(
        default_factory=lambda: _get_env_bool("WICAP_DWELL_BASELINE_ON_START", False)
    )

    def get_sql_connection_string(self) -> str:
        """Build ODBC connection string."""
        # Standardize trust_cert to YES/NO for ODBC Driver 18
        raw_trust = os.getenv("WICAP_SQL_TRUST_CERT", "true").lower()
        trust_cert = raw_trust in ("1", "true", "yes", "y", "on")
        return (
            f"DRIVER={{{self.sql_driver}}};"
            f"SERVER={self.sql_server};"
            f"DATABASE={self.sql_database};"
            f"UID={self.sql_username};"
            f"PWD={self.sql_password};"
            f"TrustServerCertificate={'YES' if trust_cert else 'NO'};"
            "Connection Timeout=10;"
        )

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)

    @property
    def wordlist_dir(self) -> Path:
        return self.wordlists_dir

    @property
    def rules_dir(self) -> Path:
        return self.hashcat_rules_dir

    @classmethod
    def from_env(cls) -> 'NexusConfig':
        """Create config from environment variables."""
        config = cls()

        # Override from environment
        if env_hashcat := os.getenv('NEXUS_HASHCAT_BINARY'):
            config.hashcat_binary = env_hashcat
        if env_wordlists := os.getenv('NEXUS_WORDLISTS_DIR'):
            config.wordlists_dir = Path(env_wordlists)
        if env_strategy := os.getenv('NEXUS_AUDIT_STRATEGY'):
            config.default_audit_strategy = env_strategy
        if os.getenv('NEXUS_AUTO_CRACK', '').lower() in ('1', 'true', 'yes'):
            config.enable_auto_crack = True

        return config


def _get_sql_password() -> str:
    """Get SQL password from environment, fail if not set.

    SECURITY: No default passwords allowed. This ensures credentials
    must be explicitly provided via environment variables.

    Raises:
        ValueError: If WICAP_SQL_PASSWORD is not set or is too short.
    """
    password = os.getenv('WICAP_SQL_PASSWORD')
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


def get_nexus_config() -> NexusConfig:
    """Get default NEXUS configuration."""
    return NexusConfig.from_env()
def _get_env(*names: str, default: str = "") -> str:
    """Return the first non-empty env var from names, else default."""
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _get_env_bool(name: str, default: bool = False) -> bool:
    """Parse common truthy values from environment variables."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}
