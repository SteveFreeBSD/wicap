"""Structured logging configuration for WICAP.

Provides opt-in JSON logging for production environments and log aggregation.
Enable with: WICAP_LOG_FORMAT=json

Usage:
    from nexus.utils.logging_config import configure_logging
    configure_logging()  # Call once at startup
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

# Common context fields that may be present in log records
_CONTEXT_FIELDS = frozenset([
    "channel", "bssid", "ssid", "sensor_id", "event_type",
    "mac", "rssi", "event_count", "alert_type", "severity",
])


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging and log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON."""
        log_obj: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_obj["exc"] = self.formatException(record.exc_info)

        # Include extra context fields
        for field in _CONTEXT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                log_obj[field] = value

        return json.dumps(log_obj, default=str)


class RichTextFormatter(logging.Formatter):
    """Human-readable text formatter with timestamps."""

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def configure_logging(
    level: str | None = None,
    format_type: str | None = None,
    replace_handlers: bool = True,
) -> None:
    """
    Configure logging based on environment or arguments.

    Args:
        level: Log level override (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Format override ('json' or 'text')
        replace_handlers: Replace root handlers if true (default: true)

    Environment Variables:
        WICAP_LOG_FORMAT: 'json' for structured logging, 'text' for human-readable
        WICAP_LOG_LEVEL: Log level (default: INFO)
    """
    use_json = (format_type or os.environ.get("WICAP_LOG_FORMAT", "text")).lower() == "json"
    log_level = (level or os.environ.get("WICAP_LOG_LEVEL", "INFO")).upper()

    # Get or create root logger
    root = logging.getLogger()

    formatter = JSONFormatter() if use_json else RichTextFormatter()

    # Replace existing handlers only when requested.
    if replace_handlers:
        root.handlers.clear()

    # Set level
    root.setLevel(getattr(logging, log_level, logging.INFO))

    if root.handlers:
        for handler in root.handlers:
            handler.setFormatter(formatter)
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        root.addHandler(handler)

    # Log configuration message
    logging.getLogger(__name__).debug(
        "Logging configured: level=%s format=%s",
        log_level,
        "json" if use_json else "text",
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name, for convenience."""
    return logging.getLogger(name)
