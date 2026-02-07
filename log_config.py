#!/usr/bin/env python3
"""
WICAP Logging Configuration

Centralized logging configuration for all WICAP modules.
Supports both human-readable and JSON structured logging.

Usage:
    from log_config import setup_logging
    setup_logging()  # Human-readable (default)
    setup_logging(json_format=True)  # JSON for production

Environment Variables:
    WICAP_LOG_LEVEL: DEBUG, INFO, WARNING, ERROR (default: INFO)
    WICAP_LOG_FORMAT: text, json (default: text)
    WICAP_LOG_MAX_BYTES: Max size per log file (default: 5MB)
    WICAP_LOG_BACKUPS: Number of backup files (default: 7)
"""

import json
import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Configuration from environment
LOG_LEVEL = os.environ.get("WICAP_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("WICAP_LOG_FORMAT", "text").lower()
LOG_MAX_BYTES = int(os.environ.get("WICAP_LOG_MAX_BYTES", 5 * 1024 * 1024))
LOG_BACKUP_COUNT = int(os.environ.get("WICAP_LOG_BACKUPS", 7))

# Standard format for human-readable logs
TEXT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
TEXT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    Outputs one JSON object per line for easy parsing by log aggregators.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "extra"):
            log_entry.update(record.extra)

        return json.dumps(log_entry, default=str)


def get_formatter(json_format: bool = False) -> logging.Formatter:
    """Get the appropriate formatter based on configuration."""
    if json_format or LOG_FORMAT == "json":
        return JSONFormatter()
    return logging.Formatter(TEXT_FORMAT, datefmt=TEXT_DATE_FORMAT)


def build_rotating_handler(log_path: Path, json_format: bool = False) -> RotatingFileHandler:
    """Build a rotating file handler with the appropriate formatter."""
    handler = RotatingFileHandler(
        str(log_path), maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
    )
    handler.setFormatter(get_formatter(json_format))
    return handler


def setup_logging(
    name: str = "wicap",
    level: str | None = None,
    json_format: bool = False,
    log_file: Path | None = None,
) -> logging.Logger:
    """
    Set up standardized logging for WICAP modules.

    Args:
        name: Logger name (use module name, e.g., 'wicap.scout')
        level: Log level override (default: from WICAP_LOG_LEVEL env)
        json_format: Use JSON structured logging
        log_file: Optional file to write logs to

    Returns:
        Configured logger instance
    """
    log_level = getattr(logging, level or LOG_LEVEL, logging.INFO)

    # Configure root logger for wicap namespace
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # Console handler
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(log_level)
    console.setFormatter(get_formatter(json_format))
    logger.addHandler(console)

    # File handler (if specified)
    if log_file:
        file_handler = build_rotating_handler(log_file, json_format)
        file_handler.setLevel(log_level)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the wicap namespace prefix.

    Args:
        name: Module name (e.g., 'scout', 'nexus.dwell_watcher')

    Returns:
        Logger with 'wicap.' prefix
    """
    if not name.startswith("wicap."):
        name = f"wicap.{name}"
    return logging.getLogger(name)

