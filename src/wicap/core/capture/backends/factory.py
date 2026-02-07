"""
Capture Backend Factory

Factory function to select and instantiate the appropriate capture backend.
"""
import os
from typing import Protocol

from .libpcap_backend import LibpcapBackend
from .scapy_backend import ScapyBackend


def get_capture_backend() -> Protocol:
    """Select capture backend based on environment configuration.

    Backend selection priority:
    1. Explicitly set via WICAP_CAPTURE_BACKEND env var
    2. Try libpcap (faster, preferred)
    3. Fall back to Scapy (slower, but always available)

    Returns:
        Capture backend instance (ScapyBackend or LibpcapBackend)
    """
    backend = os.environ.get("WICAP_CAPTURE_BACKEND", "auto").strip().lower()

    if backend == "scapy":
        return ScapyBackend()

    if backend == "libpcap":
        return LibpcapBackend()

    # Auto-select: try libpcap first, fall back to scapy
    try:
        return LibpcapBackend()
    except ImportError:
        return ScapyBackend()
