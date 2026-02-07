"""
Scapy Capture Backend

Scapy-based packet capture implementation.
This is the default fallback backend when libpcap is not available.
"""
import logging
from collections.abc import Callable

logger = logging.getLogger('wicap.capture.scapy')


class ScapyBackend:
    """Scapy-based capture backend (default fallback)."""

    def __init__(self) -> None:
        self._interface: str | None = None

    def start(self, interface: str) -> None:
        """Start capture on the given interface."""
        self._interface = interface

    def stop(self) -> None:
        """Stop capture and release resources."""
        self._interface = None

    def capture(
        self,
        timeout: float,
        on_frame: Callable[[bytes, float | None], None],
        bpf_filter: str = ""
    ) -> None:
        """Capture frames for the given timeout and invoke callback.

        Args:
            timeout: Maximum time to capture (seconds)
            on_frame: Callback function(frame_bytes, timestamp)
            bpf_filter: Optional BPF filter string
        """
        if not self._interface:
            raise RuntimeError("Scapy backend not started")

        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise ImportError("scapy not installed; cannot use ScapyBackend") from exc

        def _handle(pkt) -> None:
            ts = getattr(pkt, "time", None)
            try:
                ts = float(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts = None
            on_frame(bytes(pkt), ts)

        sniff_kwargs = {
            "iface": self._interface,
            "timeout": timeout,
            "store": False,
            "prn": _handle,
        }
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter
        sniff(**sniff_kwargs)
