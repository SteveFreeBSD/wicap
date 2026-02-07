"""
libpcap Capture Backend

libpcap-based packet capture implementation via pcapy-ng/pypcap.
This backend provides better performance than Scapy for high-throughput scenarios.
"""
import logging
import time
from collections.abc import Callable

logger = logging.getLogger('wicap.capture.libpcap')


class LibpcapBackend:
    """libpcap-backed capture via pcapy-ng/pypcap."""

    def __init__(self) -> None:
        """Initialize libpcap backend.

        Raises:
            ImportError: If pcapy-ng/pypcap is not installed
        """
        try:
            import pcapy
        except ImportError as exc:
            raise ImportError(
                "pcapy-ng/pypcap not installed; cannot use LibpcapBackend"
            ) from exc
        self._pcapy = pcapy
        self._interface: str | None = None
        self._cap = None

    def start(self, interface: str) -> None:
        """Start capture on the given interface."""
        self._interface = interface

    def stop(self) -> None:
        """Stop capture and release resources."""
        self._cap = None
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
            raise RuntimeError("Libpcap backend not started")

        if self._cap is None:
            # promisc=True, read timeout=100ms
            self._cap = self._pcapy.open_live(self._interface, 65535, True, 100)
            if bpf_filter:
                try:
                    self._cap.setfilter(bpf_filter)
                except Exception:
                    logger.debug("Libpcap filter set failed; continuing without filter")

        start = time.time()
        while time.time() - start < timeout:
            header, packet = self._cap.next()
            if not packet:
                continue
            ts = None
            try:
                ts_sec, ts_usec = header.getts()
                ts = ts_sec + (ts_usec / 1_000_000.0)
            except Exception:
                ts = None
            on_frame(packet, ts)
