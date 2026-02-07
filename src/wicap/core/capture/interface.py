"""
Capture Interface Protocol

Defines the protocol for packet capture backends using the Strategy Pattern.
This allows swapping between different capture implementations (Scapy, libpcap, etc.)
without changing the core scout logic.
"""
from collections.abc import Callable
from typing import Protocol


class CaptureInterface(Protocol):
    """Protocol for packet capture backends.

    This protocol defines the interface that all capture backends must implement.
    It uses the Strategy Pattern to allow different capture implementations.
    """

    def start(self, interface: str) -> None:
        """Start capture on the given interface.

        Args:
            interface: Network interface name (e.g., 'wlan0')
        """
        ...

    def stop(self) -> None:
        """Stop capture and release resources."""
        ...

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
        ...
