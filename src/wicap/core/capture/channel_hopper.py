"""
Channel Hopper

Encapsulates channel hopping logic and state management.
This isolates the channel switching mechanics from the main scout business logic,
making it easier to test and debug channel selection issues.
"""
import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger('wicap.capture.channel_hopper')


@dataclass
class ChannelInfo:
    """Channel information."""
    channel: int
    freq: int
    band: str


class ChannelHopper:
    """Manages channel hopping sequence and switching logic."""

    def __init__(
        self,
        channels: list[dict],
        priority_channels: list[int],
        interface: str
    ):
        """Initialize channel hopper.

        Args:
            channels: List of channel dicts with 'channel', 'freq', 'band' keys
            priority_channels: List of channel numbers to prioritize
            interface: Network interface name
        """
        self.interface = interface
        self.priority_channels = priority_channels
        self._channel_index = 0
        self._current_channel: ChannelInfo | None = None
        self._stats = {'channel_hops': 0}

        # Generate hopping sequence with priority weighting
        self._hopping_sequence = self._generate_hopping_sequence(channels, priority_channels)
        logger.info(f"Hopping sequence length: {len(self._hopping_sequence)}")

    def _generate_hopping_sequence(
        self,
        channels: list[dict],
        priority_channels: list[int]
    ) -> list[ChannelInfo]:
        """Generate channel hopping sequence with priority weighting.

        Priority channels are interleaved with other channels to ensure
        frequent visits to high-value channels.
        """
        if not channels:
            return []

        # Convert dicts to ChannelInfo objects
        channel_objs = [
            ChannelInfo(
                channel=c['channel'],
                freq=c.get('freq', 0),
                band=c.get('band', '2.4ghz')
            )
            for c in channels
        ]

        # Separate priority and other channels
        priority_chs = [
            c for c in channel_objs
            if c.channel in priority_channels
        ]
        other_chs = [
            c for c in channel_objs
            if c not in priority_chs
        ]

        if not priority_chs:
            # No priority channels, just sort by frequency
            return sorted(channel_objs, key=lambda x: x.freq)

        if not other_chs:
            # Only priority channels
            return priority_chs

        # Interleave priority and other channels
        # Pattern: priority, other, priority, other, ...
        sequence = []
        max_len = max(len(priority_chs), len(other_chs))
        for i in range(max_len):
            sequence.append(priority_chs[i % len(priority_chs)])
            sequence.append(other_chs[i % len(other_chs)])

        return sequence

    def get_next_channel(self) -> ChannelInfo:
        """Get next channel in hopping sequence.

        Returns:
            ChannelInfo for the next channel to hop to
        """
        if not self._hopping_sequence:
            # Fallback default
            return ChannelInfo(channel=1, freq=2412, band='2.4ghz')

        self._channel_index = (self._channel_index + 1) % len(self._hopping_sequence)
        self._stats['channel_hops'] += 1
        return self._hopping_sequence[self._channel_index]

    def set_channel(self, channel_info: ChannelInfo) -> bool:
        """Set the wireless interface to specified channel.

        Args:
            channel_info: ChannelInfo object with channel details

        Returns:
            True if successful, False otherwise
        """
        self._current_channel = channel_info

        # Use frequency if available, otherwise fall back to channel number
        if channel_info.freq:
            cmd = ['iw', 'dev', self.interface, 'set', 'freq', str(channel_info.freq)]
        else:
            cmd = ['iw', 'dev', self.interface, 'set', 'channel', str(channel_info.channel)]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                timeout=1,
            )
            if res.returncode != 0:
                logger.debug(
                    f"Channel switch failed ({' '.join(cmd)}): "
                    f"{res.stderr.decode().strip()}"
                )
                return False
            return True
        except Exception as e:
            logger.debug(f"Channel switch error: {e}")
            return False

    @property
    def current_channel(self) -> ChannelInfo | None:
        """Get current channel."""
        return self._current_channel

    @property
    def stats(self) -> dict:
        """Get hopping statistics."""
        return self._stats.copy()

    @property
    def hopping_sequence(self) -> list[ChannelInfo]:
        """Get the hopping sequence (read-only)."""
        return self._hopping_sequence.copy()
