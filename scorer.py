"""
WiFiWizard Phase 1 - Rule-Based Scorer

Simple scoring system for identifying "interesting" activity.
No ML - just rule-based point accumulation.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

from config import ScoutConfig

logger = logging.getLogger(__name__)


@dataclass
class ScoreResult:
    """Result from scoring a single frame."""
    points: int = 0
    reasons: list[str] = field(default_factory=list)
    is_new_ssid: bool = False
    is_new_bssid: bool = False
    is_hidden_ssid: bool = False
    is_open_network: bool = False
    is_probe_directed: bool = False
    is_strong_rssi: bool = False
    is_deauth_spike: bool = False


@dataclass
class ChannelScore:
    """Score tracking for a single channel."""
    channel: int
    score: int = 0
    last_updated: float = 0.0

    # What triggered the score
    triggers: list[str] = field(default_factory=list)

    def add_score(self, points: int, reason: str, timestamp: float) -> None:
        """Add points with reason."""
        self.score += points
        self.last_updated = timestamp
        self.triggers.append(f"+{points}: {reason}")
        if len(self.triggers) > 20:
            self.triggers = self.triggers[-20:]

    def decay(self, current_time: float, decay_seconds: float) -> None:
        """Decay score over time."""
        if self.score > 0:
            elapsed = current_time - self.last_updated
            if elapsed > decay_seconds:
                self.score = max(0, self.score - 1)
                self.last_updated = current_time


class RuleScorer:
    """
    Rule-based scorer for channel activity.

    Scores channels based on simple rules:
    - New SSID/BSSID seen
    - Hidden SSID detected
    - Open network detected
    - Probe for non-broadcast SSID
    - Deauth spike (>5 in 10s)
    - Strong RSSI (above configured threshold)
    """

    def __init__(self, config: ScoutConfig):
        self.config = config

        # Tracking state
        self._seen_ssids: set[str] = set()
        self._seen_bssids: set[str] = set()
        self._channel_scores: dict[int, ChannelScore] = {}

        # Deauth tracking: {channel: [(timestamp, bssid), ...]}
        self._deauth_events: dict[int, list[tuple[float, str]]] = defaultdict(list)

        # Statistics
        self._total_frames = 0
        self._score_events = 0

    def score_frame(self, frame) -> ScoreResult:
        """
        Score a frame and update channel score.

        Args:
            frame: Parsed frame with ssid, bssid, security, etc.

        Returns:
            ScoreResult with points and flags for what was detected.
        """
        self._total_frames += 1
        result = ScoreResult()

        channel = frame.channel
        if channel not in self._channel_scores:
            self._channel_scores[channel] = ChannelScore(channel=channel)

        ch_score = self._channel_scores[channel]

        # Rule 1: New SSID
        if frame.ssid and frame.ssid not in self._seen_ssids:
            self._seen_ssids.add(frame.ssid)
            result.points += self.config.score_new_ssid
            result.reasons.append(f"new_ssid:{frame.ssid[:20]}")
            result.is_new_ssid = True

        # Rule 2: New BSSID
        if frame.bssid and frame.bssid not in self._seen_bssids:
            self._seen_bssids.add(frame.bssid)
            result.points += self.config.score_new_bssid
            result.reasons.append(f"new_bssid:{frame.bssid}")
            result.is_new_bssid = True

        # Rule 3: Hidden SSID
        if frame.is_hidden_ssid:
            result.points += self.config.score_hidden_ssid
            result.reasons.append("hidden_ssid")
            result.is_hidden_ssid = True

        # Rule 4: Open network (exclude probe requests)
        if frame.security.is_open and frame.ssid and not frame.is_probe_request:
            result.points += self.config.score_open_network
            result.reasons.append(f"open_network:{frame.ssid[:20]}")
            result.is_open_network = True

        # Rule 5: Probe for non-broadcast SSID
        if frame.is_probe_request and not frame.probe_is_broadcast:
            result.points += self.config.score_probe_nonbroadcast
            result.reasons.append(f"probe_directed:{frame.ssid[:20] if frame.ssid else 'unknown'}")
            result.is_probe_directed = True

        # Rule 6: Strong RSSI (only if RSSI is known and above threshold)
        if frame.rssi is not None and frame.rssi > self.config.rssi_strong_threshold:
            result.points += self.config.score_strong_rssi
            result.reasons.append(f"strong_rssi:{frame.rssi}dBm")
            result.is_strong_rssi = True

        # Rule 7: Deauth spike detection
        if frame.is_deauth or frame.is_disassoc:
            is_spike = self._record_deauth_and_check_spike(frame)
            if is_spike:
                result.points += self.config.score_deauth_spike
                result.reasons.append("deauth_spike")
                result.is_deauth_spike = True

        # Apply points to channel score
        if result.points > 0:
            reason_weights = {
                "new_ssid": self.config.score_new_ssid,
                "new_bssid": self.config.score_new_bssid,
                "hidden_ssid": self.config.score_hidden_ssid,
                "open_network": self.config.score_open_network,
                "probe_directed": self.config.score_probe_nonbroadcast,
                "strong_rssi": self.config.score_strong_rssi,
                "deauth_spike": self.config.score_deauth_spike,
            }
            for reason in result.reasons:
                reason_key = reason.split(":", 1)[0]
                points = reason_weights.get(reason_key, 1)
                ch_score.add_score(points, reason, frame.timestamp)
            self._score_events += 1

        return result

    def _record_deauth_and_check_spike(self, frame) -> bool:
        """
        Record a deauth event and check if it constitutes a spike.

        Returns True if this deauth triggers a spike condition.
        """
        channel = frame.channel
        now = frame.timestamp

        # Add this deauth
        self._deauth_events[channel].append((now, frame.bssid or "unknown"))

        # Clean old events
        cutoff = now - self.config.deauth_spike_window_sec
        self._deauth_events[channel] = [
            (ts, bssid) for ts, bssid in self._deauth_events[channel]
            if ts > cutoff
        ]

        # Check if spike (only return True when we hit exactly the threshold)
        count = len(self._deauth_events[channel])
        return count == self.config.deauth_spike_count

    def get_channel_score(self, channel: int, current_time: float = None) -> int:
        """Get current score for a channel."""
        if current_time is None:
            current_time = time.time()

        if channel in self._channel_scores:
            self._channel_scores[channel].decay(current_time, self.config.score_decay_seconds)
            return self._channel_scores[channel].score
        return 0

    def should_dwell(self, channel: int, current_time: float = None) -> bool:
        """Check if channel score exceeds dwell threshold."""
        return self.get_channel_score(channel, current_time) >= self.config.dwell_threshold

    def get_hottest_channel(self, current_time: float = None) -> tuple[int, int]:
        """Get the channel with highest score."""
        if not self._channel_scores:
            return (0, 0)

        if current_time is None:
            current_time = time.time()

        # Decay all scores first
        for ch_score in self._channel_scores.values():
            ch_score.decay(current_time, self.config.score_decay_seconds)

        hottest = max(self._channel_scores.values(), key=lambda x: x.score)
        return (hottest.channel, hottest.score)

    def get_score_summary(self, channel: int) -> dict:
        """Get scoring summary for a channel."""
        if channel not in self._channel_scores:
            return {'channel': channel, 'score': 0, 'triggers': []}

        ch = self._channel_scores[channel]
        return {
            'channel': channel,
            'score': ch.score,
            'triggers': ch.triggers[-5:],
        }

    def reset_channel(self, channel: int) -> None:
        """Reset score for a channel after dwelling."""
        if channel in self._channel_scores:
            self._channel_scores[channel].score = 0
            self._channel_scores[channel].triggers.clear()

    # Public read-only accessors (avoid private attribute access)
    @property
    def seen_ssid_count(self) -> int:
        """Number of unique SSIDs seen."""
        return len(self._seen_ssids)

    @property
    def seen_bssid_count(self) -> int:
        """Number of unique BSSIDs seen."""
        return len(self._seen_bssids)

    @property
    def stats(self) -> dict:
        """Get scorer statistics."""
        return {
            'total_frames': self._total_frames,
            'score_events': self._score_events,
            'unique_ssids': len(self._seen_ssids),
            'unique_bssids': len(self._seen_bssids),
            'channel_scores': {ch: s.score for ch, s in self._channel_scores.items()},
        }
