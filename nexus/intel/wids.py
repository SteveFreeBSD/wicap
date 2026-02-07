"""
WIDS Engine - Wireless Intrusion Detection System

Real-time attack detection with throttle logic and alert management.

Attack Types Detected:
1. Deauth Flood: High rate of deauthentication frames
2. Crypto Downgrade: WPA3→WPA2 or WPA2→Open transitions
3. Evil Twin: Duplicate SSIDs with different BSSIDs
"""

import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from nexus.intel.network_baseline import NetworkBaselineSnapshot

logger = logging.getLogger(__name__)


def _encryption_label(
    *,
    is_open: bool = False,
    has_wep: bool = False,
    has_wpa: bool = False,
    has_wpa2: bool = False,
    has_wpa3: bool = False,
) -> str:
    if has_wpa3:
        return "WPA3"
    if has_wpa2:
        return "WPA2"
    if has_wpa:
        return "WPA"
    if has_wep:
        return "WEP"
    if is_open:
        return "Open"
    return "Unknown"


@dataclass
class Alert:
    """A detected security event."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    alert_type: str = ""
    severity: int = 1  # 1-5, 5 is critical
    title: str = ""
    description: str = ""
    timestamp: float = field(default_factory=time.time)
    source_mac: str | None = None
    target_mac: str | None = None
    bssid: str | None = None
    ssid: str | None = None
    channel: int | None = None
    event_count: int = 1
    acknowledged: bool = False
    suppressed: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp,
            "source_mac": self.source_mac,
            "target_mac": self.target_mac,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "event_count": self.event_count,
            "acknowledged": self.acknowledged,
        }


class WIDSEngine:
    """
    Real-time Wireless Intrusion Detection System.

    Processes frames and generates alerts for detected attacks.
    Includes throttle logic to prevent alert spam.
    """

    # Alert types
    ALERT_DEAUTH_FLOOD = "deauth_flood"
    ALERT_CRYPTO_DOWNGRADE = "crypto_downgrade"
    ALERT_EVIL_TWIN = "evil_twin"
    ALERT_ROGUE_AP = "rogue_ap"
    ALERT_BASELINE_NEW_SSID = "baseline_new_ssid"
    ALERT_BASELINE_NEW_BSSID = "baseline_new_bssid"
    ALERT_BASELINE_SECURITY_DOWNGRADE = "baseline_security_downgrade"
    ALERT_BASELINE_CHANNEL_DRIFT = "baseline_channel_drift"

    def __init__(
        self,
        deauth_threshold: int = 10,
        deauth_window_sec: float = 5.0,
        alert_cooldown_sec: float = 60.0,
        max_alerts_per_min: int = 10,
        baseline_snapshot: NetworkBaselineSnapshot | None = None,
    ):
        """
        Initialize WIDS engine.

        Args:
            deauth_threshold: Deauth frames to trigger flood alert
            deauth_window_sec: Time window for deauth counting
            alert_cooldown_sec: Suppress duplicate alerts for this duration
            max_alerts_per_min: Max alerts of same type per minute (burst control)
        """
        self.deauth_threshold = deauth_threshold
        self.deauth_window_sec = deauth_window_sec
        self.alert_cooldown_sec = alert_cooldown_sec
        self.max_alerts_per_min = max_alerts_per_min
        self.baseline_snapshot = baseline_snapshot

        # Deauth tracking: {(channel, target_bssid): [(timestamp, src_mac), ...]}
        self._deauth_events: dict[tuple[int, str], list[tuple[float, str]]] = defaultdict(list)

        # SSID baseline: {ssid: {bssid, ...}}
        self._ssid_bssids: dict[str, set[str]] = defaultdict(set)

        # Network encryption baseline: {bssid: encryption_type}
        self._network_encryption: dict[str, str] = {}

        # Baseline drift state
        self._baseline_ssids: set[str] = set()
        self._baseline_bssids: dict[str, set[str]] = defaultdict(set)
        self._baseline_encryption: dict[str, str] = {}
        self._baseline_channels: dict[str, int] = {}
        self._baseline_alerted: set[str] = set()

        if self.baseline_snapshot:
            self._initialize_baseline(self.baseline_snapshot)

        # Alert storage
        self._alerts: dict[str, Alert] = {}

        # Throttle tracking: {alert_signature: last_alert_time}
        self._last_alert_time: dict[str, float] = {}

        # Burst control: {alert_type: [timestamps, ...]}
        self._alert_burst: dict[str, list[float]] = defaultdict(list)

        # Stats
        self._total_frames = 0
        self._total_alerts = 0
        self._suppressed_alerts = 0

    def process_frame(self, frame) -> Alert | None:
        """
        Process a parsed frame and check for attacks.

        Args:
            frame: ParsedFrame object from parser.py

        Returns:
            Alert if attack detected, None otherwise
        """
        self._total_frames += 1

        # Check for deauth flood
        if frame.is_deauth or frame.is_disassoc:
            alert = self._check_deauth_flood(frame)
            if alert:
                return self._emit_alert(alert)

        # Check for evil twin and baseline drift (on beacons/probe responses)
        if frame.ssid and frame.bssid:
            # Baseline drift detection (30-day network baseline)
            alert = self._check_baseline_drift(frame)
            if alert:
                return self._emit_alert(alert)

            alert = self._check_evil_twin(frame)
            if alert:
                return self._emit_alert(alert)

            # Track encryption for downgrade detection
            if self._extract_encryption(frame):
                alert = self._check_crypto_downgrade(frame)
                if alert:
                    return self._emit_alert(alert)

        return None

    def _initialize_baseline(self, snapshot: NetworkBaselineSnapshot) -> None:
        for ssid, bssids in snapshot.ssid_bssids.items():
            self._baseline_ssids.add(ssid)
            self._baseline_bssids[ssid].update(b.upper() for b in bssids if b)
        self._baseline_encryption = {
            (bssid or "").upper(): enc
            for bssid, enc in snapshot.bssid_security.items()
            if bssid and enc
        }
        self._baseline_channels = {
            (bssid or "").upper(): int(channel)
            for bssid, channel in snapshot.bssid_channel.items()
            if bssid and channel is not None
        }

        # Seed WIDS internal tracking with baseline to avoid false positives
        for ssid, bssids in self._baseline_bssids.items():
            self._ssid_bssids[ssid].update(bssids)
        self._network_encryption.update(self._baseline_encryption)

    def _extract_encryption(self, frame) -> str | None:
        encryption = getattr(frame, "encryption", None)
        if encryption:
            return encryption
        security = getattr(frame, "security", None)
        if security is None:
            return None
        return _encryption_label(
            is_open=getattr(security, "is_open", False),
            has_wep=getattr(security, "has_wep", False),
            has_wpa=getattr(security, "has_wpa", False),
            has_wpa2=getattr(security, "has_wpa2", False),
            has_wpa3=getattr(security, "has_wpa3", False),
        )

    def _check_deauth_flood(self, frame) -> Alert | None:
        """Detect deauthentication flood attacks."""
        now = frame.timestamp if hasattr(frame, 'timestamp') else time.time()
        channel = frame.channel or 0
        target = frame.bssid or "unknown"
        key = (channel, target)

        # Record this deauth
        src = frame.src_mac or "unknown"
        self._deauth_events[key].append((now, src))

        # Prune old events
        cutoff = now - self.deauth_window_sec
        self._deauth_events[key] = [
            (ts, mac) for ts, mac in self._deauth_events[key]
            if ts > cutoff
        ]

        count = len(self._deauth_events[key])

        if count >= self.deauth_threshold:
            # Get the most frequent attacker
            attackers = [mac for _, mac in self._deauth_events[key]]
            attacker = max(set(attackers), key=attackers.count) if attackers else None

            rate = count / self.deauth_window_sec

            return Alert(
                alert_type=self.ALERT_DEAUTH_FLOOD,
                severity=4,
                title="Deauthentication Flood Detected",
                description=f"{count} deauth frames in {self.deauth_window_sec}s ({rate:.1f}/s)",
                timestamp=now,
                source_mac=attacker,
                target_mac=target,
                bssid=target,
                channel=channel,
                event_count=count,
            )

        return None

    def _check_evil_twin(self, frame) -> Alert | None:
        """Detect evil twin / rogue AP attacks."""
        ssid = frame.ssid
        bssid = frame.bssid.upper() if frame.bssid else None

        if not ssid or not bssid:
            return None

        # Track this SSID-BSSID pair
        known_bssids = self._ssid_bssids[ssid]

        if bssid not in known_bssids:
            if len(known_bssids) >= 1:
                # New BSSID for existing SSID - potential evil twin
                rssi = frame.rssi or -100

                # Only alert for reasonably strong signals
                if rssi > -75:
                    self._ssid_bssids[ssid].add(bssid)

                    return Alert(
                        alert_type=self.ALERT_EVIL_TWIN,
                        severity=3,
                        title=f"Potential Evil Twin: {ssid}",
                        description=f"New BSSID {bssid} for SSID '{ssid}' (RSSI: {rssi}dBm)",
                        timestamp=frame.timestamp if hasattr(frame, 'timestamp') else time.time(),
                        bssid=bssid,
                        ssid=ssid,
                        channel=frame.channel,
                    )

            self._ssid_bssids[ssid].add(bssid)

        return None

    def _check_crypto_downgrade(self, frame) -> Alert | None:
        """Detect encryption downgrade attacks."""
        bssid = frame.bssid.upper() if frame.bssid else None
        encryption = self._extract_encryption(frame)

        if not bssid or not encryption:
            return None

        # Check for downgrade
        known_enc = self._network_encryption.get(bssid)

        if known_enc:
            # Severity ordering: WPA3 > WPA2 > WPA > WEP > Open
            enc_order = {"WPA3": 5, "WPA2": 4, "WPA": 3, "WEP": 2, "Open": 1}
            known_level = enc_order.get(known_enc, 0)
            current_level = enc_order.get(encryption, 0)

            if current_level < known_level:
                return Alert(
                    alert_type=self.ALERT_CRYPTO_DOWNGRADE,
                    severity=5,  # Critical
                    title=f"Crypto Downgrade: {frame.ssid or bssid}",
                    description=f"Network changed from {known_enc} to {encryption}",
                    timestamp=frame.timestamp if hasattr(frame, 'timestamp') else time.time(),
                    bssid=bssid,
                    ssid=frame.ssid,
                    channel=frame.channel,
                )

        # Record current encryption
        if encryption:
            self._network_encryption[bssid] = encryption

        return None

    def _check_baseline_drift(self, frame) -> Alert | None:
        """Detect drift against 30-day baseline snapshot."""
        if not self._baseline_ssids:
            return None

        ssid = frame.ssid
        bssid = frame.bssid.upper() if frame.bssid else None
        rssi = frame.rssi if hasattr(frame, "rssi") else None
        channel = frame.channel if hasattr(frame, "channel") else None

        if ssid and ssid not in self._baseline_ssids:
            sig = f"baseline_new_ssid:{ssid}"
            if sig not in self._baseline_alerted:
                self._baseline_alerted.add(sig)
                return Alert(
                    alert_type=self.ALERT_BASELINE_NEW_SSID,
                    severity=2,
                    title=f"Baseline Drift: New SSID '{ssid}'",
                    description="SSID not seen in 30-day baseline",
                    timestamp=frame.timestamp if hasattr(frame, 'timestamp') else time.time(),
                    bssid=bssid,
                    ssid=ssid,
                    channel=frame.channel,
                )

        if ssid and bssid and ssid in self._baseline_bssids:
            if bssid not in self._baseline_bssids[ssid]:
                sig = f"baseline_new_bssid:{ssid}:{bssid}"
                if sig not in self._baseline_alerted:
                    if rssi is None or rssi > -80:
                        self._baseline_alerted.add(sig)
                        return Alert(
                            alert_type=self.ALERT_BASELINE_NEW_BSSID,
                            severity=3,
                            title=f"Baseline Drift: New BSSID for '{ssid}'",
                            description=f"New BSSID {bssid} (RSSI: {rssi}dBm)" if rssi is not None else f"New BSSID {bssid}",
                            timestamp=frame.timestamp if hasattr(frame, 'timestamp') else time.time(),
                            bssid=bssid,
                            ssid=ssid,
                            channel=frame.channel,
                        )

        if bssid:
            baseline_enc = self._baseline_encryption.get(bssid)
            current_enc = self._extract_encryption(frame)
            if baseline_enc and current_enc:
                enc_order = {"WPA3": 5, "WPA2": 4, "WPA": 3, "WEP": 2, "Open": 1, "Unknown": 0}
                if enc_order.get(current_enc, 0) < enc_order.get(baseline_enc, 0):
                    sig = f"baseline_security:{bssid}:{current_enc}"
                    if sig not in self._baseline_alerted:
                        self._baseline_alerted.add(sig)
                        return Alert(
                            alert_type=self.ALERT_BASELINE_SECURITY_DOWNGRADE,
                            severity=4,
                            title=f"Baseline Drift: Security Downgrade ({ssid or bssid})",
                            description=f"{baseline_enc} → {current_enc}",
                            timestamp=frame.timestamp if hasattr(frame, 'timestamp') else time.time(),
                            bssid=bssid,
                            ssid=ssid,
                            channel=frame.channel,
                        )

            baseline_channel = self._baseline_channels.get(bssid)
            if baseline_channel and channel and baseline_channel != channel:
                sig = f"baseline_channel:{bssid}:{channel}"
                if sig not in self._baseline_alerted:
                    if rssi is None or rssi > -80:
                        self._baseline_alerted.add(sig)
                        return Alert(
                            alert_type=self.ALERT_BASELINE_CHANNEL_DRIFT,
                            severity=2,
                            title=f"Baseline Drift: Channel Change ({ssid or bssid})",
                            description=f"Channel {baseline_channel} → {channel}",
                            timestamp=frame.timestamp if hasattr(frame, 'timestamp') else time.time(),
                            bssid=bssid,
                            ssid=ssid,
                            channel=frame.channel,
                        )

        return None

    def _emit_alert(self, alert: Alert) -> Alert | None:
        """
        Emit an alert with throttle logic.

        Returns the alert if emitted, None if suppressed.
        """
        now = time.time()

        # Create signature for dedup
        sig = f"{alert.alert_type}:{alert.bssid or ''}:{alert.ssid or ''}"

        # Check cooldown
        last_time = self._last_alert_time.get(sig, 0)
        if now - last_time < self.alert_cooldown_sec:
            self._suppressed_alerts += 1
            alert.suppressed = True
            return None

        # Check burst control
        burst_times = self._alert_burst[alert.alert_type]
        cutoff = now - 60.0
        burst_times = [t for t in burst_times if t > cutoff]
        self._alert_burst[alert.alert_type] = burst_times

        if len(burst_times) >= self.max_alerts_per_min:
            self._suppressed_alerts += 1
            alert.suppressed = True
            return None

        # Emit the alert
        self._last_alert_time[sig] = now
        self._alert_burst[alert.alert_type].append(now)
        self._alerts[alert.id] = alert
        self._total_alerts += 1

        logger.warning(f"🚨 WIDS Alert: {alert.title}")

        return alert

    def get_active_alerts(self, max_age_sec: float = 3600) -> list[Alert]:
        """Get recent unacknowledged alerts."""
        now = time.time()
        cutoff = now - max_age_sec

        return sorted(
            [a for a in self._alerts.values()
             if not a.acknowledged and a.timestamp > cutoff],
            key=lambda x: x.timestamp,
            reverse=True,
        )

    def get_all_alerts(self, limit: int = 100) -> list[Alert]:
        """Get all alerts, newest first."""
        return sorted(
            self._alerts.values(),
            key=lambda x: x.timestamp,
            reverse=True,
        )[:limit]

    def acknowledge(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        if alert_id in self._alerts:
            self._alerts[alert_id].acknowledged = True
            return True
        return False

    def get_stats(self) -> dict:
        """Get WIDS statistics."""
        active = [a for a in self._alerts.values() if not a.acknowledged]
        return {
            "total_frames": self._total_frames,
            "total_alerts": self._total_alerts,
            "suppressed_alerts": self._suppressed_alerts,
            "active_alerts": len(active),
            "tracked_ssids": len(self._ssid_bssids),
            "tracked_networks": len(self._network_encryption),
        }
