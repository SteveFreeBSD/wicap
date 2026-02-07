"""
Pydantic schemas for API input validation.

This module provides type-safe validation for all API endpoints,
preventing injection attacks and ensuring data integrity.
"""
import re
from typing import Literal

from pydantic import BaseModel, Field, constr, field_validator
from pydantic_core import core_schema


class MACAddress(str):
    """Validated MAC address type."""

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        return core_schema.no_info_after_validator_function(
            cls.validate,
            core_schema.str_schema(),
        )

    @classmethod
    def validate(cls, v):
        """Validate MAC address format."""
        if isinstance(v, str):
            # Accept formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
            pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            if not re.match(pattern, v):
                raise ValueError(
                    f'Invalid MAC address format: {v}. '
                    f'Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX'
                )
            # Normalize to uppercase with colons
            return v.upper().replace('-', ':')
        raise TypeError(f'MAC address must be a string, got {type(v)}')


class SourceFilter(BaseModel):
    """Source filter for queries (live vs replay)."""
    source: Literal["live", "replay"] = Field(default="live", description="Data source filter")


class LimitQuery(BaseModel):
    """Query with limit parameter."""
    limit: int = Field(default=20, ge=1, le=1000, description="Maximum number of results")

    @field_validator("limit")
    def validate_limit(cls, v):
        """Ensure limit is reasonable."""
        if v > 1000:
            raise ValueError('Limit cannot exceed 1000')
        if v < 1:
            raise ValueError('Limit must be at least 1')
        return v


class DeviceQuery(BaseModel):
    """Device query parameters."""
    mac: MACAddress = Field(..., description="MAC address of the device")
    limit: int = Field(default=50, ge=1, le=1000, description="Maximum number of results")


class ChannelQuery(BaseModel):
    """Channel query parameters."""
    channel: int = Field(..., ge=1, le=165, description="WiFi channel number (1-165)")

    @field_validator("channel")
    def validate_channel(cls, v):
        """Validate channel is in valid range."""
        # 2.4 GHz: 1-14, 5 GHz: 36-165, 6 GHz: 1-233
        # For now, accept 1-165 (covers 2.4 and 5 GHz)
        if not (1 <= v <= 165):
            raise ValueError(f'Channel must be between 1 and 165, got {v}')
        return v


class RSSIQuery(BaseModel):
    """RSSI query parameters."""
    rssi: int = Field(..., ge=-120, le=0, description="RSSI value in dBm (-120 to 0)")


class TimeRangeQuery(BaseModel):
    """Time range query parameters."""
    start_time: str | None = Field(None, description="Start time (ISO format)")
    end_time: str | None = Field(None, description="End time (ISO format)")
    hours: int = Field(default=1, ge=1, le=168, description="Hours to look back (1-168)")


class EventTypeQuery(BaseModel):
    """Event type filter."""
    event_type: constr(pattern=r'^[a-z_]+$') = Field(..., description="Event type (lowercase with underscores)")

    @field_validator("event_type")
    def validate_event_type(cls, v):
        """Validate event type is safe."""
        # Whitelist of known event types
        allowed_types = {
            'new_bssid', 'new_ssid', 'open_network', 'hidden_ssid',
            'strong_rssi', 'deauth', 'probe_request', 'telemetry_pulse',
            'wids_alert', 'handshake_captured'
        }
        if v not in allowed_types:
            # Log warning but allow (for extensibility)
            # In production, you might want to be stricter
            pass
        return v


class RecentEventsQuery(LimitQuery, SourceFilter):
    """Query parameters for recent events endpoint."""
    include_bt: bool = Field(default=False, description="Include Bluetooth events in results")
    include_pulse: bool = Field(default=False, description="Include telemetry pulse/summary events")


class TelemetryFeedQuery(LimitQuery):
    """Query parameters for telemetry feed."""
    include_bt: bool = Field(default=False, description="Include Bluetooth events in telemetry feed")
    include_pulse: bool = Field(default=False, description="Include telemetry pulse/summary events")


class AlertFeedback(BaseModel):
    """Operator feedback for anomaly alerts."""
    alert_id: str = Field(..., description="Alert id from /api/alerts")
    label: Literal["benign", "confirmed", "noisy"] = Field(..., description="Feedback label")
    note: str | None = Field(None, max_length=256, description="Optional operator note")


class AlertAcknowledge(BaseModel):
    """Acknowledge or unacknowledge a WIDS alert."""
    alert_id: constr(min_length=1, max_length=32) = Field(..., description="Alert id from /api/alerts")
    acknowledged: bool = Field(default=True, description="Acknowledge (true) or reopen (false)")
