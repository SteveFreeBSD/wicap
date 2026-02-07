"""
WiFi Capture Core Module

This module provides the core capture functionality for WICAP,
including capture backends, channel hopping, and related utilities.
"""

from .channel_hopper import ChannelHopper
from .interface import CaptureInterface

__all__ = ['CaptureInterface', 'ChannelHopper']
