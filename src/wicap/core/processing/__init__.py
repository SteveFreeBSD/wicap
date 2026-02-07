"""
Event Processing Core Module

This module provides core event processing functionality including
deduplication, persistence, and event enrichment.
"""

from .deduplicator import DedupCache
from .persistence import PersistenceManager

__all__ = ['DedupCache', 'PersistenceManager']
