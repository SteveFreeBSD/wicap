"""
Scavenger Module v10
Offline Forensic Intelligence Engine for WICAP.

"Feeds on the dead" - Analyzing historical PCAP artifacts.
"""

from .agents import AgentCartographer, AgentCrypt, AgentShadow, AgentSnoopy, ClientPNL, HandshakeState
from .correlator import IdentityFusion, TargetDossier
from .ingest import SCAPY_AVAILABLE, LRUDeduplicator, PCAPStreamer, extract_packet_info
from .pipeline import ScavengerPipeline

__all__ = [
    # Ingestion
    'PCAPStreamer',
    'LRUDeduplicator',
    'extract_packet_info',
    'SCAPY_AVAILABLE',

    # Agents
    'AgentShadow',
    'AgentCrypt',
    'AgentCartographer',
    'AgentSnoopy',

    # Data classes
    'ClientPNL',
    'HandshakeState',
    'TargetDossier',

    # Correlation
    'IdentityFusion',

    # Pipeline
    'ScavengerPipeline',
]

__version__ = "10.0.0"
