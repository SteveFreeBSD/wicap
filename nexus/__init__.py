"""
NEXUS - Next-level EXtended Unified Security

WiFiWizard Phase 4 Security Audit System

Modules:
- config: Centralized configuration (NexusConfig)
- security_posture: Network security assessment and risk scoring
- risk_scorer: Vulnerability scoring algorithms (RiskScorer, RiskLevel)
- eapol_parser: EAPOL frame parsing for handshake capture
- handshake_extractor: Extract WPA handshakes from PCAPs
- password_auditor: Hashcat integration for password weakness testing
- password_auditor_enhanced: Enhanced auditor with Ape-Mode features
- device_fingerprint: Client device fingerprinting
- attack_analyzer: Attack detection and analysis
- wordlist_manager: Advanced wordlist generation engine
"""

__version__ = "4.0.0"
__author__ = "WiFiWizard Team"

from .config import NexusConfig, get_nexus_config
from .password_auditor import CrackResult, CrackStatus, PasswordAuditor
from .risk_scorer import RiskLevel, RiskScorer

__all__ = [
    # Config
    "NexusConfig",
    "get_nexus_config",
    # Risk Scoring
    "RiskScorer",
    "RiskLevel",
    # Password Auditing
    "PasswordAuditor",
    "CrackStatus",
    "CrackResult",
]
