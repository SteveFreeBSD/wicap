"""
NEXUS Risk Scoring Engine

Calculates vulnerability risk scores for wireless networks based on
security configuration, cryptographic strength, and detected weaknesses.
"""

from dataclasses import dataclass, field
from enum import IntEnum


class RiskLevel(IntEnum):
    """Risk level classification."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    NONE = 0


@dataclass
class RiskFactor:
    """Individual risk factor with score contribution."""
    name: str
    score: int
    level: RiskLevel
    description: str
    remediation: str


@dataclass
class RiskAssessment:
    """Complete risk assessment for a network."""
    bssid: str
    ssid: str | None
    total_score: int
    level: RiskLevel
    factors: list[RiskFactor] = field(default_factory=list)

    @property
    def factor_names(self) -> list[str]:
        """Get list of factor names."""
        return [f.name for f in self.factors]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON/SQL storage."""
        return {
            'bssid': self.bssid,
            'ssid': self.ssid,
            'total_score': self.total_score,
            'level': self.level.name,
            'factors': [
                {
                    'name': f.name,
                    'score': f.score,
                    'level': f.level.name,
                    'description': f.description,
                }
                for f in self.factors
            ]
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Risk Factor Definitions
# ═══════════════════════════════════════════════════════════════════════════════

RISK_FACTORS = {
    # Critical - Immediate exploitation possible
    'OPEN_NETWORK': RiskFactor(
        name='OPEN_NETWORK',
        score=100,
        level=RiskLevel.CRITICAL,
        description='Network has no encryption - all traffic visible',
        remediation='Enable WPA3-SAE or WPA2-AES encryption immediately',
    ),
    'WEP_ENCRYPTION': RiskFactor(
        name='WEP_ENCRYPTION',
        score=95,
        level=RiskLevel.CRITICAL,
        description='WEP encryption is trivially broken in minutes',
        remediation='Upgrade to WPA3-SAE or WPA2-AES immediately',
    ),

    # High - Significant weakness
    'TKIP_ONLY': RiskFactor(
        name='TKIP_ONLY',
        score=70,
        level=RiskLevel.HIGH,
        description='TKIP cipher has known vulnerabilities (BEAST, fragmentation)',
        remediation='Configure AP to use CCMP/AES only',
    ),
    'WPA_PSK': RiskFactor(
        name='WPA_PSK',
        score=55,
        level=RiskLevel.HIGH,
        description='WPA-PSK with weak cipher suite is vulnerable to offline attacks',
        remediation='Upgrade to WPA2/WPA3 with strong passphrase (12+ chars)',
    ),
    'DEFAULT_SSID': RiskFactor(
        name='DEFAULT_SSID',
        score=50,
        level=RiskLevel.HIGH,
        description='Default SSID suggests default or weak password',
        remediation='Change SSID and ensure unique, strong password',
    ),
    'HANDSHAKE_CAPTURED': RiskFactor(
        name='HANDSHAKE_CAPTURED',
        score=45,
        level=RiskLevel.HIGH,
        description='WPA handshake has been captured - offline cracking possible',
        remediation='Change password immediately if weak; use 20+ character passphrase',
    ),

    # Medium - Should be addressed
    'NO_PMF': RiskFactor(
        name='NO_PMF',
        score=35,
        level=RiskLevel.MEDIUM,
        description='No Protected Management Frames - vulnerable to deauth attacks',
        remediation='Enable PMF (802.11w) on AP and clients',
    ),
    'WPA2_PSK': RiskFactor(
        name='WPA2_PSK',
        score=30,
        level=RiskLevel.MEDIUM,
        description='WPA2-PSK is secure but vulnerable to offline dictionary attacks',
        remediation='Use 20+ character passphrase or upgrade to WPA3-SAE',
    ),
    'MIXED_MODE': RiskFactor(
        name='MIXED_MODE',
        score=25,
        level=RiskLevel.MEDIUM,
        description='Mixed WPA/WPA2 or TKIP/AES mode allows downgrade attacks',
        remediation='Configure AP for WPA2/WPA3-only with AES/CCMP only',
    ),

    # Low - Minor issues
    'HIDDEN_SSID': RiskFactor(
        name='HIDDEN_SSID',
        score=15,
        level=RiskLevel.LOW,
        description='Hidden SSID provides no security and reveals connected clients',
        remediation='Broadcast SSID normally',
    ),
    'WEAK_SIGNAL': RiskFactor(
        name='WEAK_SIGNAL',
        score=10,
        level=RiskLevel.LOW,
        description='Weak signal may indicate AP far from capture point',
        remediation='Informational only',
    ),

    # Info - Security considerations (not necessarily bad)
    'EAP_ENTERPRISE': RiskFactor(
        name='EAP_ENTERPRISE',
        score=0,  # Neutral - depends on RADIUS config
        level=RiskLevel.INFO,
        description='Enterprise authentication - security depends on RADIUS config',
        remediation='Ensure proper certificate validation and strong EAP methods',
    ),

    # Good - Reduce score (negative weight internally)
    'WPA3_SAE': RiskFactor(
        name='WPA3_SAE',
        score=-20,
        level=RiskLevel.INFO,
        description='WPA3-SAE provides strong protection against offline attacks',
        remediation='None needed - excellent security posture',
    ),
    'PMF_ENABLED': RiskFactor(
        name='PMF_ENABLED',
        score=-15,
        level=RiskLevel.INFO,
        description='Protected Management Frames enabled - deauth-resistant',
        remediation='None needed - good security practice',
    ),
    'GCMP_256': RiskFactor(
        name='GCMP_256',
        score=-10,
        level=RiskLevel.INFO,
        description='Using GCMP-256 cipher for maximum encryption strength',
        remediation='None needed - excellent cipher choice',
    ),
}

# SSID prefixes that strongly suggest default/weak passwords
# These are exact manufacturer prefixes that often come with default passwords
DEFAULT_SSID_PREFIXES = [
    'linksys', 'netgear', 'dlink', 'd-link', 'belkin', 'asus', 'tp-link',
    'tplink', 'arris', 'motorola', 'xfinity', 'att-', 'spectrum', 'verizon',
    'frontier', 'centurylink', 'cox', 'comcast', 'default', 'setup',
    'ubnt', 'ubiquiti', 'orbi', 'eero', 'google_', 'googlewifi',
]

# SSIDs that are exactly these (case-insensitive) are definitely defaults
EXACT_DEFAULT_SSIDS = [
    'default', 'admin', 'router', 'wireless', 'wifi', 'network',
    'home', 'internet', 'guest', 'setup', 'configuration',
]


class RiskScorer:
    """
    Calculate risk scores for wireless networks.

    Scoring methodology:
    - Base score starts at 0
    - Each risk factor adds its score (some are positive, some negative)
    - Score capped at 0-100 range
    - Higher score = higher risk
    """

    def __init__(self):
        self.factors = RISK_FACTORS

    def assess_network(
        self,
        bssid: str,
        ssid: str | None = None,
        is_open: bool = False,
        has_wep: bool = False,
        has_wpa: bool = False,
        has_wpa2: bool = False,
        has_wpa3: bool = False,
        cipher: str | None = None,
        akm: str | None = None,
        has_pmf: bool = False,
        handshake_captured: bool = False,
        is_hidden: bool = False,
    ) -> RiskAssessment:
        """
        Assess security risk for a network.

        Returns RiskAssessment with total score and contributing factors.
        """
        factors: list[RiskFactor] = []

        # Check encryption type
        if is_open:
            factors.append(self.factors['OPEN_NETWORK'])
        elif has_wep:
            factors.append(self.factors['WEP_ENCRYPTION'])
        elif has_wpa and not has_wpa2 and not has_wpa3:
            factors.append(self.factors['WPA_PSK'])
        elif has_wpa2 and not has_wpa3:
            if akm == 'PSK':
                factors.append(self.factors['WPA2_PSK'])
            elif akm == 'EAP':
                factors.append(self.factors['EAP_ENTERPRISE'])

        # Check for WPA3
        if has_wpa3:
            factors.append(self.factors['WPA3_SAE'])

        # Check cipher
        if cipher:
            cipher_upper = cipher.upper()
            if cipher_upper == 'TKIP':
                factors.append(self.factors['TKIP_ONLY'])
            elif 'TKIP' in cipher_upper and 'CCMP' in cipher_upper:
                factors.append(self.factors['MIXED_MODE'])
            elif cipher_upper == 'GCMP-256' or cipher_upper == 'GCMP':
                factors.append(self.factors['GCMP_256'])

        # Check PMF
        if has_pmf:
            factors.append(self.factors['PMF_ENABLED'])
        elif not is_open and not has_wep:
            # PMF only relevant for WPA+
            factors.append(self.factors['NO_PMF'])

        # Check handshake status
        if handshake_captured:
            factors.append(self.factors['HANDSHAKE_CAPTURED'])

        # Check for default SSID
        if ssid and self._is_default_ssid(ssid):
            factors.append(self.factors['DEFAULT_SSID'])

        # Check hidden SSID
        if is_hidden:
            factors.append(self.factors['HIDDEN_SSID'])

        # Calculate total score
        total = sum(f.score for f in factors)
        total = max(0, min(100, total))  # Clamp to 0-100

        # Determine risk level
        level = self._score_to_level(total)

        return RiskAssessment(
            bssid=bssid,
            ssid=ssid,
            total_score=total,
            level=level,
            factors=factors,
        )

    def _is_default_ssid(self, ssid: str) -> bool:
        """
        Check if SSID matches default/generic patterns.

        This is strict to avoid false positives - only flags:
        1. SSIDs that exactly match common defaults (case-insensitive)
        2. SSIDs starting with manufacturer prefixes
        3. Manufacturer name + numbers pattern (e.g., NETGEAR45)
        """
        ssid_lower = ssid.lower().strip()

        # Exact match on known defaults
        if ssid_lower in EXACT_DEFAULT_SSIDS:
            return True

        # Manufacturer prefix match
        for prefix in DEFAULT_SSID_PREFIXES:
            if ssid_lower.startswith(prefix):
                return True

        # Check for manufacturer + numbers pattern (e.g., "NETGEAR45", "Linksys123")
        import re
        for prefix in DEFAULT_SSID_PREFIXES:
            pattern = rf'^{re.escape(prefix)}[\s_-]?\d+$'
            if re.match(pattern, ssid_lower):
                return True

        return False

    def _score_to_level(self, score: int) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    @staticmethod
    def get_level_color(level: RiskLevel) -> str:
        """Get display color for risk level."""
        colors = {
            RiskLevel.CRITICAL: '#FF0000',  # Red
            RiskLevel.HIGH: '#FF6600',       # Orange
            RiskLevel.MEDIUM: '#FFCC00',     # Yellow
            RiskLevel.LOW: '#00CC00',        # Green
            RiskLevel.INFO: '#0066CC',       # Blue
            RiskLevel.NONE: '#808080',       # Gray
        }
        return colors.get(level, '#808080')
