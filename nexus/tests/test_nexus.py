#!/usr/bin/env python3
"""
NEXUS Phase 4 Comprehensive Test Suite

Tests all modules introduced in Phase 4.0-4.2:
- Config module
- Risk scorer
- Security posture manager
- EAPOL parser
- Handshake extractor
- Password auditor

Features:
- Detailed logging with timestamps
- Error isolation (one test failure doesn't stop others)
- Summary report at end
- Exit code for CI/CD integration
"""

import logging
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Add project root to path (handle execution from nexus/tests/)
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('nexus_test')


@dataclass
class NexusTestResult:
    """Result of a single test."""
    name: str
    passed: bool
    duration_ms: float
    error: str | None = None
    details: str | None = None


@dataclass
class NexusTestSuite:
    """Collection of test results."""
    name: str
    results: list[NexusTestResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total(self) -> int:
        return len(self.results)


def run_test(name: str, test_func) -> NexusTestResult:
    """Run a single test with error handling."""
    import time
    start = time.time()

    try:
        result = test_func()
        duration = (time.time() - start) * 1000

        if result is True or result is None:
            logger.info(f"  ✅ {name}")
            return NexusTestResult(name=name, passed=True, duration_ms=duration)
        else:
            logger.error(f"  ❌ {name}: {result}")
            return NexusTestResult(name=name, passed=False, duration_ms=duration, error=str(result))

    except AssertionError as e:
        duration = (time.time() - start) * 1000
        logger.error(f"  ❌ {name}: Assertion failed - {e}")
        return NexusTestResult(name=name, passed=False, duration_ms=duration, error=str(e))

    except Exception as e:
        duration = (time.time() - start) * 1000
        tb = traceback.format_exc()
        logger.error(f"  ❌ {name}: {type(e).__name__}: {e}")
        logger.debug(tb)
        return NexusTestResult(name=name, passed=False, duration_ms=duration, error=str(e), details=tb)


# ═══════════════════════════════════════════════════════════════════════════════
# Config Module Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_config_import():
    """Test that config module imports correctly."""
    from nexus.config import NexusConfig, get_nexus_config
    assert NexusConfig is not None
    assert get_nexus_config is not None
    return None


def test_config_defaults():
    """Test config has sensible defaults."""
    from nexus.config import NexusConfig
    config = NexusConfig()

    assert config.base_dir is not None
    assert config.captures_dir is not None
    assert config.hashcat_binary == '/usr/bin/hashcat'
    assert config.risk_threshold_critical == 80
    assert config.batch_size > 0
    return None


def test_config_from_env():
    """Test config can be created from environment."""
    from nexus.config import NexusConfig
    config = NexusConfig.from_env()

    assert config is not None
    assert hasattr(config, 'get_sql_connection_string')

    # Connection string should be valid format
    conn_str = config.get_sql_connection_string()
    assert 'DRIVER=' in conn_str
    assert 'SERVER=' in conn_str
    return None


def run_config_tests() -> NexusTestSuite:
    """Run all config tests."""
    suite = NexusTestSuite(name="Config Module")

    suite.results.append(run_test("Import config module", test_config_import))
    suite.results.append(run_test("Config defaults", test_config_defaults))
    suite.results.append(run_test("Config from environment", test_config_from_env))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Risk Scorer Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_risk_scorer_import():
    """Test that risk scorer imports correctly."""
    from nexus.risk_scorer import RiskLevel, RiskScorer
    assert RiskScorer is not None
    assert RiskLevel is not None
    return None


def test_risk_scorer_open_network():
    """Open networks should be critical risk."""
    from nexus.risk_scorer import RiskLevel, RiskScorer

    scorer = RiskScorer()
    assessment = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='OpenCafe',
        is_open=True,
    )

    assert assessment.total_score >= 80, f"Expected >=80, got {assessment.total_score}"
    assert assessment.level == RiskLevel.CRITICAL
    assert 'OPEN_NETWORK' in assessment.factor_names
    return None


def test_risk_scorer_wep():
    """WEP networks should be critical risk."""
    from nexus.risk_scorer import RiskScorer

    scorer = RiskScorer()
    assessment = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='OldRouter',
        has_wep=True,
    )

    assert assessment.total_score >= 80, f"Expected >=80, got {assessment.total_score}"
    assert 'WEP_ENCRYPTION' in assessment.factor_names
    return None


def test_risk_scorer_wpa3():
    """WPA3 with PMF should be low risk."""
    from nexus.risk_scorer import RiskScorer

    scorer = RiskScorer()
    assessment = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='SecureHome',
        has_wpa3=True,
        cipher='CCMP',
        akm='SAE',
        has_pmf=True,
    )

    assert assessment.total_score < 40, f"Expected <40, got {assessment.total_score}"
    assert 'WPA3_SAE' in assessment.factor_names
    assert 'PMF_ENABLED' in assessment.factor_names
    return None


def test_risk_scorer_wpa2_with_pmf():
    """WPA2-PSK with PMF should be moderate risk."""
    from nexus.risk_scorer import RiskScorer

    scorer = RiskScorer()
    assessment = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='HomeNetwork',
        has_wpa2=True,
        cipher='CCMP',
        akm='PSK',
        has_pmf=True,
    )

    # WPA2_PSK (30) + PMF_ENABLED (-15) = 15
    assert assessment.total_score < 40, f"Expected <40, got {assessment.total_score}"
    assert 'WPA2_PSK' in assessment.factor_names
    assert 'PMF_ENABLED' in assessment.factor_names
    return None


def test_risk_scorer_wpa2_without_pmf():
    """WPA2-PSK without PMF should be high risk."""
    from nexus.risk_scorer import RiskScorer

    scorer = RiskScorer()
    assessment = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='NoPMF',
        has_wpa2=True,
        cipher='CCMP',
        akm='PSK',
        has_pmf=False,
    )

    # WPA2_PSK (30) + NO_PMF (35) = 65
    assert assessment.total_score >= 60, f"Expected >=60, got {assessment.total_score}"
    assert 'NO_PMF' in assessment.factor_names
    return None


def test_risk_scorer_default_ssid_detection():
    """Default SSIDs should be detected."""
    from nexus.risk_scorer import RiskScorer

    scorer = RiskScorer()

    # Should be detected as default
    default_ssids = ['NETGEAR45', 'linksys', 'TP-Link_Guest', 'default', 'Xfinity-Home']
    for ssid in default_ssids:
        assessment = scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid=ssid,
            has_wpa2=True,
        )
        assert 'DEFAULT_SSID' in assessment.factor_names, f"Failed for SSID: {ssid}"

    # Should NOT be detected as default
    custom_ssids = ['MyCustomNetwork2024', 'SmithFamily5G', 'OfficeWiFi']
    for ssid in custom_ssids:
        assessment = scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid=ssid,
            has_wpa2=True,
        )
        assert 'DEFAULT_SSID' not in assessment.factor_names, f"False positive for SSID: {ssid}"

    return None


def test_risk_scorer_handshake_captured():
    """Captured handshake should increase risk."""
    from nexus.risk_scorer import RiskScorer

    scorer = RiskScorer()

    without_hs = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='TestNet',
        has_wpa2=True,
        cipher='CCMP',
        akm='PSK',
        has_pmf=True,
    )

    with_hs = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='TestNet',
        has_wpa2=True,
        cipher='CCMP',
        akm='PSK',
        has_pmf=True,
        handshake_captured=True,
    )

    assert with_hs.total_score > without_hs.total_score
    assert 'HANDSHAKE_CAPTURED' in with_hs.factor_names
    return None


def test_risk_scorer_to_dict():
    """Assessment should serialize to dict."""
    from nexus.risk_scorer import RiskScorer

    scorer = RiskScorer()
    assessment = scorer.assess_network(
        bssid='00:11:22:33:44:55',
        ssid='Test',
        is_open=True,
    )

    d = assessment.to_dict()
    assert d['bssid'] == '00:11:22:33:44:55'
    assert d['ssid'] == 'Test'
    assert isinstance(d['total_score'], int)
    assert isinstance(d['factors'], list)
    assert 'level' in d
    return None


def test_risk_scorer_eap_enterprise_neutral():
    """EAP Enterprise should be neutral (score 0)."""
    from nexus.risk_scorer import RISK_FACTORS

    eap_factor = RISK_FACTORS.get('EAP_ENTERPRISE')
    assert eap_factor is not None
    assert eap_factor.score == 0, f"Expected 0, got {eap_factor.score}"
    return None


def run_risk_scorer_tests() -> NexusTestSuite:
    """Run all risk scorer tests."""
    suite = NexusTestSuite(name="Risk Scorer")

    suite.results.append(run_test("Import risk scorer", test_risk_scorer_import))
    suite.results.append(run_test("Open network critical", test_risk_scorer_open_network))
    suite.results.append(run_test("WEP critical", test_risk_scorer_wep))
    suite.results.append(run_test("WPA3 low risk", test_risk_scorer_wpa3))
    suite.results.append(run_test("WPA2+PMF moderate", test_risk_scorer_wpa2_with_pmf))
    suite.results.append(run_test("WPA2 no PMF high", test_risk_scorer_wpa2_without_pmf))
    suite.results.append(run_test("Default SSID detection", test_risk_scorer_default_ssid_detection))
    suite.results.append(run_test("Handshake captured", test_risk_scorer_handshake_captured))
    suite.results.append(run_test("Serialize to dict", test_risk_scorer_to_dict))
    suite.results.append(run_test("EAP Enterprise neutral", test_risk_scorer_eap_enterprise_neutral))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Security Posture Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_security_posture_import():
    """Test that security posture imports correctly."""
    from nexus.security_posture import NetworkPosture, SecurityPostureManager
    assert SecurityPostureManager is not None
    assert NetworkPosture is not None
    return None


def test_network_posture_dataclass():
    """Test NetworkPosture dataclass."""
    from nexus.security_posture import NetworkPosture

    posture = NetworkPosture(
        bssid='00:11:22:33:44:55',
        ssid='TestNet',
        is_open=False,
        has_wpa2=True,
        cipher_suite='CCMP',
        akm_suite='PSK',
        has_pmf=True,
        channel=6,
    )

    assert posture.bssid == '00:11:22:33:44:55'
    assert posture.ssid == 'TestNet'
    assert posture.has_wpa2
    assert posture.has_pmf
    assert posture.risk_factors == []  # Default empty list
    return None


def test_security_posture_valid_order_by():
    """Test SQL injection protection on order_by."""
    from nexus.security_posture import SecurityPostureManager

    # Check that VALID_ORDER_BY exists and has safe values
    assert hasattr(SecurityPostureManager, 'VALID_ORDER_BY')
    valid = SecurityPostureManager.VALID_ORDER_BY

    assert 'risk_score DESC' in valid
    assert 'last_seen DESC' in valid

    # Verify malicious values would be rejected
    malicious = "risk_score; DROP TABLE security_posture;--"
    assert malicious not in valid
    return None


def test_security_posture_manager_init():
    """Test SecurityPostureManager can be initialized."""
    from nexus.config import get_nexus_config
    from nexus.security_posture import SecurityPostureManager

    config = get_nexus_config()
    manager = SecurityPostureManager(config)

    assert manager is not None
    assert manager.scorer is not None
    manager.close()
    return None


def run_security_posture_tests() -> NexusTestSuite:
    """Run all security posture tests."""
    suite = NexusTestSuite(name="Security Posture")

    suite.results.append(run_test("Import security posture", test_security_posture_import))
    suite.results.append(run_test("NetworkPosture dataclass", test_network_posture_dataclass))
    suite.results.append(run_test("SQL injection protection", test_security_posture_valid_order_by))
    suite.results.append(run_test("Manager initialization", test_security_posture_manager_init))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# EAPOL Parser Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_eapol_parser_import():
    """Test that EAPOL parser imports correctly."""
    from nexus.eapol_parser import EAPOLKeyFrame, EAPOLParser, HandshakeCapture
    assert EAPOLParser is not None
    assert EAPOLKeyFrame is not None
    assert HandshakeCapture is not None
    return None


def test_eapol_key_frame_dataclass():
    """Test EAPOLKeyFrame dataclass properties."""
    from nexus.eapol_parser import EAPOLKeyFrame, KeyInfo

    # Create a mock M1 frame (has_ack, no has_mic)
    frame = EAPOLKeyFrame(
        timestamp=1234567890.0,
        src_mac='AA:BB:CC:DD:EE:FF',
        dst_mac='11:22:33:44:55:66',
        bssid='AA:BB:CC:DD:EE:FF',
        version=2,
        packet_type=3,
        packet_length=99,
        descriptor_type=2,
        key_info=int(KeyInfo.KEY_ACK | KeyInfo.KEY_TYPE),  # M1: ACK + Pairwise, no MIC
        key_length=16,
        replay_counter=bytes(8),
        key_nonce=bytes(32),
        key_iv=bytes(16),
        key_rsc=bytes(8),
        key_id=bytes(8),
        key_mic=bytes(16),
        key_data_length=0,
        key_data=b'',
    )

    assert frame.has_ack
    assert not frame.has_mic
    assert frame.is_pairwise
    assert frame.determine_message_number() == 1
    return None


def test_handshake_capture_dataclass():
    """Test HandshakeCapture dataclass."""
    from nexus.eapol_parser import HandshakeCapture

    capture = HandshakeCapture(
        bssid='AA:BB:CC:DD:EE:FF',
        ssid='TestNetwork',
        client_mac='11:22:33:44:55:66',
    )

    assert capture.bssid == 'AA:BB:CC:DD:EE:FF'
    assert capture.ssid == 'TestNetwork'
    assert capture.msg_flags == 0
    assert not capture.has_m1
    assert not capture.has_m2
    assert not capture.is_crackable
    assert capture.handshake_type == 'incomplete'
    return None


def test_handshake_capture_with_pmkid():
    """Test HandshakeCapture with PMKID."""
    from nexus.eapol_parser import HandshakeCapture

    capture = HandshakeCapture(
        bssid='AA:BB:CC:DD:EE:FF',
        ssid='TestNetwork',
        client_mac='11:22:33:44:55:66',
        pmkid='0123456789abcdef0123456789abcdef',
    )

    assert capture.handshake_type == 'pmkid'
    assert capture.is_crackable
    return None


def test_handshake_capture_hashcat_format():
    """Test hashcat 22000 format export."""
    from nexus.eapol_parser import HandshakeCapture

    capture = HandshakeCapture(
        bssid='AA:BB:CC:DD:EE:FF',
        ssid='TestNet',
        client_mac='11:22:33:44:55:66',
        pmkid='0123456789abcdef0123456789abcdef',
    )

    hashcat_str = capture.to_hashcat_22000()
    assert hashcat_str is not None
    assert hashcat_str.startswith('WPA*01*')
    assert '0123456789abcdef0123456789abcdef' in hashcat_str
    assert 'aabbccddeeff' in hashcat_str.lower()  # BSSID without colons
    return None


def test_eapol_parser_instance():
    """Test EAPOLParser instantiation."""
    from nexus.eapol_parser import EAPOLParser

    parser = EAPOLParser()
    assert parser is not None
    assert hasattr(parser, 'parse_eapol_key')
    assert hasattr(parser, 'find_eapol_in_80211')
    return None


def run_eapol_parser_tests() -> NexusTestSuite:
    """Run all EAPOL parser tests."""
    suite = NexusTestSuite(name="EAPOL Parser")

    suite.results.append(run_test("Import EAPOL parser", test_eapol_parser_import))
    suite.results.append(run_test("EAPOLKeyFrame dataclass", test_eapol_key_frame_dataclass))
    suite.results.append(run_test("HandshakeCapture dataclass", test_handshake_capture_dataclass))
    suite.results.append(run_test("HandshakeCapture with PMKID", test_handshake_capture_with_pmkid))
    suite.results.append(run_test("Hashcat format export", test_handshake_capture_hashcat_format))
    suite.results.append(run_test("EAPOLParser instance", test_eapol_parser_instance))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Handshake Extractor Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_handshake_extractor_import():
    """Test that handshake extractor imports correctly."""
    from nexus.handshake_extractor import ExtractionResult, HandshakeExtractor
    assert HandshakeExtractor is not None
    assert ExtractionResult is not None
    return None


def test_handshake_extractor_scapy_available():
    """Test that scapy is available."""
    import nexus.handshake_extractor as he
    assert he.SCAPY_AVAILABLE, "scapy is required for handshake extraction"
    return None


def test_handshake_extractor_init():
    """Test HandshakeExtractor initialization."""
    from nexus.config import get_nexus_config
    from nexus.handshake_extractor import HandshakeExtractor

    config = get_nexus_config()
    extractor = HandshakeExtractor(config)

    assert extractor is not None
    assert extractor.parser is not None
    assert extractor._handshakes == {}
    assert extractor._ssid_cache == {}

    extractor.close()
    return None


def test_extraction_result_dataclass():
    """Test ExtractionResult dataclass."""
    from nexus.handshake_extractor import ExtractionResult

    result = ExtractionResult(
        pcap_file='/path/to/file.pcapng',
        frame_count=1000,
        eapol_frames=5,
        handshakes_found=2,
        pmkids_found=1,
        errors=[],
        duration_sec=1.5,
    )

    assert result.frame_count == 1000
    assert result.handshakes_found == 2
    assert result.duration_sec == 1.5
    return None


def run_handshake_extractor_tests() -> NexusTestSuite:
    """Run all handshake extractor tests."""
    suite = NexusTestSuite(name="Handshake Extractor")

    suite.results.append(run_test("Import handshake extractor", test_handshake_extractor_import))
    suite.results.append(run_test("Scapy available", test_handshake_extractor_scapy_available))
    suite.results.append(run_test("Extractor initialization", test_handshake_extractor_init))
    suite.results.append(run_test("ExtractionResult dataclass", test_extraction_result_dataclass))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Password Auditor Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_password_auditor_import():
    """Test that password auditor imports correctly."""
    from nexus.password_auditor import AttackStrategy, CrackStatus, PasswordAuditor
    assert PasswordAuditor is not None
    assert CrackStatus is not None
    assert AttackStrategy is not None
    return None


def test_password_auditor_attack_strategies():
    """Test attack strategies are defined."""
    from nexus.password_auditor import ATTACK_STRATEGIES

    assert 'quick' in ATTACK_STRATEGIES
    assert 'standard' in ATTACK_STRATEGIES
    assert 'thorough' in ATTACK_STRATEGIES
    assert 'digits_only' in ATTACK_STRATEGIES

    quick = ATTACK_STRATEGIES['quick']
    assert quick.timeout_sec > 0
    assert quick.priority >= 0
    return None


def test_password_auditor_init():
    """Test PasswordAuditor initialization."""
    from nexus.config import get_nexus_config
    from nexus.password_auditor import PasswordAuditor

    config = get_nexus_config()
    auditor = PasswordAuditor(config)

    assert auditor is not None
    assert auditor.hashcat_path is not None

    auditor.close()
    return None


def test_password_weakness_analysis():
    """Test password weakness analysis."""
    from nexus.config import get_nexus_config
    from nexus.password_auditor import PasswordAuditor

    config = get_nexus_config()
    auditor = PasswordAuditor(config)

    # Test weak password
    weakness = auditor.analyze_password_weakness('12345678')
    assert weakness.length == 8
    assert weakness.charset_digits
    assert not weakness.charset_lowercase
    assert weakness.weakness_score >= 80  # Should be very weak
    assert len(weakness.recommendations) > 0

    # Test strong password
    weakness = auditor.analyze_password_weakness('Tr0ub4dor&3-horse')
    assert weakness.length > 12
    assert weakness.charset_count >= 3
    assert weakness.weakness_score < 50  # Should be relatively strong

    auditor.close()
    return None


def test_password_weakness_ssid_in_password():
    """Test SSID-in-password detection."""
    from nexus.config import get_nexus_config
    from nexus.password_auditor import PasswordAuditor

    config = get_nexus_config()
    auditor = PasswordAuditor(config)

    weakness = auditor.analyze_password_weakness('HomeNetwork123', ssid='HomeNetwork')
    assert 'ssid_in_password' in weakness.has_patterns
    assert weakness.weakness_score > 0

    auditor.close()
    return None


def test_password_weakness_common_patterns():
    """Test common pattern detection."""
    from nexus.config import get_nexus_config
    from nexus.password_auditor import PasswordAuditor

    config = get_nexus_config()
    auditor = PasswordAuditor(config)

    # Keyboard walk
    weakness = auditor.analyze_password_weakness('qwerty123')
    assert 'keyboard_walk' in weakness.has_patterns

    # Year pattern (new name in enhanced analyzer)
    weakness = auditor.analyze_password_weakness('password2024')
    assert 'year' in weakness.has_patterns

    # Leetspeak detection
    weakness = auditor.analyze_password_weakness('p@ssw0rd')
    assert 'leetspeak' in weakness.has_patterns

    auditor.close()
    return None


def test_crack_status_enum():
    """Test CrackStatus enum values."""
    from nexus.password_auditor import CrackStatus

    assert CrackStatus.PENDING.value == 'pending'
    assert CrackStatus.CRACKED.value == 'cracked'
    assert CrackStatus.EXHAUSTED.value == 'exhausted'
    assert CrackStatus.FAILED.value == 'failed'
    return None


def run_password_auditor_tests() -> NexusTestSuite:
    """Run all password auditor tests."""
    suite = NexusTestSuite(name="Password Auditor")

    suite.results.append(run_test("Import password auditor", test_password_auditor_import))
    suite.results.append(run_test("Attack strategies defined", test_password_auditor_attack_strategies))
    suite.results.append(run_test("Auditor initialization", test_password_auditor_init))
    suite.results.append(run_test("Password weakness analysis", test_password_weakness_analysis))
    suite.results.append(run_test("SSID in password detection", test_password_weakness_ssid_in_password))
    suite.results.append(run_test("Common pattern detection", test_password_weakness_common_patterns))
    suite.results.append(run_test("CrackStatus enum", test_crack_status_enum))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Enhanced Password Auditor Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_enhanced_auditor_import():
    """Test enhanced auditor imports."""
    from nexus.dwell_watcher import DwellWatcher
    from nexus.password_auditor_enhanced import EnhancedPasswordAuditor
    assert EnhancedPasswordAuditor is not None
    assert DwellWatcher is not None
    return None


def test_enhanced_priority_scoring():
    """Test priority score computation."""
    from nexus.config import get_nexus_config
    from nexus.password_auditor_enhanced import EnhancedPasswordAuditor

    auditor = EnhancedPasswordAuditor(get_nexus_config())

    # Strong signal + default SSID
    score = auditor.compute_priority_score('linksys', avg_rssi=-55, is_hidden=False)
    assert score >= 85  # High priority

    # Weak signal, normal SSID
    score = auditor.compute_priority_score('MyHome', avg_rssi=-80, is_hidden=False)
    assert score < 60  # Lower priority

    # Hidden SSID
    score = auditor.compute_priority_score(None, avg_rssi=-70, is_hidden=True)
    assert score >= 60  # Hidden bonus

    # Helper to clean up
    # auditor.close()
    return None


def test_enhanced_crackability_index():
    """Test crackability index calculation."""
    from nexus.config import get_nexus_config
    from nexus.password_auditor import PasswordWeakness
    from nexus.password_auditor_enhanced import EnhancedPasswordAuditor

    auditor = EnhancedPasswordAuditor(get_nexus_config())

    # Mock analysis to return fixed values to avoid wordlist dependency
    def mock_analyze(password, ssid=None, bssid=None, wordlist_path=None, triangulation_data=None):
        return PasswordWeakness(
            password=password, length=len(password),
            charset_lowercase=True, charset_uppercase=False, charset_digits=False, charset_special=False, charset_count=1,
            is_dictionary_word=True, is_common_password=True, is_rockyou_match=True,
            has_patterns=['common'], entropy_score=1.5,
            zxcvbn_score=0, crack_time_seconds=10,
            weakness_score=100,
            estimated_crack_time="10 seconds", recommendations=["Change it"]
        )

    # Store original and replace
    auditor.analyze_password_weakness = mock_analyze

    # Very weak password context
    report = auditor.analyze_with_crackability('password', priority_score=80)
    # Score: 100*0.4 + 80*0.2 + 20(entropy<2) + 20(time<60) = 40+16+20+20 = 96
    assert report.crackability_index >= 80
    assert 'dictionary' in report.attack_vector_recommendation.lower()

    # Restore? Not needed for this instance
    return None


def test_enhanced_hardening_steps():
    """Test hardening step generation."""
    from nexus.config import get_nexus_config
    from nexus.password_auditor_enhanced import EnhancedPasswordAuditor

    auditor = EnhancedPasswordAuditor(get_nexus_config())

    report = auditor.analyze_with_crackability('password123')

    assert len(report.hardening_steps) >= 2
    # Should mention WPA3 or PMF
    steps_text = ' '.join(report.hardening_steps).lower()
    assert 'wpa3' in steps_text or 'pmf' in steps_text

    auditor.close()
    return None


def run_enhanced_auditor_tests() -> NexusTestSuite:
    """Run enhanced auditor tests."""
    suite = NexusTestSuite(name="Enhanced Auditor")

    suite.results.append(run_test("Import enhanced auditor", test_enhanced_auditor_import))
    suite.results.append(run_test("Priority scoring", test_enhanced_priority_scoring))
    suite.results.append(run_test("Crackability index", test_enhanced_crackability_index))
    suite.results.append(run_test("Hardening steps", test_enhanced_hardening_steps))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Ape-Mode & Wordlist Manager Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_wordlist_manager_init():
    """Test WordlistManager initialization."""
    from nexus.config import get_nexus_config
    from nexus.wordlist_manager import WordlistManager

    wm = WordlistManager(get_nexus_config())
    assert wm is not None
    assert wm.temp_dir.exists()
    return None


def test_ssid_wordlist_generation():
    """Test generating SSID-specific wordlist using generate_custom_madness."""
    from nexus.config import get_nexus_config
    from nexus.wordlist_manager import WordlistManager

    wm = WordlistManager(get_nexus_config())
    # Use the actual method name: generate_custom_madness
    path = wm.generate_custom_madness('MyWiFi', 'AA:BB:CC:DD:EE:FF', top_n=100, hybrids=1000)

    assert path.exists()
    with open(path) as f:
        content = f.read().lower()
        # Should contain SSID-based mutations (case-insensitive check)
        assert 'mywifi' in content
        # Should contain year patterns
        assert '2024' in content or '2025' in content or '2026' in content

    return None


def run_ape_mode_tests() -> NexusTestSuite:
    """Run Ape-Mode specific tests."""
    suite = NexusTestSuite(name="Ape-Mode Features")
    suite.results.append(run_test("WordlistManager Init", test_wordlist_manager_init))
    suite.results.append(run_test("SSID Wordlist Gen", test_ssid_wordlist_generation))
    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_full_import_chain():
    """Test importing NEXUS package."""
    import nexus
    assert hasattr(nexus, '__version__')
    assert nexus.__version__ == '4.0.0'
    return None


def test_risk_scorer_with_posture():
    """Test risk scorer integration with security posture."""
    from nexus.risk_scorer import RiskScorer
    from nexus.security_posture import NetworkPosture

    scorer = RiskScorer()

    # Create a posture
    posture = NetworkPosture(
        bssid='00:11:22:33:44:55',
        ssid='IntegrationTest',
        has_wpa2=True,
        cipher_suite='CCMP',
        akm_suite='PSK',
        has_pmf=True,
    )

    # Assess it
    assessment = scorer.assess_network(
        bssid=posture.bssid,
        ssid=posture.ssid,
        has_wpa2=posture.has_wpa2,
        cipher=posture.cipher_suite,
        akm=posture.akm_suite,
        has_pmf=posture.has_pmf,
    )

    assert assessment.total_score >= 0
    assert assessment.total_score <= 100
    return None


def run_integration_tests() -> NexusTestSuite:
    """Run integration tests."""
    suite = NexusTestSuite(name="Integration")

    suite.results.append(run_test("Full import chain", test_full_import_chain))
    suite.results.append(run_test("Risk scorer with posture", test_risk_scorer_with_posture))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Device Fingerprinter Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_device_fingerprint_import():
    """Test that device fingerprinter imports correctly."""
    from nexus.device_fingerprint import ClientProfile, DeviceFingerprint, DeviceFingerprinter
    assert DeviceFingerprinter is not None
    assert ClientProfile is not None
    assert DeviceFingerprint is not None
    return None


def test_device_fingerprint_vendor_lookup():
    """Test vendor lookup from OUI database."""
    from nexus.config import get_nexus_config
    from nexus.device_fingerprint import DeviceFingerprinter

    config = get_nexus_config()
    fp = DeviceFingerprinter(config)

    # Known vendors (using verified IEEE OUIs)
    assert 'Samsung' in fp.lookup_vendor('00:00:F0:12:34:56')  # Samsung Electronics
    assert fp.lookup_vendor('04:26:65:AB:CD:EF') == 'Apple'
    assert fp.lookup_vendor('00:0D:4B:11:22:33') == 'Roku'

    # Unknown vendor (AA:BB:CC is not in IEEE registry - locally administered bit set)
    assert fp.lookup_vendor('AA:BB:CC:33:44:55') is None

    fp.close()
    return None


def test_device_fingerprint_randomized_mac():
    """Test detection of randomized MAC addresses."""
    from nexus.config import get_nexus_config
    from nexus.device_fingerprint import DeviceFingerprinter

    config = get_nexus_config()
    fp = DeviceFingerprinter(config)

    # Randomized MACs have second bit of first octet set
    assert fp.is_randomized_mac('DA:AB:CD:EF:12:34')  # D=1101, bit 1=1
    assert fp.is_randomized_mac('02:11:22:33:44:55')  # 0x02 has bit 1 set

    # Non-randomized MACs
    assert not fp.is_randomized_mac('A4:99:A8:12:34:56')  # A=1010, bit 1=0
    assert not fp.is_randomized_mac('00:11:22:33:44:55')  # 0x00

    fp.close()
    return None


def test_device_fingerprint_profile_creation():
    """Test client profile creation."""
    from nexus.config import get_nexus_config
    from nexus.device_fingerprint import DeviceFingerprinter

    config = get_nexus_config()
    fp = DeviceFingerprinter(config)

    profile = fp.get_or_create_profile('00:00:F0:12:34:56')

    assert profile.mac_address == '00:00:F0:12:34:56'
    assert 'Samsung' in str(profile.vendor)  # Samsung Electronics from IEEE db
    assert not profile.is_randomized_mac
    assert profile.probed_ssids == set()
    assert profile.total_frames == 0

    fp.close()
    return None


def test_device_fingerprint_probe_tracking():
    """Test probe request tracking."""
    from nexus.config import get_nexus_config
    from nexus.device_fingerprint import DeviceFingerprinter

    config = get_nexus_config()
    fp = DeviceFingerprinter(config)

    # Simulate probe requests
    fp.update_from_probe_request('A4:99:A8:12:34:56', 'HomeNetwork', 6, rssi=-65)
    fp.update_from_probe_request('A4:99:A8:12:34:56', 'WorkNetwork', 11, rssi=-72)
    fp.update_from_probe_request('A4:99:A8:12:34:56', 'CoffeeShop', 1, rssi=-80)

    profile = fp.get_or_create_profile('A4:99:A8:12:34:56')

    assert 'HomeNetwork' in profile.probed_ssids
    assert 'WorkNetwork' in profile.probed_ssids
    assert 'CoffeeShop' in profile.probed_ssids
    assert len(profile.probed_ssids) == 3
    assert 6 in profile.channels_seen
    assert profile.total_frames == 3
    assert profile.avg_rssi is not None

    fp.close()
    return None


def test_device_fingerprint_device_type_inference():
    """Test device type inference from vendor."""
    from nexus.config import get_nexus_config
    from nexus.device_fingerprint import ClientProfile, DeviceFingerprinter

    config = get_nexus_config()
    fp = DeviceFingerprinter(config)

    # Mobile device (Samsung)
    samsung = ClientProfile(mac_address='A4:99:A8:12:34:56', vendor='Samsung')
    samsung.probed_ssids = {'Net1', 'Net2', 'Net3', 'Net4'}
    assert fp.infer_device_type(samsung) == 'phone'

    # IoT device
    amazon = ClientProfile(mac_address='00:FC:8B:12:34:56', vendor='Amazon')
    assert fp.infer_device_type(amazon) == 'iot'

    # Streaming device (using verified Roku OUI)
    roku = ClientProfile(mac_address='00:0D:4B:11:22:33', vendor='Roku')
    assert fp.infer_device_type(roku) == 'streaming'

    # Randomized MAC = likely phone
    randomized = ClientProfile(mac_address='DA:AB:CD:EF:12:34', is_randomized_mac=True)
    assert fp.infer_device_type(randomized) == 'phone'

    fp.close()
    return None


def test_device_fingerprint_threat_scoring():
    """Test threat score calculation."""
    from nexus.config import get_nexus_config
    from nexus.device_fingerprint import DeviceFingerprinter

    config = get_nexus_config()
    fp = DeviceFingerprinter(config)

    # Create a suspicious profile - many probes with randomized MAC
    for i in range(25):
        fp.update_from_probe_request(
            'DA:AB:CD:EF:12:34',  # Randomized MAC
            f'Network{i}',
            i % 14,
            rssi=-60
        )

    profile = fp.get_or_create_profile('DA:AB:CD:EF:12:34')

    # Should have elevated threat score
    assert profile.threat_score > 0
    assert len(profile.threat_factors) > 0
    assert 'EXCESSIVE_PROBING' in profile.threat_factors or 'HIGH_PROBE_COUNT' in profile.threat_factors
    assert 'RANDOMIZED_RECON' in profile.threat_factors

    fp.close()
    return None


def test_device_fingerprint_client_profile_to_dict():
    """Test ClientProfile serialization."""
    from datetime import datetime

    from nexus.device_fingerprint import ClientProfile

    profile = ClientProfile(
        mac_address='AA:BB:CC:DD:EE:FF',
        vendor='TestVendor',
        device_type='phone',
        is_randomized_mac=False,
        probed_ssids={'Net1', 'Net2'},
        channels_seen={1, 6, 11},
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        total_frames=100,
        avg_rssi=-70,
        threat_score=15,
        threat_factors=['HIGH_PROBE_COUNT'],
    )

    d = profile.to_dict()

    assert d['mac_address'] == 'AA:BB:CC:DD:EE:FF'
    assert d['vendor'] == 'TestVendor'
    assert d['device_type'] == 'phone'
    assert d['total_frames'] == 100
    assert 'Net1' in d['probed_ssids']
    assert 1 in d['channels_seen']
    return None


def run_device_fingerprint_tests() -> NexusTestSuite:
    """Run all device fingerprinter tests."""
    suite = NexusTestSuite(name="Device Fingerprinter")

    suite.results.append(run_test("Import device fingerprinter", test_device_fingerprint_import))
    suite.results.append(run_test("Vendor lookup", test_device_fingerprint_vendor_lookup))
    suite.results.append(run_test("Randomized MAC detection", test_device_fingerprint_randomized_mac))
    suite.results.append(run_test("Profile creation", test_device_fingerprint_profile_creation))
    suite.results.append(run_test("Probe tracking", test_device_fingerprint_probe_tracking))
    suite.results.append(run_test("Device type inference", test_device_fingerprint_device_type_inference))
    suite.results.append(run_test("Threat scoring", test_device_fingerprint_threat_scoring))
    suite.results.append(run_test("Profile serialization", test_device_fingerprint_client_profile_to_dict))

    return suite


# ═══════════════════════════════════════════════════════════════════════════════
# Main Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(suites: list[NexusTestSuite]) -> tuple[int, int]:
    """Print test summary and return (passed, failed)."""
    total_passed = 0
    total_failed = 0

    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    for suite in suites:
        status = "✅" if suite.failed == 0 else "❌"
        print(f"\n{status} {suite.name}: {suite.passed}/{suite.total} passed")

        if suite.failed > 0:
            for result in suite.results:
                if not result.passed:
                    print(f"   ❌ {result.name}: {result.error}")

        total_passed += suite.passed
        total_failed += suite.failed

    print("\n" + "-" * 70)
    print(f"TOTAL: {total_passed}/{total_passed + total_failed} tests passed")

    if total_failed == 0:
        print("\n🎉 ALL TESTS PASSED! 🎉")
    else:
        print(f"\n⚠️  {total_failed} TESTS FAILED")

    print("=" * 70)

    return total_passed, total_failed


def main():
    """Main test runner."""
    start_time = datetime.now()

    print("=" * 70)
    print("NEXUS Phase 4 Test Suite")
    print(f"Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    suites = []

    # Run all test suites
    logger.info("\n📦 Config Module Tests")
    suites.append(run_config_tests())

    logger.info("\n📊 Risk Scorer Tests")
    suites.append(run_risk_scorer_tests())

    logger.info("\n🔐 Security Posture Tests")
    suites.append(run_security_posture_tests())

    logger.info("\n🔑 EAPOL Parser Tests")
    suites.append(run_eapol_parser_tests())

    logger.info("\n📁 Handshake Extractor Tests")
    suites.append(run_handshake_extractor_tests())

    logger.info("\n🔓 Password Auditor Tests")
    suites.append(run_password_auditor_tests())

    logger.info("\n🚀 Enhanced Auditor Tests")
    suites.append(run_enhanced_auditor_tests())

    logger.info("\n🦍 Ape-Mode Tests")
    suites.append(run_ape_mode_tests())

    logger.info("\n📱 Device Fingerprinter Tests")
    suites.append(run_device_fingerprint_tests())

    logger.info("\n🔗 Integration Tests")
    suites.append(run_integration_tests())

    # Print summary
    passed, failed = print_summary(suites)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    print(f"\nDuration: {duration:.2f} seconds")

    # Return exit code for CI/CD
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
