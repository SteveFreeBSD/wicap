#!/usr/bin/env python3
"""
Smart-Crack Strategy Engine - Live Test Harness
================================================

A robust and comprehensive test script for validating the
StrategyEngine and its integration with EnhancedPasswordAuditor.

Features:
- Structured logging with rotation
- Multiple test scenarios (Vendor, Semantic, Year, Priority)
- Error handling and graceful degradation
- Summary report with pass/fail counts

Usage:
    python3 test_smart_crack_engine.py [--verbose] [--live]
"""

import argparse
import logging
import os
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from unittest.mock import MagicMock

# Add project root to path
# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, project_root)

try:
    from nexus.strategy_engine import StrategyEngine
    STRATEGY_ENGINE_AVAILABLE = True
except ImportError as e:
    STRATEGY_ENGINE_AVAILABLE = False
    IMPORT_ERROR = str(e)

try:
    from nexus.password_auditor_enhanced import EnhancedPasswordAuditor, PriorityHandshake
    AUDITOR_AVAILABLE = True
except ImportError as e:
    AUDITOR_AVAILABLE = False
    AUDITOR_IMPORT_ERROR = str(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Logging Setup
# ═══════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with file and console handlers."""
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    try:
        os.makedirs(log_dir, exist_ok=True)
        # Test write access
        test_file = os.path.join(log_dir, '.write_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except PermissionError:
        log_dir = '/tmp/wicap_logs'
        os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f'smart_crack_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')


    # Create logger
    logger = logging.getLogger('smart_crack_test')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    # File handler (detailed)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)

    # Console handler (summary)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(ch)

    logger.info(f"📝 Log file: {log_file}")
    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# Test Case Data Class
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class StrategyTestCase:
    """Represents a single test case for the Strategy Engine."""
    name: str
    ssid: str
    bssid: str
    priority: int
    expected_strategies: list[str]  # Strategies that MUST appear
    unexpected_strategies: list[str] = field(default_factory=list)  # Strategies that MUST NOT appear
    description: str = ""


@dataclass
class StrategyTestResult:
    """Result of a single test case."""
    test_name: str
    passed: bool
    message: str
    duration_ms: float
    generated_plan: list[str] = field(default_factory=list)
    error: str | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Test Cases
# ═══════════════════════════════════════════════════════════════════════════════

TEST_CASES: list[StrategyTestCase] = [
    # Vendor Detection (OUI)
    StrategyTestCase(
        name="Vendor: Netgear OUI",
        ssid="MyNetwork",
        bssid="A0:04:60:11:22:33",
        priority=50,
        expected_strategies=['mask'],
        description="Should detect Netgear from OUI and add mask attack"
    ),
    StrategyTestCase(
        name="Vendor: TP-Link OUI",
        ssid="HomeWiFi",
        bssid="14:CC:20:AA:BB:CC",
        priority=50,
        expected_strategies=['mask'],
        description="Should detect TP-Link from OUI"
    ),
    StrategyTestCase(
        name="Vendor: SSID Fallback",
        ssid="NETGEAR-5G-Guest",
        bssid="00:00:00:00:00:00",  # Unknown OUI
        priority=50,
        expected_strategies=['mask'],
        description="Should detect Netgear from SSID when OUI unknown"
    ),

    # Semantic Analysis
    StrategyTestCase(
        name="Semantic: CafeNetwork",
        ssid="CafeWiFi",
        bssid="00:00:00:00:00:00",
        priority=50,
        expected_strategies=['custom_words'],
        description="Should expand 'cafe' to related words"
    ),
    StrategyTestCase(
        name="Semantic: GuestNetwork",
        ssid="Guest_Access",
        bssid="00:00:00:00:00:00",
        priority=50,
        expected_strategies=['custom_words'],
        description="Should expand 'guest' semantically"
    ),

    # Year Pattern Detection
    StrategyTestCase(
        name="Year: Conference2024",
        ssid="Conference2024",
        bssid="00:00:00:00:00:00",
        priority=50,
        expected_strategies=['year_hybrid'],
        description="Should detect year in SSID and add year_hybrid"
    ),
    StrategyTestCase(
        name="Year: Summer2023Party",
        ssid="Summer2023Party",
        bssid="00:00:00:00:00:00",
        priority=50,
        expected_strategies=['year_hybrid'],
        description="Should detect embedded year"
    ),
    StrategyTestCase(
        name="Year: NoYearPresent",
        ssid="HomeNetwork",
        bssid="00:00:00:00:00:00",
        priority=50,
        expected_strategies=[],
        unexpected_strategies=['year_hybrid'],
        description="Should NOT add year_hybrid when no year in SSID"
    ),

    # Priority-Based (Ape Mode)
    StrategyTestCase(
        name="Priority: High (Ape Mode)",
        ssid="TopSecretNetwork",
        bssid="00:00:00:00:00:00",
        priority=80,
        expected_strategies=['ape_mode'],
        description="High priority should trigger Ape Mode"
    ),
    StrategyTestCase(
        name="Priority: Low (No Ape)",
        ssid="LowPriorityNet",
        bssid="00:00:00:00:00:00",
        priority=40,
        expected_strategies=[],
        unexpected_strategies=['ape_mode'],
        description="Low priority should NOT trigger Ape Mode"
    ),

    # Universal Strategies (Always Present)
    StrategyTestCase(
        name="Universal: Digits and Standard",
        ssid="AnyNetwork",
        bssid="00:00:00:00:00:00",
        priority=50,
        expected_strategies=['digits_only', 'standard'],
        description="digits_only and standard should always be present"
    ),

    # Edge Cases
    StrategyTestCase(
        name="Edge: Empty SSID",
        ssid="",
        bssid="A0:04:60:11:22:33",
        priority=50,
        expected_strategies=['mask'],  # Vendor still detected
        description="Should handle empty SSID gracefully"
    ),
    StrategyTestCase(
        name="Edge: Very Long SSID",
        ssid="A" * 64 + "2025",  # Max SSID length + year
        bssid="00:00:00:00:00:00",
        priority=50,
        expected_strategies=['year_hybrid'],
        description="Should handle max-length SSID"
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

class SmartCrackTestRunner:
    """Runs all test cases and collects results."""

    def __init__(self, logger: logging.Logger, live_mode: bool = False):
        self.logger = logger
        self.live_mode = live_mode
        self.results: list[StrategyTestResult] = []
        self.engine: StrategyEngine | None = None

    def setup(self) -> bool:
        """Initialize the Strategy Engine."""
        if not STRATEGY_ENGINE_AVAILABLE:
            self.logger.error(f"❌ StrategyEngine not available: {IMPORT_ERROR}")
            return False

        try:
            self.engine = StrategyEngine()
            self.logger.info("✅ StrategyEngine initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize StrategyEngine: {e}")
            self.logger.debug(traceback.format_exc())
            return False

    def run_test(self, test: StrategyTestCase) -> StrategyTestResult:
        """Execute a single test case."""
        start_time = datetime.now()

        try:
            # Generate the attack plan
            plan = self.engine.generate_plan(test.ssid, test.bssid, test.priority)
            strategies = [r.strategy for r in plan]

            # Check expected strategies
            missing = [s for s in test.expected_strategies if s not in strategies]
            if missing:
                return StrategyTestResult(
                    test_name=test.name,
                    passed=False,
                    message=f"Missing strategies: {missing}",
                    duration_ms=(datetime.now() - start_time).total_seconds() * 1000,
                    generated_plan=strategies
                )

            # Check unexpected strategies
            unwanted = [s for s in test.unexpected_strategies if s in strategies]
            if unwanted:
                return StrategyTestResult(
                    test_name=test.name,
                    passed=False,
                    message=f"Unwanted strategies present: {unwanted}",
                    duration_ms=(datetime.now() - start_time).total_seconds() * 1000,
                    generated_plan=strategies
                )

            # All checks passed
            return StrategyTestResult(
                test_name=test.name,
                passed=True,
                message="All assertions passed",
                duration_ms=(datetime.now() - start_time).total_seconds() * 1000,
                generated_plan=strategies
            )

        except Exception as e:
            return StrategyTestResult(
                test_name=test.name,
                passed=False,
                message=f"Exception: {str(e)}",
                duration_ms=(datetime.now() - start_time).total_seconds() * 1000,
                error=traceback.format_exc()
            )

    def run_all(self) -> tuple[int, int]:
        """Run all test cases. Returns (passed, failed) counts."""
        self.logger.info("\n" + "═" * 70)
        self.logger.info(" 🧪 SMART-CRACK STRATEGY ENGINE TEST SUITE")
        self.logger.info("═" * 70)

        if not self.setup():
            return 0, len(TEST_CASES)

        passed = 0
        failed = 0

        for test in TEST_CASES:
            self.logger.info(f"\n📋 {test.name}")
            self.logger.debug(f"   Description: {test.description}")
            self.logger.debug(f"   SSID: '{test.ssid}' | BSSID: {test.bssid} | Priority: {test.priority}")

            result = self.run_test(test)
            self.results.append(result)

            if result.passed:
                passed += 1
                self.logger.info(f"   ✅ PASSED ({result.duration_ms:.1f}ms)")
                self.logger.debug(f"   Plan: {result.generated_plan}")
            else:
                failed += 1
                self.logger.error(f"   ❌ FAILED: {result.message}")
                self.logger.debug(f"   Plan: {result.generated_plan}")
                if result.error:
                    self.logger.debug(f"   Error:\n{result.error}")

        return passed, failed

    def run_integration_test(self) -> bool:
        """Test integration with EnhancedPasswordAuditor (mocked)."""
        self.logger.info("\n" + "═" * 70)
        self.logger.info(" 🔗 INTEGRATION TEST: Auditor <-> StrategyEngine")
        self.logger.info("═" * 70)

        if not AUDITOR_AVAILABLE:
            self.logger.warning(f"⚠️ Auditor not available: {AUDITOR_IMPORT_ERROR}")
            return False

        try:
            # Mock the config
            mock_config = MagicMock()
            auditor = EnhancedPasswordAuditor(mock_config)

            # Mock DB and Hashcat
            auditor._get_connection = MagicMock()
            auditor.audit_handshake_custom = MagicMock(return_value=MagicMock(status='exhausted'))
            auditor.audit_handshake = MagicMock(return_value=MagicMock(status='exhausted'))
            auditor.dry_run = True

            # Create test handshake
            hs = PriorityHandshake(
                id=999,
                bssid="A0:04:60:11:22:33",  # Netgear OUI
                ssid="TestNetwork2025",      # Year pattern
                priority_score=75,           # High priority
                avg_rssi=-50,
                is_hidden=False,
                is_wpa3=False,
                capture_time=datetime.now(),
                defer_count=0,
                attack_rounds=0,
                escalation_level=0,
                hashcat_hash="WPA*02*..."
            )

            self.logger.info(f"   Testing with: {hs.ssid} (BSSID: {hs.bssid}, Priority: {hs.priority_score})")

            # Run the planning (dry run)
            auditor._run_timed_rounds(hs, start_round=0, max_time=60)

            self.logger.info("   ✅ Integration test completed successfully")
            return True

        except Exception as e:
            self.logger.error(f"   ❌ Integration test failed: {e}")
            self.logger.debug(traceback.format_exc())
            return False

    def print_summary(self, passed: int, failed: int) -> None:
        """Print final summary."""
        total = passed + failed
        self.logger.info("\n" + "═" * 70)
        self.logger.info(" 📊 TEST SUMMARY")
        self.logger.info("═" * 70)
        self.logger.info(f"   Total Tests: {total}")
        self.logger.info(f"   ✅ Passed:    {passed}")
        self.logger.info(f"   ❌ Failed:    {failed}")
        self.logger.info(f"   Success Rate: {(passed/total*100) if total else 0:.1f}%")
        self.logger.info("═" * 70 + "\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='Smart-Crack Engine Test Suite')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--live', action='store_true', help='Enable live mode (actual hashcat calls)')
    args = parser.parse_args()

    logger = setup_logging(args.verbose)
    runner = SmartCrackTestRunner(logger, live_mode=args.live)

    # Run unit tests
    passed, failed = runner.run_all()

    # Run integration test
    runner.run_integration_test()

    # Print summary
    runner.print_summary(passed, failed)

    # Exit code
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
