#!/usr/bin/env python3
"""
WICAP Integration Tests
========================

End-to-end integration tests for the WICAP system.
Requires a live database connection.

Tests:
1. Database connectivity
2. Test handshake injection
3. Audit pipeline trigger
4. Result verification
"""

import argparse
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False

try:
    from nexus.config import get_nexus_config
    from nexus.password_auditor_enhanced import EnhancedPasswordAuditor
    NEXUS_AVAILABLE = True
except ImportError as e:
    NEXUS_AVAILABLE = False
    NEXUS_IMPORT_ERROR = str(e)


# Configuration
TEST_SSID = "integration-test-network"
TEST_BSSID = "00:11:22:33:44:55"
TEST_CLIENT = "AA:BB:CC:DD:EE:FF"
# Valid PMKID hash for testing (password: "password123")
TEST_HASH = "WPA*01*0ad6fdc0a540312a34414dee1ed5bf0c*001122334455*aabbccddeeff*696e746567726174696f6e2d746573742d6e6574776f726b***"


@dataclass
class IntegrationTestResult:
    """Result of an integration test."""
    name: str
    passed: bool
    message: str
    duration_sec: float = 0.0


@dataclass
class IntegrationReport:
    """Integration test report."""
    timestamp: str
    results: list = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging."""
    logger = logging.getLogger('integration_tests')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(ch)

    return logger


def test_database_connectivity(logger: logging.Logger) -> IntegrationTestResult:
    """Test 1: Database connectivity."""
    logger.info("\n📋 Test 1: Database Connectivity")

    if not PYODBC_AVAILABLE:
        return IntegrationTestResult("DB Connectivity", False, "pyodbc not installed")

    if not NEXUS_AVAILABLE:
        return IntegrationTestResult("DB Connectivity", False, f"NEXUS not available: {NEXUS_IMPORT_ERROR}")

    try:
        config = get_nexus_config()
        conn_str = config.get_sql_connection_string()

        with pyodbc.connect(conn_str, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()

        logger.info("   ✅ Database connection successful")
        return IntegrationTestResult("DB Connectivity", True, "Connected")

    except Exception as e:
        logger.error(f"   ❌ Database connection failed: {e}")
        return IntegrationTestResult("DB Connectivity", False, str(e))


def test_handshake_injection(logger: logging.Logger) -> IntegrationTestResult:
    """Test 2: Inject test handshake."""
    logger.info("\n📋 Test 2: Handshake Injection")

    try:
        config = get_nexus_config()
        conn_str = config.get_sql_connection_string()

        with pyodbc.connect(conn_str) as conn:
            cursor = conn.cursor()

            # Check if exists
            cursor.execute("SELECT id FROM handshakes WHERE ssid = ?", (TEST_SSID,))
            row = cursor.fetchone()

            if row:
                # Reset existing
                cursor.execute("""
                    UPDATE handshakes
                    SET crack_status='pending', priority_score=100,
                        attack_rounds_completed=0, cracked_password=NULL,
                        hashcat_hash=?
                    WHERE id=?
                """, (TEST_HASH, row.id))
                logger.info(f"   🔄 Reset existing test handshake (ID: {row.id})")
            else:
                # Insert new
                cursor.execute("""
                    INSERT INTO handshakes
                    (bssid, ssid, client_mac, handshake_type, hashcat_hash,
                     capture_time, priority_score, crack_status, msg_flags)
                    VALUES (?, ?, ?, 'pmkid', ?, SYSDATETIME(), 100, 'pending', 0)
                """, (TEST_BSSID, TEST_SSID, TEST_CLIENT, TEST_HASH))
                logger.info("   💉 Injected new test handshake")

            conn.commit()

        return IntegrationTestResult("Handshake Injection", True, "Injected")

    except Exception as e:
        logger.error(f"   ❌ Injection failed: {e}")
        return IntegrationTestResult("Handshake Injection", False, str(e))


def test_audit_pipeline(logger: logging.Logger, dry_run: bool = True) -> IntegrationTestResult:
    """Test 3: Trigger audit pipeline."""
    logger.info(f"\n📋 Test 3: Audit Pipeline {'(DRY RUN)' if dry_run else '(LIVE)'}")

    try:
        config = get_nexus_config()
        auditor = EnhancedPasswordAuditor(config)
        auditor.dry_run = dry_run

        # Run prioritized audit on just our test target
        result = auditor.prioritize_and_audit_pending(limit=1, max_total_time_sec=60, dry_run=dry_run)

        logger.info(f"   📊 Audited: {result.total_audited}, Cracked: {result.cracked}")

        if dry_run:
            return IntegrationTestResult("Audit Pipeline", True, f"Dry run completed ({result.total_audited} targets)")
        else:
            return IntegrationTestResult("Audit Pipeline", True, f"Audited {result.total_audited}, Cracked {result.cracked}")

    except Exception as e:
        logger.error(f"   ❌ Audit failed: {e}")
        return IntegrationTestResult("Audit Pipeline", False, str(e))


def test_result_verification(logger: logging.Logger) -> IntegrationTestResult:
    """Test 4: Verify results in database."""
    logger.info("\n📋 Test 4: Result Verification")

    try:
        config = get_nexus_config()
        conn_str = config.get_sql_connection_string()

        with pyodbc.connect(conn_str) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT crack_status, cracked_password, attack_rounds_completed
                FROM handshakes WHERE ssid = ?
            """, (TEST_SSID,))
            row = cursor.fetchone()

            if not row:
                return IntegrationTestResult("Result Verification", False, "Test handshake not found")

            status, password, rounds = row
            logger.info(f"   Status: {status}, Rounds: {rounds}, Password: {password or 'N/A'}")

            return IntegrationTestResult("Result Verification", True, f"Status: {status}")

    except Exception as e:
        logger.error(f"   ❌ Verification failed: {e}")
        return IntegrationTestResult("Result Verification", False, str(e))


def cleanup_test_data(logger: logging.Logger):
    """Clean up test data from database."""
    logger.info("\n🧹 Cleaning up test data...")

    try:
        config = get_nexus_config()
        with pyodbc.connect(config.get_sql_connection_string()) as conn:
            cursor = conn.cursor()

            # Get test handshake IDs
            cursor.execute("SELECT id FROM handshakes WHERE ssid = ?", (TEST_SSID,))
            ids = [row.id for row in cursor.fetchall()]

            if ids:
                id_str = ",".join(map(str, ids))
                cursor.execute(f"DELETE FROM audit_log WHERE handshake_id IN ({id_str})")
                cursor.execute(f"DELETE FROM handshakes WHERE id IN ({id_str})")
                conn.commit()
                logger.info(f"   Deleted {len(ids)} test record(s)")
    except Exception as e:
        logger.warning(f"   Cleanup warning: {e}")


def run_tests(logger: logging.Logger, dry_run: bool = True, cleanup: bool = False) -> IntegrationReport:
    """Run all integration tests."""
    report = IntegrationReport(timestamp=datetime.now().isoformat())

    logger.info(f"\n{'═' * 70}")
    logger.info("  🔗 WICAP INTEGRATION TESTS")
    logger.info(f"{'═' * 70}")

    # Run tests
    report.results.append(test_database_connectivity(logger))

    if report.results[-1].passed:
        report.results.append(test_handshake_injection(logger))
        report.results.append(test_audit_pipeline(logger, dry_run=dry_run))
        report.results.append(test_result_verification(logger))

        if cleanup:
            cleanup_test_data(logger)

    return report


def print_summary(report: IntegrationReport, logger: logging.Logger):
    """Print test summary."""
    logger.info(f"\n{'═' * 70}")
    logger.info("  📊 INTEGRATION TEST SUMMARY")
    logger.info(f"{'═' * 70}")

    for r in report.results:
        status = "✅" if r.passed else "❌"
        logger.info(f"  {status} {r.name}: {r.message}")

    logger.info(f"\n  Total: {len(report.results)}, Passed: {report.passed}, Failed: {report.failed}")
    logger.info(f"{'═' * 70}\n")


def main():
    parser = argparse.ArgumentParser(description='WICAP Integration Tests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--live', action='store_true', help='Run live audit (not dry run)')
    parser.add_argument('--cleanup', action='store_true', help='Clean up test data after')
    args = parser.parse_args()

    logger = setup_logging(args.verbose)
    report = run_tests(logger, dry_run=not args.live, cleanup=args.cleanup)
    print_summary(report, logger)

    return 0 if report.failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
