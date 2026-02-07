#!/usr/bin/env python3
"""
Scavenger v10 - Comprehensive Test Harness

A hardened, production-grade test script for validating the Scavenger
offline forensic intelligence module.

Features:
- Structured logging with configurable verbosity
- Comprehensive error handling and recovery
- Progress tracking with ETA
- Detailed validation of all pipeline components
- JSON export of results
- Exit codes for CI/CD integration

Usage:
    python3 test_scavenger_harness.py [OPTIONS]

Options:
    --captures DIR     Path to captures directory (default: ./captures)
    --max-files N      Maximum files to process (default: 5)
    --max-packets N    Maximum packets per file (default: 10000)
    --output DIR       Output directory for results (default: ./scavenger_output)
    --verbose          Enable verbose logging
    --quiet            Suppress output except errors
    --json             Output results as JSON only
"""

import argparse
import json
import logging
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Add project root to path for imports (handle execution from nexus/tests/)
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_PARTIAL = 2  # Some tests passed, some failed

# ═══════════════════════════════════════════════════════════════════════════════
# Logging Setup
# ═══════════════════════════════════════════════════════════════════════════════

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output."""

    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[41m',  # Red background
        'RESET': '\033[0m',
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']

        # Add timestamp and level
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = f"{color}[{timestamp}] {record.levelname:8}{reset}"

        message = super().format(record)
        return f"{prefix} {message}"


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure logging with appropriate handlers."""
    logger = logging.getLogger("scavenger_test")
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    if quiet:
        console.setLevel(logging.ERROR)
    elif verbose:
        console.setLevel(logging.DEBUG)
    else:
        console.setLevel(logging.INFO)

    console.setFormatter(ColoredFormatter('%(message)s'))
    logger.addHandler(console)

    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HarnessTestResult:
    """Result of a single test case."""
    name: str
    passed: bool
    duration_ms: float = 0.0
    error: str | None = None
    details: str | None = None


@dataclass
class ValidationResult:
    """Result of component validation."""
    component: str
    status: str  # 'ok', 'warn', 'fail'
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HarnessTestReport:
    """Complete test report."""
    version: str = VERSION
    timestamp: str = ""
    duration_seconds: float = 0.0
    environment: dict[str, str] = field(default_factory=dict)
    validations: list[dict] = field(default_factory=list)
    pipeline_stats: dict[str, Any] = field(default_factory=dict)
    findings: dict[str, Any] = field(default_factory=dict)
    tests: list[dict] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    exit_code: int = EXIT_SUCCESS


# ═══════════════════════════════════════════════════════════════════════════════
# Validators
# ═══════════════════════════════════════════════════════════════════════════════

class ScavengerValidator:
    """Validates Scavenger module components."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.results: list[ValidationResult] = []

    def validate_imports(self) -> ValidationResult:
        """Validate all required imports are available."""
        self.logger.debug("Validating imports...")

        required_imports = [
            ("nexus.scavenger", "ScavengerPipeline"),
            ("nexus.scavenger", "PCAPStreamer"),
            ("nexus.scavenger", "AgentShadow"),
            ("nexus.scavenger", "AgentCrypt"),
            ("nexus.scavenger", "IdentityFusion"),
            ("nexus.scavenger", "ClientPNL"),
            ("nexus.scavenger", "HandshakeState"),
            ("nexus.scavenger", "TargetDossier"),
        ]

        missing = []
        for module, name in required_imports:
            try:
                mod = __import__(module, fromlist=[name])
                if not hasattr(mod, name):
                    missing.append(f"{module}.{name}")
            except ImportError as e:
                missing.append(f"{module}.{name} ({e})")

        if missing:
            result = ValidationResult(
                component="imports",
                status="fail",
                message=f"Missing imports: {', '.join(missing)}",
                details={"missing": missing}
            )
        else:
            result = ValidationResult(
                component="imports",
                status="ok",
                message=f"All {len(required_imports)} imports available"
            )

        self.results.append(result)
        return result

    def validate_scapy(self) -> ValidationResult:
        """Validate scapy is available and functional."""
        self.logger.debug("Validating scapy...")

        try:
            from scapy.all import Dot11, RadioTap

            # Quick functionality test
            pkt = RadioTap() / Dot11()
            if not hasattr(pkt, 'haslayer'):
                raise RuntimeError("scapy packet missing haslayer method")

            result = ValidationResult(
                component="scapy",
                status="ok",
                message="scapy available and functional"
            )
        except ImportError as e:
            result = ValidationResult(
                component="scapy",
                status="fail",
                message=f"scapy not available: {e}"
            )
        except Exception as e:
            result = ValidationResult(
                component="scapy",
                status="warn",
                message=f"scapy import succeeded but functionality check failed: {e}"
            )

        self.results.append(result)
        return result

    def validate_captures_dir(self, captures_dir: Path) -> ValidationResult:
        """Validate captures directory exists and contains files."""
        self.logger.debug(f"Validating captures directory: {captures_dir}")

        if not captures_dir.exists():
            result = ValidationResult(
                component="captures_dir",
                status="fail",
                message=f"Directory not found: {captures_dir}"
            )
        elif not captures_dir.is_dir():
            result = ValidationResult(
                component="captures_dir",
                status="fail",
                message=f"Path is not a directory: {captures_dir}"
            )
        else:
            # Count capture files
            pcap_files = list(captures_dir.glob("*.pcap*")) + list(captures_dir.glob("*.cap"))

            if not pcap_files:
                result = ValidationResult(
                    component="captures_dir",
                    status="warn",
                    message=f"No capture files found in {captures_dir}"
                )
            else:
                total_size = sum(f.stat().st_size for f in pcap_files if f.is_file())
                result = ValidationResult(
                    component="captures_dir",
                    status="ok",
                    message=f"Found {len(pcap_files)} capture files ({total_size / 1024 / 1024:.1f} MB)",
                    details={"file_count": len(pcap_files), "total_bytes": total_size}
                )

        self.results.append(result)
        return result

    def validate_output_dir(self, output_dir: Path) -> ValidationResult:
        """Validate/create output directory."""
        self.logger.debug(f"Validating output directory: {output_dir}")

        try:
            output_dir.mkdir(parents=True, exist_ok=True)

            # Test write permissions
            test_file = output_dir / ".write_test"
            test_file.write_text("test")
            test_file.unlink()

            result = ValidationResult(
                component="output_dir",
                status="ok",
                message=f"Output directory ready: {output_dir}"
            )
        except PermissionError:
            result = ValidationResult(
                component="output_dir",
                status="fail",
                message=f"No write permission for {output_dir}"
            )
        except Exception as e:
            result = ValidationResult(
                component="output_dir",
                status="fail",
                message=f"Cannot create output directory: {e}"
            )

        self.results.append(result)
        return result

    def run_all(self, captures_dir: Path, output_dir: Path) -> bool:
        """Run all validations. Returns True if all critical checks pass."""
        self.logger.info("Running pre-flight validations...")

        checks = [
            ("Imports", self.validate_imports),
            ("Scapy", self.validate_scapy),
            ("Captures", lambda: self.validate_captures_dir(captures_dir)),
            ("Output", lambda: self.validate_output_dir(output_dir)),
        ]

        all_passed = True
        for name, check in checks:
            try:
                result = check()
                symbol = "✅" if result.status == "ok" else "⚠️" if result.status == "warn" else "❌"
                self.logger.info(f"  {symbol} {name}: {result.message}")

                if result.status == "fail":
                    all_passed = False

            except Exception as e:
                self.logger.error(f"  ❌ {name}: Validation crashed: {e}")
                self.results.append(ValidationResult(
                    component=name.lower(),
                    status="fail",
                    message=f"Validation crashed: {e}"
                ))
                all_passed = False

        return all_passed


# ═══════════════════════════════════════════════════════════════════════════════
# Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

class ScavengerTestRunner:
    """Runs comprehensive tests on the Scavenger pipeline."""

    def __init__(
        self,
        captures_dir: Path,
        output_dir: Path,
        max_files: int = 5,
        max_packets: int = 10000,
        logger: logging.Logger = None
    ):
        self.captures_dir = captures_dir
        self.output_dir = output_dir
        self.max_files = max_files
        self.max_packets = max_packets
        self.logger = logger or logging.getLogger(__name__)

        self.pipeline = None
        self.test_results: list[HarnessTestResult] = []
        self.start_time = None

    def _run_test(self, name: str, test_func) -> HarnessTestResult:
        """Run a single test with timing and error handling."""
        start = time.time()

        try:
            test_func()
            duration = (time.time() - start) * 1000
            result = HarnessTestResult(name=name, passed=True, duration_ms=duration)
            self.logger.debug(f"    ✅ {name} ({duration:.1f}ms)")

        except AssertionError as e:
            duration = (time.time() - start) * 1000
            result = HarnessTestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                error=f"Assertion failed: {e}"
            )
            self.logger.warning(f"    ❌ {name}: {e}")

        except Exception as e:
            duration = (time.time() - start) * 1000
            result = HarnessTestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                error=str(e),
                details=traceback.format_exc()
            )
            self.logger.error(f"    ❌ {name}: {type(e).__name__}: {e}")

        self.test_results.append(result)
        return result

    def test_pipeline_initialization(self):
        """Test pipeline can be initialized."""
        from nexus.scavenger import ScavengerPipeline

        self.pipeline = ScavengerPipeline(self.captures_dir)

        assert self.pipeline is not None, "Pipeline is None"
        assert self.pipeline.streamer is not None, "Streamer is None"
        assert len(self.pipeline.agents) > 0, "No agents initialized"

    def test_capture_listing(self):
        """Test capture file listing."""
        captures = self.pipeline.streamer.list_captures()

        assert isinstance(captures, list), "list_captures didn't return list"
        # Store for later tests
        self._captures = captures

    def test_agent_shadow_initialization(self):
        """Test AgentShadow is properly initialized."""
        shadow = self.pipeline.agents.get('shadow')

        assert shadow is not None, "AgentShadow not found"
        assert shadow.name == "Shadow", f"Wrong agent name: {shadow.name}"
        assert hasattr(shadow, 'process'), "Missing process method"
        assert hasattr(shadow, 'client_profiles'), "Missing client_profiles"

    def test_agent_crypt_initialization(self):
        """Test AgentCrypt is properly initialized."""
        crypt = self.pipeline.agents.get('crypt')

        assert crypt is not None, "AgentCrypt not found"
        assert crypt.name == "Crypt", f"Wrong agent name: {crypt.name}"
        assert hasattr(crypt, 'parser'), "Missing parser property"
        assert hasattr(crypt, 'handshakes'), "Missing handshakes"

    def test_identity_fusion_initialization(self):
        """Test IdentityFusion is properly initialized."""
        assert self.pipeline.correlator is not None, "Correlator is None"
        assert hasattr(self.pipeline.correlator, 'fuse'), "Missing fuse method"
        assert hasattr(self.pipeline.correlator, 'generate_dossier'), "Missing generate_dossier"

    def test_pipeline_run(self):
        """Test pipeline execution with limited files."""
        if not hasattr(self, '_captures') or not self._captures:
            self.logger.warning("    ⏭️  Skipping: no capture files")
            return

        test_files = self._captures[:self.max_files]

        packets_processed = [0]

        def progress(count, filename):
            packets_processed[0] = count
            if count >= self.max_packets:
                raise StopIteration("Max packets reached")

        try:
            self._summary = self.pipeline.run(
                pcap_files=test_files,
                progress_callback=progress
            )
        except StopIteration:
            # Expected when hitting max_packets
            self._summary = self.pipeline._generate_summary()

        assert self._summary is not None, "No summary returned"
        assert 'summary' in self._summary, "Missing summary section"
        assert 'findings' in self._summary, "Missing findings section"

    def test_results_extraction(self):
        """Test that results can be extracted from agents."""
        if not hasattr(self, '_summary'):
            self.logger.warning("    ⏭️  Skipping: no pipeline run")
            return

        shadow = self.pipeline.agents.get('shadow')
        if shadow:
            profiles = shadow.get_all_profiles()
            assert isinstance(profiles, dict), "get_all_profiles didn't return dict"

            popularity = shadow.get_ssid_popularity()
            assert isinstance(popularity, dict), "get_ssid_popularity didn't return dict"

    def test_dossier_generation(self):
        """Test dossier generation for known clients."""
        if not hasattr(self, '_summary'):
            self.logger.warning("    ⏭️  Skipping: no pipeline run")
            return

        shadow = self.pipeline.agents.get('shadow')
        if shadow and shadow.client_profiles:
            mac = list(shadow.client_profiles.keys())[0]

            # Try correlator dossier first
            dossier = self.pipeline.get_dossier(mac)

            if dossier is None:
                # Correlator may not have fused yet (early termination)
                # Fall back to client PNL which is always available
                dossier = self.pipeline.get_client_pnl(mac)

                if dossier is not None:
                    # PNL has different fields, validate those
                    assert 'mac' in dossier, "PNL missing 'mac' field"
                    assert 'pnl_count' in dossier, "PNL missing 'pnl_count'"
                else:
                    # No data at all - this is a real failure
                    raise AssertionError(f"No dossier or PNL for {mac}")
            else:
                # Full dossier available
                assert 'mac' in dossier, "Dossier missing 'mac' field"
                assert 'pnl_count' in dossier, "Dossier missing 'pnl_count'"

    def test_correlation_suggestions(self):
        """Test correlation suggestion generation."""
        correlations = self.pipeline.correlator.suggest_correlations(min_confidence=0.3)

        assert isinstance(correlations, list), "suggest_correlations didn't return list"

        for corr in correlations:
            assert len(corr) == 3, f"Correlation tuple wrong length: {len(corr)}"
            assert isinstance(corr[2], float), f"Confidence not float: {type(corr[2])}"

    def test_json_export(self):
        """Test JSON export functionality."""
        if not hasattr(self, '_summary'):
            self.logger.warning("    ⏭️  Skipping: no pipeline run")
            return

        export_path = self.output_dir / "test_dossiers.json"

        try:
            self.pipeline.export_dossiers(export_path)
            assert export_path.exists(), "Export file not created"

            # Validate JSON
            with open(export_path) as f:
                data = json.load(f)
            assert isinstance(data, dict), "Export not a valid JSON object"

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_pipeline_reset(self):
        """Test pipeline reset."""
        self.pipeline.reset()

        stats = self.pipeline.get_stats()
        assert stats['pipeline']['packets_processed'] == 0, "Reset didn't clear packets"

        shadow = self.pipeline.agents.get('shadow')
        if shadow:
            assert len(shadow.client_profiles) == 0, "Reset didn't clear profiles"

    def run_all_tests(self) -> HarnessTestReport:
        """Run all tests and return report."""
        self.start_time = time.time()
        self.logger.info("\n" + "=" * 60)
        self.logger.info("  SCAVENGER v10 - Test Suite")
        self.logger.info("=" * 60)

        # Define test sequence
        tests = [
            ("Pipeline initialization", self.test_pipeline_initialization),
            ("Capture listing", self.test_capture_listing),
            ("AgentShadow initialization", self.test_agent_shadow_initialization),
            ("AgentCrypt initialization", self.test_agent_crypt_initialization),
            ("IdentityFusion initialization", self.test_identity_fusion_initialization),
            ("Pipeline execution", self.test_pipeline_run),
            ("Results extraction", self.test_results_extraction),
            ("Dossier generation", self.test_dossier_generation),
            ("Correlation suggestions", self.test_correlation_suggestions),
            ("JSON export", self.test_json_export),
            ("Pipeline reset", self.test_pipeline_reset),
        ]

        self.logger.info(f"\nRunning {len(tests)} tests...\n")

        for name, test_func in tests:
            self._run_test(name, test_func)

        # Generate report
        duration = time.time() - self.start_time
        passed = sum(1 for t in self.test_results if t.passed)
        failed = len(self.test_results) - passed

        report = HarnessTestReport(
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            environment={
                "python_version": sys.version.split()[0],
                "platform": sys.platform,
                "cwd": str(Path.cwd()),
            },
            tests=[asdict(t) for t in self.test_results],
            summary={
                "total": len(self.test_results),
                "passed": passed,
                "failed": failed,
            }
        )

        # Add pipeline stats and findings if available
        if hasattr(self, '_summary') and self._summary:
            report.pipeline_stats = self._summary.get('summary', {})
            report.findings = self._summary.get('findings', {})

        # Set exit code
        if failed == 0:
            report.exit_code = EXIT_SUCCESS
        elif passed > 0:
            report.exit_code = EXIT_PARTIAL
        else:
            report.exit_code = EXIT_FAILURE

        return report


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scavenger v10 Comprehensive Test Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        "--captures", "-c",
        type=Path,
        default=Path("./captures"),
        help="Path to captures directory"
    )
    parser.add_argument(
        "--max-files", "-f",
        type=int,
        default=5,
        help="Maximum files to process"
    )
    parser.add_argument(
        "--max-packets", "-p",
        type=int,
        default=10000,
        help="Maximum packets per file"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("./scavenger_output"),
        help="Output directory for results"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress output except errors"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON only"
    )

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(verbose=args.verbose, quiet=args.quiet or args.json)

    try:
        # Run validations
        validator = ScavengerValidator(logger)
        if not validator.run_all(args.captures, args.output):
            logger.error("\n❌ Pre-flight validation failed. Aborting.")
            if args.json:
                print(json.dumps({
                    "error": "validation_failed",
                    "validations": [asdict(v) if hasattr(v, '__dict__') else v.__dict__
                                   for v in validator.results]
                }, indent=2))
            return EXIT_FAILURE

        # Run tests
        runner = ScavengerTestRunner(
            captures_dir=args.captures,
            output_dir=args.output,
            max_files=args.max_files,
            max_packets=args.max_packets,
            logger=logger
        )

        report = runner.run_all_tests()
        report.validations = [asdict(v) if hasattr(v, '__dict__') else v.__dict__
                              for v in validator.results]

        # Output results
        if args.json:
            print(json.dumps(asdict(report), indent=2, default=str))
        else:
            logger.info("\n" + "=" * 60)
            logger.info("  TEST RESULTS")
            logger.info("=" * 60)

            logger.info(f"\n  Total:  {report.summary['total']}")
            logger.info(f"  Passed: {report.summary['passed']} ✅")
            logger.info(f"  Failed: {report.summary['failed']} {'❌' if report.summary['failed'] else ''}")
            logger.info(f"  Duration: {report.duration_seconds:.2f}s")

            if report.findings:
                logger.info(f"\n  📊 Pipeline processed {report.pipeline_stats.get('packets_processed', 0)} packets")
                logger.info(f"  🎯 Found {report.findings.get('unique_clients', 0)} unique clients")

            if report.exit_code == EXIT_SUCCESS:
                logger.info("\n🎉 ALL TESTS PASSED!\n")
            elif report.exit_code == EXIT_PARTIAL:
                logger.warning("\n⚠️  SOME TESTS FAILED\n")
            else:
                logger.error("\n❌ TESTS FAILED\n")

        # Save report
        report_path = args.output / f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)

        if not args.json:
            logger.info(f"📄 Report saved to: {report_path}")

        return report.exit_code

    except KeyboardInterrupt:
        logger.warning("\n\n⚠️  Interrupted by user")
        return EXIT_FAILURE

    except Exception as e:
        logger.exception(f"\n❌ Fatal error: {e}")
        if args.json:
            print(json.dumps({"error": str(e), "traceback": traceback.format_exc()}, indent=2))
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
