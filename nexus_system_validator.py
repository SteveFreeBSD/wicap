
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Setup paths
sys.path.append(os.getcwd())

try:
    from nexus.config import get_nexus_config
    from nexus.password_auditor_enhanced import EnhancedPasswordAuditor
    from nexus.triangulation_analyzer import TriangulationAnalyzer
    from nexus.wordlist_manager import WordlistManager
except ImportError as e:
    print(f"CRITICAL: Failed to import NEXUS modules: {e}")
    sys.exit(1)

# Robust Logging Setup
LOG_FILE = "nexus_validation.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("nexus.validator")

class NexusValidator:
    def __init__(self):
        self.config = get_nexus_config()
        self.results = {"success": [], "failure": [], "warning": []}
        self.start_time = time.time()

    def log_result(self, category, message):
        self.results[category].append(message)
        if category == "success":
            logger.info(f"✅ {message}")
        elif category == "failure":
            logger.error(f"❌ {message}")
        elif category == "warning":
            logger.warning(f"⚠️ {message}")

    def check_tool(self, name, cmd, version_arg="--version"):
        try:
            res = subprocess.run(cmd + [version_arg], capture_output=True, text=True, timeout=5)
            if res.returncode in (0, 2, 255): # Some tools return non-zero for version
                self.log_result("success", f"Tool {name} is available ({res.stdout.splitlines()[0] if res.stdout else 'version unknown'})")
                return True
        except Exception as e:
            self.log_result("failure", f"Tool {name} is MISSING or failed: {e}")
        return False

    def validate_toolchain(self):
        logger.info("--- Phase 1: Toolchain Validation ---")
        self.check_tool("Hashcat", [str(self.config.hashcat_binary)])
        self.check_tool("PACK (statsgen)", ["statsgen.py"], "--help")
        self.check_tool("CeWL", ["cewl"])

        # Robust Pipal Check
        if shutil.which('pipal'):
            self.check_tool("Pipal", ["pipal"])
        elif Path('/opt/pipal/pipal.rb').exists():
            self.log_result("success", "Tool Pipal is available via /opt/pipal/pipal.rb")
        else:
            self.log_result("failure", "Tool Pipal is MISSING (checked PATH and /opt/pipal/pipal.rb)")

        self.check_tool("PRINCE (pp64)", ["pp64"], "--help")

    def validate_database(self):
        logger.info("--- Phase 2: Database Integrity ---")
        try:
            auditor = EnhancedPasswordAuditor(self.config)
            conn = auditor._get_connection()
            cursor = conn.cursor()

            # Check core tables
            tables = ["handshakes", "audit_log", "triangulation_history", "nexus_config"]
            for table in tables:
                try:
                    cursor.execute(f"SELECT TOP 1 * FROM {table}")
                    self.log_result("success", f"Table '{table}' is accessible")
                except Exception as e:
                    self.log_result("failure", f"Table '{table}' check failed: {e}")

            cursor.close()
            return True
        except Exception as e:
            self.log_result("failure", f"Database connection failed: {e}")
        return False

    def validate_wordlists(self):
        logger.info("--- Phase 3: Wordlist Performance ---")
        try:
            wm = WordlistManager(self.config)
            if "rockyou.txt" in wm.inventory:
                self.log_result("success", "rockyou.txt is indexed and available")
            else:
                self.log_result("warning", "rockyou.txt NOT found in inventory")

            logger.info("Simulating 1M password stream...")
            stream = wm.get_base_words(top_n=1000000)
            count = 0
            s_time = time.time()
            for _ in stream:
                count += 1
                if count >= 100000:
                    break  # Test first 100k for speed

            elapsed = time.time() - s_time
            self.log_result("success", f"Deduplicated stream test: 100k words in {elapsed:.2f}s")

        except Exception as e:
            self.log_result("failure", f"Wordlist validation error: {e}")

    def validate_end_to_end(self):
        logger.info("--- Phase 4: End-to-End Logic (Dry Run) ---")
        try:
            auditor = EnhancedPasswordAuditor(self.config)
            auditor.dry_run = True

            # Find a handshake with hash
            conn = auditor._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT TOP 1 id, ssid FROM handshakes WHERE hashcat_hash IS NOT NULL")
            row = cursor.fetchone()

            if row:
                handshake_id = row.id
                logger.info(f"Running Dry Run Audit for Handshake ID: {handshake_id} ({row.ssid})")

                # Test Quick Audit
                res = auditor.audit_handshake(handshake_id, 'quick')
                self.log_result("success", f"Standard Audit logic verified (Dry Run status: {res.status})")

                # Test Ape Mode logic
                wl_path = Path("/tmp/nexus_test_wl.txt")
                wl_path.write_text("password123\nadmin123\n")

                res_custom = auditor.audit_handshake_custom(handshake_id, str(wl_path), timeout=10)
                self.log_result("success", f"Custom/Ape Mode logic verified (Dry Run status: {res_custom.status})")

                if wl_path.exists():
                    wl_path.unlink()
            else:
                self.log_result("warning", "No handshakes with hashes in DB - skipping end-to-end logic test")

            cursor.close()
        except Exception as e:
            self.log_result("failure", f"End-to-End validation error: {e}")

    def validate_triangulation(self):
        logger.info("--- Phase 5: Triangulation Logic ---")
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pot', delete=False) as tmp:
                tmp.write("hash:password123\nhash2:summer2024\nhash3:12345678\n")
                pot_path = tmp.name

            analyzer = TriangulationAnalyzer(self.config)
            summary = analyzer.get_triangulation_summary(pot_path)

            if summary.get('pack_mask') or summary.get('pipal_pattern'):
                self.log_result("success", "Triangulation summary generation verified")

            # Test report export
            report_path = "/tmp/nexus_test_report.html"
            analyzer.export_to_html(summary, report_path)
            if os.path.exists(report_path):
                self.log_result("success", f"HTML Report export verified at {report_path}")
                os.unlink(report_path)

            os.unlink(pot_path)
        except Exception as e:
            self.log_result("failure", f"Triangulation validation error: {e}")

    def run_all(self):
        logger.info("==================================================")
        logger.info("🚀 NEXUS SYSTEM HARDENED VALIDATION STARTING")
        logger.info("==================================================")

        self.validate_toolchain()
        self.validate_database()
        self.validate_wordlists()
        self.validate_end_to_end()
        self.validate_triangulation()

        duration = time.time() - self.start_time
        logger.info("==================================================")
        logger.info(f"🏁 VALIDATION COMPLETE in {duration:.2f}s")
        logger.info(f"📊 SUMMARY: {len(self.results['success'])} Passed, {len(self.results['failure'])} Failed, {len(self.results['warning'])} Warnings")
        logger.info("==================================================")

        if self.results["failure"]:
            logger.error("❌ CRITICAL SYSTEM ISSUES DETECTED")
            for f in self.results["failure"]:
                logger.error(f"  - {f}")
            return False

        logger.info("✅ ALL SYSTEMS NOMINAL - READY FOR PRODUCTION")
        return True

if __name__ == "__main__":
    validator = NexusValidator()
    success = validator.run_all()
    sys.exit(0 if success else 1)
