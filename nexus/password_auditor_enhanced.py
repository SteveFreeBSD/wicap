"""
NEXUS Enhanced Password Auditor (Ape-Moon Mode)

Next-level white-hat auditing with:
- Priority-based handshake queue management
- Time-boxed multi-round attack strategy (Quick -> Digits -> Standard -> Deferred -> Ape)
- Deep analysis with custom wordlist generation
- Dwell file monitoring integration
- ASCII Dashboard and ethical logging
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import NexusConfig, get_nexus_config
from .password_auditor import CrackResult, CrackStatus, PasswordAuditor, PasswordWeakness
from .strategy_engine import StrategyEngine
from .triangulation_analyzer import TriangulationAnalyzer
from .wordlist_manager import WordlistManager

logger = logging.getLogger('nexus.auditor_enhanced')


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PriorityHandshake:
    """Handshake with computed priority for audit queue."""
    id: int
    bssid: str
    ssid: str | None
    priority_score: int
    avg_rssi: int | None
    is_hidden: bool
    is_wpa3: bool
    capture_time: datetime
    defer_count: int
    attack_rounds: int
    escalation_level: int
    hashcat_hash: str


@dataclass
class WeaknessReport:
    """Enhanced weakness analysis with crackability index."""
    weakness: PasswordWeakness
    crackability_index: int  # 0-100 combined score
    attack_vector_recommendation: str
    hardening_steps: list[str]
    ssid: str | None = None
    bssid: str | None = None


@dataclass
class PrioritizedAuditResult:
    """Result of prioritized audit session."""
    total_queued: int
    total_audited: int
    cracked: int
    exhausted: int
    deferred: int
    total_duration_sec: float
    cracked_results: list[CrackResult] = field(default_factory=list)

# ═══════════════════════════════════════════════════════════════════════════════
# Common patterns for Priority Scoring
# ═══════════════════════════════════════════════════════════════════════════════

COMMON_SSID_PATTERNS = {
    'default': ['linksys', 'netgear', 'dlink', 'belkin', 'default', 'setup', 'tp-link'],
    'isp': ['xfinity', 'spectrum', 'att', 'verizon', 'comcast', 'frontier'],
    'guest': ['guest', 'visitor', 'public', 'free'],
    'mobile': ['iphone', 'android', 'galaxy', 'hotspot'],
}


class EnhancedPasswordAuditor(PasswordAuditor):
    """
    Enhanced password auditor with prioritization, deferred queue,
    capture pipeline integration, and 'Ape-Moon' features.
    """

    def __init__(self, config: NexusConfig | None = None):
        super().__init__(config)
        self.dry_run = False
        self.wordlist_manager = WordlistManager(self.config)
        self.triangulation_analyzer = TriangulationAnalyzer(self.config)
        self.strategy_engine = StrategyEngine()
        self.session_id = str(datetime.now().timestamp())

    # ═══════════════════════════════════════════════════════════════════════════
    # Priority Scoring
    # ═══════════════════════════════════════════════════════════════════════════

    def compute_priority_score(
        self,
        ssid: str | None,
        avg_rssi: int | None,
        is_hidden: bool,
        handshake_count: int = 1
    ) -> int:
        """Compute priority score (0-100)."""
        score = 50  # Base score

        # Signal strength
        if avg_rssi is not None:
            if avg_rssi > -50:
                score += 35
            elif avg_rssi > -60:
                score += 30
            elif avg_rssi > -70:
                score += 15

        # Hidden
        if is_hidden:
            score += 15

        # SSID Patterns
        if ssid:
            ssid_lower = ssid.lower()
            for category, patterns in COMMON_SSID_PATTERNS.items():
                for p in patterns:
                    if p in ssid_lower:
                        boost = {'default': 25, 'isp': 20, 'guest': 15, 'mobile': 10}
                        score += boost.get(category, 5)
                        break

        # Data density
        if handshake_count > 1:
            score += min(10, handshake_count * 3)

        return min(100, max(0, score))

    def _update_handshake_status(
        self,
        handshake_id: int,
        status: CrackStatus,
        password: str | None = None,
        crack_time: float | None = None,
        method: str | None = None
    ) -> None:
        """Update status and trigger triangulation if cracked."""
        super()._update_handshake_status(handshake_id, status, password, crack_time, method)

        if status == CrackStatus.CRACKED:
            logger.info(f"🎯 Automated Triangulation triggered for handshake {handshake_id}")
            try:
                summary = self.triangulation_analyzer.get_triangulation_summary(str(self.potfile))
                self.triangulation_analyzer.save_triangulation_to_db(summary, str(self.potfile), self._get_connection())
            except Exception as e:
                logger.error(f"Automated triangulation failed: {e}")

    # ═══════════════════════════════════════════════════════════════════════════
    # Prioritized Audit Queue
    # ═══════════════════════════════════════════════════════════════════════════

    def get_pending_prioritized(self, limit: int = 20) -> list[PriorityHandshake]:
        """Get pending handshakes sorted by priority score.

        Args:
            limit: Maximum number of handshakes to return (1-100, clamped)

        Returns:
            List of PriorityHandshake objects sorted by priority score
        """
        # Sanitize limit to prevent injection and bound range
        limit = max(1, min(100, int(limit)))
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            query = f"""
                SELECT TOP ({limit})
                    id, bssid, ssid,
                    COALESCE(priority_score, 50) as priority_score,
                    avg_rssi,
                    CASE WHEN ssid IS NULL OR ssid = '' THEN 1 ELSE 0 END as is_hidden,
                    0 as is_wpa3,
                    capture_time,
                    COALESCE(defer_count, 0) as defer_count,
                    COALESCE(attack_rounds_completed, 0) as attack_rounds,
                    COALESCE(escalation_level, 0) as escalation_level,
                    hashcat_hash
                FROM handshakes
                WHERE crack_status IN ('pending', 'running')
                  AND hashcat_hash IS NOT NULL
                  AND (defer_count IS NULL OR defer_count < 3)
                ORDER BY
                    COALESCE(priority_score, 50) DESC,
                    capture_time DESC
            """
            cursor.execute(query)

            results = []
            for row in cursor.fetchall():
                results.append(PriorityHandshake(
                    id=row.id,
                    bssid=row.bssid,
                    ssid=row.ssid,
                    priority_score=row.priority_score,
                    avg_rssi=row.avg_rssi,
                    is_hidden=bool(row.is_hidden),
                    is_wpa3=bool(row.is_wpa3),
                    capture_time=row.capture_time,
                    defer_count=row.defer_count,
                    attack_rounds=row.attack_rounds,
                    escalation_level=row.escalation_level,
                    hashcat_hash=row.hashcat_hash,
                ))
            return results
        finally:
            cursor.close()

    def get_deferred_handshakes(self, limit: int = 50) -> list[PriorityHandshake]:
        """Get handshakes marked as deferred."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(f"""
                SELECT TOP ({limit})
                    id, bssid, ssid,
                    COALESCE(priority_score, 50) as priority_score,
                    avg_rssi,
                    CASE WHEN ssid IS NULL OR ssid = '' THEN 1 ELSE 0 END as is_hidden,
                    0 as is_wpa3,
                    capture_time,
                    COALESCE(defer_count, 0) as defer_count,
                    COALESCE(attack_rounds_completed, 0) as attack_rounds,
                    COALESCE(escalation_level, 0) as escalation_level,
                    hashcat_hash
                FROM handshakes
                WHERE crack_status = 'deferred' AND hashcat_hash IS NOT NULL
                ORDER BY priority_score DESC, last_attempt ASC
            """)
            return [PriorityHandshake(
                id=r.id, bssid=r.bssid, ssid=r.ssid,
                priority_score=r.priority_score, avg_rssi=r.avg_rssi,
                is_hidden=bool(r.is_hidden), is_wpa3=bool(r.is_wpa3),
                capture_time=r.capture_time, defer_count=r.defer_count,
                attack_rounds=r.attack_rounds, escalation_level=r.escalation_level,
                hashcat_hash=r.hashcat_hash
            ) for r in cursor.fetchall()]
        finally:
            cursor.close()

    # ═══════════════════════════════════════════════════════════════════════════
    # Audit Execution
    # ═══════════════════════════════════════════════════════════════════════════

    def prioritize_and_audit_pending(self, limit=20, max_total_time_sec=7200, dry_run=False, triangulate=False) -> PrioritizedAuditResult:
        self.dry_run = dry_run
        start_time = time.time()
        queue = self.get_pending_prioritized(limit)

        if not queue:
            return PrioritizedAuditResult(0,0,0,0,0,0.0)

        logger.info(f"📋 Loaded {len(queue)} targets for prioritized audit")
        if triangulate:
            logger.info("📐 Triangulation enabled: analyzing previous cracks for optimal vectors")

        total_queued = len(queue)
        total_audited = 0
        cracked = 0
        exhausted = 0
        deferred = 0
        cracked_results = []

        # Pre-triangulate if requested
        tri_data = {}
        if triangulate and self.is_pack_available() and self.is_pipal_available():
            tri_data = self.triangulation_analyzer.get_triangulation_summary(str(self.potfile))

        for hs in queue:
            # Check total session time
            elapsed = time.time() - start_time
            if elapsed > max_total_time_sec:
                logger.warning(f"⏰ Session timeout ({max_total_time_sec}s). Deferring remaining {total_queued - total_audited} targets.")
                break

            logger.info(f"\n⚡ Target: {hs.ssid or '[HIDDEN]'} ({hs.bssid}) | Prio: {hs.priority_score}")

            # Pass tri_data to rounds if we want to use it
            result, new_status = self._run_timed_rounds(hs, hs.attack_rounds, max_total_time_sec - elapsed, tri_data)
            total_audited += 1

            if new_status == 'cracked':
                cracked += 1
                cracked_results.append(result)
                logger.info(f"   ✅ CRACKED: {result.password}")
            elif new_status == 'exhausted':
                exhausted += 1
                logger.info("   ⏳ Exhausted")
            elif new_status == 'deferred':
                deferred += 1
                logger.info("   📌 Deferred")

        return PrioritizedAuditResult(
            len(queue), total_audited, cracked, exhausted, deferred,
            time.time() - start_time, cracked_results
        )

    def _run_timed_rounds(self, hs: PriorityHandshake, start_round: int, max_time: float, tri_data: dict[str, Any] | None = None) -> tuple[CrackResult | None, str]:
        conn = self._get_connection()
        cursor = conn.cursor()

        result = None
        new_status = 'pending'
        current_round = start_round
        round_start_global = time.time()

        # GENERATE DYNAMIC PLAN
        plan = self.strategy_engine.generate_plan(hs.ssid, hs.bssid, hs.priority_score)
        logger.info(f"   🧠 Intelligence Engine: Generated {len(plan)} tailored attack rounds")

        try:
            for round_idx, r_conf in enumerate(plan):
                if round_idx < start_round:
                    continue

                # Check priority threshold
                if r_conf.min_priority > 0 and hs.priority_score < r_conf.min_priority:
                    continue

                if time.time() - round_start_global > max_time:
                    new_status = 'deferred'
                    break

                logger.info(f"   🥊 Round {round_idx+1}: {r_conf.description}")

                if self.dry_run:
                    logger.info(f"   [DRY RUN] Simulating {r_conf.name}")
                    current_round = round_idx + 1
                    continue

                # Prepare Strategy & Execution
                if r_conf.strategy == 'ape_mode':
                    wordlist = self.wordlist_manager.create_hybrid_list(priority=100, ssid=hs.ssid, bssid=hs.bssid)
                    custom_mask = tri_data.get('pack_mask') if tri_data else None
                    if custom_mask:
                        logger.info(f"   📐 Injecting PACK-triangulated mask: {custom_mask}")

                    result = self.audit_handshake_custom(
                        hs.id,
                        wordlist_path=str(wordlist),
                        timeout=r_conf.timeout_sec,
                        use_prince=True,
                        rules_file='/usr/share/hashcat/rules/augmented_onerule.rule',
                        mask=custom_mask
                    )

                elif r_conf.strategy == 'mask':
                    # Vendor specific masks
                    mask_val = r_conf.config.get('mask')
                    logger.info(f"   🎭 Using Vendor Mask: {mask_val}")
                    # Create empty wordlist for mask attack
                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                        pass
                    result = self.audit_handshake_custom(
                        hs.id,
                        wordlist_path=f.name,
                        timeout=r_conf.timeout_sec,
                        mask=mask_val
                    )
                    os.unlink(f.name)

                elif r_conf.strategy == 'custom_words':
                    # Semantic wordlist
                    words = r_conf.config.get('words', [])
                    logger.info(f"   📚 Semantic Dictionary: {words}")

                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                        f.write('\n'.join(words))
                        wl_path = f.name

                    # Run with best64 rule to mutate semantic words
                    result = self.audit_handshake_custom(
                        hs.id,
                        wordlist_path=wl_path,
                        timeout=r_conf.timeout_sec,
                        rules_file='/usr/share/hashcat/rules/best64.rule'
                    )
                    os.unlink(wl_path)

                elif r_conf.strategy == 'quick':
                    wordlist = self.wordlist_manager.create_hybrid_list(priority=20, ssid=hs.ssid, bssid=hs.bssid)
                    result = self.audit_handshake_custom(hs.id, wordlist_path=str(wordlist), timeout=r_conf.timeout_sec)
                    if result.status != CrackStatus.CRACKED:
                         result = self.audit_handshake(hs.id, 'quick')

                elif r_conf.strategy == 'year_hybrid':
                    # Year-based attack
                    years = r_conf.config.get('years', [])
                    logger.info(f"   📅 Year Hybrid: Checking {len(years)} years for {hs.ssid}")

                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                        if hs.ssid:
                            for y in years:
                                f.write(f"{hs.ssid}{y}\n")
                                f.write(f"{hs.ssid.lower()}{y}\n")
                                f.write(f"{hs.ssid.upper()}{y}\n")
                                f.write(f"{y}{hs.ssid}\n")
                            # Add just years too? Maybe too weak.
                        else:
                            f.write('\n'.join(years))
                        wl_path = f.name

                    # Run with best64 rule for variations
                    result = self.audit_handshake_custom(
                        hs.id,
                        wordlist_path=wl_path,
                        timeout=r_conf.timeout_sec,
                        rules_file='/usr/share/hashcat/rules/best64.rule'
                    )
                    os.unlink(wl_path)

                else:
                    # 'digits_only', 'standard' etc mapped to internal methods?
                    # PasswordAuditor base class handles these string keys if implementation exists
                    # Check base class support. 'digits_only' is supported?
                    # If not, implement fallback.
                    if r_conf.strategy == 'digits_only':
                        result = self.audit_handshake(hs.id, 'digits_only')
                    elif r_conf.strategy == 'standard':
                        result = self.audit_handshake(hs.id, 'standard')
                    else:
                        result = self.audit_handshake(hs.id, r_conf.strategy)

                current_round = round_idx + 1
                self._log_audit_event(hs, r_conf.name, result)

                if result and result.status == CrackStatus.CRACKED:
                    new_status = 'cracked'
                    break

            if new_status == 'pending':
                # If we finished logic but didn't crack, assume defer/exhaust
                # StrategyEngine doesn't append explicit 'defer'.
                # If all rounds done, marked as exhausted? Or deferred?
                # User wants "seamless". If failed all tailored, maybe defer.
                new_status = 'exhausted'

            cursor.execute("""
                UPDATE handshakes
                SET crack_status = ?, attack_rounds_completed = ?,
                    last_attempt = ?, defer_count = CASE WHEN ? = 'deferred' THEN COALESCE(defer_count,0)+1 ELSE defer_count END
                WHERE id = ?
            """, (new_status, current_round, datetime.now(), new_status, hs.id))
            conn.commit()

        except Exception as e:
            logger.error(f"Audit error: {e}")
            new_status = 'failed'
            conn.rollback()
        finally:
            cursor.close()

        return result, new_status

    def _log_audit_event(self, hs: PriorityHandshake, strategy: str, result: CrackResult | None):
        """Write high-level stats to audit_log."""
        if self.dry_run or not result:
            return
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log
                (session_id, audit_mode, handshake_id, priority_score, status, rounds_attempted, duration_sec, strategy_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.session_id, 'prioritized', hs.id, hs.priority_score,
                result.status.value, hs.attack_rounds, result.crack_time_sec, strategy
            ))
            conn.commit()
            cursor.close()
        except Exception as e:
            logger.warning(f"Failed to write audit log: {e}")

    def audit_handshake_custom(
        self,
        handshake_id: int,
        wordlist_path: str,
        timeout: int,
        use_prince: bool = False,
        rules_file: str | None = None,
        mask: str | None = None
    ) -> CrackResult:
        """
        Run a real hashcat audit using specific wordlists/masks.
        """
        # 1. Fetch Hash
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT bssid, ssid, hashcat_hash FROM handshakes WHERE id = ?", (handshake_id,))
            row = cursor.fetchone()
            if not row:
                return CrackResult(handshake_id, '', None, CrackStatus.FAILED, "Handshake not found")
            bssid, ssid, hash_val = row.bssid, row.ssid, row.hashcat_hash
        finally:
            cursor.close()

        # 2. Prepare Command
        with tempfile.NamedTemporaryFile(mode='w', suffix='.22000', delete=False) as f:
            f.write(hash_val + "\n")
            hash_file = f.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.out', delete=False) as out_f:
            out_file = out_f.name

        hc_cmd = [
            str(self.hashcat_path), '-m', '22000',
            '-a', '3' if mask else '0',
            '--potfile-path', str(self.potfile),
            '--runtime', str(timeout),
            '--outfile-format', '2', '--quiet', '-d', '1', '--force',
            '-o', out_file, hash_file
        ]

        if mask:
            hc_cmd.append(mask)
        elif not use_prince:
            hc_cmd.append(wordlist_path)

        if rules_file and not mask: # Rules only for dict
            if Path(rules_file).exists():
                hc_cmd.extend(['-r', rules_file])

        if self.dry_run:
            logger.info(f"   🦍 [DRY RUN] Would execute: {' '.join(hc_cmd)}")
            if os.path.exists(hash_file):
                os.unlink(hash_file)
            if os.path.exists(out_file):
                os.unlink(out_file)
            return CrackResult(handshake_id, bssid, ssid, CrackStatus.SKIPPED, method='dry_run')

        # 3. Execution
        logger.info(f"   🚀 Starting real hashcat ({'PRINCE' if use_prince else 'Dict' if not mask else 'Mask'})")
        start_time = time.time()
        try:
            if use_prince and not mask:
                pp_bin = shutil.which('pp64') or shutil.which('princeprocessor')
                if not pp_bin:
                    logger.warning("pp64 not found, falling back to direct")
                    hc_cmd.append(wordlist_path)
                    proc = subprocess.run(hc_cmd, capture_output=True, text=True, timeout=timeout+30)
                else:
                    with open(wordlist_path, 'rb') as wl_f:
                        pp_proc = subprocess.Popen([pp_bin], stdin=wl_f, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                        proc = subprocess.run(hc_cmd, stdin=pp_proc.stdout, capture_output=True, text=True, timeout=timeout+30)
                        pp_proc.terminate()
            else:
                proc = subprocess.run(hc_cmd, capture_output=True, text=True, timeout=timeout+30)

            # Debug Output
            if proc.returncode != 0:
                logger.warning(f"Hashcat Non-Zero Exit: {proc.returncode}")
            logger.info(f"Hashcat STDOUT: {proc.stdout[:500]}...")
            logger.info(f"Hashcat STDERR: {proc.stderr[:500]}...")

            # 4. Result Parsing
            cracked_password = None
            if os.path.exists(out_file):
                with open(out_file) as f:
                    line = f.read().strip()
                    if line:
                        cracked_password = line.split(':')[-1]
                os.unlink(out_file)

            status = CrackStatus.CRACKED if cracked_password else CrackStatus.EXHAUSTED

            # Update DB
            self._update_handshake_status(
                handshake_id, status, cracked_password,
                time.time() - start_time, 'prince' if use_prince else 'mask' if mask else 'custom'
            )

            return CrackResult(
                handshake_id, bssid, ssid, status, cracked_password,
                time.time() - start_time, 'custom', proc.stdout or proc.stderr
            )

        except Exception as e:
            logger.error(f"Execution error: {e}")
            return CrackResult(handshake_id, bssid, ssid, CrackStatus.FAILED, hashcat_output=str(e))
        finally:
            if os.path.exists(hash_file):
                os.unlink(hash_file)

    # ═══════════════════════════════════════════════════════════════════════════
    # Dashboard & Reporting
    # ═══════════════════════════════════════════════════════════════════════════

    def compute_crackability_index(self, weakness: PasswordWeakness, priority_score: int = 50) -> int:
        """Combined crackability index (0-100)."""
        weakness_contrib = weakness.weakness_score * 0.4
        priority_contrib = priority_score * 0.2

        if weakness.entropy_score < 2.0:
            entropy_contrib = 20
        elif weakness.entropy_score < 3.0:
            entropy_contrib = 15
        elif weakness.entropy_score < 4.0:
            entropy_contrib = 10
        else:
            entropy_contrib = 5

        if weakness.crack_time_seconds < 60:
            time_contrib = 20
        elif weakness.crack_time_seconds < 3600:
            time_contrib = 15
        elif weakness.crack_time_seconds < 86400:
            time_contrib = 10
        elif weakness.crack_time_seconds < 86400 * 365:
            time_contrib = 5
        else:
            time_contrib = 0

        return min(100, int(weakness_contrib + priority_contrib + entropy_contrib + time_contrib))

    def analyze_with_crackability(self, password: str, ssid: str | None = None, bssid: str | None = None, priority_score: int = 50) -> WeaknessReport:
        # Triangulation enhancement
        tri_data = {}
        if self.is_pack_available() and self.is_pipal_available():
            tri_data = self.triangulation_analyzer.get_triangulation_summary(str(self.potfile))

        weakness = self.analyze_password_weakness(
            password, ssid, bssid, triangulation_data=tri_data
        )

        # Increase crackability score if triangulation shows high risk
        crackability = int(weakness.weakness_score)
        if tri_data.get('tri_score'):
            crackability = min(100, crackability + int(tri_data['tri_score'] / 2))

        return WeaknessReport(
            weakness=weakness,
            crackability_index=crackability,
            attack_vector_recommendation=self.get_attack_vector_recommendation(weakness),
            hardening_steps=self.get_hardening_steps(weakness, bssid),
            ssid=ssid,
            bssid=bssid
        )

    def get_attack_vector_recommendation(self, weakness: PasswordWeakness) -> str:
        patterns = weakness.has_patterns
        if weakness.is_common_password or weakness.is_rockyou_match:
            return "Direct dictionary attack - password in common wordlists"
        if weakness.charset_count == 1:
            if weakness.charset_digits:
                return f"Mask attack: ?d x {weakness.length} (numeric only)"
            if weakness.charset_lowercase:
                return f"Mask attack: ?l x {weakness.length} (lowercase only)"
        if 'keyboard_walk' in patterns:
            return "Keyboard walk variants + common mutations"
        if 'ssid_in_password' in patterns or 'ssid_similarity' in patterns:
            return "SSID-based wordlist with common modifiers"
        if 'year' in patterns:
            return "Word + year hybrid attack (e.g., word2024)"
        if 'leetspeak' in patterns:
            return "Dictionary + leetspeak rules (e.g., best64.rule)"
        if weakness.length <= 8:
            return "Brute force feasible for 8-char passwords"
        return "Standard dictionary + rules attack"

    def get_hardening_steps(self, weakness: PasswordWeakness, bssid: str | None = None) -> list[str]:
        steps = []
        if weakness.is_common_password or weakness.is_rockyou_match:
            steps.append("🔴 CRITICAL: Change password immediately - it's in public wordlists")
        if weakness.weakness_score >= 70:
            steps.append("🔴 Generate new password with: openssl rand -base64 24")
        if weakness.length < 16:
            steps.append("Use 16+ character passphrase (e.g., 'correct-horse-battery-staple')")
        if weakness.entropy_score < 3.0:
            steps.append("Increase randomness - avoid dictionary words and patterns")
        if 'ssid_in_password' in weakness.has_patterns:
            steps.append("Never include network name in password")

        steps.append("Enable WPA3-SAE if router supports it")
        steps.append("Enable Protected Management Frames (PMF/802.11w)")
        return steps

    def get_top_weak_passwords(self, limit: int = 10) -> list[WeaknessReport]:
        """Get top N weakest cracked passwords by crackability index."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(f"""
                SELECT TOP ({limit})
                    id, bssid, ssid, cracked_password,
                    COALESCE(priority_score, 50) as priority_score
                FROM handshakes
                WHERE crack_status = 'cracked' AND cracked_password IS NOT NULL
                ORDER BY capture_time DESC
            """)
            rows = cursor.fetchall()
            reports = []
            for row in rows:
                reports.append(self.analyze_with_crackability(
                    row.cracked_password, row.ssid, row.bssid, row.priority_score
                ))
            reports.sort(key=lambda x: x.crackability_index, reverse=True)
            return reports[:limit]
        finally:
            cursor.close()

    def report_dashboard(self) -> None:
        """Generate ASCII dashboard."""
        conn = self._get_connection()
        cursor = conn.cursor()

        print("\n" + "="*60)
        print(" 🦍 NEXUS APE-MOON SECURITY DASHBOARD")
        print("="*60)

        cursor.execute("SELECT COUNT(*), COUNT(CASE WHEN crack_status='cracked' THEN 1 END) FROM handshakes")
        row = cursor.fetchone()
        total, cracked = row[0], row[1]
        cursor.close()

        success_rate = (cracked/total*100) if total else 0

        print(f"\n📊 TOTAL NETWORKS: {total}")
        print(f"🔓 SUCCESSFULLY AUDITED: {cracked} ({success_rate:.1f}%)")

        print("\n🏆 TOP 5 WEAKEST DETECTED")
        top_weak = self.get_top_weak_passwords(5)
        for i, r in enumerate(top_weak):
            bars = "█" * int(min(100, r.crackability_index) / 10)
            print(f" {i+1}. {r.weakness.password:<16} {bars} ({r.crackability_index}/100)")
            print(f"    Target: {r.ssid or 'Unknown'}")

        cursor = conn.cursor()
        cursor.execute("SELECT crack_status, COUNT(*) FROM handshakes GROUP BY crack_status")
        status_counts = dict(cursor.fetchall())
        cursor.close()

        print(f"\n📥 QUEUE: Pending: {status_counts.get('pending',0)} | Deferred: {status_counts.get('deferred',0)} | Exhausted: {status_counts.get('exhausted',0)}")

        print("\n" + "="*60 + "\n")


# Dwell watcher is maintained in nexus/dwell_watcher.py to avoid duplicate logic.


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Main
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description='NEXUS Enhanced Auditor (Ape-Mode)')
    subparsers = parser.add_subparsers(dest='command')

    # Audit Prioritized
    p_audit = subparsers.add_parser('prioritized')
    p_audit.add_argument('--limit', type=int, default=20)
    p_audit.add_argument('--max-time', type=int, default=7200)
    p_audit.add_argument('--dry-run', action='store_true')
    p_audit.add_argument('--triangulate', action='store_true', help='Use triangulation to optimize attack')

    # Audit Deferred

    # Audit Deferred
    subparsers.add_parser('deferred')

    # Dashboard
    subparsers.add_parser('dashboard')

    # Watch Daemon
    subparsers.add_parser('watch')

    # Triangulation
    p_tri = subparsers.add_parser('triangulation')
    p_tri.add_argument('--potfile', type=str, help='Path to potfile to analyze')
    p_tri.add_argument('--export-html', type=str, help='Path to export HTML report')

    args = parser.parse_args()
    config = get_nexus_config()
    auditor = EnhancedPasswordAuditor(config)

    if args.command == 'prioritized':
        auditor.prioritize_and_audit_pending(args.limit, args.max_time, args.dry_run, args.triangulate)
    elif args.command == 'dashboard':
        auditor.report_dashboard()
    elif args.command == 'watch':
        from .dwell_watcher import DwellWatcher
        watcher = DwellWatcher(config)
        watcher.watch(interval=300)
    elif args.command == 'triangulation':
        potfile = args.potfile or str(config.hashcat_potfile)
        print(f"\n📐 NEXUS TRIANGULATION REPORT: {potfile}")
        print("="*60)

        analyzer = TriangulationAnalyzer(config)
        report = analyzer.get_triangulation_summary(potfile)

        print("\n📊 STATISTICAL INSIGHTS (Pipal):")
        print(f"  Top Pattern:  {report['pipal_pattern']}")
        print(f"  Top 3 Lengths: {', '.join([f'{k} chars ({v}%)' for k,v in list(report['raw_pipal']['length_distribution'].items())[:3]])}")

        print("\n🦾 OPTIMAL ATTACK VECTORS (PACK):")
        print(f"  Suggested Hack Mask: {report['pack_mask']}")
        print(f"  Top 3 Masks:          {', '.join(report['raw_pack']['top_masks'][:3])}")

        print(f"\n🛡️  TRIANGULATION SCORE: {report['tri_score']}/100")
        if report['tri_score'] > 50:
            print("  ⚠️ ALERT: High predictability detected in current crack set.")

        if args.export_html:
            report_path = args.export_html
            if not report_path.endswith('.html'):
                report_path = os.path.join(report_path, 'triangulation_report.html')

            # Ensure dir exists
            report_dir = os.path.dirname(report_path)
            if report_dir:
                os.makedirs(report_dir, exist_ok=True)

            analyzer.export_to_html(report, report_path)
            print(f"\n📄 HTML Report exported to: {report_path}")

        print("\n" + "="*60 + "\n")
    else:
        parser.print_help()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
