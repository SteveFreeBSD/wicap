"""
NEXUS Password Auditor

Integrates with hashcat to perform password weakness testing on
captured WPA handshakes and PMKIDs.

Supports multiple attack strategies from quick checks to exhaustive brute-force.
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False

from .config import NexusConfig, get_nexus_config

logger = logging.getLogger('nexus.password_auditor')


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

class CrackStatus(str, Enum):
    """Status of password cracking attempt."""
    PENDING = 'pending'
    RUNNING = 'running'
    CRACKED = 'cracked'
    EXHAUSTED = 'exhausted'
    FAILED = 'failed'
    SKIPPED = 'skipped'


@dataclass
class AttackStrategy:
    """Configuration for a password attack strategy."""
    name: str
    description: str
    wordlists: list[str]
    rules: list[str] | None = None
    masks: list[str] | None = None
    timeout_sec: int = 60
    priority: int = 50


@dataclass
class CrackResult:
    """Result of a password cracking attempt."""
    handshake_id: int
    bssid: str
    ssid: str | None
    status: CrackStatus
    password: str | None = None
    crack_time_sec: float = 0.0
    method: str = ''
    strategy_used: str = ''
    hashcat_output: str = ''


@dataclass
class BatchCrackResult:
    """Result of batch password auditing."""
    total_attempted: int
    cracked: int
    exhausted: int
    failed: int
    skipped: int
    results: list[CrackResult] = field(default_factory=list)
    duration_sec: float = 0.0


@dataclass
class PasswordWeakness:
    """Deep analysis of a cracked password's weakness."""
    password: str
    length: int
    charset_lowercase: bool
    charset_uppercase: bool
    charset_digits: bool
    charset_special: bool
    charset_count: int
    is_dictionary_word: bool
    is_common_password: bool
    is_rockyou_match: bool  # Found in rockyou/top10k
    has_patterns: list[str]  # date, phone, keyboard walk, leetspeak, etc
    estimated_crack_time: str  # human readable
    weakness_score: int  # 0-100 (higher = weaker)
    recommendations: list[str]
    # Enhanced fields
    entropy_score: float = 0.0  # Shannon entropy bits/char
    entropy_total: float = 0.0  # Total entropy bits
    ssid_similarity: float = 0.0  # Jaro-Winkler to SSID (0-1)
    bssid_similarity: float = 0.0  # Jaro-Winkler to BSSID (0-1)
    zxcvbn_score: int = 0  # 0-4 strength (if available)
    zxcvbn_guesses: float = 0.0  # Estimated guesses needed
    crack_time_seconds: float = 0.0  # Estimated seconds to crack
    # Triangulation fields
    pack_mask_suggestion: str | None = None
    cewl_custom_count: int = 0
    pipal_top_pattern: str | None = None
    triangulation_score: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Strategies
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_STRATEGIES = {
    'quick': AttackStrategy(
        name='quick',
        description='Fast check for common WiFi passwords',
        wordlists=['common_wifi.txt', 'top10k.txt'],
        masks=['?d?d?d?d?d?d?d?d'],  # 8 digit
        timeout_sec=60,
        priority=100,
    ),
    'standard': AttackStrategy(
        name='standard',
        description='Standard audit with rockyou + rules',
        wordlists=['rockyou.txt'],
        rules=['best64.rule'],
        masks=[
            '?d?d?d?d?d?d?d?d',      # 8 digits
            '?d?d?d?d?d?d?d?d?d',   # 9 digits
            '?d?d?d?d?d?d?d?d?d?d', # 10 digits
        ],
        timeout_sec=3600,
        priority=50,
    ),
    'thorough': AttackStrategy(
        name='thorough',
        description='Deep analysis with multiple wordlists and rules',
        wordlists=['rockyou.txt'],
        rules=['best64.rule', 'dive.rule'],
        timeout_sec=86400,  # 24 hours
        priority=10,
    ),
    'digits_only': AttackStrategy(
        name='digits_only',
        description='Numeric-only passwords (common for WiFi)',
        wordlists=[],
        masks=[
            '?d?d?d?d?d?d?d?d',
            '?d?d?d?d?d?d?d?d?d',
            '?d?d?d?d?d?d?d?d?d?d',
        ],
        timeout_sec=1800,
        priority=90,
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
# Password Auditor Class
# ═══════════════════════════════════════════════════════════════════════════════

class PasswordAuditor:
    """
    Hashcat-powered WPA password weakness detection.

    Manages password cracking jobs, tracks results, and analyzes
    password weakness for security audits.
    """

    def __init__(self, config: NexusConfig | None = None):
        self.config = config or get_nexus_config()
        self._conn: pyodbc.Connection | None = None

        # Verify hashcat is available
        self.hashcat_path = Path(self.config.hashcat_binary)
        self.potfile = self.config.hashcat_potfile

        # Track running jobs
        self._active_processes: dict[int, subprocess.Popen] = {}

    def _get_connection(self) -> 'pyodbc.Connection':
        """Get or create SQL connection."""
        if not PYODBC_AVAILABLE:
            raise ImportError("pyodbc is required")
        needs_reconnect = self._conn is None
        if not needs_reconnect:
            try:
                needs_reconnect = getattr(self._conn, 'closed', False)
            except Exception:
                needs_reconnect = True
        if needs_reconnect:
            self._conn = pyodbc.connect(
                self.config.get_sql_connection_string(),
                autocommit=False
            )
        return self._conn

    def close(self) -> None:
        """Close SQL connection and cleanup."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def is_hashcat_available(self) -> bool:
        """Check if hashcat is installed and accessible."""
        try:
            result = subprocess.run(
                [str(self.hashcat_path), '--version'],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"hashcat not available: {e}")
            return False

    def get_hashcat_version(self) -> str | None:
        """Get hashcat version string."""
        try:
            result = subprocess.run(
                [str(self.hashcat_path), '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def is_pack_available(self) -> bool:
        """Check if PACK (statsgen.py) is available."""
        try:
            # Check for statsgen.py in PATH
            result = subprocess.run(['statsgen.py', '--help'], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def is_cewl_available(self) -> bool:
        """Check if CeWL is available."""
        try:
            result = subprocess.run(['cewl', '--version'], capture_output=True, timeout=5)
            # CeWL might return 2 for --version if not bundled, but let's check success or specific error
            return result.returncode in (0, 2)
        except Exception:
            return False

    def is_pipal_available(self) -> bool:
        """Check if Pipal is available."""
        if shutil.which('pipal'):
            return True
        return Path('/opt/pipal/pipal.rb').exists()

    def check_potfile(self, hash_value: str) -> str | None:
        """
        Check if a hash has already been cracked and is in the potfile.

        Returns the cracked password if found, None otherwise.
        """
        if not self.potfile.exists():
            return None

        try:
            # Hash in potfile is stored as: hash:password
            with open(self.potfile, errors='replace') as f:
                for line in f:
                    if line.startswith(hash_value + ':'):
                        parts = line.strip().split(':', 1)
                        if len(parts) == 2:
                            return parts[1]
        except Exception as e:
            logger.warning(f"Error reading potfile: {e}")

        return None

    def audit_handshake(
        self,
        handshake_id: int,
        strategy: str = 'quick'
    ) -> CrackResult:
        """
        Run password audit on a captured handshake.

        Args:
            handshake_id: Database ID of the handshake
            strategy: Attack strategy name

        Returns:
            CrackResult with outcome
        """
        # Get handshake from database
        handshake = self._get_handshake(handshake_id)
        if not handshake:
            return CrackResult(
                handshake_id=handshake_id,
                bssid='unknown',
                ssid=None,
                status=CrackStatus.FAILED,
                hashcat_output='Handshake not found',
            )

        bssid = handshake['bssid']
        ssid = handshake['ssid']
        hashcat_hash = handshake['hashcat_hash']

        if not hashcat_hash:
            return CrackResult(
                handshake_id=handshake_id,
                bssid=bssid,
                ssid=ssid,
                status=CrackStatus.FAILED,
                hashcat_output='No hashcat hash available',
            )

        # Check potfile first
        potfile_result = self.check_potfile(hashcat_hash)
        if potfile_result:
            self._update_handshake_status(handshake_id, CrackStatus.CRACKED, potfile_result)
            return CrackResult(
                handshake_id=handshake_id,
                bssid=bssid,
                ssid=ssid,
                status=CrackStatus.CRACKED,
                password=potfile_result,
                method='potfile',
                strategy_used=strategy,
            )

        # Get attack strategy
        attack = ATTACK_STRATEGIES.get(strategy, ATTACK_STRATEGIES['quick'])

        # Update status to running
        self._update_handshake_status(handshake_id, CrackStatus.RUNNING)

        # Run hashcat
        start_time = time.time()
        result = self._run_hashcat(hashcat_hash, attack)
        crack_time = time.time() - start_time

        # Update database with result
        if result.status == CrackStatus.CRACKED:
            self._update_handshake_status(
                handshake_id,
                CrackStatus.CRACKED,
                result.password,
                crack_time,
                result.method
            )
        elif result.status == CrackStatus.EXHAUSTED:
            self._update_handshake_status(handshake_id, CrackStatus.EXHAUSTED)
        else:
            self._update_handshake_status(handshake_id, CrackStatus.FAILED)

        result.handshake_id = handshake_id
        result.bssid = bssid
        result.ssid = ssid
        result.crack_time_sec = crack_time
        result.strategy_used = strategy

        return result

    def _run_hashcat(
        self,
        hash_value: str,
        attack: AttackStrategy
    ) -> CrackResult:
        """
        Execute hashcat with the given attack strategy.

        Returns CrackResult with outcome.
        """
        if not self.is_hashcat_available():
            return CrackResult(
                handshake_id=0,
                bssid='',
                ssid=None,
                status=CrackStatus.FAILED,
                hashcat_output='hashcat not available',
            )

        # Create temp file for hash
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            f.write(hash_value + '\n')
            hash_file = f.name

        # Use a separate temp file for output to avoid /dev/stdout pollution
        with tempfile.NamedTemporaryFile(mode='w', suffix='.out', delete=False) as out_f:
            out_file = out_f.name

        try:
            # Build hashcat command
            # hashcat mode 22000 = WPA-PBKDF2-PMKID+EAPOL
            cmd = [
                str(self.hashcat_path),
                '-m', '22000',
                '-a', '0',  # Dictionary attack
                '--potfile-path', str(self.potfile),
                '--runtime', str(attack.timeout_sec),
                '--outfile-format', '2',
                '--quiet',
                '-d', '1',
                '--force',
                '-o', out_file
            ]

            # Add Hash File (Must be after options)
            cmd.append(hash_file)

            # Add wordlists
            for wl in attack.wordlists:
                wl_path = self.config.wordlists_dir / wl
                if wl_path.exists():
                    cmd.append(str(wl_path))
                elif Path(f'/usr/share/wordlists/{wl}').exists():
                    cmd.append(f'/usr/share/wordlists/{wl}')
                elif Path(f'/usr/share/seclists/Passwords/{wl}').exists():
                    cmd.append(f'/usr/share/seclists/Passwords/{wl}')

            # Add rules if specified
            if attack.rules:
                for rule_file in attack.rules:
                    rule_path = self.config.hashcat_rules_dir / rule_file
                    if rule_path.exists():
                        cmd.extend(['-r', str(rule_path)])

            logger.debug(f"Running: {' '.join(cmd)}")

            # Run hashcat
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=attack.timeout_sec + 30
            )

            if os.path.exists(out_file):
                with open(out_file) as f:
                    output = f.read().strip()
                os.unlink(out_file)
            else:
                output = ""

            # Check for cracked password
            if output:
                # Hashcat outfile format 2 is hash:password
                # For WPA2 mode 22000, hash is WPA*01*...
                pw = output.split(':')[-1] if ':' in output else output
                return CrackResult(
                    handshake_id=0,
                    bssid='',
                    ssid=None,
                    status=CrackStatus.CRACKED,
                    password=pw,
                    method='dictionary',
                    hashcat_output=output,
                )

            # Check for already cracked in potfile
            if result.returncode == 0:
                show_cmd = [str(self.hashcat_path), '-m', '22000', '--show', '--potfile-path', str(self.potfile), hash_file]
                show_proc = subprocess.run(show_cmd, capture_output=True, text=True)
                show_output = show_proc.stdout.strip()
                if show_output and ':' in show_output:
                    # potfile line could be bssid:mac:ssid:pw or hash*hash:pw
                    pw = show_output.split(':')[-1]
                    return CrackResult(
                        handshake_id=0,
                        bssid='',
                        ssid=None,
                        status=CrackStatus.CRACKED,
                        password=pw,
                        method='potfile',
                        hashcat_output=show_output,
                    )

            # Check for exhausted (return code 1)
            if result.returncode == 1:
                return CrackResult(
                    handshake_id=0,
                    bssid='',
                    ssid=None,
                    status=CrackStatus.EXHAUSTED,
                    hashcat_output=result.stderr[:500] if result.stderr else 'Exhausted',
                )

            # Mask attack if specified
            if attack.masks:
                for mask in attack.masks:
                    mask_result = self._run_mask_attack(hash_file, mask, attack.timeout_sec // len(attack.masks))
                    if mask_result.status == CrackStatus.CRACKED:
                        return mask_result

            return CrackResult(
                handshake_id=0,
                bssid='',
                ssid=None,
                status=CrackStatus.EXHAUSTED,
                hashcat_output='No password found',
            )

        except subprocess.TimeoutExpired:
            return CrackResult(
                handshake_id=0,
                bssid='',
                ssid=None,
                status=CrackStatus.EXHAUSTED,
                hashcat_output='Timeout',
            )
        except Exception as e:
            logger.error(f"hashcat error: {e}")
            return CrackResult(
                handshake_id=0,
                bssid='',
                ssid=None,
                status=CrackStatus.FAILED,
                hashcat_output=str(e),
            )
        finally:
            try:
                os.unlink(hash_file)
            except Exception:
                pass

    def _run_mask_attack(
        self,
        hash_file: str,
        mask: str,
        timeout: int
    ) -> CrackResult:
        """Run mask (brute-force) attack."""
        # Use a separate temp file for output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.out', delete=False) as out_f:
            out_file = out_f.name

        cmd = [
            str(self.hashcat_path),
            '-m', '22000',
            '-a', '3',  # Mask attack
            '--potfile-path', str(self.potfile),
            '--runtime', str(timeout),
            '--outfile-format', '2',
            '--quiet',
            '-d', '1',
            '--force',
            '-o', out_file,
            hash_file,
            mask,
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30
            )

            output = ""
            if os.path.exists(out_file):
                with open(out_file) as f:
                    output = f.read().strip()
                os.unlink(out_file)

            if output:
                return CrackResult(
                    handshake_id=0,
                    bssid='',
                    ssid=None,
                    status=CrackStatus.CRACKED,
                    password=output,
                    method=f'mask:{mask}',
                    hashcat_output=output,
                )
        except Exception:
            pass

        return CrackResult(
            handshake_id=0,
            bssid='',
            ssid=None,
            status=CrackStatus.EXHAUSTED,
        )

    def _get_handshake(self, handshake_id: int) -> dict | None:
        """Get handshake data from database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT bssid, ssid, hashcat_hash FROM handshakes WHERE id = ?",
                (handshake_id,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'bssid': row.bssid,
                    'ssid': row.ssid,
                    'hashcat_hash': row.hashcat_hash,
                }
        finally:
            cursor.close()

        return None

    def _update_handshake_status(
        self,
        handshake_id: int,
        status: CrackStatus,
        password: str | None = None,
        crack_time: float | None = None,
        method: str | None = None
    ) -> None:
        """Update handshake cracking status in database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if password:
                cursor.execute("""
                    UPDATE handshakes
                    SET crack_status = ?, cracked_password = ?,
                        crack_time_sec = ?, crack_method = ?
                    WHERE id = ?
                """, (status.value, password, int(crack_time or 0), method, handshake_id))
            else:
                cursor.execute(
                    "UPDATE handshakes SET crack_status = ? WHERE id = ?",
                    (status.value, handshake_id)
                )
            conn.commit()
        finally:
            cursor.close()

    def audit_all_pending(
        self,
        strategy: str = 'quick',
        limit: int = 100
    ) -> BatchCrackResult:
        """
        Audit all handshakes with pending status.

        Args:
            strategy: Attack strategy to use
            limit: Maximum handshakes to attempt

        Returns:
            BatchCrackResult with aggregate statistics
        """
        start_time = time.time()

        conn = self._get_connection()
        cursor = conn.cursor()

        # Get pending handshakes
        cursor.execute(f"""
            SELECT TOP ({limit}) id, bssid, ssid
            FROM handshakes
            WHERE crack_status = 'pending' AND hashcat_hash IS NOT NULL
            ORDER BY capture_time DESC
        """)

        pending = [(row.id, row.bssid, row.ssid) for row in cursor.fetchall()]
        cursor.close()

        results = []
        cracked = 0
        exhausted = 0
        failed = 0
        skipped = 0

        for handshake_id, bssid, ssid in pending:
            try:
                result = self.audit_handshake(handshake_id, strategy)
                results.append(result)

                if result.status == CrackStatus.CRACKED:
                    cracked += 1
                    logger.info(f"✅ CRACKED: {ssid or bssid} -> {result.password}")
                elif result.status == CrackStatus.EXHAUSTED:
                    exhausted += 1
                    logger.debug(f"⏳ Exhausted: {ssid or bssid}")
                elif result.status == CrackStatus.FAILED:
                    failed += 1

            except Exception as e:
                logger.error(f"Error auditing {handshake_id}: {e}")
                failed += 1

        return BatchCrackResult(
            total_attempted=len(pending),
            cracked=cracked,
            exhausted=exhausted,
            failed=failed,
            skipped=skipped,
            results=results,
            duration_sec=time.time() - start_time,
        )

    def analyze_password_weakness(
        self,
        password: str,
        ssid: str | None = None,
        bssid: str | None = None,
        wordlist_path: str | None = None,
        triangulation_data: dict[str, Any] | None = None
    ) -> PasswordWeakness:
        """
        Deep analysis of a cracked password for weakness indicators.

        Args:
            password: The cracked password
            ssid: Optional network SSID for similarity check
            bssid: Optional BSSID for MAC-derived pattern check
            wordlist_path: Optional path to custom wordlist

        Returns:
            PasswordWeakness with comprehensive analysis
        """
        import re

        length = len(password)
        lower_pw = password.lower()

        # Character set analysis
        charset_lower = bool(re.search(r'[a-z]', password))
        charset_upper = bool(re.search(r'[A-Z]', password))
        charset_digits = bool(re.search(r'[0-9]', password))
        charset_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        charset_count = sum([charset_lower, charset_upper, charset_digits, charset_special])

        # Shannon entropy calculation
        entropy_score, entropy_total = self._calculate_entropy(password)

        patterns = []

        # Date patterns
        if re.search(r'\d{2}[-/]\d{2}[-/]\d{2,4}', password):
            patterns.append('date_format')
        if re.search(r'(19|20)\d{2}', password):
            patterns.append('year')

        # Phone number
        if re.search(r'\d{3}[-.]?\d{3}[-.]?\d{4}', password):
            patterns.append('phone_number')

        # Keyboard walks
        keyboard_walks = ['qwerty', 'asdf', 'zxcv', '1234', '123456', 'qazwsx',
                         'qweasd', 'asdfgh', 'zxcvbn', '!@#$%', 'qwertyuiop']
        for walk in keyboard_walks:
            if walk in lower_pw:
                patterns.append('keyboard_walk')
                break

        # Sequential patterns
        if re.search(r'(abc|bcd|cde|def|efg|xyz)', lower_pw):
            patterns.append('sequential_letters')
        if re.search(r'(012|123|234|345|456|567|678|789|987|876|765)', password):
            patterns.append('sequential_numbers')

        # Repetition
        if re.search(r'(.)\1{2,}', password):
            patterns.append('repetition')

        # Leetspeak detection
        leetspeak_map = {'@': 'a', '4': 'a', '3': 'e', '1': 'i', '0': 'o', '$': 's', '5': 's', '7': 't'}
        deleet = password.lower()
        for leet, char in leetspeak_map.items():
            deleet = deleet.replace(leet, char)
        if deleet != lower_pw:
            patterns.append('leetspeak')

        # Common suffix/prefix patterns
        if re.search(r'(^|[a-z])(123|1234|12345|!)$', lower_pw):
            patterns.append('common_suffix')
        if re.search(r'^(123|!)[a-z]', lower_pw):
            patterns.append('common_prefix')

        # Palindrome check
        if len(password) > 4 and password == password[::-1]:
            patterns.append('palindrome')

        # SSID in password
        ssid_similarity = 0.0
        if ssid:
            if ssid.lower() in lower_pw:
                patterns.append('ssid_in_password')
            ssid_similarity = self._jaro_winkler(lower_pw, ssid.lower())
            if ssid_similarity > 0.8 and 'ssid_in_password' not in patterns:
                patterns.append('ssid_similar')

        # BSSID/MAC patterns
        bssid_similarity = 0.0
        if bssid:
            mac_clean = bssid.replace(':', '').replace('-', '').lower()
            if len(mac_clean) >= 6:
                # Check for partial MAC in password
                for i in range(0, len(mac_clean) - 3, 2):
                    if mac_clean[i:i+4] in lower_pw:
                        patterns.append('mac_derived')
                        break
            bssid_similarity = self._jaro_winkler(lower_pw, mac_clean)

        # Common password check
        common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
            '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
            'master', 'sunshine', 'ashley', 'bailey', 'shadow', '123123',
            'password1', 'password123', 'admin', 'welcome', 'login'
        ]
        is_common = lower_pw in common_passwords

        # Rockyou/wordlist check
        is_rockyou = self._check_wordlist(password, wordlist_path)

        # Dictionary word check
        is_dict_word = len(password) <= 8 and password.isalpha() and password.islower()

        # zxcvbn-like strength (simplified)
        zxcvbn_score, zxcvbn_guesses = self._estimate_zxcvbn(password, ssid)

        # Calculate crack time
        crack_time_seconds = zxcvbn_guesses / 10_000_000_000  # 10B guesses/sec GPU

        # Weakness score (weighted formula)
        weakness_score = self._calculate_weakness_score(
            length, charset_count, entropy_score, is_common, is_rockyou,
            is_dict_word, patterns, ssid_similarity, bssid_similarity
        )

        # Human-readable crack time
        estimated_crack_time = self._format_crack_time(crack_time_seconds)

        # Recommendations
        recommendations = self._generate_recommendations(
            length, charset_count, is_common, is_rockyou, is_dict_word,
            patterns, entropy_score, ssid_similarity
        )

        return PasswordWeakness(
            password=password,
            length=length,
            charset_lowercase=charset_lower,
            charset_uppercase=charset_upper,
            charset_digits=charset_digits,
            charset_special=charset_special,
            charset_count=charset_count,
            is_dictionary_word=is_dict_word,
            is_common_password=is_common,
            is_rockyou_match=is_rockyou,
            has_patterns=patterns,
            estimated_crack_time=estimated_crack_time,
            weakness_score=weakness_score,
            recommendations=recommendations,
            entropy_score=round(entropy_score, 2),
            entropy_total=round(entropy_total, 2),
            ssid_similarity=round(ssid_similarity, 3),
            bssid_similarity=round(bssid_similarity, 3),
            zxcvbn_score=zxcvbn_score,
            zxcvbn_guesses=zxcvbn_guesses,
            crack_time_seconds=crack_time_seconds,
            pack_mask_suggestion=triangulation_data.get('pack_mask') if triangulation_data else None,
            cewl_custom_count=triangulation_data.get('cewl_count', 0) if triangulation_data else 0,
            pipal_top_pattern=triangulation_data.get('pipal_pattern') if triangulation_data else None,
            triangulation_score=triangulation_data.get('tri_score', 0.0) if triangulation_data else 0.0,
        )

    def _calculate_entropy(self, password: str) -> tuple:
        """Calculate Shannon entropy (bits/char and total)."""
        import math
        from collections import Counter

        if not password:
            return 0.0, 0.0

        freq = Counter(password)
        length = len(password)
        entropy = 0.0

        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy, entropy * length

    def _jaro_winkler(self, s1: str, s2: str) -> float:
        """Jaro-Winkler similarity (0-1, higher = more similar)."""
        if s1 == s2:
            return 1.0

        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0

        match_distance = max(len1, len2) // 2 - 1
        if match_distance < 0:
            match_distance = 0

        s1_matches = [False] * len1
        s2_matches = [False] * len2
        matches = 0
        transpositions = 0

        for i in range(len1):
            start = max(0, i - match_distance)
            end = min(i + match_distance + 1, len2)
            for j in range(start, end):
                if s2_matches[j] or s1[i] != s2[j]:
                    continue
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break

        if matches == 0:
            return 0.0

        k = 0
        for i in range(len1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1

        jaro = (matches/len1 + matches/len2 + (matches-transpositions/2)/matches) / 3

        # Winkler modification
        prefix = 0
        for i in range(min(4, len1, len2)):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break

        return jaro + prefix * 0.1 * (1 - jaro)

    def _check_wordlist(self, password: str, wordlist_path: str | None = None) -> bool:
        """Check if password exists in wordlist (top 10k subset)."""
        # Built-in top 100 for quick check
        top100 = {
            '123456', 'password', '12345678', 'qwerty', '123456789', '12345',
            '1234', '111111', '1234567', 'dragon', '123123', 'baseball',
            'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master',
            '666666', 'qwertyuiop', '123321', 'mustang', '1234567890',
            'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212',
            '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan',
            'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer',
            'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou',
            '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger',
            'daniel', 'starwars', 'klaster', '112233', 'george', 'computer',
            'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555',
            '11111111', '131313', 'freedom', '777777', 'pass', 'maggie',
            '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese',
            'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea',
            'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas',
            'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom',
            'monitor', 'monitoring', 'montana', 'moon', 'moscow'
        }

        if password.lower() in top100:
            return True

        # Check custom wordlist if provided
        if wordlist_path:
            try:
                with open(wordlist_path, errors='ignore') as f:
                    for line in f:
                        if line.strip().lower() == password.lower():
                            return True
            except Exception:
                pass

        return False

    def _estimate_zxcvbn(self, password: str, ssid: str | None = None) -> tuple:
        """Simplified zxcvbn-like strength estimation."""
        import math

        guesses = 1.0

        # Base guesses from charset
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 33

        if charset_size > 0:
            guesses = charset_size ** len(password)

        # Reduce for patterns
        lower_pw = password.lower()
        if any(w in lower_pw for w in ['password', 'qwerty', '123456', 'letmein']):
            guesses = min(guesses, 1000)

        # Reduce for SSID similarity
        if ssid and ssid.lower() in lower_pw:
            guesses = min(guesses, guesses / 1000)

        # Score 0-4
        log_guesses = math.log10(max(1, guesses))
        if log_guesses < 3:
            score = 0
        elif log_guesses < 6:
            score = 1
        elif log_guesses < 9:
            score = 2
        elif log_guesses < 12:
            score = 3
        else:
            score = 4

        return score, guesses

    def _calculate_weakness_score(
        self, length, charset_count, entropy, is_common, is_rockyou,
        is_dict, patterns, ssid_sim, bssid_sim
    ) -> int:
        """Calculate weighted weakness score 0-100."""
        score = 0

        # Length penalty
        if length < 8:
            score += 40
        elif length < 12:
            score += 20
        elif length < 16:
            score += 5

        # Charset penalty
        if charset_count == 1:
            score += 25
        elif charset_count == 2:
            score += 10

        # Entropy penalty (low entropy = weak)
        if entropy < 2.0:
            score += 20
        elif entropy < 3.0:
            score += 10

        # Common/wordlist
        if is_common:
            score += 40
        if is_rockyou:
            score += 30
        if is_dict:
            score += 15

        # Pattern penalties
        pattern_weights = {
            'keyboard_walk': 15, 'ssid_in_password': 20, 'ssid_similar': 15,
            'mac_derived': 15, 'leetspeak': 5, 'common_suffix': 10,
            'sequential_numbers': 10, 'sequential_letters': 10,
            'repetition': 10, 'year': 5, 'phone_number': 10,
        }
        for p in patterns:
            score += pattern_weights.get(p, 5)

        # Similarity penalties
        if ssid_sim > 0.8:
            score += 15
        if bssid_sim > 0.7:
            score += 10

        return min(100, score)

    def _format_crack_time(self, seconds: float) -> str:
        """Format crack time as human readable string."""
        if seconds < 0.001:
            return "instant"
        elif seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 86400 * 365:
            return f"{seconds/86400:.1f} days"
        elif seconds < 86400 * 365 * 100:
            return f"{seconds/(86400*365):.1f} years"
        else:
            return "centuries+"

    def _generate_recommendations(
        self, length, charset_count, is_common, is_rockyou, is_dict,
        patterns, entropy, ssid_sim
    ) -> list[str]:
        """Generate prioritized recommendations."""
        recs = []

        if is_common or is_rockyou:
            recs.append("🚨 CRITICAL: Password is in common wordlists - change immediately")
        if 'ssid_in_password' in patterns or ssid_sim > 0.8:
            recs.append("Never use network name or similar strings in password")
        if length < 12:
            recs.append("Use at least 12 characters (16+ recommended)")
        if length >= 12 and charset_count < 3:
            recs.append("Add uppercase, lowercase, numbers, AND symbols")
        if 'keyboard_walk' in patterns:
            recs.append("Avoid keyboard patterns like 'qwerty' or '123456'")
        if 'leetspeak' in patterns and (is_common or is_rockyou):
            recs.append("Simple leetspeak (@ for a) doesn't improve security")
        if entropy < 3.0:
            recs.append("Increase randomness - avoid predictable patterns")
        if not recs:
            recs.append("✅ Consider using a random 20+ char passphrase (diceware)")

        return recs

    def get_audit_summary(self) -> dict[str, Any]:
        """Get summary of password audit results."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN crack_status = 'cracked' THEN 1 ELSE 0 END) as cracked,
                    SUM(CASE WHEN crack_status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN crack_status = 'exhausted' THEN 1 ELSE 0 END) as exhausted,
                    AVG(crack_time_sec) as avg_crack_time
                FROM handshakes
                WHERE hashcat_hash IS NOT NULL
            """)

            row = cursor.fetchone()
            return {
                'total_handshakes': row.total or 0,
                'cracked': row.cracked or 0,
                'pending': row.pending or 0,
                'exhausted': row.exhausted or 0,
                'crack_rate': (row.cracked / row.total * 100) if row.total else 0,
                'avg_crack_time_sec': row.avg_crack_time or 0,
            }
        finally:
            cursor.close()


def main() -> None:
    """CLI entry point for password auditor."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    parser = argparse.ArgumentParser(description='NEXUS Password Auditor')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # check command
    subparsers.add_parser('check', help='Check hashcat availability')

    # audit command
    audit_parser = subparsers.add_parser('audit', help='Audit password')
    audit_parser.add_argument('--id', type=int, help='Specific handshake ID')
    audit_parser.add_argument('--all', action='store_true', help='Audit all pending')
    audit_parser.add_argument('--strategy', default='quick',
                             choices=list(ATTACK_STRATEGIES.keys()),
                             help='Attack strategy')
    audit_parser.add_argument('--limit', type=int, default=10, help='Max to audit')

    # analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze password weakness')
    analyze_parser.add_argument('password', help='Password to analyze')
    analyze_parser.add_argument('--ssid', help='Network SSID for similarity check')
    analyze_parser.add_argument('--bssid', help='BSSID for MAC-derived pattern check')
    analyze_parser.add_argument('--wordlist', help='Path to custom wordlist file')

    # summary command
    subparsers.add_parser('summary', help='Show audit summary')

    args = parser.parse_args()

    config = get_nexus_config()
    auditor = PasswordAuditor(config)

    try:
        if args.command == 'check':
            if auditor.is_hashcat_available():
                version = auditor.get_hashcat_version()
                print(f"✅ hashcat available: {version}")
            else:
                print(f"❌ hashcat not found at {config.hashcat_binary}")

        elif args.command == 'audit':
            if not auditor.is_hashcat_available():
                print("❌ hashcat not available")
                return 1

            if args.id:
                result = auditor.audit_handshake(args.id, args.strategy)
                print(f"\n📋 Audit Result for handshake {args.id}")
                print(f"   Network: {result.ssid or result.bssid}")
                print(f"   Status: {result.status.value}")
                if result.password:
                    print(f"   Password: {result.password}")
                    print(f"   Crack time: {result.crack_time_sec:.2f}s")
            elif args.all:
                result = auditor.audit_all_pending(args.strategy, args.limit)
                print("\n📊 Batch Audit Complete")
                print(f"   Attempted: {result.total_attempted}")
                print(f"   Cracked: {result.cracked}")
                print(f"   Exhausted: {result.exhausted}")
                print(f"   Failed: {result.failed}")
                print(f"   Duration: {result.duration_sec:.2f}s")
            else:
                print("Specify --id or --all")

        elif args.command == 'analyze':
            weakness = auditor.analyze_password_weakness(
                args.password,
                ssid=args.ssid,
                bssid=args.bssid,
                wordlist_path=args.wordlist
            )
            print(f"\n🔍 Deep Password Analysis: {args.password}")
            print("\n   📏 Basic Metrics")
            print(f"      Length: {weakness.length}")
            print(f"      Character sets: {weakness.charset_count}")
            print(f"      Entropy: {weakness.entropy_score} bits/char ({weakness.entropy_total:.1f} total)")
            print("\n   🔎 Detection Results")
            print(f"      Common password: {'Yes ⚠️' if weakness.is_common_password else 'No'}")
            print(f"      Rockyou match: {'Yes ⚠️' if weakness.is_rockyou_match else 'No'}")
            print(f"      Dictionary word: {'Yes' if weakness.is_dictionary_word else 'No'}")
            print(f"      Patterns: {', '.join(weakness.has_patterns) or 'None detected'}")
            if args.ssid:
                print(f"      SSID similarity: {weakness.ssid_similarity:.1%}")
            if args.bssid:
                print(f"      BSSID similarity: {weakness.bssid_similarity:.1%}")
            print("\n   📊 Scoring")
            print(f"      Weakness score: {weakness.weakness_score}/100 ({'WEAK' if weakness.weakness_score >= 60 else 'MODERATE' if weakness.weakness_score >= 30 else 'STRONG'})")
            print(f"      zxcvbn score: {weakness.zxcvbn_score}/4")
            print(f"      Est. guesses: {weakness.zxcvbn_guesses:.2e}")
            print(f"      Est. crack time: {weakness.estimated_crack_time}")
            print("\n   💡 Recommendations:")
            for rec in weakness.recommendations:
                print(f"      • {rec}")

        elif args.command == 'summary':
            summary = auditor.get_audit_summary()
            print("\n📊 Password Audit Summary")
            print(f"   Total handshakes: {summary['total_handshakes']}")
            print(f"   Cracked: {summary['cracked']} ({summary['crack_rate']:.1f}%)")
            print(f"   Pending: {summary['pending']}")
            print(f"   Exhausted: {summary['exhausted']}")
            print(f"   Avg crack time: {summary['avg_crack_time_sec']:.1f}s")

        else:
            parser.print_help()

    finally:
        auditor.close()


if __name__ == '__main__':
    main()
