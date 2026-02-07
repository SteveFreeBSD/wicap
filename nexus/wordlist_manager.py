"""
NEXUS Wordlist Manager
Advanced wordlist generation, merging, and optimization engine for "Ape-Moon Mode".
Handles massive wordlists, custom SSID-based generation, and dynamic mask creation.
"""

import argparse
import itertools
import logging
import os
import re
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

# Try to import config, handle running as script
try:
    from .config import NexusConfig, get_nexus_config
except ImportError:
    # Standalone mode support
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from nexus.config import NexusConfig, get_nexus_config

logger = logging.getLogger('nexus.wordlist_manager')

class WordlistManager:
    """
    Manages wordlist inventory, generation, and "Crazy Algorithm Madness".
    """

    def __init__(self, config: NexusConfig):
        self.config = config
        self.wordlist_dir = Path(config.wordlist_dir)
        self.temp_dir = self._init_temp_dir()

        # Known wordlist locations to check
        self.search_paths = [
            self.wordlist_dir,
            Path('/usr/share/wordlists'),
            Path('/opt/seclists/Passwords'),
        ]

        self.inventory: dict[str, Path] = {}
        self._discover_wordlists()

    def _init_temp_dir(self) -> Path:
        """Create a writable temp directory for generated wordlists."""
        candidates = [
            Path(tempfile.gettempdir()) / 'nexus_wordlists',
            Path(tempfile.gettempdir()) / f"nexus_wordlists_{os.getuid()}",
            Path.home() / ".cache" / "nexus_wordlists",
        ]
        for candidate in candidates:
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                if os.access(candidate, os.W_OK):
                    return candidate
            except Exception:
                continue
        return Path(tempfile.gettempdir())

    def _discover_wordlists(self):
        """Scan system for known wordlists."""
        # Prioritize configured wordlist directory, then system corpora paths.
        for path in self.search_paths:
            if not path.exists():
                continue
            for file_path in path.rglob('*.txt'):
                # Store full path, overwrite duplicates if in higher priority search path
                self.inventory[file_path.name] = file_path

        logger.info(f"📚 Wordlist Manager: Discovered {len(self.inventory)} wordlists across {len(self.search_paths)} paths")

    def get_wordlist(self, name: str) -> Path | None:
        """Get path to a specific wordlist by name (fuzzy match)."""
        if name in self.inventory:
            return self.inventory[name]
        for key, path in self.inventory.items():
            if name.lower() in key.lower():
                return path
        return None

    def get_base_words(self, top_n: int = 5000000) -> Iterator[str]:
        """
        Yields words from all lists, dedup via Bloom-like set (memory safe for 5M).
        Prioritizes 'rockyou.txt' and 'top*' lists.
        """
        seen: set[int] = set() # Store hashes for memory efficiency
        count = 0

        # Priority list
        priority_files = ['rockyou.txt'] + [k for k in self.inventory.keys() if 'top' in k.lower() or '10-million' in k.lower()]
        other_files = [k for k in self.inventory.keys() if k not in priority_files]

        def process_file(path: Path) -> Iterator[str]:
            nonlocal count
            if count >= top_n:
                return
            try:
                with open(path, encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        w = line.strip()
                        if len(w) < 4:
                            continue
                        h = hash(w)
                        if h not in seen:
                            seen.add(h)
                            yield w
                            count += 1
                            if count >= top_n:
                                return
            except Exception as e:
                logger.debug(f"Error reading {path}: {e}")

        # Process priority first
        for name in priority_files:
            if name in self.inventory:
                yield from process_file(self.inventory[name])
                if count >= top_n:
                    break

        # Fill with rest
        for name in other_files:
            if count >= top_n:
                break
            if name in self.inventory:
                yield from process_file(self.inventory[name])

        logger.info(f"Generated stream of {count} unique base words from {len(self.inventory)} lists")

    def generate_custom_madness(self, ssid: str, bssid: str | None, top_n: int = 10000, hybrids: int = 5000000) -> Path:
        """
        Crazy Custom Generation Algorithm.

        Flow:
        1. Base: Get top N words (streamed)
        2. Target: Split SSID/BSSID
        3. Hybrids: Word+Target combinations, Leetspeak, Years
        4. Write to file line-by-line
        """
        # 1. Base Words (materialize small sample for combos)
        base_stream = self.get_base_words(top_n=hybrids)
        base_sample = [] # We need a materialized list for Cartesian products

        # 2. Target Parts
        targets = set()
        if ssid:
            # Split by non-alphanumeric, camelCase, etc.
            raw = ssid.strip()
            targets.add(raw)
            parts = re.split(r'[^a-zA-Z0-9]', raw)
            parts += re.findall(r'[A-Z][^A-Z]*', raw) # camelCase
            for p in parts:
                if p:
                    targets.add(p)
                    targets.add(p.lower())

        if bssid:
            clean = bssid.replace(':', '').replace('-', '').lower()
            if len(clean) >= 6:
                targets.add(clean[-6:])
                targets.add(clean[-4:])

        # 3. Generators
        years = [str(y) for y in range(2010, 2031)]
        digits = [f"{i:04d}" for i in range(10000)] # 0000-9999 (subset for speed? User said 0000-9999)
        # 0000-9999 is 10k items. 10k * top_N is huge. We limit hybrids count.
        symbols = list("!@#$%^&*()")

        # Leet mapping
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        def leet_gen(w: str) -> Iterator[str]:
            yield w
            # Simple transform: all chars
            chars = list(w)
            changed = False
            for i, c in enumerate(chars):
                if c.lower() in leet_map:
                    chars[i] = leet_map[c.lower()]
                    changed = True
            if changed:
                yield "".join(chars)

        # Helper to write
        outfile = self.temp_dir / f"madness_{re.sub(r'[^a-zA-Z0-9]', '_', ssid or 'none')}_{int(datetime.now().timestamp())}.txt"

        count = 0
        with open(outfile, 'w', encoding='utf-8') as f:
            def emit(w: str) -> None:
                nonlocal count
                if len(w) >= 8:
                    f.write(w + '\n')
                    count += 1

            # Process stream and capture sample
            for w in base_stream:
                if len(base_sample) < top_n:
                    base_sample.append(w)
                emit(w)
                for leet_word in leet_gen(w):
                    emit(leet_word)
                if count > hybrids:
                    break

            for t in targets:
                for leet_word in leet_gen(t):
                    emit(leet_word)
                if count > hybrids:
                    break

            # Word + Part + Year
            combo_iter = itertools.product(base_sample[:500], targets, years)
            for w, t, y in combo_iter:
                emit(f"{w}{t}{y}")
                emit(f"{t}{w}{y}")
                if count > hybrids:
                    break

            # Word + Digits (4-digit pin)
            if count < hybrids:
                for w in base_sample[:200]:
                    for d in digits:
                        emit(f"{w}{d}")
                    if count > hybrids:
                        break

            # Word + Symbol
            if count < hybrids:
                for w in base_sample[:1000]:
                    for s in symbols:
                        emit(f"{w}{s}")
                        emit(f"{w}{s}123")
                    if count > hybrids:
                        break

            # Target + Year/Digit (High probability)
            for t in targets:
                for y in years:
                    emit(f"{t}{y}")
                for d in range(1000):
                    emit(f"{t}{d}")  # 0-999
                for s in symbols:
                    emit(f"{t}{s}")

        logger.info(f"🔥 Crazy Madness: Generated {count} candidates for SSID '{ssid}' in {outfile}")
        return outfile

    def create_hybrid_list(self, priority: int, ssid: str | None = None, bssid: str | None = None) -> Path:
        """
        Create merged wordlist, calling madness if priority is high.
        """
        if priority >= 50 and ssid:
            # Ape/High Priority: Use Crazy Madness
            # Limits: Ape gets more processing
            top_n = 50000 if priority > 80 else 10000
            hybrids = 5000000 if priority > 80 else 1000000

            logger.info(f"🦍 Ape Mode (P{priority}): Engaging Crazy Algorithm Madness for {ssid}")
            return self.generate_custom_madness(ssid, bssid, top_n=top_n, hybrids=hybrids)

        else:
            # Standard/Quick
            return self.generate_custom_madness(ssid or "unknown", bssid, top_n=1000, hybrids=100000)

def main() -> None:
    parser = argparse.ArgumentParser(description="NEXUS Wordlist Generator")
    parser.add_argument('action', choices=['generate-custom'], help='Action to perform')
    parser.add_argument('--ssid', required=True, help='Target SSID')
    parser.add_argument('--bssid', help='Target BSSID')
    parser.add_argument('--output', help='Output file path')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    config = get_nexus_config()
    manager = WordlistManager(config)

    if args.action == 'generate-custom':
        path = manager.generate_custom_madness(args.ssid, args.bssid)
        if args.output:
            import shutil
            shutil.copy(str(path), args.output)
            print(f"Saved to {args.output}")
        else:
            print(f"Generated at {path}")

if __name__ == '__main__':
    main()
