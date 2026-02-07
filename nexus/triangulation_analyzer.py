"""
NEXUS Triangulation Analyzer

Integrates PACK, CeWL, and Pipal for advanced password intelligence.
- analyze_with_pack: Extract masks from successful cracks
- generate_with_cewl: Create context-aware wordlists
- analyze_with_pipal: Deep statistical analysis of potfiles
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger('nexus.triangulation')

class TriangulationAnalyzer:
    def __init__(self, config):
        self.config = config
        self.wordlists_dir = Path(config.wordlists_dir)
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir = Path("/tmp/nexus_triangulation")
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self._get_connection = None # Set by Auditor if needed

    def analyze_with_pack(self, potfile_path: str) -> dict[str, Any]:
        """
        Run statsgen.py on potfile to find the most frequent masks.
        """
        if not os.path.exists(potfile_path) or os.path.getsize(potfile_path) == 0:
            return {}

        results = {
            'top_masks': [],
            'top_characters': [],
            'mask_suggestion': None
        }

        try:
            # 1. Extract passwords from potfile (strip hash prefixes)
            # Potfile format: <hash>:<password> or <hash>$<password>
            passwords = []
            with open(potfile_path) as f:
                for line in f:
                    if ':' in line:
                        passwords.append(line.split(':', 1)[1].strip())
                    elif '*' in line:
                        # WPA2 potfile sometimes uses * as a delimiter in the hash
                        # but might end with :password or just be the password if it's a cracked line
                        # Let's try to find the last part
                        parts = line.strip().split(':')
                        if len(parts) > 1:
                            passwords.append(parts[-1])

            if not passwords:
                return {}

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_pw:
                tmp_pw.write('\n'.join(passwords) + '\n')
                pw_file = tmp_pw.name

            # statsgen.py stats_file
            cmd = ['statsgen.py', pw_file]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            os.unlink(pw_file)

            if proc.returncode == 0:
                output = proc.stdout
                # Simple parser for PACK output
                # Example: [+]      ?l?l?l?l?l?l?d?d?d?d: 100% (1)
                masks = re.findall(r'\[\+\]\s+([\?\w]+):\s+\d+%\s+\((\d+)\)', output)
                if masks:
                    # Sort by frequency and take top 5
                    sorted_masks = sorted(masks, key=lambda x: int(x[1]), reverse=True)
                    results['top_masks'] = [m[0] for m in sorted_masks[:5]]
                    results['mask_suggestion'] = sorted_masks[0][0]

                # Check for character distribution
                char_sets = re.findall(r'\[\+\] ([\w\s]+): (\d+)%', output)
                results['char_distribution'] = {c[0].strip(): int(c[1]) for c in char_sets}

        except Exception as e:
            logger.error(f"PACK analysis error: {e}")

        return results

    def generate_with_cewl(self, ssid: str, bssid: str | None = None, url: str | None = None) -> str:
        """
        Generate a custom wordlist using CeWL.
        If URL is provided, crawl it.
        Otherwise, try to use SSID as a search seed if possible,
        but strictly CeWL needs a URL.
        """
        output_path = self.wordlists_dir / f"cewl_{ssid.replace(' ', '_')}.txt"

        # If no URL, we might try to search, but for now let's use a placeholder
        # or a localized search if the user provides a URL field later.
        if not url:
            # Mock or check if SSID looks like a domain
            if '.' in ssid and ' ' not in ssid:
                url = f"http://{ssid}"
            else:
                # Without a URL, CeWL can't do much.
                # We could potentially search Google for the SSID and pick the first site,
                # but that's complex. For now, we'll log it.
                logger.warning(f"CeWL requires a URL. SSID '{ssid}' provided without URL.")
                return str(output_path)

        try:
            cmd = ['cewl', '-w', str(output_path), '-m', '5', url]
            subprocess.run(cmd, capture_output=True, timeout=120)

            if output_path.exists():
                logger.info(f"CeWL generated {os.path.getsize(output_path)} bytes of words for {ssid}")
        except Exception as e:
            logger.error(f"CeWL error: {e}")

        return str(output_path)

    def analyze_with_pipal(self, potfile_path: str) -> dict[str, Any]:
        """
        Run Pipal on potfile and parse the statistical report.
        """
        if not os.path.exists(potfile_path) or os.path.getsize(potfile_path) == 0:
            return {}

        results = {
            'top_patterns': [],
            'length_distribution': {},
            'top_passwords': [],
            'entropy_avg': 0.0
        }

        try:
            pipal_bin = shutil.which('pipal')
            if not pipal_bin:
                # Try common opt path
                opt_path = Path('/opt/pipal/pipal.rb')
                if opt_path.exists():
                    pipal_bin = f"ruby {opt_path}"
                else:
                    logger.error("Pipal not found in PATH or /opt/pipal/pipal.rb")
                    return {}

            cmd = (pipal_bin.split() if ' ' in pipal_bin else [pipal_bin]) + [potfile_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if proc.returncode == 0:
                output = proc.stdout

                # Parse Top 10 patterns (e.g. "String + Number")
                patterns = re.findall(r'Top \d+ patterns\n-*\n(.*?)\n\n', output, re.S)
                if patterns:
                    results['top_patterns'] = [p.strip() for p in patterns[0].split('\n')[:5]]

                # Parse Length distribution
                lengths = re.findall(r'Password lengths\n-*\n(.*?)\n\n', output, re.S)
                if lengths:
                    for line in lengths[0].split('\n'):
                        match = re.search(r'(\d+) = \d+ \((\d+)%\)', line)
                        if match:
                            results['length_distribution'][int(match.group(1))] = int(match.group(2))

                # Parse characters base
                # Pipal shows entropy or variety?
                # For now let's capture the 'Top 10 passwords'
                passwords = re.findall(r'Top \d+ passwords\n-*\n(.*?)\n\n', output, re.S)
                if passwords:
                    results['top_passwords'] = [p.strip() for p in passwords[0].split('\n')[:5]]

        except Exception as e:
            logger.error(f"Pipal analysis error: {e}")

        return results

    def get_triangulation_summary(self, potfile_path: str) -> dict[str, Any]:
        """Combine all tools for a master report."""
        pack = self.analyze_with_pack(potfile_path)
        pipal = self.analyze_with_pipal(potfile_path)

        # Calculate a simple "triangulation score"
        # High score means predictable/weak patterns
        score = 0
        if pack.get('mask_suggestion') in ('?l?l?l?l?l?l?l?l', '?d?d?d?d?d?d?d?d'):
            score += 30

        if pipal.get('length_distribution'):
            # If most passwords are 8 characters
            if pipal['length_distribution'].get(8, 0) > 50:
                score += 20

        return {
            'pack_mask': pack.get('mask_suggestion'),
            'pipal_pattern': pipal['top_patterns'][0] if pipal['top_patterns'] else None,
            'tri_score': float(score),
            'raw_pack': pack,
            'raw_pipal': pipal,
            'crack_count': len(pack.get('top_masks', [])), # Rough estimate or parse better
            'timestamp': datetime.now().isoformat()
        }

    def get_potfile_checksum(self, potfile_path: str) -> str:
        """Compute SHA256 of potfile."""
        if not os.path.exists(potfile_path):
            return ""
        sha256_hash = hashlib.sha256()
        with open(potfile_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def save_triangulation_to_db(self, summary: dict[str, Any], potfile_path: str, conn) -> None:
        """Save results to triangulation_history table."""
        try:
            checksum = self.get_potfile_checksum(potfile_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO triangulation_history
                (top_masks, mask_suggestion, top_patterns, pattern_suggestion,
                 length_distribution, triangulation_score, potfile_checksum, crack_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                json.dumps(summary['raw_pack'].get('top_masks', [])),
                summary['pack_mask'],
                json.dumps(summary['raw_pipal'].get('top_patterns', [])),
                summary['pipal_pattern'],
                json.dumps(summary['raw_pipal'].get('length_distribution', {})),
                summary['tri_score'],
                checksum,
                summary.get('crack_count', 0)
            ))
            conn.commit()
            cursor.close()
            logger.info("✅ Triangulation history saved to DB")
        except Exception as e:
            logger.error(f"Failed to save triangulation history: {e}")

    def export_to_html(self, summary: dict[str, Any], output_path: str) -> None:
        """Generate a professional HTML report."""

        # Build Length Distribution Rows
        len_rows = ""
        len_dist = summary['raw_pipal'].get('length_distribution', {})
        for length, freq in len_dist.items():
            len_rows += f"""
            <tr>
                <td>{length} chars</td>
                <td>{freq}%</td>
                <td><div class='bar-container'><div class='bar' style='width: {freq}%'></div></div></td>
            </tr>"""

        # Build Pattern List
        patterns = summary['raw_pipal'].get('top_patterns', [])
        pattern_list = "".join([f"<li>{p}</li>" for p in patterns])

        # Build Mask Table
        masks = summary['raw_pack'].get('top_masks', [])
        mask_rows = "".join([f"<tr><td>{m}</td></tr>" for m in masks])

        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>NEXUS Triangulation Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f1f5f9; padding: 40px; }}
        .header {{ border-bottom: 2px solid #38bdf8; padding-bottom: 20px; margin-bottom: 40px; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 25px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        h1 {{ color: #38bdf8; margin: 0; }}
        h2 {{ color: #7dd3fc; margin-top: 0; }}
        .score {{ font-size: 3em; color: #fbbf24; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #334155; }}
        th {{ color: #94a3b8; font-weight: 600; }}
        .bar-container {{ background: #334155; height: 10px; border-radius: 5px; width: 100%; margin-top: 5px; }}
        .bar {{ background: #38bdf8; height: 100%; border-radius: 5px; }}
        .label {{ color: #94a3b8; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📐 NEXUS Triangulation Intelligence</h1>
        <p class="label">Generated: {summary['timestamp']}</p>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 25px;">
        <div class="card">
            <h2>🛡️ Predictability Score</h2>
            <div class="score">{int(summary['tri_score'])}%</div>
            <p class="label">Higher scores indicate predictable user behavior and easier targets.</p>
        </div>
        <div class="card">
            <h2>🦾 Optimal Attack Mask</h2>
            <div style="font-size: 1.5em; font-family: monospace; color: #10b981; background: #0f172a; padding: 15px; border-radius: 8px;">
                {summary['pack_mask']}
            </div>
            <p class="label">Inject this mask into APE MODE for maximal efficiency.</p>
        </div>
    </div>

    <div class="card">
        <h2>📊 Password Length Distribution</h2>
        <table>
            <tr><th>Length</th><th>Frequency</th><th>Graph</th></tr>
            {len_rows}
        </table>
    </div>

    <div class="card">
        <h2>🔬 Pattern Analysis (Pipal)</h2>
        <ul>
            {pattern_list}
        </ul>
    </div>

    <div class="card">
        <h2>🎭 Common Masks (PACK)</h2>
        <table style="font-family: monospace;">
            {mask_rows}
        </table>
    </div>

</body>
</html>
"""
        with open(output_path, 'w') as f:
            f.write(html_template)
        logger.info(f"✅ HTML Report exported to {output_path}")
