import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class EvidenceCollector:
    """
    Manages the extraction of forensic evidence from PCAP archives.
    Uses 'editcap' for high-performance slicing.
    """

    def __init__(self, capture_dir: str = "captures", evidence_dir: str = "captures/evidence"):
        self.capture_dir = Path(capture_dir)
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Ensure editcap is available
        try:
            subprocess.run(["editcap", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            self.has_editcap = True
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("⚠️  editcap (Wireshark) not found. PCAP slicing will be disabled or slow.")
            self.has_editcap = False

    def slice_pcap(self, start_ts: float, end_ts: float, bssid: str | None = None) -> str | None:
        """
        Slices a time range from available PCAP files.
        Arguments:
            start_ts: Start Unix timestamp
            end_ts: End Unix timestamp
            bssid: (Optional) Unused in editcap-only implementation, but reserved for tshark filtering.
        Returns:
            Path to the generated PCAP slice, or None if failed.
        """
        if not self.has_editcap:
            return None

        # 1. Identify relevant files
        # The file format seems to be dwell_YYYYMMDD_HHMMSS_chX.pcapng
        # We need to find files that overlap with the requested window.
        # Since files are 30s chunks mostly, we can look at the timestamp in the filename.

        relevant_files = self._find_files_in_range(start_ts, end_ts)
        if not relevant_files:
            return None

        output_filename = f"evidence_{int(start_ts)}_{int(end_ts)}.pcapng"
        output_path = self.evidence_dir / output_filename

        # 2. Merge if multiple files (using mergecap)
        temp_merged = None
        input_for_slicing = relevant_files[0]

        if len(relevant_files) > 1:
            try:
                import tempfile
                # Create a temp file for the merge
                fd, temp_merged = tempfile.mkstemp(suffix=".pcapng")
                os.close(fd)

                # Use mergecap to combine
                cmd = ["mergecap", "-w", temp_merged] + [str(f) for f in relevant_files]
                subprocess.run(cmd, check=True)
                input_for_slicing = Path(temp_merged)
            except Exception as e:
                print(f"Error merging PCAPs: {e}")
                if temp_merged and os.path.exists(temp_merged):
                    os.unlink(temp_merged)
                return None

        # 3. Slice using editcap
        # editcap -A <start_time> -B <stop_time> <input> <output>
        # Time format: YYYY-MM-DD HH:MM:SS
        start_str = datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S')
        end_str = datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S')

        try:
            cmd = [
                "editcap",
                "-A", start_str,
                "-B", end_str,
                str(input_for_slicing),
                str(output_path)
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            return str(output_path)

        except subprocess.CalledProcessError as e:
            print(f"Error slicing PCAP: {e}")
            return None
        finally:
            # Cleanup temp merged file
            if temp_merged and os.path.exists(temp_merged):
                os.unlink(temp_merged)

    def _find_files_in_range(self, start_ts: float, end_ts: float) -> list[Path]:
        """
        Locates PCAP files that might contain packets within [start_ts, end_ts].
        Assumes filenames: dwell_YYYYMMDD_HHMMSS_chX.pcapng (Time in UTC)
        """
        all_files = sorted(self.capture_dir.glob("dwell_*.pcapng"))
        selected = []

        # We need to parse timestamps from filenames
        # Format: dwell_%Y%m%d_%H%M%S_ch%d.pcapng

        for p in all_files:
            try:
                parts = p.name.split('_')
                if len(parts) >= 3:
                    ts_str = f"{parts[1]}_{parts[2]}"
                    # 20260112_141801
                    file_dt = datetime.strptime(ts_str, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
                    file_ts = file_dt.timestamp()

                    # Assuming ~35s duration per file (margin of error)
                    # If file starts before end_ts AND ends after start_ts
                    if file_ts < end_ts and (file_ts + 45) > start_ts:
                        selected.append(p)
            except ValueError:
                continue

        return selected
