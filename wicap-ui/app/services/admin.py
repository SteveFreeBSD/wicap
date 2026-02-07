from pathlib import Path

import app.services.state as state

# CAPTURE_DIR: Configurable via env, defaults to ../captures for bare-metal
# In Docker: set WICAP_CAPTURE_DIR=/app/captures
REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURE_DIR = Path(
    state._get_env("WICAP_CAPTURE_DIR", "WICAP_CAPTURES_DIR", default=str(REPO_ROOT / "captures"))
)
REPLAY_ALLOWED_SUFFIXES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz")


def _is_safe_filename(filename: str) -> bool:
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    return True


def _resolve_capture_path(filename: str) -> Path | None:
    try:
        file_path = (CAPTURE_DIR / filename).resolve()
        capture_root = CAPTURE_DIR.resolve()
    except Exception:
        return None
    if capture_root not in file_path.parents and file_path != capture_root:
        return None
    return file_path
