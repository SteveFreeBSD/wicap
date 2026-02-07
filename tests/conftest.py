import os
import sys
from functools import lru_cache
from pathlib import Path
from urllib import error
from urllib import request as urlrequest

import pytest

# Add project root to sys.path so tests can import nexus, config, parser, etc.
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
SRC_DIR = BASE_DIR / "src"
if SRC_DIR.exists() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
UI_DIR = BASE_DIR / "wicap-ui"
if UI_DIR.exists() and str(UI_DIR) not in sys.path:
    sys.path.insert(0, str(UI_DIR))

# Some test runners import via a package-qualified path (e.g., wicap.nexus).
# Provide a lightweight alias so collection succeeds without installing a wheel.
try:
    import nexus as _nexus  # noqa: F401
    sys.modules.setdefault("wicap.nexus", _nexus)
except Exception:
    pass

# Fix for Arch Linux / externally managed environments where Playwright
# is installed via pipx but not in the global site-packages.
# This ensures all tests can find the playwright module.
PIPX_PLAYWRIGHT = Path.home() / ".local/share/pipx/venvs/playwright/lib/python3.14/site-packages"
if PIPX_PLAYWRIGHT.exists():
    sys.path.insert(0, str(PIPX_PLAYWRIGHT))

# Test harness defaults:
# Some modules enforce required secrets at import time. For unit tests we set
# safe dummy values so imports don't fail and DB connections can be mocked.
os.environ.setdefault("WICAP_SQL_PASSWORD", "test-password-123")
os.environ.setdefault("WICAP_INTERNAL_SECRET", "test-internal-secret-123")
os.environ.setdefault("WICAP_INTERNAL_SECRET_REQUIRED", "false")
# Prefer a fast-fail SQL host during tests (avoids long connect timeouts).
os.environ.setdefault("WICAP_SQL_HOST", "127.0.0.1,1433")
os.environ.setdefault("WICAP_SQL_SERVER", "127.0.0.1,1433")


@lru_cache(maxsize=4)
def _ui_base_reachable(base_url: str) -> bool:
    try:
        with urlrequest.urlopen(base_url, timeout=2.0) as resp:
            return bool(resp.status and resp.status < 500)
    except error.HTTPError as exc:
        return exc.code < 500
    except Exception:
        return False


@pytest.fixture(autouse=True)
def _skip_e2e_when_ui_unavailable(request):
    """Skip e2e/browser tests unless the configured UI base URL is reachable."""
    if request.node.get_closest_marker("e2e") is None:
        return

    base_url = os.environ.get("WICAP_UI_URL", "http://localhost:8080")
    if not _ui_base_reachable(base_url):
        pytest.skip(f"UI unavailable for e2e tests at {base_url}. Start stack with: docker compose up -d")
