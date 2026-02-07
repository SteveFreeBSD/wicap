import sys

sys.path.insert(0, "/app")
from nexus.config import get_nexus_config
from nexus.scavenger.persistence import ScavengerDAO


class ScavengerState:
    """Manages the Scavenger pipeline state."""

    def __init__(self):
        self.pipeline = None
        self.status = "idle"  # idle, running, complete, error
        self.progress = {
            "percent": 0,
            "message": "",
            "files_done": 0,
            "files_total": 0,
            "packets": 0,
            "intelligence": 0,
        }
        self.results = None
        self.error = None
        self._thread = None

    def reset(self):
        self.status = "idle"
        self.progress = {
            "percent": 0,
            "message": "",
            "files_done": 0,
            "files_total": 0,
            "packets": 0,
            "intelligence": 0,
        }
        self.results = None
        self.error = None


scavenger_state = ScavengerState()

try:
    scavenger_dao = ScavengerDAO(get_nexus_config())
except Exception as exc:
    print(f"Failed to init ScavengerDAO: {exc}")
    scavenger_dao = None
