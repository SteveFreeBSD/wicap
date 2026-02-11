from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def test_check_wicap_status_emits_json_local_only(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "check_wicap_status.py"
    captures_dir = tmp_path / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--local-only",
            "--json",
            "--captures-dir",
            str(captures_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert "generated_at" in payload
    assert "local" in payload
    assert payload["sql"] is None
    assert isinstance(payload["local"], dict)
