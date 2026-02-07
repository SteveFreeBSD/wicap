#!/usr/bin/env python3
"""
WICAP Dependency Manager
Simplifies adding Python packages and syncing the offline environment.

Usage:
    python3 scripts/add_package.py <package_name> [--ui]

Examples:
    python3 scripts/add_package.py requests
    python3 scripts/add_package.py pandas --ui
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# Constants
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
CORE_REQS = PROJECT_ROOT / "requirements.txt"
UI_REQS = PROJECT_ROOT / "wicap-ui" / "requirements.txt"
SETUP_SCRIPT = PROJECT_ROOT / "scripts" / "setup_offline.sh"

def check_internet():
    """Simple connectivity check."""
    try:
        subprocess.check_call(["curl", "-s", "--head", "https://pypi.org"], stdout=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def add_requirement(package: str, req_file: Path):
    """Adds a package to the requirements file if not present."""
    if not req_file.exists():
        print(f"❌ Error: {req_file} not found.")
        sys.exit(1)

    content = req_file.read_text()
    if package in content:
        print(f"⚠️  Package '{package}' seems to be already in {req_file.name}")
        # We continue anyway to ensure wheels are downloaded
    else:
        print(f"📝 Adding '{package}' to {req_file.name}...")
        with req_file.open("a") as f:
            f.write(f"\n{package}")

def sync_offline():
    """Runs the setup_offline.sh script."""
    print("\n🔄 Syncing offline environment (downloading wheels)...")
    try:
        subprocess.check_call([str(SETUP_SCRIPT)], cwd=PROJECT_ROOT)
        print("\n✅ Verification complete. Environment is synced.")
    except subprocess.CalledProcessError:
        print("\n❌ Error: setup_offline.sh failed.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Add package and sync offline env.")
    parser.add_argument("package", help="Name of the package (e.g. 'requests' or 'requests==2.31.0')")
    parser.add_argument("--ui", action="store_true", help="Add to UI requirements instead of Core")
    args = parser.parse_args()

    # 1. Check for Prerequisites
    if not shutil.which("docker"):
        print("❌ Error: Docker is required to run the sync process.")
        sys.exit(1)

    # 2. Add to text file
    target_file = UI_REQS if args.ui else CORE_REQS
    add_requirement(args.package, target_file)

    # 3. Sync
    print("⏳ Note: This requires internet access to fetch wheels.")
    sync_offline()

    # 4. Prompt for Rebuild
    print("\n🎉 Package added successfully!")
    print("To apply changes, run:")
    print("  docker compose build")
    print("  docker compose up -d")

if __name__ == "__main__":
    main()
