"""
NEXUS Watcher CLI
Usage: python -m nexus.watcher start
"""

import argparse
import logging

from nexus.config import get_nexus_config
from nexus.dwell_watcher import DwellWatcher


def main() -> None:
    parser = argparse.ArgumentParser(description="NEXUS Dwell Watcher")
    parser.add_argument('action', choices=['start'], help='Start the watcher')
    parser.add_argument('--interval', type=int, default=60, help='Polling interval in seconds')
    parser.add_argument('--baseline', action='store_true',
                        help='Mark existing dwell_*.pcapng as processed before watching')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    if args.action == 'start':
        config = get_nexus_config()
        watcher = DwellWatcher(config)
        if args.baseline:
            watcher.baseline_existing()
        watcher.watch(interval=args.interval)

if __name__ == '__main__':
    main()
