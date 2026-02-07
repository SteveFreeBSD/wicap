"""
WICAP Deterministic Replay Driver

Replays PCAP captures through the Scout pipeline without hardware,
producing deterministic event outputs for CI validation.

Usage:
    # Single file replay
    python -m replay_driver --pcap tests/fixtures/pcap/file.pcapng --output /tmp/out

    # Validate against expected
    python -m replay_driver --pcap tests/fixtures/pcap/file.pcapng \
        --expected tests/fixtures/events/file.expected.jsonl

    # Override run_id (default: hash of file contents)
    python -m replay_driver --pcap tests/fixtures/pcap/file.pcapng \
        --run-id replay-fixed-id

    # Force channel for replay
    python -m replay_driver --pcap tests/fixtures/pcap/file.pcapng \
        --channel 6

    # Batch replay from manifest
    python -m replay_driver --batch tests/fixtures/manifest.json

Manifest entries support optional fields:
- run_id: override replay run_id for stable output naming
- channel: force channel when the filename does not include _chX

    # Generate golden snapshot
    python -m replay_driver --pcap tests/fixtures/pcap/file.pcapng --snapshot
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config import get_scout_config
from event_processor import EventProcessor
from scout import Scout

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('replay_driver')


@dataclass
class ValidationResult:
    """Result of comparing actual vs expected events."""
    passed: bool
    total_expected: int = 0
    total_actual: int = 0
    matched: int = 0
    mismatches: list[dict] = field(default_factory=list)
    missing: list[dict] = field(default_factory=list)
    extra: list[dict] = field(default_factory=list)

    def summary(self) -> str:
        if self.passed:
            return f"✅ PASS: {self.matched}/{self.total_expected} events matched"
        lines = [
            f"❌ FAIL: {self.matched}/{self.total_expected} matched",
            f"   Mismatches: {len(self.mismatches)}",
            f"   Missing: {len(self.missing)}",
            f"   Extra: {len(self.extra)}",
        ]
        return "\n".join(lines)


@dataclass
class ReplayConfig:
    """Configuration for a replay run."""
    pcap_path: Path
    output_dir: Path
    push_to_sql: bool = False
    push_to_ui: bool = False
    expected_path: Path | None = None
    generate_snapshot: bool = False
    run_id: str | None = None
    force_channel: int | None = None


def normalize_event(event: dict) -> dict:
    """
    Normalize an event for comparison by removing volatile fields.

    Removes:
    - inserted_at (runtime timestamp)
    - vendor (may change with OUI updates)
    - run_id (varies per run unless controlled)
    - event_id (derived from event payload shape)
    """
    normalized = dict(event)

    # Remove volatile fields
    for key in ['inserted_at', 'vendor', 'run_id', 'ts_epoch', 'event_id']:
        normalized.pop(key, None)

    # Normalize nested payload if present
    if 'payload' in normalized and isinstance(normalized['payload'], str):
        try:
            payload = json.loads(normalized['payload'])
            payload.pop('vendor', None)
            payload.pop('run_id', None)
            normalized['payload'] = payload
        except json.JSONDecodeError:
            pass

    return normalized


def _is_expected_subset(expected_event: dict, actual_event: dict) -> bool:
    """
    Compare events with subset semantics.

    Expected fixtures intentionally capture the stable core shape; runtime output
    may include extra metadata fields that should not fail validation.
    """
    for key, expected_value in expected_event.items():
        if actual_event.get(key) != expected_value:
            return False
    return True


def event_fingerprint(event: dict) -> str:
    """Generate a stable fingerprint for an event."""
    normalized = normalize_event(event)
    content = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def load_events(path: Path) -> list[dict]:
    """Load events from a JSONL file."""
    events = []
    if not path.exists():
        return events

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning(f"Skipping malformed line in {path}")
    return events


def save_events(events: list[dict], path: Path) -> None:
    """Save events to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        for event in events:
            f.write(json.dumps(event, separators=(',', ':')) + '\n')


def validate_events(actual: list[dict], expected: list[dict]) -> ValidationResult:
    """
    Compare actual events against expected events.

    Uses event_id for matching when available, otherwise fingerprints.
    """
    # telemetry_pulse is periodic/non-deterministic by design and excluded from
    # strict fixture validation.
    expected_filtered = [e for e in expected if e.get("event_type") != "telemetry_pulse"]
    actual_filtered = [e for e in actual if e.get("event_type") != "telemetry_pulse"]

    result = ValidationResult(passed=True)
    result.total_expected = len(expected_filtered)
    result.total_actual = len(actual_filtered)

    # Keep normalized + original for efficient matching and reporting.
    actual_pool: list[tuple[dict, dict]] = [
        (event, normalize_event(event))
        for event in actual_filtered
    ]

    for expected_event in expected_filtered:
        expected_norm = normalize_event(expected_event)
        match_idx = None
        for idx, (_actual_orig, actual_norm) in enumerate(actual_pool):
            if _is_expected_subset(expected_norm, actual_norm):
                match_idx = idx
                break

        if match_idx is None:
            result.missing.append(expected_event)
            result.passed = False
            continue

        _actual_orig, actual_norm = actual_pool.pop(match_idx)
        result.matched += 1
        if not _is_expected_subset(expected_norm, actual_norm):
            result.mismatches.append({
                'expected': expected_event,
                'actual': _actual_orig,
            })
            result.passed = False

    if actual_pool:
        result.extra.extend(actual_orig for actual_orig, _ in actual_pool)
        result.passed = False

    return result


def replay_pcap(config: ReplayConfig) -> Path:
    """
    Replay a PCAP file through the Scout pipeline.

    Returns path to the curated events file.
    """
    logger.info(f"Replaying: {config.pcap_path}")

    # Create isolated config
    scout_config = get_scout_config()
    scout_config.captures_dir = config.output_dir

    # Initialize scout and run replay
    scout = Scout(scout_config)
    scout.replay_file(
        config.pcap_path,
        force_channel=config.force_channel,
        run_id=config.run_id,
    )

    # Now process the event queue
    logger.info("Processing event queue...")
    if not config.push_to_ui:
        os.environ.setdefault("WICAP_INTERNAL_SECRET_REQUIRED", "false")
    processor = EventProcessor(
        scout_config,
        push_to_sql=config.push_to_sql
    )

    # Disable UI push if not requested
    if not config.push_to_ui:
        processor._ui_ready = False

    # Process all events (drain rotated queues if needed)
    total_new = total_curated = total_suppressed = 0
    while True:
        new_events, curated_events, suppressed = processor.process_batch()
        total_new += new_events
        total_curated += curated_events
        total_suppressed += suppressed
        if new_events == 0 and curated_events == 0 and suppressed == 0:
            break
    logger.info(
        f"Processed: {total_new} new, {total_curated} curated, {total_suppressed} suppressed"
    )

    # Save final state
    processor._save_state()
    processor.dedup_cache.save()

    curated_path = config.output_dir / "curated_events.jsonl"
    return curated_path


def run_single(args) -> bool:
    """Run a single PCAP replay with optional validation."""
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {pcap_path}")
        return False

    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        cleanup = False
    else:
        output_dir = Path(tempfile.mkdtemp(prefix='wicap_replay_'))
        cleanup = True

    config = ReplayConfig(
        pcap_path=pcap_path,
        output_dir=output_dir,
        push_to_sql=args.sql,
        push_to_ui=args.ui,
        expected_path=Path(args.expected) if args.expected else None,
        generate_snapshot=args.snapshot,
        run_id=args.run_id,
        force_channel=args.channel,
    )

    try:
        curated_path = replay_pcap(config)
        actual_events = load_events(curated_path)

        if config.generate_snapshot:
            # Save as golden snapshot
            snapshot_name = pcap_path.stem + '.expected.jsonl'
            snapshot_path = Path('tests/fixtures/events') / snapshot_name
            save_events(actual_events, snapshot_path)
            logger.info(f"✅ Generated snapshot: {snapshot_path} ({len(actual_events)} events)")
            return True

        if config.expected_path:
            # Validate against expected
            expected_events = load_events(config.expected_path)
            result = validate_events(actual_events, expected_events)
            print(result.summary())

            if not result.passed:
                # Save failure artifacts
                failure_dir = Path('/tmp/wicap_replay_failures')
                failure_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy(curated_path, failure_dir / 'actual.jsonl')
                shutil.copy(config.expected_path, failure_dir / 'expected.jsonl')
                logger.info(f"Failure artifacts saved to {failure_dir}")

            return result.passed

        # No validation, just report
        logger.info(f"✅ Replay complete: {len(actual_events)} curated events")
        logger.info(f"   Output: {curated_path}")
        return True

    finally:
        if cleanup:
            shutil.rmtree(output_dir, ignore_errors=True)


def run_batch(args) -> bool:
    """Run batch replay from manifest file."""
    manifest_path = Path(args.batch)
    if not manifest_path.exists():
        logger.error(f"Manifest not found: {manifest_path}")
        return False

    with open(manifest_path) as f:
        manifest = json.load(f)

    fixtures = manifest.get('fixtures', [])
    if not fixtures:
        logger.warning("No fixtures in manifest")
        return True

    results = []
    for fixture in fixtures:
        name = fixture.get('name', 'unknown')
        pcap = Path(fixture['pcap'])
        expected = Path(fixture['expected']) if fixture.get('expected') else None

        logger.info(f"━━━ {name} ━━━")

        # Create args namespace for single run
        class SingleArgs:
            pass
        single_args = SingleArgs()
        single_args.pcap = str(pcap)
        single_args.output = None
        single_args.expected = str(expected) if expected else None
        single_args.sql = False
        single_args.ui = False
        single_args.snapshot = False
        single_args.run_id = fixture.get('run_id')
        single_args.channel = fixture.get('channel')

        passed = run_single(single_args)
        results.append((name, passed))

    # Summary
    print("\n" + "━" * 50)
    print("REPLAY TEST SUMMARY")
    print("━" * 50)
    passed_count = sum(1 for _, p in results if p)
    for name, passed in results:
        status = "✅" if passed else "❌"
        print(f"  {status} {name}")
    print(f"\nTotal: {passed_count}/{len(results)} passed")

    return all(p for _, p in results)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='WICAP Deterministic Replay Driver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--pcap', help='Path to PCAP file to replay')
    parser.add_argument('--output', help='Output directory (uses temp if not specified)')
    parser.add_argument('--expected', help='Path to expected events JSONL for validation')
    parser.add_argument('--batch', help='Path to manifest JSON for batch replay')
    parser.add_argument('--snapshot', action='store_true',
                        help='Generate golden snapshot instead of validating')
    parser.add_argument('--run-id', help='Override replay run_id (default: hash of file)')
    parser.add_argument('--channel', type=int, help='Force channel for replay')
    parser.add_argument('--sql', action='store_true', help='Push to SQL (default: disabled)')
    parser.add_argument('--ui', action='store_true', help='Push to UI (default: disabled)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.batch:
        success = run_batch(args)
    elif args.pcap:
        success = run_single(args)
    else:
        parser.print_help()
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
