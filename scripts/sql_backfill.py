#!/usr/bin/env python3
"""
sql_backfill.py
Robust backfill tool for WiFiWizard.

Replays 'curated_events.jsonl' into SQL Server using idempotent MERGE operations.
Tracks progress in 'sql_backfill.state.json' to support resuming.

Usage:
  python sql_backfill.py [--reset] [-v]
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import time

# Import shared config
from config import get_scout_config
from nexus.config import NexusConfig

logger = logging.getLogger('backfill')

class BackfillEngine:
    BATCH_SIZE = 100
    STATE_FILE = "sql_backfill.state.json"
    SOURCE_FILE = "curated_events.jsonl"

    def __init__(self, reset_state: bool = False):
        self.config = get_scout_config()
        self.captures_dir = self.config.captures_dir

        self.source_path = self.captures_dir / self.SOURCE_FILE
        self.state_path = self.captures_dir / self.STATE_FILE

        # State
        self.byte_offset = 0
        self.events_processed = 0
        self.running = True

        # SQL
        self.conn = None
        self.cursor = None

        if reset_state and self.state_path.exists():
            self.state_path.unlink()
            logger.info("State reset requested - starting from 0")

        self._load_state()

    def _load_state(self):
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text())
                self.byte_offset = data.get('byte_offset', 0)
                self.events_processed = data.get('events_processed', 0)
                logger.info(f"Resuming from offset {self.byte_offset} (processed {self.events_processed})")
            except Exception as e:
                logger.warning(f"Failed to load state ({e}) - starting from 0")
        else:
            logger.info("No state file found - starting from 0")

    def _save_state(self):
        data = {
            'byte_offset': self.byte_offset,
            'events_processed': self.events_processed,
            'updated_at': time.time()
        }
        temp_path = self.state_path.with_suffix('.tmp')
        with open(temp_path, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, self.state_path)

    def _connect_sql(self):
        try:
            import pyodbc

            config = NexusConfig.from_env()
            self.conn = pyodbc.connect(config.get_sql_connection_string(), timeout=30)
            self.cursor = self.conn.cursor()
            logger.info("Connected to SQL Server")
            self._ensure_schema()

        except ImportError:
            logger.error("pyodbc not installed")
            sys.exit(1)
        except Exception as e:
            logger.error(f"SQL Connection failed: {e}")
            sys.exit(1)

    def _ensure_schema(self) -> None:
        from event_processor import EventProcessor
        helper = EventProcessor(self.config, push_to_sql=True)
        helper._sql_conn = self.conn
        helper._ensure_sql_table()

    def _flush_batch(self, batch: list[dict]):
        if not batch:
            return

        try:
            # Reusing the robust Staging+MERGE logic from event_processor
            rows = []
            for event in batch:
                event_id = event.get('event_id')
                if not event_id:
                     content = json.dumps(event, sort_keys=True, separators=(',', ':'))
                     event_id = hashlib.sha256(content.encode()).hexdigest()

                rows.append((
                    event_id,
                    event.get('ts_epoch', 0),
                    event.get('event_type', 'unknown'),
                    event.get('channel', 0),
                    event.get('score', 0),
                    json.dumps(event)
                ))

            # Temp table
            self.cursor.execute("CREATE TABLE #BackfillStaging (event_id CHAR(64) PRIMARY KEY, ts_epoch DECIMAL(19,9), event_type VARCHAR(50), channel INT, score INT, payload NVARCHAR(MAX))")

            # Bulk Insert
            self.cursor.fast_executemany = False
            self.cursor.executemany("INSERT INTO #BackfillStaging VALUES (?, ?, ?, ?, ?, ?)", rows)

            # MERGE
            self.cursor.execute("""
                MERGE curated_events AS target
                USING #BackfillStaging AS source
                ON target.event_id = source.event_id
                WHEN NOT MATCHED THEN
                    INSERT (event_id, ts_epoch, event_type, channel, score, payload)
                    VALUES (source.event_id, source.ts_epoch, source.event_type, source.channel, source.score, source.payload);
            """)

            self.cursor.execute("DROP TABLE #BackfillStaging")
            self.conn.commit()

        except Exception as e:
            logger.error(f"Batch flush failed: {e}")
            # In backfill, we crash on error so we can retry later.
            # We do NOT drop data like the live processor.
            raise

    def run(self):
        if not self.source_path.exists():
            logger.error(f"Source file not found: {self.source_path}")
            return

        self._connect_sql()

        batch = []
        new_offset = self.byte_offset
        total_in_batch = 0

        logger.info("Starting backfill loop...")

        try:
            with open(self.source_path) as f:
                f.seek(self.byte_offset)

                while self.running:
                    line_start = f.tell()
                    raw_line = f.readline()

                    if not raw_line:
                        break # EOF

                    line_is_complete = raw_line.endswith('\n')
                    line = raw_line.strip()

                    if not line:
                        new_offset = f.tell()
                        continue

                    try:
                        event = json.loads(line)
                        batch.append(event)
                        total_in_batch += 1
                        new_offset = f.tell()

                        if len(batch) >= self.BATCH_SIZE:
                            self._flush_batch(batch)
                            self.byte_offset = new_offset
                            self.events_processed += len(batch)
                            self._save_state()
                            logger.info(f"Backfilled batch of {len(batch)} (Total: {self.events_processed})")
                            batch = []

                    except json.JSONDecodeError:
                        if not line_is_complete:
                            logger.info(f"Partial line at offset {line_start}, waiting for completion")
                            break
                        logger.warning(f"Skipping invalid JSON at offset {line_start}")
                        new_offset = f.tell()
                        self.byte_offset = new_offset

        except KeyboardInterrupt:
            logger.info("Interrupted")
        except Exception as e:
            logger.error(f"Fatal error: {e}")
        finally:
            # Flush remaining
            if batch:
                self._flush_batch(batch)
                self.byte_offset = new_offset
                self.events_processed += len(batch)
                self._save_state()
                logger.info(f"Flushed final batch of {len(batch)}")

            if self.conn:
                self.conn.close()

        logger.info(f"Done. Processed {self.events_processed} events total.")

def main():
    parser = argparse.ArgumentParser(description="WiFiWizard SQL Backfill")
    parser.add_argument("--reset", action="store_true", help="Reset state (backfill from start)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s | %(levelname)-7s | %(message)s',
        datefmt='%H:%M:%S'
    )

    engine = BackfillEngine(reset_state=args.reset)
    engine.run()

if __name__ == "__main__":
    main()
