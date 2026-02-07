#!/usr/bin/env python3
"""
init_db.py
Database Initialization Tool for WiFiWizard + NEXUS.

Features:
- creates tables if missing (idempotent)
- --recreate: drops existing tables and recreates them (fresh start)
- --nexus: creates NEXUS Phase 4 security audit tables

Usage:
  python init_db.py
  python init_db.py --recreate
  python init_db.py --nexus
  python init_db.py --recreate --nexus
"""

import argparse
import logging
import os
import sys
from pathlib import Path

try:
    import pyodbc
except ImportError:
    print("Error: pyodbc not installed.")
    sys.exit(1)

from config import get_scout_config
from event_processor import SQL_CONFIG, EventProcessor

logger = logging.getLogger('init_db')

# Phase 3 tables (original)
PHASE3_TABLES = ['summary_stats', 'curated_events']

# NEXUS Phase 4 tables
NEXUS_TABLES = [
    'nexus_config',
    'wordlists',
    'audit_reports',
    'pcap_index',
    'attack_timeline',
    'attack_feedback',
    'sensor_registry',
    'client_profiles',
    'handshakes',
    'security_posture',
    'triangulation_history',
]

def drop_tables(cursor, tables):
    """Drop specified tables in order (handles FK dependencies)."""
    for table in tables:
        try:
            cursor.execute(f"IF OBJECT_ID('{table}', 'U') IS NOT NULL DROP TABLE {table}")
            logger.info(f"Dropped table {table}")
        except Exception as e:
            logger.error(f"Failed to drop {table}: {e}")


def _connect_sql():
    """Connect to SQL Server using environment variables or defaults."""
    server = (
        os.environ.get('WICAP_SQL_SERVER')
        or os.environ.get('WICAP_SQL_HOST')
        or SQL_CONFIG.server
    )
    database = os.environ.get('WICAP_SQL_DATABASE', SQL_CONFIG.database)
    username = (
        os.environ.get('WICAP_SQL_USERNAME')
        or os.environ.get('WICAP_SQL_USER')
        or SQL_CONFIG.username
    )
    pwd = os.environ.get('WICAP_SQL_PASSWORD', SQL_CONFIG.password)
    driver = os.environ.get('WICAP_SQL_DRIVER', SQL_CONFIG.driver)
    conn_str = (
        f"DRIVER={{{driver}}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={pwd};"
        "TrustServerCertificate=YES;"
    )
    return pyodbc.connect(conn_str, timeout=30)


def create_nexus_tables(cursor, schema_path: Path):
    """Create NEXUS tables from schema.sql."""
    if not schema_path.exists():
        logger.error(f"Schema file not found: {schema_path}")
        return False

    schema_sql = schema_path.read_text()

    # Split by CREATE TABLE and execute each statement
    # We need to handle the SQL statements carefully
    statements = []
    current = []

    for line in schema_sql.split('\n'):
        stripped = line.strip()
        # Skip comments and empty lines for statement grouping
        if stripped.startswith('--') and not current:
            continue
        if stripped.startswith('--') and '═' in stripped:
            # Section divider - commit current statement if any
            if current:
                statements.append('\n'.join(current))
                current = []
            continue

        current.append(line)

        # Check if this line ends a statement
        if stripped.endswith(';'):
            statements.append('\n'.join(current))
            current = []

    if current:
        statements.append('\n'.join(current))

    # Execute each statement
    created = 0
    for stmt in statements:
        stmt = stmt.strip()
        if not stmt or stmt.startswith('--'):
            continue

        # Skip existing table checks for NEXUS tables
        if 'CREATE TABLE' in stmt:
            # Extract table name
            import re
            match = re.search(r'CREATE TABLE\s+(\w+)', stmt, re.IGNORECASE)
            if match:
                table_name = match.group(1)
                # Check if table already exists
                cursor.execute(f"SELECT OBJECT_ID('{table_name}', 'U')")
                if cursor.fetchone()[0] is not None:
                    logger.info(f"Table {table_name} already exists, skipping")
                    continue

        try:
            cursor.execute(stmt)
            if 'CREATE TABLE' in stmt:
                created += 1
                logger.info("Created table")
            elif 'CREATE INDEX' in stmt:
                logger.debug("Created index")
            elif 'INSERT INTO' in stmt:
                logger.debug("Inserted default data")
        except Exception as e:
            # Ignore "already exists" errors
            if 'already exists' in str(e).lower() or 'duplicate' in str(e).lower():
                logger.debug("Object already exists, skipping")
            else:
                logger.warning(f"Statement failed: {e}")

    return created


def main():
    parser = argparse.ArgumentParser(description="Initialize WiFiWizard + NEXUS SQL Schema")
    parser.add_argument("--recreate", action="store_true", help="DROP and RECREATE tables (Destructive)")
    parser.add_argument("--nexus", action="store_true", help="Create NEXUS Phase 4 security audit tables")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(name)s: %(message)s')

    config = get_scout_config()

    try:
        conn = _connect_sql()
    except Exception as e:
        logger.error(f"Failed to connect to SQL Server: {e}")
        sys.exit(1)

    cursor = conn.cursor()

    # Determine which tables to manage
    tables_to_drop = PHASE3_TABLES.copy()
    if args.nexus:
        tables_to_drop = NEXUS_TABLES + PHASE3_TABLES  # NEXUS tables first (they may reference Phase3)

    if args.recreate:
        logger.warning("!!! DROPPING TABLES !!!")
        drop_tables(cursor, tables_to_drop)
        conn.commit()

    # Create Phase 3 tables using EventProcessor
    logger.info("Ensuring Phase 3 schema exists...")
    processor = EventProcessor(config, push_to_sql=True)
    processor._sql_conn = conn
    processor._ensure_sql_table()

    # Create NEXUS tables if requested
    if args.nexus:
        logger.info("Creating NEXUS Phase 4 tables...")
        schema_path = Path(__file__).parent / 'schema.sql'
        create_nexus_tables(cursor, schema_path)
        conn.commit()
        logger.info("✅ NEXUS tables created")

    logger.info("✅ Database initialization complete.")
    conn.close()

if __name__ == "__main__":
    main()
