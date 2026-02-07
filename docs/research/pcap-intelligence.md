# PCAP Intelligence Extraction - 2026-Ready, Realistic Plan

## Objective
Modernize WICAP's NEXUS Scavenger pipeline using proven tools (not wheel-rebuilding) and keep any post-analysis out of the hot path.

Status note:
- This document began as a planning/spec artifact. Use it as background research.
- Canonical current-state and next steps live in `docs/ROADMAP.md`.
- Operational backfill commands live in `docs/BACKFILL.md` (this is not a runbook).

## User Decisions (Confirmed)
| Topic | Decision |
|-------|----------|
| Associations | Dedicated `client_associations` table + derived JSON summary in `client_profiles` |
| RSSI | Aggregate only (avg/max/last + sample_count in `client_profiles`) |
| Backfill | 30 days first, then full; use `pcap_index.processing_status` as resume cursor |
| Future RSSI | Per-dwell samples if needed later |
| Dissector | Skip `tshark/pyshark` for now; add a `--dissector tshark` flag later if IE fidelity needs it |

## Principles
- Keep ingestion deterministic and fast; post-analysis runs after extraction on aggregated summaries.
- Reuse ScavengerPipeline, agents, and DAO; add optional "dissector mode" only if needed.
- Avoid schema explosion; store time-series only if a real query needs it.

## Architecture (ASCII)
```
PCAP -> PCAPStreamer (scapy) -> Agents (Shadow/Cartographer/Crypt) -> Correlator -> SQL
                                  |                        |
                                  +--> Optional Tshark Path +--> Post-Analysis
```

## Modern Tools That Avoid Rebuilding the Wheel

### 1. Wireshark dissectors via tshark/pyshark (optional, recommended for IE fidelity)
- Why: Wireshark decoders are the most complete for 802.11 IEs, including newer HE/EHT elements.
- Use for backfill or validation; keep scapy as default path for live runs.

Example field extraction (one process per file, JSON/CSV output):
```
tshark -r file.pcapng -Y "wlan.fc.type_subtype==4" \
  -T fields -e frame.time_epoch -e wlan.sa -e wlan_mgt.ssid \
  -e radiotap.dbm_antsignal -e wlan_radio.channel -e wlan.tag.number
```

### 2. Scapy streaming (default)
- Already implemented in `nexus/scavenger/ingest.py`.
- Extend parsing instead of replacing it; preserve dedup and memory behavior.

### 3. hcxtools stays for handshakes
- Keep `hcxpcapngtool` for handshake/PMKID extraction (already integrated).

### 4. 2026-ready fingerprint signals (no ML required)
- Capture IE tag order, vendor IEs, and modern capabilities:
  - HT (802.11n), VHT (802.11ac), HE (802.11ax/6E), EHT (802.11be/7)
  - 802.11k/v/r indicators if present
- Store raw/hex where parsing is partial; keep upgrade path.

## Data Model (SQL Server syntax)

### Dedicated association table (confirmed)
```
CREATE TABLE client_associations (
    id BIGINT IDENTITY PRIMARY KEY,
    client_mac CHAR(17) NOT NULL,
    bssid CHAR(17) NOT NULL,
    ssid NVARCHAR(64),
    first_seen DATETIME2 NOT NULL,
    last_seen DATETIME2 NOT NULL,
    association_count INT NOT NULL DEFAULT 1,
    last_assoc_type VARCHAR(16) NULL, -- assoc_req, assoc_resp, reassoc, auth, data
    CONSTRAINT UQ_client_assoc UNIQUE (client_mac, bssid)
);

CREATE INDEX IX_client_assoc_client ON client_associations(client_mac);
CREATE INDEX IX_client_assoc_bssid ON client_associations(bssid);
```

### RSSI aggregates in client_profiles (confirmed)
```
ALTER TABLE client_profiles ADD
    rssi_avg INT NULL,
    rssi_max INT NULL,
    rssi_last INT NULL,
    rssi_sample_count INT DEFAULT 0,
    rssi_last_seen DATETIME2 NULL;
```

### Ensure channels_active exists (ScavengerDAO expects it)
```
ALTER TABLE client_profiles ADD channels_active NVARCHAR(MAX);
```

Optional (future): per-dwell RSSI samples
```
-- Only if time-series needed later
CREATE TABLE rssi_dwell_samples (
    id BIGINT IDENTITY PRIMARY KEY,
    mac CHAR(17) NOT NULL,
    dwell_file NVARCHAR(255) NOT NULL,
    sample_time DATETIME2 NOT NULL,
    rssi_avg INT,
    rssi_max INT,
    rssi_min INT,
    channel INT
);
```

## Extraction Updates (No Wheel Rebuild)

### Probe requests
- Use existing `AgentShadow` and persist to `client_profiles`:
  - `probed_ssids`, `probe_count`, `first_seen`, `last_seen`, `channels_active`.

### Associations
- Implement `AgentCartographer`:
  - Parse `Dot11AssoReq`, `Dot11AssoResp`, `Dot11ReassoReq/Resp`, `Dot11Auth`.
  - Optionally infer associations from data frames when BSSID and client are clear.
  - Persist to `client_associations` and update JSON summary in `client_profiles.associated_bssids`.
  - Expose `export_associations()` returning dicts with `client_mac`, `bssid`, `ssid`,
    `assoc_type`, `first_seen`, `last_seen`, `association_count`.

### Fingerprints
- Extend `DeviceFingerprinter` to store:
  - `ie_fingerprint`: ordered IE tag list (e.g., "0,1,45,50,191,255")
  - `probe_fingerprint`: stable hash of IE list + vendor IE OUIs + capability bytes
  - `supported_rates`: probe IE 1/50 decoded into a compact string
  - `ht_capabilities_probe`: raw HT bytes (VHT/HE/EHT presence captured by tags)
  - Vendor IE OUIs included in the hash input (no new column yet)

### RSSI aggregates
- Compute per-client aggregates per file:
  - Update avg/max/last + count and last_seen.
  - Use `ClientPNL.rssi_history` to compute aggregates before DAO upsert.
  - Optionally per-dwell samples later using `rssi_dwell_samples`.

## Backfill (30 days first)
- CLI: `scripts/mine_pcaps.py --since 30d --resume`
- Use `pcap_index.processing_status` for resume and to avoid duplicate work.
- Batch inserts with `pyodbc` + `fast_executemany`.
- Emit progress stats per file and per N packets.

## Implementation Phases

### Phase 1: Schema + Persistence (Week 1)
- Add `client_associations` + RSSI aggregate columns.
- Extend `ScavengerDAO` for new table and RSSI fields.

### Phase 2: Agent Updates (Week 1)
- Implement `AgentCartographer`.
- Extend `DeviceFingerprinter` IE extraction and storage.

### Phase 3: Backfill + Resume (Week 2)
- CLI backfill with `pcap_index` cursor, 30-day window.
- Validate counts and query latency.

## Dependencies (Optional, Minimal)
```
# Optional: high-fidelity dissectors
pyshark>=0.6.0   # requires tshark installed

# Optional: fast offline analytics
polars>=0.20.0
```

## Reference Files
| File | Purpose |
|------|---------|
| `nexus/scavenger/pipeline.py:18` | ScavengerPipeline entrypoint |
| `nexus/scavenger/agents.py:117` | AgentShadow and AgentCartographer |
| `nexus/scavenger/ingest.py:104` | PCAPStreamer |
| `nexus/device_fingerprint.py:272` | DeviceFingerprinter |
| `nexus/scavenger/persistence.py:42` | ScavengerDAO |

## Success Criteria
1. 30-day backfill completes without errors and is resumable.
2. Query: "Associations for client X" returns first/last/count.
3. `client_profiles` has RSSI aggregates populated.
4. No regression in handshake extraction or existing Scavenger outputs.

---

## Field Ownership Mapping

Prevents schema drift and duplicate sources of truth.

### client_profiles
| Column | Owner | Write Pattern |
|--------|-------|---------------|
| `mac_addr` | ScavengerDAO | Insert on first sight |
| `vendor` | DeviceFingerprinter | Update on probe/assoc if known |
| `is_randomized` | AgentShadow | Set from MAC LAA bit |
| `device_type` | DeviceFingerprinter | Update if confidence improves |
| `probe_fingerprint` | DeviceFingerprinter | Hash of IE list + vendor IEs |
| `ie_fingerprint` | DeviceFingerprinter | Ordered IE tag list string |
| `supported_rates` | DeviceFingerprinter | Update from probe IEs |
| `ht_capabilities_probe` | DeviceFingerprinter | Raw HT bytes |
| `probed_ssids` | AgentShadow | Append JSON array (unique) |
| `probe_count` | AgentShadow | Increment |
| `associated_bssids` | AgentCartographer | Derived JSON summary |
| `channels_active` | AgentShadow | JSON set of channels |
| `channel_distribution` | AgentShadow | Optional JSON counts (future) |
| `rssi_avg` | AgentShadow | Running average |
| `rssi_max` | AgentShadow | Max observed |
| `rssi_last` | AgentShadow | Most recent |
| `rssi_sample_count` | AgentShadow | Increment |
| `rssi_last_seen` | AgentShadow | Timestamp of last sample |
| `threat_score` | DeviceFingerprinter | Update on profile save |
| `threat_indicators` | DeviceFingerprinter | JSON reasons |
| `first_seen` | ScavengerDAO | Set once |
| `last_seen` | ScavengerDAO | Update on any frame |
| `updated_at` | ScavengerDAO | Update on write |

Note: Align `DeviceFingerprinter.save_profile` columns with this mapping.

### client_associations
| Column | Owner | Write Pattern |
|--------|-------|---------------|
| `client_mac` | AgentCartographer | Insert/Upsert |
| `bssid` | AgentCartographer | Insert/Upsert |
| `ssid` | AgentCartographer | Update if null |
| `first_seen` | AgentCartographer | Set once |
| `last_seen` | AgentCartographer | Update on each frame |
| `association_count` | AgentCartographer | Increment |
| `last_assoc_type` | AgentCartographer | Update |

### pcap_index
| Column | Owner | Write Pattern |
|--------|-------|---------------|
| `filepath` | DwellWatcher | Insert on capture complete |
| `processing_status` | BackfillCLI | Transition: pending→processing→complete/error |
| `processed_at` | BackfillCLI | Set on complete |
| `processing_error` | BackfillCLI | Set on error |

---

## Idempotent Migration Patterns

Safe to re-run; no-op if already applied.

### Add column if not exists
```sql
-- RSSI columns
IF COL_LENGTH('client_profiles', 'rssi_avg') IS NULL
    ALTER TABLE client_profiles ADD rssi_avg INT NULL;
IF COL_LENGTH('client_profiles', 'rssi_max') IS NULL
    ALTER TABLE client_profiles ADD rssi_max INT NULL;
IF COL_LENGTH('client_profiles', 'rssi_last') IS NULL
    ALTER TABLE client_profiles ADD rssi_last INT NULL;
IF COL_LENGTH('client_profiles', 'rssi_sample_count') IS NULL
    ALTER TABLE client_profiles ADD rssi_sample_count INT DEFAULT 0;
IF COL_LENGTH('client_profiles', 'rssi_last_seen') IS NULL
    ALTER TABLE client_profiles ADD rssi_last_seen DATETIME2 NULL;
IF COL_LENGTH('client_profiles', 'channels_active') IS NULL
    ALTER TABLE client_profiles ADD channels_active NVARCHAR(MAX);
```

### Create table if not exists
```sql
IF OBJECT_ID('client_associations', 'U') IS NULL
BEGIN
    CREATE TABLE client_associations (
        id BIGINT IDENTITY PRIMARY KEY,
        client_mac CHAR(17) NOT NULL,
        bssid CHAR(17) NOT NULL,
        ssid NVARCHAR(64),
        first_seen DATETIME2 NOT NULL,
        last_seen DATETIME2 NOT NULL,
        association_count INT NOT NULL DEFAULT 1,
        last_assoc_type VARCHAR(16) NULL,
        CONSTRAINT UQ_client_assoc UNIQUE (client_mac, bssid)
    );
END
```

### Create index if not exists
```sql
IF NOT EXISTS (
    SELECT 1 FROM sys.indexes
    WHERE name = 'IX_client_assoc_client'
      AND object_id = OBJECT_ID('client_associations')
)
    CREATE INDEX IX_client_assoc_client ON client_associations(client_mac);
IF NOT EXISTS (
    SELECT 1 FROM sys.indexes
    WHERE name = 'IX_client_assoc_bssid'
      AND object_id = OBJECT_ID('client_associations')
)
    CREATE INDEX IX_client_assoc_bssid ON client_associations(bssid);
```

### Rollback (if needed)
```sql
-- Rollback RSSI columns
IF COL_LENGTH('client_profiles', 'rssi_avg') IS NOT NULL
    ALTER TABLE client_profiles DROP COLUMN rssi_avg;
IF COL_LENGTH('client_profiles', 'rssi_max') IS NOT NULL
    ALTER TABLE client_profiles DROP COLUMN rssi_max;
IF COL_LENGTH('client_profiles', 'rssi_last') IS NOT NULL
    ALTER TABLE client_profiles DROP COLUMN rssi_last;
IF COL_LENGTH('client_profiles', 'rssi_sample_count') IS NOT NULL
    ALTER TABLE client_profiles DROP COLUMN rssi_sample_count;
IF COL_LENGTH('client_profiles', 'rssi_last_seen') IS NOT NULL
    ALTER TABLE client_profiles DROP COLUMN rssi_last_seen;

-- Rollback associations table
IF OBJECT_ID('client_associations', 'U') IS NOT NULL
    DROP TABLE client_associations;
```

---

## Association Inference Rules

### Frame Types & Subtypes
| Type | Subtype | Scapy Class | Trust Level | Action |
|------|---------|-------------|-------------|--------|
| 0 (Mgmt) | 0 | Dot11AssoReq | High | Create/update association |
| 0 (Mgmt) | 1 | Dot11AssoResp | High | Confirm association |
| 0 (Mgmt) | 2 | Dot11ReassoReq | High | Update association |
| 0 (Mgmt) | 3 | Dot11ReassoResp | High | Confirm reassociation |
| 0 (Mgmt) | 11 | Dot11Auth | Medium | Pre-association signal |
| 2 (Data) | * | Dot11 / Dot11QoS | Low | Infer if BSSID clear |

### DS Bit Mapping (To DS / From DS)
| ToDS | FromDS | Meaning | addr1 | addr2 | addr3 | Trust |
|------|--------|---------|-------|-------|-------|-------|
| 0 | 0 | Ad-hoc / Mgmt | DA | SA | BSSID | High for mgmt |
| 0 | 1 | AP → Client | DA=Client | BSSID | SA | High |
| 1 | 0 | Client → AP | BSSID | SA=Client | DA | High |
| 1 | 1 | WDS | RA | TA | DA | Skip (bridge) |

### Inference Logic
```python
def _is_broadcast_or_multicast(mac):
    if not mac:
        return True
    mac = mac.lower()
    if mac == "ff:ff:ff:ff:ff:ff":
        return True
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return True
    return bool(first_octet & 0x01)

def infer_association(pkt):
    """Extract client↔BSSID from frame"""
    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]
    fc = dot11.FCfield
    to_ds = (fc & 0x01) != 0
    from_ds = (fc & 0x02) != 0

    # Management frames: BSSID in addr3
    if dot11.type == 0:
        bssid = dot11.addr3
        if dot11.subtype in (0, 2):  # AssoReq, ReassoReq
            client = dot11.addr2  # SA
            assoc_type = "assoc_req"
        elif dot11.subtype in (1, 3):  # AssoResp, ReassoResp
            client = dot11.addr1  # DA
            assoc_type = "assoc_resp"
        elif dot11.subtype == 11:  # Auth
            client = dot11.addr2
            assoc_type = "auth"
        else:
            return None

        if _is_broadcast_or_multicast(client) or _is_broadcast_or_multicast(bssid):
            return None
        return (client, bssid, assoc_type)

    # Data frames: use DS bits
    if dot11.type == 2 and not (to_ds and from_ds):  # Skip WDS
        if to_ds and not from_ds:
            # Client → AP
            bssid = dot11.addr1
            client = dot11.addr2
        elif from_ds and not to_ds:
            # AP → Client
            bssid = dot11.addr2
            client = dot11.addr1
        else:
            return None

        if _is_broadcast_or_multicast(client) or _is_broadcast_or_multicast(bssid):
            return None
        return (client, bssid, "data")

    return None
```

### When to Trust Data Frames
- Only if no mgmt frame association exists for that pair
- Mark `last_assoc_type = 'data'` to indicate inferred
- Prefer mgmt frames when both exist
- Ignore broadcast/multicast client or BSSID addresses

---

## Backfill Runbook

### Configuration
| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Batch size | 100 files | Balance memory vs. commit frequency |
| SQL batch | 500 rows | `fast_executemany` sweet spot |
| Concurrency | 1 (serial) | Avoid lock contention |
| Error policy | Log + continue | Don't block on single file |
| Progress | Every 10 files | Visible feedback |

### pcap_index Status Transitions
```
pending → processing (on file start)
processing → complete (on success)
processing → error (on exception, store message)
```

### CLI Usage
```bash
# 30-day backfill with resume
python scripts/mine_pcaps.py --since 30d --resume --batch 100

# Full backfill (after validation)
python scripts/mine_pcaps.py --all --resume --batch 100

# Retry failed files only
python scripts/mine_pcaps.py --retry-errors --batch 50

# Dry run (no writes)
python scripts/mine_pcaps.py --since 30d --dry-run
```

### Implementation Pattern
```python
def backfill(args):
    config = get_nexus_config()
    conn = pyodbc.connect(config.get_sql_connection_string(), autocommit=False)
    cursor = conn.cursor()
    cursor.fast_executemany = True
    
    # Get files to process
    files = query_pcap_index(
        status='pending' if not args.retry_errors else 'error',
        since=args.since,
        conn=conn,
    )
    
    for i, pcap_path in enumerate(files):
        try:
            # Mark processing
            update_status(conn, pcap_path, "processing")
            
            # Process through pipeline
            pipeline = ScavengerPipeline(
                capture_dir=pcap_path.parent,
                config=config,
                agents=["shadow", "cartographer", "crypt"],
            )
            pipeline.run(pcap_files=[pcap_path], deduplicate=True)
            cartographer = pipeline.agents.get("cartographer")
            shadow = pipeline.agents.get("shadow")
            
            # Batch persist
            if cartographer:
                persist_associations(cursor, cartographer.export_associations())
            if shadow:
                persist_rssi_aggregates(cursor, shadow.get_all_profiles())
            
            # Mark complete
            update_status(conn, pcap_path, "complete")
            
        except Exception as e:
            update_status(conn, pcap_path, "error", str(e))
            logger.error(f"Failed {pcap_path}: {e}")
            continue
        
        if i % 10 == 0:
            logger.info(f"Progress: {i}/{len(files)} files")
    
    conn.commit()
    cursor.close()
    conn.close()
```

### Expected Performance
| Metric | Estimate |
|--------|----------|
| Files/minute | ~50-100 (SSD + local SQL) |
| 30-day (~500 files) | 5-10 minutes |
| Full 7,900 files | 1.5-3 hours |

Note: Estimates vary with disk speed, SQL latency, and PCAP size.

---

## Test & Validation

### Unit Test: Scapy-Crafted Frames
```python
# tests/test_association_extraction.py
from scapy.all import Dot11, Dot11AssoReq, RadioTap
from nexus.scavenger.agents import AgentCartographer

def test_assoc_request_extraction():
    """Test AgentCartographer extracts from AssoReq"""
    pkt = RadioTap() / Dot11(
        type=0, subtype=0,  # AssoReq
        addr1="00:11:22:33:44:55",  # BSSID
        addr2="aa:bb:cc:dd:ee:ff",  # Client
        addr3="00:11:22:33:44:55"   # BSSID
    ) / Dot11AssoReq()
    
    agent = AgentCartographer()
    result = agent.process(pkt)
    assert result["client_mac"] == "aa:bb:cc:dd:ee:ff"
    assert result["bssid"] == "00:11:22:33:44:55"
    assert result["assoc_type"] == "assoc_req"

def test_data_frame_to_ap():
    """Test data frame with ToDS=1, FromDS=0"""
    pkt = RadioTap() / Dot11(
        type=2, subtype=0,  # Data
        FCfield=0x01,  # ToDS=1, FromDS=0
        addr1="00:11:22:33:44:55",  # BSSID
        addr2="aa:bb:cc:dd:ee:ff",  # Client
        addr3="ff:ff:ff:ff:ff:ff"   # DA
    )
    
    agent = AgentCartographer()
    result = agent.process(pkt)
    assert result["client_mac"] == "aa:bb:cc:dd:ee:ff"
    assert result["bssid"] == "00:11:22:33:44:55"
    assert result["assoc_type"] == "data"

def test_wds_frame_skipped():
    """Test WDS frame (ToDS=1, FromDS=1) returns None"""
    pkt = RadioTap() / Dot11(
        type=2, subtype=0,
        FCfield=0x03  # ToDS=1, FromDS=1
    )
    
    agent = AgentCartographer()
    result = agent.process(pkt)
    assert result is None

def test_broadcast_skipped():
    """Test broadcast/multicast client MACs are ignored"""
    pkt = RadioTap() / Dot11(
        type=0, subtype=0,
        addr1="00:11:22:33:44:55",
        addr2="ff:ff:ff:ff:ff:ff",
        addr3="00:11:22:33:44:55"
    ) / Dot11AssoReq()

    agent = AgentCartographer()
    result = agent.process(pkt)
    assert result is None
```

### Integration Test: Fixture PCAP
```python
# tests/test_backfill_integration.py
from pathlib import Path
from nexus.config import get_nexus_config
from nexus.scavenger.pipeline import ScavengerPipeline

FIXTURE_PCAP = "tests/fixtures/assoc_test.pcapng"

# Fixture contains:
# - 3 AssocReq frames (3 unique client→BSSID pairs)
# - 2 AssocResp frames (confirmations)
# - 10 Data frames (2 already seen, 1 new pair)
# - 5 Probe Requests
# Expected: 4 associations (3 mgmt + 1 data-inferred)

def test_backfill_counts():
    """Validate extraction counts from fixture PCAP"""
    pcap_path = Path(FIXTURE_PCAP)
    pipeline = ScavengerPipeline(
        capture_dir=pcap_path.parent,
        config=get_nexus_config(),
        agents=["shadow", "cartographer", "crypt"],
    )
    pipeline.run(pcap_files=[pcap_path], deduplicate=True)

    cartographer = pipeline.agents.get("cartographer")
    associations = cartographer.export_associations()
    assert len(associations) == 4
    assert len([a for a in associations if a["assoc_type"] != "data"]) == 3

    shadow = pipeline.agents.get("shadow")
    profiles = shadow.get_all_profiles()
    assert sum(len(p.rssi_history) for p in profiles.values()) >= 15

def test_no_handshake_regression():
    """Ensure handshake extraction still works"""
    # Use existing handshake fixture
    hs_pcap = "tests/fixtures/wpa2_handshake.pcapng"
    hs_path = Path(hs_pcap)
    pipeline = ScavengerPipeline(
        capture_dir=hs_path.parent,
        config=get_nexus_config(),
        agents=["crypt"],
    )
    pipeline.run(pcap_files=[hs_path], deduplicate=True)

    crypt = pipeline.agents.get("crypt")
    assert len(crypt.get_complete_handshakes()) == 1
```

### Validation Queries (Post-Backfill)
```sql
-- Count associations per client
SELECT client_mac, COUNT(*) as bssid_count
FROM client_associations
GROUP BY client_mac
ORDER BY bssid_count DESC;

-- Verify RSSI populated
SELECT 
    COUNT(*) as total,
    COUNT(rssi_avg) as with_rssi,
    AVG(rssi_sample_count) as avg_samples
FROM client_profiles;

-- Check for duplicates (should be 0)
SELECT client_mac, bssid, COUNT(*)
FROM client_associations
GROUP BY client_mac, bssid
HAVING COUNT(*) > 1;
```
