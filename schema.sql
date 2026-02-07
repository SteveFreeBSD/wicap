-- ═══════════════════════════════════════════════════════════════════════════════
-- WiFiWizard NEXUS Security Audit Schema v4.0
-- ═══════════════════════════════════════════════════════════════════════════════

-- ═══════════════════════════════════════════════════════════════════════════════
-- 1. CURATED EVENTS - Main event stream (Phase 3 - unchanged)
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE curated_events (
    id BIGINT IDENTITY,
    event_id CHAR(64) NOT NULL,          -- SHA256 of payload (deterministic ID)
    ts_epoch DECIMAL(19,9) NOT NULL,     -- Source timestamp
    event_type VARCHAR(50) NOT NULL,
    channel INT NOT NULL,
    score INT NOT NULL,
    payload NVARCHAR(MAX) NOT NULL,      -- Full JSON
    inserted_at DATETIME2 DEFAULT SYSDATETIME(),
    -- Computed columns for fast UI queries
    payload_run_id AS CAST(JSON_VALUE(payload, '$.run_id') AS NVARCHAR(64)) PERSISTED,
    payload_vendor AS CAST(JSON_VALUE(payload, '$.vendor') AS NVARCHAR(100)) PERSISTED,
    payload_encryption AS CAST(JSON_VALUE(payload, '$.encryption') AS NVARCHAR(64)) PERSISTED,
    payload_keys_sa AS CAST(JSON_VALUE(payload, '$.keys.sa') AS NVARCHAR(17)) PERSISTED,
    payload_keys_da AS CAST(JSON_VALUE(payload, '$.keys.da') AS NVARCHAR(17)) PERSISTED,
    payload_keys_bssid AS CAST(JSON_VALUE(payload, '$.keys.bssid') AS NVARCHAR(17)) PERSISTED,
    payload_keys_ssid AS CAST(JSON_VALUE(payload, '$.keys.ssid') AS NVARCHAR(64)) PERSISTED,
    payload_source AS CAST(JSON_VALUE(payload, '$.source') AS NVARCHAR(17)) PERSISTED,
    payload_dest AS CAST(JSON_VALUE(payload, '$.dest') AS NVARCHAR(17)) PERSISTED,
    payload_effective_bssid AS CAST(COALESCE(JSON_VALUE(payload, '$.keys.bssid'), JSON_VALUE(payload, '$.bssid')) AS NVARCHAR(17)) PERSISTED,
    payload_effective_ssid AS CAST(COALESCE(JSON_VALUE(payload, '$.keys.ssid'), JSON_VALUE(payload, '$.ssid')) AS NVARCHAR(64)) PERSISTED,
    payload_rssi_int AS TRY_CAST(COALESCE(JSON_VALUE(payload, '$.keys.rssi_dbm'), JSON_VALUE(payload, '$.rssi')) AS INT) PERSISTED,
    payload_freq AS TRY_CAST(JSON_VALUE(payload, '$.freq') AS INT) PERSISTED,
    payload_band AS CAST(JSON_VALUE(payload, '$.band') AS NVARCHAR(16)) PERSISTED,
    payload_wifi6 AS CAST(JSON_VALUE(payload, '$.fingerprint.is_wifi6') AS BIT) PERSISTED,
    device_identity_id AS CAST(JSON_VALUE(payload, '$.device_identity_id') AS NVARCHAR(8)) PERSISTED,
    payload_protocol AS CAST(JSON_VALUE(payload, '$.protocol') AS NVARCHAR(8)) PERSISTED,
    payload_bt_addr AS CAST(JSON_VALUE(payload, '$.bt.addr') AS NVARCHAR(17)) PERSISTED,
    payload_bt_rssi AS TRY_CAST(JSON_VALUE(payload, '$.bt.rssi') AS INT) PERSISTED,
    payload_bt_company_id AS CAST(JSON_VALUE(payload, '$.bt.company_id') AS NVARCHAR(16)) PERSISTED,
    payload_bt_local_name AS CAST(JSON_VALUE(payload, '$.bt.local_name') AS NVARCHAR(128)) PERSISTED,
    payload_bt_adv_type AS CAST(JSON_VALUE(payload, '$.bt.adv_type') AS NVARCHAR(16)) PERSISTED,
    payload_bt_addr_type AS CAST(JSON_VALUE(payload, '$.bt.addr_type') AS NVARCHAR(16)) PERSISTED,
    CONSTRAINT PK_curated_events PRIMARY KEY (event_id)
);

CREATE INDEX IX_curated_events_run_id ON curated_events(payload_run_id);
CREATE INDEX IX_curated_events_vendor ON curated_events(payload_vendor);
CREATE INDEX IX_curated_events_keys_sa ON curated_events(payload_keys_sa);
CREATE INDEX IX_curated_events_keys_da ON curated_events(payload_keys_da);
CREATE INDEX IX_curated_events_effective_bssid ON curated_events(payload_effective_bssid);
CREATE INDEX IX_curated_events_effective_ssid ON curated_events(payload_effective_ssid);
CREATE INDEX IX_curated_events_protocol ON curated_events(payload_protocol);
CREATE INDEX IX_curated_events_bt_addr ON curated_events(payload_bt_addr);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 2. SUMMARY STATS - Aggregates (Phase 3 - unchanged)
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE summary_stats (
    stat_id BIGINT IDENTITY PRIMARY KEY,
    window_start DATETIME2 NOT NULL,
    window_end DATETIME2 NOT NULL,
    events_count INT NOT NULL,
    unique_bssids INT NOT NULL,
    unique_ssids INT NOT NULL,
    top_category NVARCHAR(50),
    top_vendor NVARCHAR(100),
    inserted_at DATETIME2 DEFAULT SYSDATETIME()
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 3. SECURITY POSTURE - Per-network security assessment
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE security_posture (
    bssid CHAR(17) NOT NULL PRIMARY KEY,
    ssid NVARCHAR(64),
    
    -- Security Configuration
    is_open BIT DEFAULT 0,
    has_wep BIT DEFAULT 0,
    has_wpa BIT DEFAULT 0,
    has_wpa2 BIT DEFAULT 0,
    has_wpa3 BIT DEFAULT 0,
    cipher_suite VARCHAR(32),           -- CCMP, TKIP, CCMP+TKIP, GCMP-256
    akm_suite VARCHAR(32),              -- PSK, SAE, EAP, OWE
    has_pmf BIT DEFAULT 0,              -- Protected Management Frames
    
    -- Vulnerability Assessment
    risk_score INT DEFAULT 0,           -- 0-100 calculated score
    risk_factors NVARCHAR(MAX),         -- JSON: ["TKIP", "NO_PMF", ...]
    
    -- Metadata
    channel INT,
    frequency INT,
    band VARCHAR(16),
    vendor NVARCHAR(100),
    first_seen DATETIME2,
    last_seen DATETIME2,
    beacon_count INT DEFAULT 0,
    
    -- Capabilities fingerprint
    ie_fingerprint VARCHAR(256),        -- Ordered IE tags: "0,1,3,5,7,42,48,..."
    ht_capabilities VARBINARY(26),      -- Raw HT caps IE
    vht_capabilities VARBINARY(12),     -- Raw VHT caps IE
    
    updated_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE INDEX IX_security_posture_risk ON security_posture(risk_score DESC);
CREATE INDEX IX_security_posture_ssid ON security_posture(ssid);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 4. CAPTURED HANDSHAKES - WPA/WPA2 authentication material
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE handshakes (
    id BIGINT IDENTITY PRIMARY KEY,
    
    -- Target Network
    bssid CHAR(17) NOT NULL,
    ssid NVARCHAR(64),
    
    -- Client involved
    client_mac CHAR(17) NOT NULL,
    
    -- Handshake details
    handshake_type VARCHAR(16) NOT NULL,  -- '4way_full', '4way_partial', 'pmkid'
    msg_flags INT NOT NULL,                -- Bitmap: M1=1, M2=2, M3=4, M4=8
    
    -- EAPOL data
    anonce VARBINARY(32),                  -- AP nonce
    snonce VARBINARY(32),                  -- Client nonce
    mic VARBINARY(16),                     -- Message Integrity Code
    eapol_data VARBINARY(MAX),             -- Full EAPOL frames
    pmkid CHAR(32),                        -- PMKID if captured (hex)
    
    -- Source reference
    capture_time DATETIME2 NOT NULL,
    pcap_file NVARCHAR(256),
    pcap_offset BIGINT,
    avg_rssi INT,                          -- Signal strength at capture
    
    -- Cracking status
    hashcat_hash NVARCHAR(MAX),            -- Pre-formatted for hashcat
    crack_status VARCHAR(16) DEFAULT 'pending', -- pending, cracking, cracked, exhausted, deferred
    cracked_password NVARCHAR(64),         -- Result if cracked (potfile reference only)
    crack_time_sec INT,                    -- Duration to crack
    crack_method VARCHAR(32),              -- Dictionary, rule, mask, brute
    
    -- Priority & deferral tracking
    priority_score INT DEFAULT 50,         -- 0-100 priority for audit queue
    defer_count INT DEFAULT 0,             -- Number of times deferred
    last_attempt DATETIME2,                -- Last audit attempt timestamp
    attack_rounds_completed INT DEFAULT 0, -- 0-4 rounds completed
    escalation_level INT DEFAULT 0,        -- 0=standard, 1=aggressive, 2=ape
    dwell_file NVARCHAR(255),              -- Source capture file path
    
    inserted_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE INDEX IX_handshakes_bssid ON handshakes(bssid);
CREATE INDEX IX_handshakes_status ON handshakes(crack_status);
CREATE INDEX IX_handshakes_time ON handshakes(capture_time);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 4.5. AUDIT LOG - High-level execution stats (Ethical Logging)
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE audit_log (
    id BIGINT IDENTITY PRIMARY KEY,
    
    -- Execution context
    session_id CHAR(36),                   -- UUID for the audit run
    audit_mode VARCHAR(16),                -- quick, full, ape
    start_time DATETIME2 DEFAULT SYSDATETIME(),
    end_time DATETIME2,
    
    -- Target
    handshake_id BIGINT FOREIGN KEY REFERENCES handshakes(id),
    priority_score INT,
    
    -- Outcome
    status VARCHAR(16),                    -- cracked, exhausted, deferred, timeout, error
    rounds_attempted INT,
    duration_sec FLOAT,
    
    -- Resources
    strategy_used VARCHAR(32),
    wordlist_lines BIGINT,
    
    inserted_at DATETIME2 DEFAULT SYSDATETIME()
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 5. CLIENT PROFILES - Device fingerprinting
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE client_profiles (
    mac_addr CHAR(17) NOT NULL PRIMARY KEY,
    
    -- Identity
    vendor NVARCHAR(100),
    is_randomized BIT DEFAULT 0,          -- MAC randomization detected
    device_type VARCHAR(32),              -- phone, laptop, iot, unknown
    
    -- Probe fingerprint
    probe_fingerprint VARCHAR(256),       -- Hash of probe request pattern
    probed_ssids NVARCHAR(MAX),           -- JSON array of SSIDs probed
    probe_count INT DEFAULT 0,
    
    -- IE fingerprint (from probe requests)
    ie_fingerprint VARCHAR(256),
    supported_rates VARCHAR(64),
    ht_capabilities_probe VARBINARY(26),
    
    -- Behavioral patterns
    first_seen DATETIME2,
    last_seen DATETIME2,
    associated_bssids NVARCHAR(MAX),      -- JSON array
    channel_distribution NVARCHAR(MAX),   -- JSON: {ch: count}
    channels_active NVARCHAR(MAX),        -- JSON: [ch, ch, ...]

    -- Signal aggregates (RSSI)
    rssi_avg INT,
    rssi_max INT,
    rssi_last INT,
    rssi_sample_count INT DEFAULT 0,
    rssi_last_seen DATETIME2,
    
    -- Intelligence
    threat_score INT DEFAULT 0,           -- 0-100: likelihood of attacker
    threat_indicators NVARCHAR(MAX),      -- JSON: reasons for score
    
    updated_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE INDEX IX_client_profiles_threat ON client_profiles(threat_score DESC);
CREATE INDEX IX_client_profiles_type ON client_profiles(device_type);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 5.5. CLIENT ASSOCIATIONS - Client <-> AP relationships
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE client_associations (
    id BIGINT IDENTITY PRIMARY KEY,
    client_mac CHAR(17) NOT NULL,
    bssid CHAR(17) NOT NULL,
    ssid NVARCHAR(64),
    first_seen DATETIME2 NOT NULL,
    last_seen DATETIME2 NOT NULL,
    association_count INT NOT NULL DEFAULT 1,
    last_assoc_type VARCHAR(16),
    CONSTRAINT UQ_client_assoc UNIQUE (client_mac, bssid)
);

CREATE INDEX IX_client_assoc_client ON client_associations(client_mac);
CREATE INDEX IX_client_assoc_bssid ON client_associations(bssid);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 5.6. DEVICE IDENTITY CLUSTERS - Cross-MAC correlation
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE device_identity_clusters (
    cluster_id CHAR(12) NOT NULL PRIMARY KEY,
    member_count INT NOT NULL,
    confidence FLOAT NOT NULL,
    signals NVARCHAR(MAX),
    updated_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE TABLE device_identity_members (
    cluster_id CHAR(12) NOT NULL,
    identifier NVARCHAR(64) NOT NULL,
    protocol VARCHAR(8),
    vendor NVARCHAR(100),
    device_type VARCHAR(32),
    local_name NVARCHAR(128),
    first_seen DATETIME2,
    last_seen DATETIME2,
    CONSTRAINT PK_device_identity_members PRIMARY KEY (cluster_id, identifier)
);

CREATE INDEX IX_identity_members_identifier ON device_identity_members(identifier);

-- ═══════════════════════════════════════════════════════════════════════════════  
-- 6. ATTACK TIMELINE - Correlated attack events
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE attack_timeline (
    id BIGINT IDENTITY PRIMARY KEY,
    
    -- Attack classification
    attack_type VARCHAR(32) NOT NULL,     -- deauth_flood, beacon_flood, evil_twin, 
                                          -- karma_attack, pmkid_harvest, wps_brute
    severity INT NOT NULL,                -- 1=info, 2=low, 3=med, 4=high, 5=critical
    confidence INT NOT NULL,              -- 0-100 confidence score
    
    -- Target
    target_bssid CHAR(17),
    target_ssid NVARCHAR(64),
    target_client CHAR(17),
    
    -- Attribution (if detectable)
    attacker_mac CHAR(17),
    attacker_vendor NVARCHAR(100),
    
    -- Timeline
    start_time DATETIME2 NOT NULL,
    end_time DATETIME2,
    duration_sec INT,
    event_count INT,
    
    -- Evidence chain
    evidence_events NVARCHAR(MAX),        -- JSON: [event_id, event_id, ...]
    evidence_pcaps NVARCHAR(MAX),         -- JSON: [{file, offset, len}, ...]
    
    -- Analysis
    description NVARCHAR(MAX),
    ioc_summary NVARCHAR(MAX),            -- Indicators of Compromise
    mitre_technique VARCHAR(32),          -- MITRE ATT&CK mapping (e.g., T1557.002)
    
    inserted_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE INDEX IX_attack_timeline_type ON attack_timeline(attack_type);
CREATE INDEX IX_attack_timeline_time ON attack_timeline(start_time);
CREATE INDEX IX_attack_timeline_severity ON attack_timeline(severity DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 6.1 ATTACK FEEDBACK - Operator labeling for anomaly retraining
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE attack_feedback (
    id BIGINT IDENTITY PRIMARY KEY,
    attack_id BIGINT NOT NULL,
    label VARCHAR(16) NOT NULL,           -- benign | confirmed | noisy
    note NVARCHAR(256),
    analyst NVARCHAR(64),
    inserted_at DATETIME2 DEFAULT SYSDATETIME(),
    CONSTRAINT FK_attack_feedback_attack
        FOREIGN KEY (attack_id) REFERENCES attack_timeline(id)
);

CREATE INDEX IX_attack_feedback_attack ON attack_feedback(attack_id, inserted_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 6.1.1 ATTACK ALERTS - WIDS alert persistence
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE attack_alerts (
    alert_id NVARCHAR(8) NOT NULL,
    alert_signature NVARCHAR(256),
    alert_type NVARCHAR(50) NOT NULL,
    severity INT NOT NULL,
    title NVARCHAR(200),
    description NVARCHAR(500),
    ts_epoch DECIMAL(19,9) NOT NULL,
    first_seen DATETIME2 NULL,
    last_seen DATETIME2 NULL,
    source_mac NVARCHAR(17),
    target_mac NVARCHAR(17),
    bssid NVARCHAR(17),
    ssid NVARCHAR(64),
    channel INT,
    event_count INT DEFAULT 1,
    acknowledged BIT DEFAULT 0,
    acknowledged_at DATETIME2 NULL,
    inserted_at DATETIME2 DEFAULT SYSDATETIME(),
    CONSTRAINT PK_attack_alerts PRIMARY KEY (alert_id)
);

CREATE INDEX IX_attack_alerts_last_seen ON attack_alerts(ts_epoch DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 6.2 SENSOR REGISTRY - Distributed sensor status
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE sensor_registry (
    sensor_id CHAR(8) NOT NULL PRIMARY KEY,
    name NVARCHAR(64),
    interface NVARCHAR(32),
    location NVARCHAR(128),
    location_lat DECIMAL(9,6) NULL,
    location_lon DECIMAL(9,6) NULL,
    status VARCHAR(16) NOT NULL,
    connected_at DATETIME2 NOT NULL,
    last_heartbeat DATETIME2 NOT NULL,
    frames_received INT DEFAULT 0,
    alerts_received INT DEFAULT 0,
    frames_sent INT DEFAULT 0,
    alerts_sent INT DEFAULT 0,
    events_received INT DEFAULT 0,
    last_event_at DATETIME2 NULL,
    inserted_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE INDEX IX_sensor_registry_status ON sensor_registry(status, last_heartbeat DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 6.3 RF LOCATION ESTIMATES - Shared Wi‑Fi + BLE triangulation results
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE rf_location_estimates (
    protocol VARCHAR(8) NOT NULL,
    target_id NVARCHAR(64) NOT NULL,
    lat DECIMAL(9,6) NOT NULL,
    lon DECIMAL(9,6) NOT NULL,
    accuracy_m FLOAT NULL,
    sensor_count INT NOT NULL,
    sample_count INT NOT NULL,
    window_start DATETIME2 NULL,
    window_end DATETIME2 NULL,
    algorithm NVARCHAR(64) NULL,
    sensors NVARCHAR(MAX) NULL,
    updated_at DATETIME2 DEFAULT SYSDATETIME(),
    CONSTRAINT PK_rf_location_estimates PRIMARY KEY (protocol, target_id)
);

CREATE INDEX IX_rf_location_estimates_protocol ON rf_location_estimates(protocol, updated_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 7. PCAP INDEX - Fast lookup into raw captures
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE pcap_index (
    id BIGINT IDENTITY PRIMARY KEY,
    
    -- File reference
    filename NVARCHAR(256) NOT NULL,
    filepath NVARCHAR(512) NOT NULL,
    file_size BIGINT,
    file_hash CHAR(64),                   -- SHA256 of file
    
    -- Content summary
    capture_start DATETIME2,
    capture_end DATETIME2,
    channel INT,
    frame_count INT,
    
    -- Frame type distribution
    mgmt_frames INT DEFAULT 0,
    ctrl_frames INT DEFAULT 0,
    data_frames INT DEFAULT 0,
    eapol_frames INT DEFAULT 0,
    
    -- Notable events
    deauth_count INT DEFAULT 0,
    handshakes_extracted INT DEFAULT 0,
    
    -- Processing status
    processing_status VARCHAR(16) DEFAULT 'pending', -- pending, processing, complete, error
    processing_error NVARCHAR(MAX),
    processed_at DATETIME2,
    
    inserted_at DATETIME2 DEFAULT SYSDATETIME(),
    
    CONSTRAINT UQ_pcap_index_filepath UNIQUE (filepath)
);

CREATE INDEX IX_pcap_index_filename ON pcap_index(filename);
CREATE INDEX IX_pcap_index_status ON pcap_index(processing_status);
CREATE INDEX IX_pcap_index_time ON pcap_index(capture_start);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 8. AUDIT REPORTS - Generated security assessments
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE audit_reports (
    id BIGINT IDENTITY PRIMARY KEY,
    
    -- Report metadata
    report_name NVARCHAR(128) NOT NULL,
    report_type VARCHAR(32) NOT NULL,     -- full_audit, password_audit, device_audit
    generated_at DATETIME2 DEFAULT SYSDATETIME(),
    
    -- Scope
    scope_start DATETIME2,
    scope_end DATETIME2,
    scope_bssids NVARCHAR(MAX),           -- JSON filter or NULL for all
    
    -- Summary stats
    networks_analyzed INT DEFAULT 0,
    clients_analyzed INT DEFAULT 0,
    handshakes_captured INT DEFAULT 0,
    passwords_cracked INT DEFAULT 0,
    attacks_detected INT DEFAULT 0,
    critical_findings INT DEFAULT 0,
    
    -- Scores
    overall_risk_score INT,               -- 0-100
    
    -- Content
    executive_summary NVARCHAR(MAX),
    findings_json NVARCHAR(MAX),          -- Full structured findings
    
    -- Output
    pdf_path NVARCHAR(512),
    html_path NVARCHAR(512)
);

CREATE INDEX IX_audit_reports_time ON audit_reports(generated_at DESC);
CREATE INDEX IX_audit_reports_type ON audit_reports(report_type);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 9. WORDLISTS - Password dictionary management
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE wordlists (
    id INT IDENTITY PRIMARY KEY,
    name NVARCHAR(64) NOT NULL,
    filepath NVARCHAR(512) NOT NULL,
    description NVARCHAR(256),
    word_count BIGINT,
    file_size BIGINT,
    priority INT DEFAULT 50,              -- Higher = try first
    is_enabled BIT DEFAULT 1,
    inserted_at DATETIME2 DEFAULT SYSDATETIME(),
    
    CONSTRAINT UQ_wordlists_name UNIQUE (name)
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 10. NEXUS CONFIG - System configuration key-value store
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE nexus_config (
    config_key VARCHAR(64) NOT NULL PRIMARY KEY,
    config_value NVARCHAR(MAX),
    description NVARCHAR(256),
    updated_at DATETIME2 DEFAULT SYSDATETIME()
);

-- Insert default configuration
INSERT INTO nexus_config (config_key, config_value, description) VALUES
('hashcat_binary', '/usr/bin/hashcat', 'Path to hashcat executable'),
('hashcat_potfile', '~/.local/share/hashcat/hashcat.potfile', 'Hashcat potfile location'),
('default_audit_strategy', 'quick', 'Default password audit strategy'),
('risk_threshold_critical', '80', 'Risk score threshold for critical'),
('risk_threshold_high', '60', 'Risk score threshold for high'),
('risk_threshold_medium', '40', 'Risk score threshold for medium'),
('enable_auto_crack', '0', 'Auto-start cracking on handshake capture'),
('retention_days_pcap', '30', 'PCAP file retention in days'),
('retention_days_events', '90', 'Event retention in days');

-- ═══════════════════════════════════════════════════════════════════════════════
-- 11. TRIANGULATION HISTORY - Intelligence extracted from cracks
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE triangulation_history (
    id BIGINT IDENTITY PRIMARY KEY,
    generated_at DATETIME2 DEFAULT SYSDATETIME(),
    
    -- Insights extracted
    top_masks NVARCHAR(MAX),            -- JSON array of strings
    mask_suggestion NVARCHAR(128),
    top_patterns NVARCHAR(MAX),         -- JSON array of strings
    pattern_suggestion NVARCHAR(128),
    length_distribution NVARCHAR(MAX),  -- JSON object: {length: percentage}
    
    -- Scoring
    triangulation_score FLOAT,          -- 0-100 predictability score
    
    -- Reference
    potfile_checksum CHAR(64),          -- SHA256 of potfile at time of analysis
    crack_count INT                     -- Number of cracks analyzed
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 12. BLUETOOTH INTELLIGENCE (Phase 4 - Integrated)
-- ═══════════════════════════════════════════════════════════════════════════════

-- 12.1 Bluetooth Devices (Profiles)
CREATE TABLE bt_devices (
    addr CHAR(17) NOT NULL PRIMARY KEY,  -- MAC address
    addr_type VARCHAR(16),               -- public, random, etc.
    vendor NVARCHAR(100),
    device_type VARCHAR(32),             -- inferred type
    
    first_seen DATETIME2 DEFAULT SYSDATETIME(),
    last_seen DATETIME2 DEFAULT SYSDATETIME(),
    
    -- Signal stats
    rssi_avg INT,
    rssi_max INT,
    rssi_last INT,
    rssi_sample_count INT DEFAULT 0,
    rssi_last_seen DATETIME2,
    
    -- Capabilities
    services NVARCHAR(MAX),              -- JSON array of UUIDs
    local_name NVARCHAR(128),
    manufacturer_data_hash CHAR(64),     -- fingerprint of mfg data
    
    updated_at DATETIME2 DEFAULT SYSDATETIME()
);

-- 12.2 Bluetooth Observations (Time-series)
CREATE TABLE bt_observations (
    id BIGINT IDENTITY PRIMARY KEY,
    addr CHAR(17) NOT NULL,
    sensor_id CHAR(8),                   -- Optional sensor ID
    ts_epoch DECIMAL(19,9) NOT NULL,
    rssi INT,
    channel INT,
    adv_type VARCHAR(32),                -- ADV_IND, SCAN_RSP, etc.
    
    -- Payload snippets
    company_id CHAR(6),                  -- Hex 0xXXXX
    service_uuids NVARCHAR(MAX),         -- JSON
    local_name NVARCHAR(128),
    
    inserted_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE INDEX IX_bt_observations_addr ON bt_observations(addr, ts_epoch DESC);
CREATE INDEX IX_bt_observations_time ON bt_observations(ts_epoch);

-- 12.3 Bluetooth Connections (Future)
CREATE TABLE bt_connections (
    id BIGINT IDENTITY PRIMARY KEY,
    addr CHAR(17) NOT NULL,
    peer_addr CHAR(17),
    access_address CHAR(10),             -- Hex 0xXXXXXXXX
    first_seen DATETIME2,
    last_seen DATETIME2,
    inserted_at DATETIME2 DEFAULT SYSDATETIME()
);
