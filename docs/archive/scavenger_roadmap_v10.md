# Scavenger Module v10: Roadmap & Implementation Strategy (ARCHIVED)

This document is kept for historical context only.

Canonical docs:
- Current priorities: `docs/ROADMAP.md`
- PCAP intelligence design notes: `docs/research/pcap-intelligence.md`

## 1. Mission Statement
**Scavenger v10** is the offline forensic intelligence engine of WICAP. While `Watcher` handles real-time surveillance and `Trifecta` targets immediate cryptographic material, **Scavenger** "feeds on the dead" — analyzing historical PCAP artifacts to extract deep intelligence, reconstruction timelines, and uncover hidden relationships that are impossible to detect in real-time.

---

## 2. Core Operational Pillars (The Research)

### A. Deep Forensic Analysis Techniques
1.  **Temporal Pattern-of-Life (POL) Analysis** ✅
    *   *Technique*: K-Means clustering on timestamp distributions to categorize devices by behavior.
    *   *Goal*: Automatic clustering into behavioral groups (Commuter, Resident, Visitor, Night Owl).
    *   *Implementation*: `nexus/intel/pol_analyzer.py` with silhouette score validation.
2.  **Device Fingerprinting & Deanonymization**
    *   *Technique*: Beyond OUI, analyze **Information Elements (IEs)** in Probe Requests.
    *   *Goal*: Identify specific device models (e.g., "iPhone 12, iOS 15") and correlate randomized MAC addresses to a single physical device based on unique IE signatures and signal strength patterns.
3.  **Preferred Network List (PNL) Reconstruction**
    *   *Technique*: Aggregating all directed Probe Requests from a client.
    *   *Goal*: Build a geographic/social history of the target (e.g., "Device connects to 'Starbucks', 'Home-WiFi', and 'Corporate-Secure'").
4.  **Hidden Network Inference**
    *   *Technique*: Correlating "Wildcard" Probe Responses and Association Responses.
    *   *Goal*: Decloak hidden SSIDs by catching the moment a client successfully connects (when the AP reveals the SSID in the Assoc Response or Beacon).
5.  **Weakness Scavenging**
    *   *Technique*: Retrospective search for legacy vulnerabilities.
    *   *Goal*: Detect WEP IV clusters, WPS Pin attempts, and identify devices negotiating older/weaker cipher suites (TKIP) which might be vulnerable to downgrade attacks.

### B. Logic & flow
The module will operate as a **Pipeline**:
`Input (PCAPs) -> Normalization -> Analysis Chains (Plugins) -> Correlation -> Output (SQL/JSON)`

---

## 3. Logical Implementation Steps

### Phase 1: The "Maw" (Ingestion & Normalization)
*Goal: Efficiently handle gigabytes of fragmented PCAP files.*
- [x] **Unified Loader**: Build a wrapper around `tshark` / `pyshark` to stream-read files without loading entire blobs into RAM.
- [x] **De-Duplication**: Implement logic to discard duplicate frames (common in multi-radio captures) based on Sequence Number + Source MAC + Timestamp.
- [x] **Session Reassembly**: Group fragmented PCAPs into logical "Sessions" based on time continuity.

### Phase 2: The "Digest" (Analysis Chains)
*Goal: The core processing logic. Modular "Agents" that extract specific intelligence.*
- [ ] **Agent: Cartographer (Topology)**
    - Parses Beacons and Probe Responses.
    - Updates the SQL `AccessPoints` table with historical signal data.
    - Links Clients to APs based on `Association Request/Response` frames.
- [x] **Agent: Shadow (Clients)**
    - Tracks Client Probe Requests to build PNL (Preferred Network Lists).
    - Stores "Seen" timestamps for POL analysis.
- [x] **Agent: Crypt (Handshakes)**
    - Re-scans for EAPOL 4-way handshakes (M1-M4) that Trifecta might have missed due to timing.
    - **New**: Scavenge for **PMKIDs** in Association Request frames (RSN IE) for client-less cracking.
- [ ] **Agent: Snoopy (Metadata)**
    - Extracts DNS queries (if captured unencrypted/open networks).
    - Extracts User-Agents or cleartext HTTP headers (rare, but valuable "scavenging").

### Phase 3: The "Nexus" (Correlation Engine)
*Goal: Connecting the dots.*
- [x] **Identity Fusion**: Merge records where IE fingerprints and Signal Strength profiles suggest two randomized MACs are the same device.
- [x] **Dossier Generation**: A JSON builder that aggregates everything known about specific MAC addresses (Target Dossiers).
- [x] **ML-Powered Correlation**: Decision Tree classifier using 6 features (PNL overlap, RSSI similarity, temporal overlap, channel overlap, randomization flags, activity ratio) for interpretable device correlation with confidence scores and decision path visualization.

### Phase 4: Visualization & Reporting
*Goal: Make the data usable.*
- [x] **UI Integration**: Full Scavenger dashboard with status, controls, and findings.
- [x] **API Endpoints**: REST API for managing analysis and retrieving results.
- [ ] **Timeline View**: Vis.js timeline of when specific networks/devices were active.
- [ ] **Relationship Graph**: Force-directed graph updating `wicap-ui` with historical edges (Client -> Probed -> SSID).

---

## 4. Technical Architecture
*   **Language**: Python 3.10+ (Integration with existing `nexus` package).
*   **Libraries**:
    *   `scapy` (for precise packet manipulation/parsing) or `pyshark` (wrapper for tshark, faster for parsing).
    *   `pandas` (for time-series analysis of timestamps).
*   **Data Store**: Staging results in SQLite (fast, local) before committing curated intelligence to the primary MSSQL Server.

## 5. Execution Plan (Next Steps)
1.  **Scaffold**: Create `nexus/scavenger/` directory structure.
2.  **Prototype Ingest**: Write the `PCAPStreamer` class.
3.  **Implement Agent: Shadow**: Focus on PNL reconstruction (high value, easier implementation).
4.  **Implement Agent: Crypt**: Add PMKID extraction.
