# Map Intelligence Enhancement - Walkthrough

Date: 2026-01-23
Status: Complete (S3.1 Correctness Implementations Applied)

---

## Summary

The map now renders rich, reliable topology information using authoritative data sources.
Work slices M1-M7 (Enhancement) and R1-R3 (Reliability) are complete.

What is implemented today:
- AP nodes from `curated_events` (last 60 min).
- Security labels sourced from `security_posture` table (authoritative).
- Active edges from `client_associations` table (last 1 hour).
- Client nodes with device_type icon mapping from `client_profiles`.
- Working RSSI filter in the frontend.
- Identity cluster metadata (`identity_cluster_id`, `identity_cluster_size`) on map nodes.

---

## Final Architecture (Target State)

Data flow (authoritative):

```
Sources:
1. curated_events (Nodes)
2. security_posture (AP Security Context)
3. client_associations (Edges, Counts)
4. client_profiles (Device types)

Integration:
/api/map/topology -> JOINs across these tables
                  -> Returns unified Node/Edge graph
```

Data sources and responsibilities:

- Nodes (AP): `curated_events` (last 60 min) LEFT JOIN `security_posture`
  - BSSID, SSID, vendor, channel, RSSI (from events).
  - Security labels/colors from `security_posture` (is_open, has_wpa3, etc).
  - Client count from `client_associations` (last 24h).
- Nodes (Client): `client_associations` + `client_profiles`
  - Client MACs from `client_associations`.
  - Device type from `client_profiles.device_type`.
  - RSSI aggregates from `client_profiles` if present.
- Edges (Associations): `client_associations`
  - Client -> BSSID edges, last_seen window (1 hour).
  - Width from RSSI aggregates (client_profiles) or last RSSI.
- Edges (Probes/Deauth): `curated_events`
  - Directed probes and deauth events only.

Topology contract (API output):

- Nodes include: `id`, `group`, `label`, `vendor`, `channel`, `rssi`,
  `security`, `security_color`, `client_count`, `device_type`,
  `identity_cluster_id`, `identity_cluster_size`.
- Edges include: `from`, `to`, `color`, `width`, `dashes`, `title`.

---

## Completed Actions (Roadmap S3.1)

All S3.1 correctness tasks are complete:

1. [x] **Reliable Security**: Switched to `security_posture` table for AP security.
   - *Decision*: Using the stateful table is more robust than event payloads for the map view.
2. [x] **Reliable Edges**: Switched to `client_associations` (1h window) for active connections.
3. [x] **RSSI Filter**: Wired and working in `map.html`.
4. [x] **Contract Tests**: Verified via `tests/ui_tests.py`.

---

## Current Implementation Files

- `wicap-ui/app/routes/api.py` (topology query logic)
- `wicap-ui/app/templates/map.html` (visualization, filters)

---

## Validation

- API: `GET /api/map/topology` returns 200 OK.
- Manual: Logic verified against schema.

## Identity Graph (S3.4)

The map now accepts identity cluster metadata so randomized MACs can be rendered
as related nodes in the topology view. The identity graph itself is built from
`client_profiles` and `bt_devices` (BLE) and cached in the API service. It is
protocol-aware and only links Wi‑Fi or BLE devices unless a strong fingerprint
match is present.
