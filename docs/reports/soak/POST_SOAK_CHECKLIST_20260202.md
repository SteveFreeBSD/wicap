# Post-Soak Checklist — 5-Hour Run (2026-02-02)

This is the canonical checklist/report for the 2026-02-02 soak. For commands
and current soak knobs, always reference `docs/TESTING.md`.

## 📊 Final Soak Summary

| Metric | Value |
|--------|-------|
| **Duration** | 300 minutes (5 hours) |
| **Total Events** | 6,717 |
| **Avg EPS** | 0.37 |
| **Playwright Checks** | 1/20 Passed ⚠️ |
| **Errors Logged** | 19 (all Playwright timeout failures) |

### Postflight Checks
- ✅ Identity Graph: 4,153 clusters, 25 edges (cached)
- ✅ WiFi Vendors: 6 labels
- ✅ BLE Vendors: 325 devices, 46 unique vendors
- ✅ SIEM Export: 3 alerts

### Memory Profile

| Metric | Start | End | Delta |
|--------|-------|-----|-------|
| **RSS** | 223.2 MiB | 1,318.5 MiB | **+1,095 MiB** |
| **tracemalloc current** | 0.0 MiB | 49.6 MiB | +49.6 MiB |
| **tracemalloc peak** | 0.0 MiB | 214.3 MiB | n/a |

**Memory Growth Rate**: ~219 MiB/hour ⚠️

### Top Memory Allocations (End of Soak)

| Size | Allocs | Location |
|------|--------|----------|
| 18,752 KB | 122,942 | `<frozen importlib._bootstrap_external>:672` |
| 5,701 KB | 52,518 | `<frozen importlib._bootstrap>:241` |
| 1,834 KB | 49 | `websockets/permessage_deflate.py:64` |
| 1,652 KB | 7,615 | `nexus/intel/identity_graph_store.py:42` |
| 1,375 KB | 16,803 | `<string>:3` |
| 861 KB | 19,010 | `nexus/intel/identity_graph_store.py:72` |
| 838 KB | 1,605 | `abc.py:106` |
| 811 KB | 3,843 | `<string>:15` |
| 775 KB | 250 | `scipy/_lib/doccer.py:85` |
| 292 KB | 8,306 | `nexus/intel/identity_graph.py:323` |

---

## ✅ A. Capture the Final Evidence (No Changes Yet)

- [x] Soak report saved: `logs/soak/soak_test_20260202_143536.json`
- [x] Soak log saved: `logs/soak/soak_300m_20260202_093437.log`
- [x] Memory snapshot captured in report
- [ ] Archive to `docs/reports/soak/` for permanent record:
  ```bash
  mkdir -p docs/reports/soak/20260202
  cp logs/soak/soak_test_20260202_143536.json docs/reports/soak/20260202/
  cp logs/soak/soak_300m_20260202_093437.log docs/reports/soak/20260202/
  ```

---

## ✅ B. Baseline Health Validation

- [x] Pipeline ingesting: 6,717 events over 5 hours ✅
- [x] EPS maintained: 0.37 avg ✅
- [x] DB write path: Events persisted ✅
- [x] BLE capture path: 325 devices detected ✅
- [ ] Verify queue backlog cleared:
  ```bash
  curl -s http://localhost:8080/api/system/status | python3 -m json.tool
  ```

---

## ⚠️ C. Memory Growth Triage (UI) — ACTION REQUIRED

### Findings

| Issue | Severity | Evidence |
|-------|----------|----------|
| **RSS grew 1,095 MiB in 5h** | 🔴 High | 219 MiB/hour linear growth |
| **Identity Graph Store** | 🟡 Medium | Lines 42, 72 — 2.5 MB combined |
| **WebSocket deflate** | 🟡 Medium | 1.8 MB in 49 allocations |
| **importlib** | 🟢 Low | Normal module loading overhead |

### Suspects for Follow-Up

1. **`identity_graph_store.py:42`** (1.6 MB, 7,615 allocs)
   - Likely caching device/identity mappings
   - Check if cache is unbounded

2. **`identity_graph_store.py:72`** (861 KB, 19,010 allocs)
   - Second hot path in same file
   - Review allocation patterns

3. **`identity_graph.py:323`** (292 KB, 8,306 allocs)
   - Graph construction logic
   - Check for retained references

4. **`websockets/permessage_deflate.py:64`** (1.8 MB)
   - Per-connection compression context
   - May accumulate with long-lived connections

### Recommended Profiling Mode

- [x] On-demand tracemalloc captured
- [ ] Compare with shorter run baseline
- [ ] Run `py-spy top --pid $(pgrep -f uvicorn)` during next soak

---

## ⚠️ D. UI Correctness Validation — ACTION REQUIRED

### Playwright Failures

All 19 failures were the same pattern:
- `/map` — Timeout 120s exceeded
- `/scavenger` — Timeout 120s exceeded

### Root Cause Hypotheses

1. **Memory pressure** — UI at 1.3 GB may slow page rendering
2. **Heavy SQL queries** — Map/Scavenger fetch large datasets
3. **Identity graph rebuild** — May block during page load

### Action Items

- [ ] Increase timeout for `/map` and `/scavenger` to 180s
- [ ] Mark these tests as `@pytest.mark.slow`
- [ ] Profile map/scavenger API endpoints for slow queries
- [ ] Consider pagination for large result sets

---

## ✅ E. Log & Error Review

### Summary

| Category | Count | Action |
|----------|-------|--------|
| Playwright timeouts | 19 | Addressed in D |
| Auth errors (401/403) | 0 | None |
| Capture failures | 0 | None |
| Connection resets | 0 | None |
| Governor warnings | Multiple | Informational only |

---

## ✅ F. Device State Cleanup

- [x] WICAP stopped cleanly (exit code 0)
- [x] wlan1 reset to managed mode
- [x] BLE dongle released
- [x] Docker containers removed
- [ ] Verify dongle LED is idle (visual check)

---

## ✅ G. Documentation Updates

- [ ] This checklist archived to `docs/reports/soak/`
- [ ] Update `TESTING.md` with findings:
  - Recommend 180s timeout for heavy pages
  - Document memory growth rate observation
- [ ] Update roadmap status if soak gate passed

---

## 🔴 H. Decide Next Action

### Verdict: **Memory Leak Investigation Required**

| Finding | Impact | Action |
|---------|--------|--------|
| 219 MiB/hour growth | Critical for 8h+ runs | **Open "Memory Leak Fix" workslice** |
| `/map` + `/scavenger` timeouts | Tests fail at scale | Increase timeouts + optimize queries |
| Identity Graph Store | Primary suspect | Profile and fix caching strategy |

### Recommended Priority

1. **Immediate**: Open Memory Leak Fix workslice
2. **Before next soak**: Fix identity_graph_store caching
3. **Follow-up**: Optimize map/scavenger query performance

---

## 📋 Post-Soak Commands Reference

```bash
# Quick health check
curl -s http://localhost:8080/api/system/status | python3 -m json.tool

# Memory endpoint
curl -s http://localhost:8080/api/system/memory | python3 -m json.tool

# View soak results
cat logs/soak/soak_test_20260202_143536.json | python3 -m json.tool

# Live memory profiling (attach to running uvicorn)
py-spy top --pid $(pgrep -f uvicorn)

# Identity graph summary
curl -s http://localhost:8080/api/identity/graph/summary | python3 -m json.tool
```
