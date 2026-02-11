# WiCAP x WICAP Assistant Cross-Repo Agentic Integration

Status: In Progress (W0-W4 foundations implemented; W5 rollout-gate baselines implemented)
Owner: WiCAP Core (with wicap-assistant integration partners)
Companion plan: `/home/steve/apps/wicap-assistant/docs/CROSS_REPO_INTELLIGENCE_WORKSLICES.md`

## 0. Implementation Snapshot
- Implemented W0 baseline artifacts:
  - `ops/contracts/wicap.event.v1.json`
  - `ops/contracts/wicap.control.v1.json`
  - `tests/fixtures/contracts/*` exports
  - `tests/test_contract_schemas.py` validation suite
- Implemented W1 control intake hardening:
  - `wicap-ui/app/services/control_intent.py` validation + policy plane evaluation.
  - `/api/system/control-intent` endpoint with per-intent accept/reject audit records.
  - `scripts/check_wicap_status.py` control-intent validation gate (`--validate-control-intent-json`).
- Implemented W2 network semantics baseline:
  - `src/wicap/telemetry/network_events.py` for `wicap.event.v1` normalization.
  - Zeek conn-compatible and Suricata EVE-compatible exporters + script wrapper.
  - Runtime emission hook in `event_processor.py` to append normalized network events.
- Implemented W3.2 anomaly output baseline:
  - `ops/contracts/wicap.anomaly.v1.json` + fixture parity tests.
  - `src/wicap/telemetry/anomaly_events.py` with runtime append hook from stream scorer output.
- Implemented W3.3 feedback capture baseline:
  - `ops/contracts/wicap.feedback.v1.json` + fixture parity tests.
  - Feedback route now appends `wicap.feedback.v1` events to `captures/wicap_anomaly_feedback.jsonl`.
- Implemented W4.1 OTLP collector baseline:
  - compose `otel` profile and `ops/otel/collector-config.yaml` with OTLP receiver and required processors.
- Implemented W4.2 redaction policy baseline:
  - fail-open exporter redacts sensitive key/value paths before OTLP enqueue.
  - regression tests cover nested secret/token/PII masking behavior.
- Implemented W4.3 delivery resilience baseline:
  - bounded queue with retry backoff + non-blocking flush in `event_processor.py`.
  - collector failure paths remain fail-open and do not degrade batch processing.
- Implemented OTLP endpoint/auth profile validation baseline:
  - profile-aware config resolution (`disabled`, `self_hosted`, `vendor`, `cloud`).
  - auth material handling for bearer/api-key header injection with validation tests.
- Remaining: optional production tuning of thresholds per deployment.

## 1. Program Objective
Evolve WiCAP into the runtime intelligence substrate for a new class of network-aware agentic assistants:
- OpenClaw-style policy plane separation
- Nanobot-style memory/automation discipline
- Suricata/Zeek-compatible network semantics
- Provider-neutral OTLP observability

## 2. Architectural Direction
1. WiCAP remains the canonical sensor/runtime execution platform.
2. Suricata/Zeek are optional shadow validation tools, not mandatory production dependencies.
3. Assistant decisions are accepted only through versioned control intent contracts.
4. All telemetry export is provider-neutral OTLP with redaction controls.

## 3. Contracts WiCAP Must Own

### Contract W1: Network Event Envelope (`wicap.event.v1`)
Required fields:
- `ts`, `source`, `category`, `signature`, `severity`
- `sensor_id`, `evidence_ref`
- Flow/session fields when available: `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `duration`, `bytes`, `packets`, `community_id`

### Contract W2: Control Intent Intake (`wicap.control.v1`)
Required checks before execution:
- schema version match
- policy profile match
- allowlisted action id
- safety class compliance
- precheck satisfaction

### Contract W3: Telemetry Envelope (`wicap.telemetry.v1`)
OTLP-aligned output for:
- traces (decision/action lifecycle)
- metrics (anomaly rates, recovery outcomes, queue health)
- logs (audit/control records)

## 4. Milestones and Work Slices

## Milestone W0: Contract and Fixture Baseline

### Work Slice W0.1 - Publish Contract Artifacts (Implemented)
- Files:
  - `ops/contracts/wicap.event.v1.json` (new)
  - `ops/contracts/wicap.control.v1.json` (new)
- Tests:
  - schema shape tests + required field tests.
- Exit criteria:
  - contract fixtures used by both repos and validated in CI.

### Work Slice W0.2 - Cross-Repo Fixture Export (Implemented)
- Files:
  - `tests/fixtures/contracts/*` (new)
- Tests:
  - parity tests with assistant fixtures.
- Exit criteria:
  - fixture drift breaks CI.

## Milestone W1: Runtime Control Plane Hardening

### Work Slice W1.1 - Intent Validation Gate (Implemented)
- Goal: reject invalid/out-of-policy control intents before any action dispatch.
- Files:
  - control API/dispatcher modules
  - `scripts/check_wicap_status.py`
- Tests:
  - reject-path tests (bad version, unknown action, policy mismatch).
- Exit criteria:
  - no non-compliant action reaches execution layer.

### Work Slice W1.2 - Plane Metadata Emission (Implemented)
- Goal: emit plane evaluation metadata for each accepted/rejected intent.
- Files:
  - control audit modules
  - runtime status modules
- Tests:
  - control audit contract tests.
- Exit criteria:
  - every intent has an auditable accept/reject reason.

## Milestone W2: WiCAP-Native Network Semantics

### Work Slice W2.1 - Suricata-Compatible Event Classes (Implemented Baseline)
- Goal: map WiCAP detections to EVE-like typed categories where data exists (`alert`, `flow`, `dns`, `http`, etc.).
- Files:
  - `event_processor.py`
  - parser/normalization modules
- Tests:
  - category mapping + required field tests.
- Exit criteria:
  - compatibility matrix documented and passing tests.

### Work Slice W2.2 - Zeek-Compatible Connection Summaries (Implemented Baseline)
- Goal: emit conn-like summaries for connection behavior and correlation.
- Files:
  - telemetry/export modules under `src/wicap/`
- Tests:
  - conn fixture tests for field completeness/stability.
- Exit criteria:
  - output supports direct correlation against Zeek-style conn workflows.

### Work Slice W2.3 - Community ID and Evidence Pointer Standardization (Implemented Baseline)
- Goal: normalize flow correlation keys and evidence refs used by assistant memory/ranking.
- Files:
  - parser + event serialization modules.
- Tests:
  - key derivation consistency tests.
- Exit criteria:
  - same flow generates same correlation key across replay/live paths.

## Milestone W3: Anomaly Intelligence Feed

### Work Slice W3.1 - Windowed Feature Aggregation
- Goal: publish 30s/60s/5m feature windows for anomaly scoring.
- Files:
  - `nexus/intel/*`
- Tests:
  - deterministic aggregation tests using replay fixtures.
- Exit criteria:
  - feature windows persisted and queryable.

### Work Slice W3.2 - Streaming Anomaly Output Contract (Implemented Baseline)
- Goal: emit anomaly events with score, confidence, and contributing features.
- Files:
  - anomaly modules + serialization/export path.
- Tests:
  - anomaly payload contract tests.
- Exit criteria:
  - assistant can consume anomaly events without bespoke parsing logic.

### Work Slice W3.3 - Operator Feedback Capture for False Positive Control (Implemented Baseline)
- Goal: capture feedback labels to support bounded recalibration.
- Files:
  - API/DB modules for feedback capture.
- Tests:
  - feedback persistence + range-bound update tests.
- Exit criteria:
  - feedback records can be safely consumed by assistant reward/calibration logic.

## Milestone W4: OTLP Observability

### Work Slice W4.1 - Collector Profile in Compose (Implemented)
- Goal: add optional OTLP collector profile for traces/metrics/logs export.
- Files:
  - `docker-compose.yml`
  - `ops/otel/collector-config.yaml` (new)
- Tests:
  - compose profile smoke tests.
- Exit criteria:
  - local runtime exports telemetry through collector with no runtime regressions.

### Work Slice W4.2 - Telemetry Redaction Policy (Implemented Baseline)
- Goal: enforce field-level redaction before OTLP export.
- Files:
  - `src/wicap/telemetry/otlp_resilience.py`
  - `event_processor.py`
- Tests:
  - redaction regression tests for secrets/tokens/PII.
- Exit criteria:
  - sensitive fields blocked from export in CI and runtime tests.

### Work Slice W4.3 - Delivery Resilience (Implemented Baseline)
- Goal: telemetry backpressure/failure must not degrade capture/control pipelines.
- Files:
  - `src/wicap/telemetry/otlp_resilience.py`
  - `event_processor.py`
- Tests:
  - collector-down and high-latency failure simulations.
- Exit criteria:
  - bounded memory and stable runtime when telemetry endpoint unavailable.

## Milestone W5: Rollout and Validation

### Work Slice W5.1 - Shadow Validation with Suricata/Zeek (Optional, Implemented Baseline)
- Goal: compare WiCAP-native outputs against Suricata/Zeek in controlled replay/soak.
- Files:
  - research/validation harness docs and scripts.
- Tests:
  - parity reports generated from shared fixtures.
- Exit criteria:
  - gap report available with field-level parity metrics.

### Work Slice W5.2 - Canary Deployment (Implemented Baseline)
- Goal: enable new intelligence contracts for limited environments only.
- Tests:
  - canary soak with escalation/recovery telemetry checks.
- Exit criteria:
  - canary SLOs pass before wider rollout.

### Work Slice W5.3 - Production Gate (Implemented Baseline)
- Goal: promote to default only after SLO compliance.
- SLOs:
  - anomaly precision/recall proxy improvements
  - autonomous recovery durability
  - zero high-severity telemetry redaction violations
- Exit criteria:
  - two consecutive release windows pass SLO gate.

## 5. Governance
- `docs/ROADMAP.md` remains primary WiCAP roadmap.
- This document is the canonical cross-repo integration companion for assistant interoperability.
- Any change here requires matching updates in assistant companion plan.

## 6. References
- OpenClaw policy planes: https://raw.githubusercontent.com/openclaw/openclaw/main/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md
- OpenClaw failover model: https://raw.githubusercontent.com/openclaw/openclaw/main/docs/concepts/model-failover.md
- Nanobot project: https://github.com/HKUDS/nanobot
- Suricata EVE JSON output: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Zeek conn log: https://docs.zeek.org/en/current/logs/conn.html
- OTLP specification: https://opentelemetry.io/docs/specs/otlp/
- OpenTelemetry Collector: https://opentelemetry.io/docs/collector/
