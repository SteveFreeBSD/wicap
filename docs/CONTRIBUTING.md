# Contributing to WICAP

This document defines the mandatory workflow for making changes without
breaking live capture, replay determinism, or the UI.

Start here: `docs/INDEX.md`

---

## 1. Non-Negotiables

- Keep the repo’s documentation structure intact (see `docs/INDEX.md`).
- Prefer small, reviewable slices over “mega commits”.
- Do not ship new detectors without spam controls (throttle/burst) and replay fixtures.
- Do not commit secrets (use `.env`, env vars, or your secrets manager).
- Do not treat `onboarding/` snapshots as authoritative; the live truth is in `docs/`.

---

## 2. New Contributor / Agent Onboarding

1) Read the canonical docs:
- `docs/ROADMAP.md` (what is next)
- `docs/CONFIGURATION.md` (required secrets + knobs)
- `docs/TESTING.md` (how we validate)

2) Get a green baseline locally:
- Run the fast local gate from `docs/TESTING.md`

---

## 3. Implementation Workflow

### Step A: Preflight

- Confirm the change belongs to an existing workstream in `docs/ROADMAP.md` or `docs/CROSS_REPO_AGENTIC_INTEGRATION.md` for cross-repo assistant integration.
- Identify the test(s) you will add/update before coding.

### Step B: Implement

- Keep feature flags default-safe (especially anything active/TX).
- Keep DB writes idempotent (MERGE/upsert patterns; avoid double-count).
- Avoid new data duplication: add one canonical table/field, derive everything else.

### Step C: Validate (Required Before Commit)

Run the canonical review gate from `docs/TESTING.md`:
- `./scripts/review_gate.sh`

Then run additional targeted checks when applicable:
- deterministic replay (`python3 -m replay_driver --batch tests/fixtures/manifest.json`) when parsing/detection changes
- e2e/soak when UI or long-running stability is impacted

### Step D: Update Docs

- Update `docs/ROADMAP.md` if scope/status changed.
- Update `CHANGELOG.md` if the change is user-visible or operationally relevant.
- Do not add ad-hoc roadmaps; extend the canonical roadmap docs (`docs/ROADMAP.md` and, for cross-repo scope, `docs/CROSS_REPO_AGENTIC_INTEGRATION.md`).

---

## 4. Known Pitfalls (Hard-Won Lessons)

SQL batch truncation:
- With `fast_executemany`, you must use `cursor.setinputsizes()` for NVARCHAR(MAX)
  or the driver may default to 510 byte buffers.

Docker “baking”:
- Code changes may require `docker compose build` before they take effect.

Schema drift:
- Runtime guards do not auto-migrate column sizes/types. Treat schema changes as
  explicit migrations.

Wi‑Fi interface cleanup:
- Always restore managed mode on exit (use finally/atexit patterns).

Silent failures:
- Watch data-flow counters and logs, not just `/health`.

---

## 5. Documentation Governance (No Drift)

- **Single source of truth**: `docs/` only.
- **Roadmap**: `docs/ROADMAP.md` is canonical for WiCAP runtime; `docs/CROSS_REPO_AGENTIC_INTEGRATION.md` is canonical for cross-repo assistant integration scope.
- **Onboarding bundles**: `onboarding/` is snapshot-only. If it conflicts with `docs/`, update `docs/` and regenerate the bundle later.
