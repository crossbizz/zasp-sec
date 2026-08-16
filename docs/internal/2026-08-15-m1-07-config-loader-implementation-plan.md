# M1-07 Configuration Loader Implementation Plan

**Goal:** Load one strict typed platform configuration that fails startup for
missing required dependencies while allowing optional integrations to remain
absent.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- Required Stytch, Neon, AWS, and in-cluster OTLP configuration fails closed.
- PostHog, OpenRouter, and remote OTLP remain optional and explicitly absent.
- Secret material is never accepted, resolved, retained, logged, or emitted;
  configuration contains only strict Secrets Manager references.
- Source lookup is injected and no ambient process/file/profile state is read.
- Fixed errors do not contain rejected configuration values.
- M1-08 remains Pending until M1-07 completes and exact-SHA CI passes.
- Existing M0 blockers and R-03/R-11 boundaries remain unchanged.

### Task 1: Start M1-07

- [x] Add a repository contract binding source, architecture/PRD rules,
  design, plan, completed M1-06, unique active status, arithmetic, and blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-07 to In progress at `688/1/36/3` overall and M1
  `68/55/1/12/0`; document the configuration boundary.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-07 config loader`.

### Task 2: Implement the loader tests-first

- [x] Add Go tests before production and capture genuine missing-symbol RED.
- [x] Implement strict source loading, required and optional groups, opaque
  endpoint/region/project/secret-reference values, accessors, and validation.
- [x] Cover required omissions, optional absence/partial groups, malformed
  values, direct invalid state, source failures, comparability, and secrecy.
- [x] Run six focused passes, platform/service/worker/root regressions, full
  repository gates, audit, whitespace, and scans; commit
  `feat: add typed platform config loader`.

### Task 3: Review the configuration boundary

- [x] Audit required/optional classification, secret-reference grammar,
  endpoint parsing, source ambiguity, zero/direct state, error secrecy, and
  command-boundary assumptions.
- [x] Add tests-first fixes for every concrete finding and rerun affected gates.
- [x] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-07

- [x] Change only completion expectations and capture focused RED.
- [x] Move only M1-07 to Complete at `688/0/37/3` and M1
  `68/55/0/13/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-07 config loader`, push, and
  watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-08.
