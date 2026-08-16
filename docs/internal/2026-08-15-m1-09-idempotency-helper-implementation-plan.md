# M1-09 Idempotency Helper Implementation Plan

**Goal:** Provide one scoped atomic idempotency claim/completion interface and
request helper that returns a prior canonical result for completed duplicates.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- Request identity binds scope, operation, key, and exact request fingerprint.
- Only the unique acquired claim executes the operation.
- Completed duplicates return the prior canonical product result reference.
- In-progress, conflicting, failed, canceled, panicked, or malformed outcomes do
  not execute automatically.
- Fixed helper errors expose no request, key, result, store, or provider data.
- M1-10 remains Pending until M1-09 completes and exact-SHA CI passes.
- Existing M0 blockers and R-03/R-11 boundaries remain unchanged.

### Task 1: Start M1-09

- [ ] Add a repository contract binding source, PRD reliability rules, design,
  plan, completed M1-08, unique active status, arithmetic, and blockers.
- [ ] Capture focused RED at the still-Pending README/tracker state.
- [ ] Move only M1-09 to In progress at `686/1/38/3` overall and M1
  `68/53/1/14/0`; document the idempotency boundary.
- [ ] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-09 idempotency helper`.

### Task 2: Implement the helper tests-first

- [ ] Add Go tests before production and capture genuine missing-symbol RED.
- [ ] Implement opaque request/claim/result values, atomic store interface, and
  conservative execute-on-acquired helper.
- [ ] Cover duplicate prior results, in-progress/conflict outcomes, exact request
  identity, invalid state, cancellation, operation/store failures, invalid
  results, concurrency, completion ownership, and panic retention.
- [ ] Run six focused passes, platform/service/worker/root regressions, full
  repository gates, audit, whitespace, and scans; commit
  `feat: add idempotency helper`.

### Task 3: Review the duplicate-execution boundary

- [ ] Audit tenant/key/fingerprint collisions, store atomicity, claim-shape
  validation, stale completion, context races, unknown outcomes, panic behavior,
  result identity, typed-nil interfaces, and error secrecy.
- [ ] Add tests-first fixes for every concrete finding and rerun affected gates.
- [ ] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-09

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-09 to Complete at `686/0/39/3` and M1
  `68/53/0/15/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-09 idempotency helper`, push,
  and watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-10.
