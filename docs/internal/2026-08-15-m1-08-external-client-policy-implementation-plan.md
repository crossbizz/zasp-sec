# M1-08 External Client Policy Implementation Plan

**Goal:** Provide one shared strict deadline/retry/concurrency executor for
platform HTTP clients.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- Every execution has one total deadline including slot wait and backoff.
- Only classified transient outcomes retry.
- Non-idempotent mutations receive exactly one attempt.
- Concurrency is bounded across complete attempt sequences.
- Intermediate response bodies close; final response ownership is explicit.
- Fixed errors contain no external request, response, URL, or provider data.
- M1-09 remains Pending until M1-08 completes and exact-SHA CI passes.
- Existing M0 blockers and R-03/R-11 boundaries remain unchanged.

### Task 1: Start M1-08

- [x] Add a repository contract binding source, PRD reliability rules, design,
  plan, completed M1-07, unique active status, arithmetic, and blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-08 to In progress at `687/1/37/3` overall and M1
  `68/54/1/13/0`; document the external-client boundary.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-08 external client policy`.

### Task 2: Implement the executor tests-first

- [x] Add Go tests before production and capture genuine missing-symbol RED.
- [x] Implement opaque policy/request-kind values, total deadline, bounded
  semaphore, transient classifier, retry loop, response close, and backoff.
- [x] Cover transient/permanent statuses and errors, request kinds, attempts,
  deadlines, cancellation, slot wait/release, response ownership, malformed
  results, direct invalid state, panic release, and comparability.
- [x] Run six focused passes, platform/service/worker/root regressions, full
  repository gates, audit, whitespace, and scans; commit
  `feat: add external client policy`.

### Task 3: Review the reliability boundary

- [x] Audit deadline scope, cancellation races, retry/idempotency taxonomy,
  status/error classification, body lifecycle, concurrency, backoff overflow,
  zero/direct state, panic unwinding, and error secrecy.
- [x] Add tests-first fixes for every concrete finding and rerun affected gates.
- [x] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-08

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-08 to Complete at `687/0/38/3` and M1
  `68/54/0/14/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-08 external client policy`,
  push, and watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-09.
