# M1-06 Product Error Envelope Implementation Plan

**Goal:** Define one strict stable product API error code and exact four-field
JSON error envelope.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- Codes are bounded lowercase product identifiers, not vendor error names.
- Messages are bounded customer-safe text without control characters.
- Correlation IDs are canonical nonzero product IDs and grant no authority.
- Retryability is explicit and cannot be inferred from message/vendor state.
- Invalid/zero values refuse JSON serialization with fixed errors.
- M1-07 remains Pending until M1-06 completes and exact-SHA CI passes.
- Existing M0 blockers and R-03/R-11 boundaries remain unchanged.

### Task 1: Start M1-06

- [x] Add a repository contract binding source, public API/UX rules, design,
  plan, completed M1-05, unique active status, arithmetic, and blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-06 to In progress at `689/1/35/3` overall and M1
  `68/56/1/11/0`; document the error-envelope boundary.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-06 product error envelope`.

### Task 2: Implement the envelope tests-first

- [ ] Add Go tests before production and capture genuine missing-symbol RED.
- [ ] Implement opaque strict ProductErrorCode and ProductErrorEnvelope values,
  accessors, validation, and exact JSON marshaling.
- [ ] Cover the snapshot, retryable variants, invalid codes/messages/IDs,
  direct malformed state, comparability, fixed errors, and escaping.
- [ ] Run six focused passes, platform/service/worker/root regressions, full
  repository gates, audit, whitespace, and scans; commit
  `feat: add product error envelope`.

### Task 3: Review the public error boundary

- [ ] Audit stable shape/code grammar, message bounds, correlation semantics,
  retryability, JSON escaping, zero/direct state, error secrecy, and misuse.
- [ ] Add tests-first fixes for every concrete finding and rerun affected gates.
- [ ] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-06

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-06 to Complete at `689/0/36/3` and M1
  `68/56/0/12/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-06 product error envelope`,
  push, and watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-07.
