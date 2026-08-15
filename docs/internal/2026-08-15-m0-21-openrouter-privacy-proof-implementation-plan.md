# M0-21 OpenRouter privacy proof implementation plan

Date: August 15, 2026

## Goal

Build, review, and run the local redacted OpenRouter explanation proof while
leaving the M0-21a planner boundary and R-14 decision untouched.
Every behavior change follows a witnessed tests-only RED.

## Invariants

- Only a synthetic numeric-loopback OpenRouter-compatible endpoint is allowed.
- Product code creates a closed request, redacts seeded secret/PII material,
  and proves no residual prohibited value before I/O.
- Only one closed structured result schema is accepted.
- No `.env`, real credential, hosted endpoint, SDK, proxy, provider setting,
  or arbitrary model output enters product state or fixed output.
- Fixed output, absolute deadlines, independent cleanup, and cleanup precedence
  apply on every path.
- M0-21a remains Pending and R-14 remains Not run through M0-21 completion.

## Tasks

### Task 1: Record design and start status

- [x] Capture the tests-only repository-contract RED.
- [x] Add this design and executable plan.
- [x] Move only M0-21 from Pending to In progress at `703/1/20/3` overall and
  `27/2/1/20/3` in M0.

### Task 2: Implement the privacy gateway

- [ ] RED/GREEN closed typed input, deterministic redaction, residual scanning,
  exact OpenRouter request construction, and zero-I/O rejection.
- [ ] RED/GREEN hostile objects, invalid identity/metadata, bounds, unsupported
  purpose/model/provider, destination, and sensitive aliases.

### Task 3: Implement endpoint and response validation

- [ ] RED/GREEN strict request bytes, raw headers, one-request authority, and
  OpenRouter-compatible synthetic response.
- [ ] RED/GREEN strict outer response plus closed structured result schema,
  identity binding, URL/shell/tool/prose rejection, and response bounds.

### Task 4: Complete lifecycle and root commands

- [ ] RED/GREEN absolute main/request/cleanup deadlines, cancellation, socket
  drainage, cleanup precedence, panic containment, and fixed output.
- [ ] Add root test/run commands and README boundary; run the exact local proof.

### Task 5: Review, verify, and ship

- [ ] Fix every adversarial review finding tests-first.
- [ ] Run six focused passes, full pinned repository gates, audit, whitespace,
  and redacted secret scans.
- [ ] Transition only M0-21 to Complete after retained evidence; leave M0-21a
  Pending and R-14 Not run.
- [ ] Commit, push, and watch the exact-SHA Runnable UI gate.
