# M0-20 PostHog privacy proof implementation plan

Date: August 15, 2026

## Goal

Build, review, and run the local allowlist-only PostHog privacy proof, then make
the evidence-backed R-13 decision. Every behavior change follows a witnessed tests-only RED.

## Invariants

- The fake endpoint is numeric-loopback-only and accepts one exact capture.
- The serializer constructs a closed document and never copies arbitrary
  caller properties.
- Every prohibited seeded field must fail before network I/O.
- No `.env`, credential, proxy, hosted endpoint, SDK, or ambient configuration
  enters the proof.
- Fixed output and independent cleanup apply on every path.
- M0-09, M0-18, M0-19, and PROV-01 remain Blocked; M0-21 remains Pending until
  the final M0-20 evidence decision.

## Tasks

### Task 1: Record design and start status

- [x] Capture the tests-only repository-contract RED.
- [x] Add this design and executable plan.
- [x] Move only M0-20 from Pending to In progress at `704/1/19/3` overall and
  `27/3/1/19/3` in M0.

### Task 2: Implement the strict serializer

- [x] RED/GREEN exact typed allowlist construction and deterministic encoding.
- [x] RED/GREEN unknown/accessor/prototype/type/value rejection for prompt,
  secret, IP, raw evidence, arbitrary context, and hostile coercion.

### Task 3: Implement the fake endpoint and proof lifecycle

- [x] RED/GREEN numeric-loopback server, strict bounded request/response
  parsing, one-request authority, absolute deadlines, and zero-I/O rejection.
- [x] RED/GREEN panic containment, independent cleanup, cleanup precedence,
  socket drainage, fixed output, and exact receipt evidence.

### Task 4: Expose root commands and evidence

- [x] Add hermetic test and run commands plus README boundary.
- [x] Run the exact local proof and record R-13 only from retained evidence.

### Task 5: Review, verify, and ship

- [x] Fix every adversarial review finding tests-first.
- [x] Run six focused passes, full pinned repository gates, audit, whitespace,
  and redacted secret scans.
- [x] Transition M0-20 from In progress to Complete only after the exact proof,
  zero-resource cleanup, and review pass; otherwise Block it explicitly.
- [x] Keep M0-21 Pending through the transition.
- [x] Commit, push, and watch the exact-SHA Runnable UI gate.
