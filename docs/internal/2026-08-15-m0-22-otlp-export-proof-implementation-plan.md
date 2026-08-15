# M0-22 OTLP export proof implementation plan

Date: August 15, 2026

## Goal

Build, review, and run the exact-pinned bounded Collector export/failure proof,
then decide R-12 from the combined M0-13/M0-22 evidence.
Every behavior change follows a witnessed tests-only RED.

## Invariants

- Only the exact synthetic operation and fixed OTLP destination are accepted.
- The source queue, batching, retry, body, cardinality, and deadlines are bounded.
- Application progress is independent of exporter availability.
- The source uses Docker's built-in bridge only for numeric-loopback host
  publication and is then attached to the proof-owned private exporter
  network; the sink exists only as the exact private peer.
- No credential, hosted backend, dotenv, profile, proxy, arbitrary endpoint, or
  customer payload enters the lifecycle.
- Mutation authority is retained before interpretation; cleanup re-proves exact
  ownership, settles late work, continues in reverse order, and wins precedence.

## Tasks

### Task 1: Record design and start status

- [x] Capture the tests-only repository-contract RED.
- [x] Add this design and executable plan.
- [x] Move only M0-22 from Pending to In progress at `701/1/22/3` overall and
  `27/0/1/22/3` in M0; leave R-12 Not run.

### Task 2: Implement bounded telemetry and configuration

- [x] RED/GREEN exact operation document, privacy bounds, source/sink configs,
  bounded queue/retry, and strict sink artifact validation.
- [x] RED/GREEN malformed, duplicate, oversized, identity, endpoint, queue,
  retry, and application-state drift.

### Task 3: Implement exact lifecycle and failure proof

- [x] RED/GREEN exact image/network/container/temp ownership and reconciliation.
- [x] RED/GREEN first delivery, exact sink stop, failed exporter, application
  completion bound, mutation settlement, reverse cleanup, and global absence.
- [x] RED/GREEN deadlines, replacements, delayed mutations, output caps,
  cleanup continuation/precedence, and fixed output.

### Task 4: Expose commands, review, and ship

- [x] Add hermetic/live root commands and README boundary.
- [x] Run two consecutive exact live passes, six focused passes, M0-13
  regression, full pinned gates, audit, license, whitespace, and secret scans.
- [x] Fix every adversarial review finding tests-first.
- [ ] Transition only M0-22 to Complete and R-12 to PASS after combined proof;
  keep M0-23 Pending.
- [ ] Commit, push, and watch the exact-SHA Runnable UI gate.
