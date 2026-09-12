# Precision observation contract

> **For agentic workers:** Use Superpowers test-driven-development and independent review.

**Goal:** Preserve a source-observed nanosecond instant without broadening V1.
**Architecture:** Separate `PreciseObservation` type in runtimelineage, containing
the existing qualifier fields and required `SourceEventTime`. Closed decoding
and canonical time validation; V1 code remains unchanged.
**Tech Stack:** Go, encoding/json, time.
**Spec:** `2026-09-11-process-precision-design.md`.

## One coupled contract task

Create `services/platform/runtimelineage/precise_observation.go` and matching
test. Export `PreciseObservation`, `Valid() bool`, `ValidAt(time.Time) bool` and
`TimeAt(time.Time) (time.Time,error)`. Wire time must be UTC and exactly a
millisecond boundary. Precise time truncates to that boundary. No new source
emission or V1 decoder acceptance in this task.

- [x] Write failing tests for a process start .123456789 before event
  .123999999, wire .123; retain exact PID/start and return exact event instant.
  Reject process after source, wrong millisecond bin, missing/noncanonical time,
  duplicate/unknown/escaped keys and V2 through the V1 decoder.
- [x] Implement the separate closed type. Reuse existing qualifier validation
  internally on a copy with the V1 profile; never expose that copy as an event.
  Marshal explicit fields and preserve source time verbatim.
- [x] Run `go test -race -count=1 ./runtimelineage ./sensoradapter ./runtimeevent
  ./runtimecorrelation ./runtimeprojection`; verify old wire/replay tests stay
  unchanged, request independent review and update the authoritative ledger.

Original728 scope unchanged. No milestone, source emission, deployment or
production-availability credit from this local contract task.

The positive same-millisecond case failed before implementation in
`/tmp/zasp-precision-contract-red.log`. Final five-package race results passed
in `/tmp/zasp-precision-contract-green.log`: runtimelineage1.638s,
sensoradapter10.197s, runtimeevent3.373s, runtimecorrelation1.811s and
runtimeprojection1.938s. Independent Superpowers review approved this local
contract. Fresh UI build passed in `/tmp/zasp-precision-ui-build.log`; ledger
and diff checks passed. Source time remains an observation, not host attestation.
