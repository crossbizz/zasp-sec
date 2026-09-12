# Precise source receipt and checkpoint retirement

> Use Superpowers test-driven-development and independent requesting-code-review.

**Goal:** Verify V3 consumption and retire only its completed V2 checkpoint.
**Architecture:** Separate public precise entry points select exact source,
checkpoint and target versions, then reuse existing proof, filesystem, lock,
authorization and unlink/sync checks. The daemon selects by admitted source.
**Tech Stack:** Go, os.Root, existing durable completion and ACK protocol.
**Spec:** `2026-09-11-process-precision-design.md`, lifecycle prerequisite.

Create `sensoradapter/precise_retirement.go` and tests. Export
`VerifyPreciseConsumptionSource` with the same arguments as VerifyConsumptionSource
and `RetirePreciseConsumedCheckpoint(ctx, ChunkRetirementConfig) error`.
Extract the existing implementations into private helpers. V1 retains its source
validator and fixed V1 checkpoint/envelope versions; V3 uses source profile3,
checkpoint2 and envelope2. Retirement still refuses any pending record.
Select these functions in sensor-agent/lineage_receipt.go and lineage_completion.go
only when the already-validated source profile is V3.

- [x] Add a real precise processor fixture, consumption reread and retirement
  test, with V1 refusal, same lock after deletion and authorized absent retry.
  Add denial/mismatch/pending/live-lock tests retaining checkpoint bytes.
- [x] Confirm RED with new entry points returning ErrStream.
- [x] Extract shared verification/retirement bodies and implement precise gates.
- [x] Verify actual daemon ACK, producer reclaim/completion and checkpoint
  retirement on V3, including unchanged completion evidence and retry.
- [x] Run platform and sensor-agent race suites, UI build, independent review,
  diff and ledger checks. Keep activation/server persistence gates open.

All destructive tests operate only on newly created test directories. No live
checkpoint, spool or deployed source is retired by this implementation task.

The existing fixed-slot lifecycle test also now runs for V3 across24 generations,
including alternating empty/record sources, producer completion collection and
bounded slot reuse. The focused completion/slot race run passed12.921s in
`/tmp/zasp-precision-retirement-slots.log`.

Entry-point RED: `/tmp/zasp-precision-retirement-red.log`. Daemon verifier and
retirement dispatch were independently RED in
`/tmp/zasp-precision-retirement-daemon-red.log` and
`/tmp/zasp-precision-retirement-dispatch-red.log`. Final platform races passed
sensoradapter14.091s/runtimelineage1.272s/runtimeevent3.549s in
`/tmp/zasp-precision-retirement-full.log`. Full daemon races passed119.190s in
`/tmp/zasp-precision-retirement-daemon.log`; the subsequently added V3 slot test
passed in the focused run above. UI build exited0 in
`/tmp/zasp-precision-retirement-ui.log`. Independent Superpowers review found
no findings; its full-daemon condition is satisfied. No production task credit.
