# Precise sensor envelope implementation plan

> Use Superpowers test-driven-development and independent requesting-code-review.
> This is one coupled transport unit, implemented inline in the existing worktree.

**Goal:** Freeze and replay precise sensor records with enrollment constraints.
**Architecture:** Add separate envelope and body types using the existing
ProductionClient credential/HTTPS request path. V1 methods and frozen bytes stay
unchanged. No daemon activation or server acceptance is enabled by this change.
**Tech Stack:** Go, encoding/json, net/http, existing sensor token credentials.
**Spec:** `2026-09-11-process-precision-design.md`, envelope portion of step2.

## Contract

Create `services/platform/sensoradapter/precise_envelope.go` and its test file.
`type PreciseRuntimeEnvelope RuntimeEnvelope` is a distinct Go type with the same
credential-free fields. Use version `sensor-ingest-envelope-v2`, schema
`runtime-event-enrollment-v2` and `runtime-v2:` plus SHA256(body) idempotency.
Its body is `{source:"tetragon",events:[]PreciseRuntimeEvent}`. Public methods:

```go
func (client *ProductionClient) PreparePreciseEnvelope(events []PreciseRuntimeEvent) (PreciseRuntimeEnvelope, error)
func (client *ProductionClient) IngestPreciseEnvelope(ctx context.Context, envelope PreciseRuntimeEnvelope) error
```

Before reading credentials, both validate enrollment and all record fields;
replay also checks destination, exact version/schema, canonical body and digest.
Use the existing1000 event,8MiB body,24h age and5min future bounds. Validate
precise observation against wire time, then reuse legacy content checks with
observation removed from a local copy only. Retained event/envelope cannot change.
The shared `send` method must send `X-Zasp-Expected-Enrollment` for V2 as for V1.
Each transport attempt reads the current credential, but retries the frozen body.
Old IngestEnvelope rejects explicit conversion of a V2 envelope, even when all
records lack lineage. V2 rejects V1. No silent fallback after server rejection.

- [x] Write a real-normalizer fixture test: prepare with zero credential reads,
  first transport fails, serialize/restore envelope, rotate token, retry and
  assert identical bytes, schema, enrollment header and idempotency. Check
  precise source/start values in the restored body and V1/V2 rejection both ways.
- [x] Run the tests with ErrClient-only method stubs. Confirm positive replay
  fails before implementation.
- [x] Implement the contract and shared header condition. Add negative cases
  for destination/enrollment/version/schema/digest drift, canonical hostile JSON,
  empty/oversized batches, invalid/future/expired time and canceled contexts;
  require rejection before credential access.
- [x] Run `go test -C services/platform -race -count=1 ./sensoradapter
  ./runtimelineage ./runtimeevent`, fresh UI build, independent review, diff and
  status-ledger checks. Record evidence without production task credit.

Owned chunk checkpoints, source generation activation, server V2 archive ingest
and downstream persistence remain required. A successful fake HTTP response is
only transport evidence, not a running production API accepting this schema.

Local evidence: positive replay RED in `/tmp/zasp-precision-envelope-red.log`.
Final sensoradapter/runtimelineage/runtimeevent races passed11.383s/1.405s/3.653s
in `/tmp/zasp-precision-envelope-final-reviewed.log`. Sensor-agent's existing
package race suite passed107.051s in `/tmp/zasp-precision-envelope-daemon.log`.
Fresh UI build exited0 in `/tmp/zasp-precision-envelope-ui.log`.
Independent review requested stronger body/count/rejection tests. All were added;
removing only the replay byte limit reached credential access in
`/tmp/zasp-precision-envelope-limit-mutation.log`, proving the size regression.
The guard was restored before final verification. Scoped re-review found no
remaining findings. No push, daemon activation or production task credit.
