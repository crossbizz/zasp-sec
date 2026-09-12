# Precise server archive implementation plan

> Execute this tightly coupled codec unit inline with Superpowers TDD, then request independent code review. User-authorized autonomous decisions apply.

**Goal:** Carry the precise sensor envelope through content filtering into a separately versioned, tenant-scoped server archive without enabling live acceptance.

**Spec:** `2026-09-11-process-precision-design.md`, integration step3.

**Architecture:** Add `runtimeevent/precise_archive.go`. A separate `PreciseRecord` embeds the legacy record and shadows its observation with `runtimelineage.PreciseObservation`. Validate exact time separately, reuse legacy Tetragon conversion/filtering on a local observation-free copy, then restore the V2 observation marker. Do not promote observations into semantic authority fields.

The archive root has `version: runtime-archive-v2`, `source`, and `events`. This version is mandatory even when every event lacks qualified lineage. Legacy archive decoding must reject it. The private preparation function accepts only canonical Tetragon precise-envelope bodies, checks authenticated authority and current-time bounds, filters content and emits canonical archive bytes. Replay is closed/canonical and gets scope only from its trusted argument, with no current-time expiry. Existing HTTP, SQL, job routing and V1 decoders remain unchanged.

Alternative: widening the V1 record/archive decoder would alter frozen historical acceptance. Sharing one unversioned archive for unqualified events would lose the worker-version fence. Neither meets the existing design.

## Local deliverable

Files: create `services/platform/runtimeevent/precise_archive.go` and `precise_archive_test.go`; update the authoritative ledger and precision design after verification.

Interfaces:

```go
type PreciseRecord struct {
    Record
    ObservedLineage runtimelineage.PreciseObservation
}
type PreciseArchivedBatch struct { Source string; Records []PreciseRecord }
func DecodePreciseArchivedBatch(domain.Scope, []byte) (PreciseArchivedBatch, error)
func decodePreciseProductionInput([]byte, IngestAuthority, time.Time) (preciseIngestInput, []byte, error)
```

- [x] Write tests for source/process `.123999999`/`.123456789` survival, metadata-only filtering, tenant assignment and legacy archive rejection with both qualified and absent lineage. Test noncanonical/hostile inputs, wrong bins, unknown versions, invalid authority, stale ingest and replay without expiry. Live V2 HTTP acceptance must still fail before reservation.
- [x] Run the focused tests against rejecting stubs and record expected RED assertions.
- [x] Implement only the described private preparation and public replay decoder. Bounds are1..1000 records and64MiB, existing ingest windows24h past/5min future, UTC clock. Check canonical serialization before filtering and again on archive replay.
- [x] Run `go test -C services/platform -race -count=1 ./runtimeevent ./sensoradapter ./runtimelineage`, UI build and `git diff --check`.
- [x] Request read-only Superpowers review, resolve findings, record exact evidence and unchanged original task counts. Leave the wider unpublished draft unpushed until its release gates pass.

Evidence: expected stub failures in `/tmp/zasp-precision-archive-red.log`;
focused pass in `...-green.log`; real normalizer/envelope controls in
`...-controls-final.log`. The initial integration fixture omitted required
cluster fields; root-cause inspection corrected the fixture only. Removing
only the byte guard reproduced decoder entry in `...-size-mutation.log`;
the guard was restored. Fresh races in `...-final.log` passed runtimeevent4.987s,
sensoradapter10.909s and runtimelineage1.430s. UI build exited0 in
`/tmp/zasp-precision-archive-ui.log`. Independent review closed all conditions
with no findings. These are local codec results, not SQL or live acceptance.
