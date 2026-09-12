# V3 daemon admission and consumer plan

> Use Superpowers test-driven-development and independent requesting-code-review.
> Implement this connected admission path inline.

**Goal:** Admit an owned V3 source and consume its actual immutable spool records.
**Architecture:** Reuse the identity-bracketed generation startup and pump. A
separate precise constructor selects V3; the existing production constructor
stays V2. Manifest admission binds V3 to record-format3 and consumer selection
uses that admitted profile to choose the precise checkpoint processor.
**Tech Stack:** Go, Unix gRPC, os.Root, Kubernetes identity adapter.
**Spec:** `2026-09-11-process-precision-design.md`, daemon ownership portion of step2.

Create `services/sensor-agent/lineage_precision_test.go` and extend
`lineage_cgroup_manifest_test.go`'s exhaustive prefix tests to include V3.
Modify `lineage_generation.go` with a private profile-selected helper and
`startPreciseLineageGeneration` using the existing signature. Only V2 and V3
are valid startup choices; invalid selection closes the owned endpoint.
Modify `lineage_spool.go` to validate V3 through NewPreciseLineageNormalizer and
bind `zasp-tetragon-record-v3`; V1/V2 stay exact. Extend both reservation prefix
loops in `lineage_reservation_manifest.go` to3, preserving enrollment comparison.
Modify `lineage_consumer.go` to store a private processor interface with the
existing four methods and select NewPreciseChunkProcessor only for admitted V3.
All source/root/slot/enrollment/protected-input checks remain in place.

- [x] Test every V3 startup prefix and mixed source/record format rejection.
  Test an actual owned Unix subscription and pump into files, V3 reader admission,
  precise consumer uncertain send and restart with byte-identical payload and
  exact source/process times. Preserve default V2 producer behavior.
- [x] Confirm RED with the new constructor temporarily forwarding to old startup.
- [x] Implement the shared startup selection, manifest and consumer changes.
- [x] Run sensor-agent and platform races, fresh UI build, independent review,
  diff and ledger checks. Record precise scope and original task status.

No production configuration/default switch. No actual Kubernetes/provider or
server acceptance proof is claimed from local fixtures. Server V2 archive,
durable stage versioning, precise matching and composed activation remain open.
Inspection also found `sensoradapter.RetireConsumedCheckpoint` still admits only
V1 source/checkpoint contracts. Add a separately versioned precise retirement
path and exercise producer completion/slot reuse before any V3 activation.

Local evidence: `/tmp/zasp-precision-daemon-red.log` rejected V3 manifest and
detected the old constructor's V2 source. Focused Unix-stream/spool/consumer
tests passed in `/tmp/zasp-precision-daemon-green.log`. Full sensor-agent races
passed110.715s in `/tmp/zasp-precision-daemon-full.log`; platform races passed
sensoradapter13.457s/runtimelineage1.657s/runtimeevent3.756s in
`/tmp/zasp-precision-daemon-platform.log`. UI build exited0 in
`/tmp/zasp-precision-daemon-ui.log`. Independent Superpowers review found no
findings, conditional only on the now-passed full sensor-agent run.
The test uses real Unix gRPC and files with controlled identity/provider/HTTP
fixtures. Production's existing constructor still selects V2. No original task
credit or live deployment claim.
