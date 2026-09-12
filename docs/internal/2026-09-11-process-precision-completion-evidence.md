# Precise completion worker checkpoint

Completion V3 accepts only projection V3 through the precise receipt decoder.
It requires authorized execution, matching predecessor digest and exact stored
artifact identity/integrity. Its4MiB input bound matches the precise projection
codec; historical completion paths retain their1MiB bound and receipt bytes.

Completion emits a versioned stage receipt with sorted risk IDs and retains the
original projection receipt bytes for the finalizer. Cancellation and current
lease checks fence writes and successful effects. New workers can drain old
versions without reinterpreting their receipts.

Superpowers evidence:

- New completion tests failed at unsupported V3 construction before implementation.
- The local chain executes V4 correlation, V3 projection and V3 completion using
  real codecs/executors with declared database, graph and artifact providers.
  Tests preserve source-qualified Strong identity and accept a valid1000-item
  projection receipt above1MiB and below4MiB.
- Tests reject invalid capabilities before I/O and receipt checksum, returned
  version, generation, effect digest, old schema and size mismatches before writes.
  A dedicated provider wrapper returns an altered object version; merely removing
  the requested version would instead test the missing-object retry path.
- Cancellation/renewal and historical byte regressions pass. The real stage
  processor hands exact projection bytes and V3 version to a declared finisher.
- Final expanded worker races exited0 in8.128s with
  `go test -C services/platform -race -count=1 ./agentsec-worker -run '^TestPrecise|^TestSandboxCompleteWorker|^TestRuntimeComplete|^TestSandboxProjectionWorker|^TestRuntimeProjection'`.
  runtimeevent/runtimeprojection/runtimecorrelation races exited0 in5.290s/1.750s/
  2.214s. UI build and diff checks passed. Independent Superpowers source review
  returned no findings.

At this earlier checkpoint database finalization and production routing were
not wired. Registered51, archive/indexV2 and explicit production configuration
now exist; see `2026-09-11-process-precision-finalization-plan.md` for the current
acceptance gaps. The scoped worker results above do not independently prove
database finalization, live providers or release readiness. No original task credit.
