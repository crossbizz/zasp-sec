# Precise candidate freezing

Use Superpowers TDD and independent review for the next part of precision design
step3. Add a private SQL fragment derived from the checked schema50 sandbox
freeze function. It consumes `runtime-archive-v2` Tetragon archives and
`runtime-index-v2` receipts under a `runtime-correlation-v4` lease, then retains
`runtime-candidate-snapshot-v3` bytes. Old functions and snapshots stay unchanged.

The source epoch is exact numeric, obtained from the precise observation text.
Keep an indexed millisecond range prefilter, extend its upper bound by1ms, then
apply the exact five-minute numeric predicate BEFORE LIMIT1001. Preserve all
scope/enrollment, predecessor/digest, live delivery, stage/sensor locking,
overflow, historical replay and final post-lock checks from the predecessor.
Semantic observations still come from the existing admitted OTLP store; the V2
Tetragon path cannot create semantic observations.

Files: new `migrations/sql/fragments/runtime_precision_candidates.sql` and
`apiserver/runtime_precision_freeze_postgres_test.go`; add optional fixture
serialization versions to the existing candidate test helper, preserving its
default V1 behavior. The new function is authority-owned with PUBLIC revoked,
without a worker grant. Disposable integration tests explicitly grant its role
after checking refusal. Actual deployment still requires the future migration's
checksum/fingerprint/lifecycle and worker-routing changes.

- [x] Write failing PostgreSQL tests for exact lower/upper window boundaries,
  V3 snapshot persistence/replay, late candidates, old-version refusal, private
  execution, forged lineage and expired leases. Keep schema50 fixtures intact.
- [x] Observe failures against a rejecting stub.
- [x] Derive the separate function using checked single replacements, including
  archive/index-stage version binding and exact selection before truncation.
- [x] Verify actual PostgreSQL races, legacy freeze tests, UI and independent review.
- [x] Record local evidence, open migration/Go-worker integration and unchanged counts.

Evidence: actual PostgreSQL rejecting stub failed in
`/tmp/zasp-precision-freeze-red.log`. Exact selection, SQL time contract and
historical sandbox snapshot races passed15.757s in
`/tmp/zasp-precision-freeze-final.log`. Added version refusals passed6.880s in
`/tmp/zasp-precision-freeze-versions.log`. The test fixture now passes its index
version directly to the real stage-receipt encoder, retaining correct bytes,
digest and content-derived evidence reference. Final new+legacy freeze races
passed13.953s in `/tmp/zasp-precision-freeze-reviewed.log`; UI build exited0 in
`/tmp/zasp-precision-freeze-ui.log`. Independent Superpowers review approved all
scoped changes; its final regression condition is satisfied. The owner-seeded
crowding tests prove1001 just-outside-window rows cannot hide two exact candidates;
1001 inside-window candidates reject with54000 and no partial snapshot.

No production worker grant or migration registration was added. The fragment
still inherits schema50 readiness and must be covered by complete precision
readiness before activation. SQL fixture execution is not authenticated V2
ingest, worker-dispatched processing or deployed acceptance.
