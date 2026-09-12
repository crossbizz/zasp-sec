# Precise freeze repository

Implement the Go consumer of the reviewed precise freeze SQL using Superpowers
TDD and independent review. Keep the legacy repository method and decoders
unchanged. Add `FreezePreciseCandidates` and a distinct sealed
`PreciseFrozenCandidateSnapshot` in `runtimeevent/precise_candidates.go`.

Require a current V4 correlation lease and matching V2 index receipt/archive
digests before SQL. Decode exact snapshot-v3 bytes, scope/batch/generation,
source enrollment equal to runtime enrollment, sorted unique semantic candidates,
nullable historical sandbox identity and exact source-time window. A Tetragon
batch cannot be its own semantic candidate. Recheck cancellation/lease expiry
after the provider returns. Use existing sanitized provider error classes and
copy-returning snapshot accessors. Do not grant execution or activate claiming.

- [x] Write rejecting-stub tests for valid snapshots, exact lower-window refusal,
  malformed/provider bindings, legacy versions, sealed copies and expired/canceled
  replies. Run RED.
- [x] Implement the separate repository method and strict decoder.
- [x] Change the existing real PostgreSQL precision-freeze test to consume the
  actual Go method and its sealed snapshot bytes. Run new and legacy race tests.
- [x] Run UI build, independent review and ledger checks; record integration gaps.

Expected rejecting-stub failures are in `/tmp/zasp-precision-repository-red.log`.
Fresh actual Go-to-PostgreSQL plus legacy freeze races passed13.781s in
`/tmp/zasp-precision-repository-postgres.log`. Runtimeevent/runtimelineage/
runtimecorrelation races passed5.269s/1.694s/2.239s in
`/tmp/zasp-precision-repository-full.log`; UI build exited0 in
`/tmp/zasp-precision-repository-ui.log`. Independent Superpowers review approved
the repository and closed nullable-sandbox/provider-error test recommendations.
SQL argument binding, copied state, exact window, wrong versions and delayed
responses are covered. No migration readiness, execution grant, V4 claiming or
V4 correlation algorithm is activated by this method.
