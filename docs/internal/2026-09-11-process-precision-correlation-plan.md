# Precise frozen correlation

Use Superpowers TDD and independent review. Add `CorrelatePreciseFrozen(Batch,
runtimeevent.PreciseFrozenCandidateSnapshot)` in `runtimecorrelation/precise_correlator.go`.
This separate V4 algorithm consumes only V2 Tetragon archives and sealed
snapshot-v3. Match V2 runtime identity to admitted V1 semantic observations by
host/container scope, exact source-time window and nonconflicting optional
PID/start/cgroup. A matching single complete source/sandbox/agent/session binding
is Strong; competing bindings are Probable with no assigned identity. Preserve
historical unknown sandbox values. Kernel observations never become Exact.

Bind results to a new `zasp.runtime-correlation.batch.v4` digest domain and the
archive/snapshot digests. Leave historical algorithms and receipt codecs
unchanged. Receipt-v4, worker dispatch and migration activation remain next.

- [x] Write rejecting-stub tests for same-ms process identity, ambiguity,
  unknown sandbox, conflicting PID/start/cgroup, exact time boundaries and
  input/snapshot binding. Observe RED before implementation.
- [x] Implement V4 matching and deterministic sorted, version-bound results.
- [x] Extend real Go/PostgreSQL freeze integration through V4 correlation,
  proving immutable replay and new ambiguity after late admission.
- [x] Run related race tests, historical vectors, UI and independent review.
- [x] Record evidence and open activation work without original task credit.

Evidence: expected stub failures in `/tmp/zasp-precision-correlation-red.log`;
focused GREEN in `/tmp/zasp-precision-correlation-green.log`; actual PostgreSQL
and legacy integration in `/tmp/zasp-precision-correlation-postgres.log`;
four package races in `/tmp/zasp-precision-correlation-full.log`; UI build in
`/tmp/zasp-precision-correlation-ui.log`. Independent Superpowers review closed
with no findings. This is a local algorithm checkpoint, not deployed acceptance.
