# Precise session search worker

The explicit precise constructor requires an ApplyPrecise index capability.
On the V2 search target it verifies V3 receipts within4MiB, reads the bound V2
archive, rebuilds precise documents and calls the precise driver. Historical
receipts retain their1MiB artifact gate and legacy reader/driver selection.
Document IDs and provider result bindings are checked before checkpoint handoff.

Superpowers evidence:

- The initial new tests failed with the rejecting constructor before implementation.
- Actual local correlation-V4/project-V3 fixtures cover strong sandbox identity
  and a valid1000-item receipt larger than1MiB. Tests reject old worker/target,
  missing capability, wrong document IDs, cancellation and provider result drift.
- Review found stale original-deadline checks despite successful heartbeats.
  An expired-original/future-confirmed-renewal test reproduced the failure.
  The processor now owns synchronized renewal state and updates it only after
  a successful live heartbeat. Worker/archive/write checks use that deadline.
- Processor publication, historical drain, renewed execution and lost-renewal
  controls pass. Independent re-review closed the finding with no new issues.
- Final worker/search/driver race suites exited0:19.540s/1.585s/1.436s.
  The UI build also exited0. Diff checks passed.

The index provider in these worker tests is declared. Production startup at that
checkpoint selected the old constructor; explicit migration-gated startup and
precise queue/finalization now exist. Current provider review and remaining
release gaps are in `2026-09-11-process-precision-finalization-plan.md`.
No live deployment or original task credit follows from these worker tests.
