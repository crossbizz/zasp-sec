# Precise correlation worker checkpoint

The correlation executor now supports explicit V4 configuration with a separate
`FreezePreciseCandidates` authority. It requires both historical authority (for
draining existing jobs) and precise authority. V4 requires index V2, reads its
bound archive, freezes snapshot-v3 and calls the precise correlator/receipt
codec. V1/V2/V3 jobs retain their own algorithms and receipt bytes through the
existing immutable per-version configuration copy.

The shared execution path retains exact worker/token checks, receipt and archive
bindings, error classification, one replay under a confirmed newer lease window,
and cancellation/expiry checks around effects. V4 validates receipt serialization
before writing the graph. Receipt persistence follows successful graph application.

Superpowers TDD and review evidence:

- The new constructor/execution tests failed with `runtime unavailable` before
  V4 support was implemented.
- Review identified graph writes before deterministic receipt-size rejection.
  A1000-event fixture with one admitted semantic binding independently produced
  valid Strong correlations, then failed with graphcalls1/receiptcalls0. V4
  receipt preflight now rejects this case with zero writes.
- Worker tests cover unattributed and admitted Strong receipts, old-index and
  old-worker refusal, missing authority/credentials, provider failure classes,
  empty snapshots, cancellation at freeze/graph/receipt, confirmed-window replay
  and unchanged V1/V2/V3 receipt bytes. Independent review closed all findings.
- Related runtimecorrelation/runtimeevent/runtimeprojection/runtimelineage race
  suites exited0 in1.530s/5.325s/1.980s/1.487s. `npm run build` exited0 and produced
  the standalone UI.
- Final focused worker race command `go test -C services/platform -race -count=1
  ./agentsec-worker -run '^TestPreciseCorrelationExecutor|^TestFrozenCorrelation|^TestSandboxCorrelation|^TestRuntimeCorrelation'`
  exited0 in4.773s, including the admitted Strong receipt assertion.

These are local executor checks using declared database responses and graph/
artifact adapters. The repository, snapshot decoder, correlator and receipt
codec are real, but the checks do not prove live database/graph/storage writes.
Renewal tests supply a declared confirmed window; they do not prove a live SQL
heartbeat. Production config, database factory wiring, claim routing, migration
readiness, index/archive V2 workers and downstream V4 receipt consumption remain
open. No production activation, push or original microtask credit.

The database factory wiring is now implemented as a subsequent checkpoint.
It rejects injected historical/precise authorities, constructs a single
correlation-authorized PostgreSQL repository and binds both interfaces for V4.
The declared-response composition test proves the precise SQL route, capability
arguments and resulting Strong receipt through the actual executor/repository/
codec. Expected RED exposed missing V4 wiring and acceptance of extraneous
precise authority in old configurations. After the fix, focused V4 and historical
worker races exited0 in4.654s; UI build and diff checks passed. Independent
Superpowers review returned no findings. Production config, claim routing,
migration readiness and downstream consumers remain open. No live-provider
acceptance or original task credit is implied.
