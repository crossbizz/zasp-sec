# Registered stopped-work settlement evidence

Owned grouped session80184 exited0 (680f14; case output ecc245,
86ff9a and d018ae). ComposedStopped passed32.05s, ReconcileLease22.84s,
and StoppedQueued24.91s, four execution modes each. All twelve registered
worker child checks passed; all three owned PostgreSQL processes joined.
The database ran offline in a read-only Docker container with temporary data.

The composed test uses actual ReconcileOne twice per scope. It covers stopped
leased work with started/completed journals and journal-free retryable work.
Owner assertions require settled ownership, matching proof/effect digest,
preserved stopped parent, correct step/effect classification and exactly one
settlement audit. Both worker polls require zero artifact reads. A late adapter
callback must preserve the entire saved settlement, not only its outcome.
Existing common assertions retain journal history and refuse new invocation.

Independent source review found no actionable findings. The production SQL
and worker algorithm were unchanged in this acceptance extension. Current
compiled migration fingerprint is
`d64a65660783c429fb046bb7efb913127948492405fdd74216f943c10a6cdf11`.

This is registered-client/database component evidence, not deployed-worker,
live provider, production scheduling, restart recovery or user-flow proof.
M7A-21 remains component-only/disabled and unshipped. No status promotion,
commit or push. Production scheduling/runtime composition is the next gap:
production_runtime.go does not mount existingTestClient/ReconcileOne, and
the current client requires an explicit tenant scope from its caller.

Verification policy: group expensive integration suites and independent
review by connected feature; retain focused TDD checks and per-task evidence.
Tenant boundaries, authorization, migration rollback and recovery remain
explicit acceptance requirements. UI and release checks precede every push.
