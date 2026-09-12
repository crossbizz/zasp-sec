# Session search v2 cutover

This is an implementation dependency of the original M3 work, not a scope change.
The user authorized autonomous decisions and waived repeated approval pauses.

## Decision

Keep v1 checkpoints unchanged. Add `zasp_runtime_sandbox_search_outbox`, with
the same receipt-bound job identity and lease invariants as the existing outbox.
Its sole target is `zasp-runtime-sessions-v2`. An old worker cannot acknowledge
this queue. Resetting v1 rows destroys checkpoint history; adding an index column
to the old primary key changes contracts used by deployed binaries. Both were
rejected. A separate queue costs a second set of progress rows during migration.

## Database boundary

Migration50 is still unpublished. Extend it, never released42/43. Under the
runner's existing receipt/stage locks, backfill every canonical receipt into a
pending v2 row using the committed project's exact object reference, object
version, digest and ordered occurrence IDs. Reject installation if any receipt
lacks matching successful project/complete authority. Do not infer progress from
v1's state. Install an AFTER INSERT receipt trigger in the same transaction.
Duplicate completion must leave both queues unchanged.

Force RLS; only the discovery authority owns table access. No direct worker/API
table grants. Include table, constraints, columns, indexes, policy, trigger,
function definitions and ACLs in pinned50 readiness. Rollback locks the new queue
NOWAIT and refuses any row whose attempt is nonzero or state is not pending.
Unattempted derived backfill can be rebuilt from retained receipts after reinstall.
Existing sandbox evidence/version rollback guards remain in force.

## Worker and query boundary

New `zasp_runtime_sandbox_search_claim`, `_heartbeat`, `_finish` functions accept
the existing lease signatures. Each checks registered index authority and pinned
release50 before mutation, after blocking row locks and before returning.
Claim skips held recovery scopes and retains attempt exhaustion in quarantine.
No v1 fallback. Exact completion retry reconciles a lost acknowledgement only
for the same worker/token/attempt/digest/ordered IDs. Same lease text in the v1
queue conveys no authority in v2.

New `zasp_runtime_sandbox_query_status` and `_hydrate` preserve the external JSON
shape but derive freshness solely from the new queue, with current tenant and
principal authorization on both calls. Both check release50. The API constructor
and worker authority must use the same closed target selection as their driver.
Missing functions/readiness reject v2 operation, never query v1 progress.

## Cutover and old work

Install compatible binaries on49 with v1 configuration, then apply50. Initialize
v2 and run its worker to backfill historical v1 receipts while v1 API stays live.
Verify completed backfill and provider visibility before switching API to v2.
Only then enable correlation3/project2/complete2 producers. V1 enqueue/claim must
exclude new-schema receipts while preserving historical v1 rows, and old in-flight
workers cannot alter v2 progress. Document rollback as unavailable once new
version evidence or attempted v2 indexing exists; use forward recovery.

The compatibility install is an explicit CLI `up-to-50`; plain `up` remains49
for this phase, and the49 chart job is pinned to `up-to-49`. The matching
`down-to-49` invokes only the existing guarded50 rollback and stops at49.
It cannot remove earlier releases or bypass attempted-indexing/evidence guards.
Neither command changes new-batch producer routing. Deployment registration must
still sequence compatible49 binaries,50 install, parallel v2 indexing, verified
backfill, API switch and a separately gated forward producer activation.

## Acceptance

Use actual PostgreSQL for backfill, atomic enqueue, replay, ACL/RLS, claim
contention, expired leases, wrong target/token/receipt, lost ACK, recovery holds,
readiness drift across row waits, freshness and rollback/reinstall. Use actual
OpenSearch for v1-history plus v2 documents, immutable replay and visibility.
Compose API/worker/database/provider to prove empty v2 cannot claim v1 freshness.
Run UI/browser acceptance, full verification and independent Superpowers review
before publishing. No task credit from database-only tests.
