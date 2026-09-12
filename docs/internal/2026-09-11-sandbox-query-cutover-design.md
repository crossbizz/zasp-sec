# One serialized sandbox query cutover

Status: proposed implementation boundary. This document does not authorize a
deployment, establish live evidence, or close the original M3 acceptance work.

The operation is fixed: schema50/backfill with API target v1 to schema50/query
with API target v2. Keep both session workers running. Do not run migrations,
initializers, Helm upgrades, producer activation or queue repair inside it.

This supplements `2026-09-11-sandbox-rollout-design.md`. That design's receipt
cutoff, 30-second observation limit, retained v1 worker and forward-recovery
requirements still apply. Schema51 activation is outside this operation.

## What the operation owns

Implement `ExecuteSandboxQueryCutover` in a new Go package,
`services/platform/internal/sandboxcutover`. One process owns its PostgreSQL
connection, provider reads, Kubernetes dispatch and cleanup. An eventual command
can call the package, but the first slice must not expose a live deployment CLI.

The executor loads one approved release reference. It obtains all observations
itself. It does not accept a previous observation, readiness Boolean, arbitrary
patch, receipt subset, caller-selected target or reusable authorization token.

The result has two separate states:

| Dispatch outcome | Meaning |
| --- | --- |
| `refused` | Nothing was dispatched, or Kubernetes definitively rejected the sole conditional mutation. |
| `applied` | The response and/or readback establishes the exact intended Deployment UID, target template and transition annotation. |
| `indeterminate` | Dispatch started, but its persistence cannot be established or excluded. |

Rollout is separately `not_started`, `pending`, `complete` or `failed`. An applied
patch with a failed rollout stays applied/failed. Never relabel it refused.

Audit output records transition ID, reviewed release digest, database/provider
identities, receipt-set digest/count, authorization time, API UID, source/result
resourceVersion and target-template digest. It contains no credentials. Nothing
in the package accepts that output as authority for another mutation.

## Approval and connection identity

Production execution requires a trusted release verifier. It must authenticate
the reviewed artifact against the deployment system's configured trust root,
then bind its exact source/rendered digest, approved images, schema50 phases,
cluster server/CA, namespace UID, database identity and provider identity. It
must also bind the admitted templates, including defaults and admission changes,
to that release. A manifest digest supplied alongside arbitrary bytes is not
provenance. Neither is copying the current cluster template into `expected`.

There is no such production provenance adapter in the inspected repository.
The first slice uses a clearly labelled fixture verifier with a test-owned
approved artifact. There is no permissive production fallback. Defining and
wiring the production verifier is a separate prerequisite, not a solved gate.

Construct immutable clients from the verified binding. For Kubernetes, pin the
HTTPS server, decoded CA digest, context and namespace UID; reject TLS bypass,
unexpected proxies, redirects and unapproved credential execution. Resolve
kubeconfig once so a path replacement cannot retarget later operations. Pass the
same pinned configuration to observation and mutation. Check namespace UID again
before dispatch. Pin database endpoint/database and provider endpoint/account/
region through the deployment identity; a database name alone is insufficient.

`deploy/production/release-contract.mjs` already renders and validates both50
phases. Require that the approved backfill/query render differs functionally
only in the API session-index selection. The final mutation contains only that
reviewed API template and executor audit annotations.

## Capture every canonical receipt

Read `zasp_runtime_session_projection_receipts` across the whole database, ordered
by organization, workspace, environment, batch and generation. The query cannot
start from the target queue, because that would hide a missing queue row.

For every receipt, join `zasp_runtime_stage_work` twice for project/complete and
require both succeeded, project result digest equal to receipt digest, and exact
project result reference/version. Require exactly one matching
`zasp_runtime_sandbox_search_outbox` row, state indexed, matching receipt
digest/reference/version and exact ordered document IDs derived from canonical
event IDs. Reject pending, leased, quarantined, missing or mismatched work.

Hash a length-delimited canonical encoding of the complete tuple, receipt digest,
ordered event IDs, project reference/version/digest, stage implementation
versions and ordered document IDs. Do not hash ambiguous delimiter-joined text.
Compare counts as well as digests. Preserve array order. Bound total rows, bytes
and elapsed time; a bound breach refuses the operation and never samples rows.

Canonical receipts and the v2 queue have forced RLS and belong to
`zasp_discovery_authority`. Registered API/index roles have function execution,
not global table or locking access. The real fence adapter requires the existing
explicit migration-owner connection and validates that expected identity. It
does not grant privileges, register principals or change RLS. A least-privilege
deployment authority would require separately reviewed database work.

## Search visibility is a read

Use immutable receipt/archive references and versions, validate their digests,
then reuse `sessionsearch.BuildDocuments`. Do not construct expected documents
from provider responses or trust queue state as provider evidence.

`opensearchdriver.SessionIndex.Ready` already checks exact mapping and marker.
Its `Search` method returns aggregated investigation IDs, so it cannot prove all
occurrences. Its private writeside `exactDocuments` uses `_mget`, which also
doesn't prove search visibility. Add a bounded read-only exact-document `_search`
method: tenant-scoped IDs query, complete shards, no timeout/partial result,
exact hit count/IDs and exact document contents. Compare in canonical ID order;
provider hit ordering is not authority. This uses existing API `_search` IAM.
It must not bulk-write, initialize, refresh or widen permissions.

All receipt documents must be observed within the evidence window. Refuse a set
too large to verify within the bound. Provider writes by independent privileged
actors are not fenced by PostgreSQL; fixed-index mutation restrictions remain a
deployment prerequisite.

## The short fence

First observe the backfill consumers, capture receipts and verify provider
visibility without blocking writers. Then open a dedicated READ COMMITTED
transaction with a proposed 15-second server-side transaction limit, a shorter
statement limit, and a client deadline. Never use a prepared transaction.

Acquire these locks in order, all NOWAIT:

1. SHARE on `zasp_schema_versions` and `zasp_schema_metadata`.
2. SHARE ROW EXCLUSIVE on `zasp_runtime_session_projection_receipts` and
   `zasp_runtime_sandbox_search_outbox`.

These modes allow ordinary SELECTs, conflict with receipt/queue writes and are
self-conflicting for cutover callers. Existing guarded50/51 migration runners
also conflict with the fence. On NOWAIT contention, the executor rolls back to
release the partial lock set; there is no wait/retry loop while holding some
locks. PostgreSQL describes these
conflicts and transaction-end release in its [locking documentation](https://www.postgresql.org/docs/18/explicit-locking.html).

Inside the fence, recheck exact50 registry and compiled50 readiness. Recapture
the complete canonical set after acquiring locks and require its digest/count
to match the provider-verified set. A receipt arriving before the fence changes
the set and causes refusal. Inserts after the fence wait until release, then
use normal catching-up semantics. Do not wait for workers to drain while fenced.

Revalidate the same backfill consumer identities immediately before dispatch,
using `observeSandboxBackfill` / `revalidateSandboxBackfill`. All11 deployments
must retain their admitted templates, resolved images, UID/generation/controller
chains and complete ready replicas, with no old pods. A short-lived read-only
Node adapter can reuse this implementation; it receives the pinned kubeconfig
and approved expected templates, never an arbitrary shell command.

Recheck mapping/marker and evidence age. Require a live transaction query and
database time immediately before dispatch. Evidence must be younger than30
seconds; reserve enough of the 15-second fence for the bounded API request.
Limits are fixed configuration of the executor, not request overrides.

## One Kubernetes compare-and-swap

Read the API Deployment's opaque resourceVersion; never parse it as a number.
Send one JSON Patch that tests UID, resourceVersion and the exact old template,
replaces the template with the approved query template, and records the transition
ID, release digest, receipt-set digest/count and cutoff in metadata annotations.
Use JSON Pointer escaping and preserve unrelated annotations.

Kubernetes supports conditional JSON Patch and resourceVersion-based lost-update
detection. A failed test is terminal for this invocation, not permission to read
a new version and retry. See [Kubernetes update mechanisms](https://kubernetes.io/docs/reference/using-api/api-concepts/#choosing-an-update-mechanism).

There is at most one dispatch per invocation, not globally across invocations.
While one invocation holds the database fence, a contender refuses lock
contention. After an indeterminate invocation releases its fence, a new invocation
can collect fresh evidence and dispatch against a still-old Deployment before
the first delayed request persists. Both requests can reach Kubernetes. Against
the same old UID/resourceVersion/template, at most one conditional mutation can
apply; its accepted update invalidates the other's resourceVersion test. Each
invocation has its own transition ID, evidence and outcome. Reconciliation must
not credit one invocation with another's transition annotation, even when their
target templates match. The executor has no durable cross-invocation intent or
server admission fence and does not claim globally one dispatch.

The cutoff is authorization at dispatch while the database fence is held. It is
not Kubernetes persistence time or the completion of the rolling update. A
network timeout can leave a request that persists after local cancellation and
fence cleanup. Report indeterminate and reconcile exact UID/template/transition
annotation. Do not claim atomic DB/Kubernetes commit or server-enforced30-second
expiry. Strict server expiry requires a trusted admission/write boundary, which
is not implemented by this slice.

Release the fence after the bounded dispatch/readback attempt, even if its
outcome is indeterminate. Deferred rollback uses a separate bounded cleanup
context and then closes the dedicated connection. PostgreSQL18
[`transaction_timeout`](https://www.postgresql.org/docs/18/runtime-config-client.html)
limits a disconnected executor's transaction lifetime. Lost cleanup confirmation
is recorded; it is not proof that the fence remains held or that HTTP was canceled.

## Observe recovery, don't improvise it

After release, observe the exact new API generation, template and images through
its ReplicaSet/pod chain. Complete means all requested replicas updated and
available, with no old replicas. `Progressing=True` alone is insufficient, as the
[Deployment documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#complete-deployment)
explains. Workers remain on their approved backfill selections.

No blind retry, automatic rollback, queue reset or checkpoint repair follows a
lost response or failed rollout. An indeterminate operation can be read back by
transition ID, but reconciliation is read-only and cannot dispatch. If the API
is already on query at a new invocation, refuse a new cutover and direct the
caller to reconciliation. A cooperative Kubernetes Lease would not fence other
Helm/admin writers; the proposed first slice does not add one.

## Acceptance boundary

The bounded first implementation proves the executor with real disposable
PostgreSQL, real HTTP/TLS transports and controlled provider/Kubernetes state.
Its fixture approval is labelled local. Production artifact verification, real
cluster admission/RBAC, managed-provider/IAM evidence, live rollout, schema51
activation and authenticated browser acceptance remain outside that proof.
