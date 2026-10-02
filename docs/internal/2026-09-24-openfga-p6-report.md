# P6 permission synchronization and revocation fence

Status: implementation candidate for the single independent review. P5 was
accepted separately and its13 source files plus report remain unchanged. This is
local application evidence, not production enforcement or release approval.

## Implemented contract

SQL79 is an additive extension with its own registration and drift fingerprint.
It requires registered canonical migrations19 and25 and a canonical version in
25..61. It neither consumes nor depends on the private Temporal78 schema. The
installation is transactional and replay verifies the existing registration;
there is no destructive downgrade or automatic model publication.

Each organization has durable desired/applied revisions, pinned store/model,
generation, pending age, last attempt and a bounded blocked-reason vocabulary.
Every permission-affecting source write atomically advances desired and inserts
an outbox record. BEFORE-row triggers cover direct scoped grants, membership
roles/activation, verified member-group claims, group mappings, organization/
workspace/environment identity, resource ancestry and machine activation/task
sources. Triggers cover existing repository DML and raw SQL callers, including
SQL0019 login group replacement and webhook deprovision. Existing identity
repository/handler files required no changes.

Projection reads current SQL facts, not historical event payloads. Scoped roles
remain exact environment grants. Both SQL and Go reject multiple parents and
unresolved ancestry; projection does not manufacture a parent from request data.
Active humans are product principals. Agent membership comes from a supervised
or autonomous, undeleted product definition. Service membership comes from an
enabled discovery schedule, active integration and current verified connection.
Neither machine source creates a Stytch membership.

The resource catalog covers findings, attack paths, retained generic workflow
records, integrations, security-agent definitions/runs, discovery schedules/
syncs and active inventory entities. Duplicate source rows with identical facts
are deduplicated; conflicting parents fail closed. Future P7 resource types must
be mapped to authoritative sources before using resource-level checks.

Explicit resource/task grants live in the authority-owned SQL79 `grants` table.
No API write privilege or implicit creator grant is introduced. Current-state
joins exclude inactive principals, missing targets and inactive/unrelated tasks.
Agent tasks must match the exact run/definition/scope; service tasks must match
the exact schedule principal, integration, scope and scheduled/retry sync.
Concurrent tasks project distinct P5 delegation objects and revoke independently.
Future grant admission still needs P7 grantor, policy, approval and budget checks.

## Delivery and fence

One dedicated PostgreSQL session holds the organization advisory lock while the
reconciler runs. External OpenFGA calls never occur inside a SQL transaction.
Permission writes remain available during delivery and invalidate its final CAS.
Configuration changes acquire the same advisory lock before changing generation.

Before any SDK call, Stage durably unions all candidate tuple keys into the
per-store inventory. The official SDK deletes known keys then writes the current
desired set in batches of at most100, always with explicit store/model IDs and
bounded deadlines. Conditions do not make duplicate delete keys. A crash after
any successful batch leaves enough inventory to remove intermediate tuples on
replay. Failed/incomplete writes never advance applied. Ack compares desired
revision, generation, store, model and the exact staged tuple set, then records a
durable receipt and acknowledges the superseded outbox prefix atomically.

`CheckRevision` checks current readiness and revision before and after the FGA
Check. Pending, wrong-model and changed decisions fail closed. The returned
proof binds the exact request. `RevalidateDecision` locks the organization row in
the caller's existing SQL transaction and checks applied/desired/generation/pins
before its protected action. The lock must survive through commit.

P7 MUST additionally revalidate current identity/session/PAT, SQL tenant and
resource ownership, and product policy/approval/budget/state. The revision proof
does not replace those checks. No current API, worker, list, search, export or
capability path is switched to FGA by this batch.

## Lock inversion and retry contract

BEFORE-row triggers do not precede PostgreSQL tuple locks or historical explicit
membership locks. An existing membership-first grant write can conflict with an
organization-first fenced product transaction. This is intentionally fail-closed,
not described as globally inversion-free ordering.

The live test held the organization fence and staged a product-effect fixture,
then ran registered SQL0019 group resolution on another connection, holding the
membership row while waiting for the organization. A conflicting registered call
in the fenced transaction produced a real PostgreSQL deadlock. Both attempts
were rolled back, no effect survived, and a new Check plus transaction committed
exactly once using the same effect ID. `RetryableConflict` recognizes SQLSTATE
40001,40P01,55P03 and the normalized ErrConflict. Callers must roll back and retry
the entire authorization attempt, retaining effect/idempotency IDs. There is no
hidden retry within the transaction, stale-decision reuse or allow fallback.

Tradeoffs: organization writes serialize on one revision row; verified group
replacement can generate several revision records. Delivery uses full current
organization snapshots and delete/rewrite, so pending organizations are denied
during repair. Readiness fingerprint queries add catalog work. Production-scale
latency/lock-contention evidence and deployment sizing remain release gates.

## Operator interface

`agentsec-migrate up-authorization-projection` installs/verifies SQL79 through the
registered migration authority. It verifies the configured migration and outbox
principal bindings and does not register a new broad runtime role.

`go run ./cmd/zasp-authorization-reconcile -mode configure -organization PID`
uses the existing runtime-service configuration and registered migration DSN to
pin the configured store/model for one existing organization. An unchanged pin
is a no-op; `-repair` starts a fresh generation and full replay. It neither creates
an organization nor publishes a model nor edits active configuration files.

Run `-mode reconcile` with the registered outbox-worker DSN for one bounded queue
pass, default20 and maximum100 organizations. `-organization PID` selects one
organization. Total deadline defaults to2minutes, capped at10minutes. Repeat a
failed pass to read current state and repair; there is no second scheduler or
unbounded internal retry. Output includes organization/status, receipt and
pending age; SQL retains blocked reason and last attempt. The command reuses the
existing client connector, including its current Temporal readiness dependency.
No deployment configuration or service was changed.

## Verification and evidence

The grouped application TDD failures and final terminal evidence are in the P6
packet. Initial projection/revision/reconcile stubs failed the expected examples.
The SQL installation stub failed the permission-write test. A separate race
example failed when a revision changed during Check, then passed after the
post-Check comparison. The first live fixture used invalid provider references;
its exact SQL22023 failure is retained and was corrected to the existing contract.

The final private-PostgreSQL/local-OpenFGA test passed in3.78s (package4.759s),
producing11 durable receipts and checking:

- grant pending until application, registered verified-group replacement;
- stale revision/generation, including identical revision with only stale generation;
- crash after tuple write before Ack, current-state replay and stale Stage rejection;
- registered deprovision replay and immediate membership/session/PAT revocation;
- independent simultaneous agent tasks, per-task and activation revocation;
- service verified-connection revocation and cross-tenant machine denial;
- SQL duplicate ancestry rejection, non-destructive installation replay;
- real lock inversion, rollback and fresh-Check retry with stable effect identity.

Final owned store `01M3AAGG5XCME5PZYXN9GJYD7J`, model
`01M3AAGG6AFJ1YQ80CVWVQV3GE`. The SQL79 drift fingerprint was
`4bfdaa7caf34ecc2f04b130ab177adc6b5fde3e90204d39edcc636b8a7180356`.
This store/model is isolated from active product configuration. Test PostgreSQL
was stopped and joined by its owned fixture. Scratch development FGA stores were
retained; no shared service restart/reset or direct FGA database write occurred.

The grouped Go application tests and migration command tests pass. A separate
HTTP-edge test fails a later actual SDK batch, proves no acknowledgement, then
repairs the staged inventory with bounded calls. Scoped vet for authorization,
migrations, agentsec-migrate and the reconciliation command passes.

CLI evidence is dispatch/registration unit coverage and compilation/vet, not an
end-to-end shell invocation with deployed environment variables. The connected
test invokes the actual Runner, SQL functions, repository and SDK directly.

Full affected-package vet is blocked by an unrelated existing test:
`apiserver/security_agent_attack_lab_settlement_postgres_test.go:330:9:
append with no values`. That file was not changed. This remains a release
verification gate; the passing scoped tests are not a claim of broad-suite green.

## Remaining gates

P7 production composition and all authorization/identity commit-boundary consumers
are pending. Explicit grant creation is authority-only until P7 admission is
implemented. Live Stytch support/evidence is unchanged: this batch uses the
existing supported local deprovision and verified-login contracts, not a new
provider-event claim. Production credentials, migration publication, model
promotion, deployment, performance evidence and rollout approval are out of scope.

Superpowers grouped application TDD and verification-before-completion drove
the retained RED/verification evidence. The parent dispatches the single
independent review from the frozen packet; no duplicate review was spawned.
