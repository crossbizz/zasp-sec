# Existing-test action execution design

Status: selected design for M7A-21, not implemented acceptance. The original
728-task scope and availability ledger remain authoritative. User authorization
allows autonomous design decisions and feature-batched verification.

## Contract

Implement both `run_test` and `rerun_test` against a persisted, enabled,
exact-version TestDefinition. Neither action accepts prompt, URL, target,
credential, category, scope or safety overrides. One selected test is configured
on a single-action definition as `existing_test: {definition_id,
definition_version}`. Absence stays valid for all old non-test definitions.
Require `verification_kind=test_run`; reject a test reference on any other
action and reject a test action without a reference. Version bounds are
1..1000000 and IDs are canonical Product IDs.

The public production capability remains off until the complete path below has
verification evidence. Completing the private parser/resolver is not sufficient.
The component action registry is not a production execution backend.

## Architecture and alternatives

Use a new release55 with a private shared Red Team enqueue core and a separate
lease-bound Security Agent wrapper. Keep the registered API principal check on
the existing human/API wrapper. Reuse the existing Red Team outbox, runner,
artifact storage and completion authority. No worker gains API-role membership
or direct EXECUTE on the enqueue core.

Rejected alternatives: calling the public API from the worker would require
browser/API identity it does not have; copying enqueue logic creates two safety
and replay implementations. A core shared by two separately authorized callers
preserves one transactional run/outbox/receipt implementation.

The private resolver in54 is an input to55. Do not retrofit the full execution
change into the run-context release or alter published predecessor files.
Release55 saves every replaced definition/ACL, extends compatibility through a
new compiled pin and restores54 on rollback. Old binaries must refuse55.
Rollback is permitted only before any test link or new-format invocation/history
row exists, including terminal rows. Once used,55 requires a forward repair;
down-migration refuses atomically without deleting or exposing retained history.
Restoring legacy retry/claim functions over retained uncertain work is forbidden.

Intermediate dispatch functions remain private with no application EXECUTE
grant. The SQL readiness/admission guard refuses linked execution until the
invocation protocol covers claim, retry and actual invocation. Catalog/UI
disablement alone is not a rollout gate. Release55 is published only as the
complete A-D batch, never with Batch B dispatch reachable before C safeguards.

## Definition, planner and admission

1. Extend strict Go/API/OpenAPI/web definition contracts together. Use the
   existing duplicate-aware reference decoder; store only canonical ID/version.
   The UI selects from scoped real TestDefinitions and displays their version.
   No free-form prompt or destination field is introduced.
2. Creation/update/activation re-resolve current scope, version, enabled state,
   non-production environment, target freshness and active credential safety.
   Capture the persisted definition version, not just a mutable body field.
   Simulation resolves the same intent but never enqueues a test.
3. Planner context contains a single allowed target: the configured test
   definition ID. Keep the existing candidate schema (action/index/target_id).
   The model cannot select a version or test parameters. Context digest includes
   exact reference/version and trigger evidence. Acceptance recomputes it.
4. Preparation binds the selected reference/target snapshot into the durable
   plan/step and enforces the existing approval and execution-control contract.
   `run_test` and `rerun_test` remain low-risk with approval floor none, as in
   their original metadata; supervised/autonomous execution still obeys tenant
   controls, credential policy and budget admission. No bypass of the planner
   or organization data-egress policy is introduced.
   In particular, supervised agents require a pending approval bound to the
   exact plan hash even when the action's approval floor is none. Autonomous
   preparation creates an authorized step and queues the run without approval.
   Both paths clear the planner lease only after all preparation writes and
   final authority checks. Preserve authorization in the hashed step; the
   private dispatch candidate must consume this contract before it is exposed.
5. Dispatch takes organization admission before run/step locks, then definition,
   test, environment, target and credential locks in a fixed order. Call the
   current lease/budget guards again after all blocking prerequisite locks and
   immediately before reserving the step and writing the enqueue transaction.
   Use wall-clock expiry, not transaction-start time, after waits.

## Durable association and replay

Create `zasp_security_agent_test_links` with full organization/workspace/
environment keys and a unique agent run/step/action association. Store selected
test ID/version, target ID/kind, exact linked Red Team run ID, the original
trigger identity/version, selected baseline run/attempt if present, input and
result digests, outcome/evidence references, state/version and timestamps.
Foreign keys include the complete scope and point to the existing step and
Red Team run. Public/application direct table access is revoked.

Derive the linked run ID with the existing canonical-ID helper using full scope
and agent run/step/action. Both actions create one fresh test run per distinct
agent step; retrying the same step returns the same durable link. `rerun_test`
does not mutate or replay an old test run as new work.

Reserve the step, insert the effect/link and create the Red Team run/outbox/
audit/receipt in one transaction. A conflict must compare the complete stored
intent. Never reinterpret a duplicate ID as successful admission. A lost reply
after commit is recovered from the link; a crash before commit creates no work.
Durable agent links survive expiration of the public API idempotency receipt.

Use actor_id on the exact persisted agent definition-version row as the recorded
requesting principal, validating its canonical Product ID and retaining the
agent/run/step provenance in the link and audit. There is no created_by column
on the current definition table. That
principal field is provenance only: worker lease and policy checks authorize
execution, not impersonation of a browser user.

## Completion is separate from enqueue

Dispatch returns `running/pending`, using the existing worker pending-effect
contract. A scoped reconciler reads the exact linked Red Team run and final
attempt through database authority. It performs no arbitrary network requests
and cannot change a different step. Queued, leased and retryable test states
remain pending; bounded run expiry and cancellation still stop new work.

Check the exact definition version, input digest, attempt, terminal verdict,
evidence reference, storage object version, checksum and size against the
persisted completion record before accepting verification. An artifact reference
or HTTP200 alone is insufficient. Red Team's existing runner defines `pass` as
all curated security checks protected; `fail` means unsafe behavior observed.
Engine/transport failure is never a protected result.

The PRD11.9 requires a re-test to show a change from vulnerable to protected.
At dispatch snapshot the latest complete, evidence-backed failed attempt for
the same scoped test/version/target, if present; only runs completed before the
new enqueue qualify. Retain its exact run/attempt/digest.

Comparability is an immutable tuple, recorded at actual adapter invocation and
bound to both versioned input artifacts: scope, test ID/version, target ID/kind,
endpoint identity digest, effective target-configuration digest, safety policy
digest, credential binding ID/version (never secret bytes), engine/version,
runner image digest, curated-pack version and ordered category/check IDs with
prompt and assertion digests. Exclude per-run IDs/timestamps from the tuple;
their exact association is checked separately. Any unequal/missing tuple member
means baseline unavailable. Older artifacts without this tuple remain readable
but cannot establish remediation. Endpoint/config identity must come from the
adapter's pinned target resolution, not a caller-supplied artifact field.

Expected reason is a versioned deterministic criterion: every check in the
selected baseline's failed-category set changes from unsafe-marker-observed to
the same curated assertion passing, all other selected checks pass, and both
evaluations have complete successful adapter HTTP responses. Record per-check
IDs, before/after pass flags, response status and assertion/prompt digests in
the validated evidence bundle. Transport denial, engine failure, missing checks
or changed assertions are not improvement. Current bundles redact raw response
and reason text; the new proof remains structured and must not expose secrets.
This proves the selected bounded security condition changed, not what external
actor caused the change or that a finding is universally fixed.

At settlement:

| Linked result | Agent outcome |
| --- | --- |
| Complete/pass with valid comparable failed baseline and both artifacts | Verified step; Remediated with linked before/after test evidence |
| Complete/pass without comparable baseline | Test step succeeded; Needs human, reason `test_baseline_unavailable`; no remediation claim |
| Complete/fail with valid evidence | Needs human, reason `test_condition_persists` |
| Engine error, missing/mismatched evidence or uncertain external outcome | Inconclusive |
| Definitive pre-execution rejection | Failed with bounded safe error code |
| Cancelled test and confirmed cancellation | Cancelled, retaining attempt/evidence history |

Do not add a new success state to hide missing before/after proof. Do not mark a
risk finding resolved merely because a configured test passed. The UI must
distinguish action completion from verification and the agent's final outcome.

## Cancellation and safety after dispatch

Cancel through a private scoped cancellation core shared with the existing
Red Team cancel wrapper. The API role checks remain on that wrapper. Stop
creating new work immediately. Do not report the linked test cancelled until
the invocation ledger proves it never started or its external completion is
known; retain `outcome_unknown` when an in-flight request may have executed.
Local process termination is not external cancellation proof.

The existing worker automatically retries outcome_unknown and records local
cancellation. Release55 must change this for linked agent test runs. Before
each adapter request, reserve a unique scoped run/attempt/category invocation
record, commit `started` before network I/O, and persist its terminal response
digest separately. A crash or cancellation after started without a terminal
receipt is uncertain even if no bytes were actually sent. Fail closed: no
automatic retry of that invocation or linked run; preserve the receipt and
settle the Security Agent Inconclusive. Enforce this in DB retry/claim/invocation
authority as well as worker code, so a restarted or older worker cannot bypass
it. Successful per-category receipts replay without another network request.

For an entirely unstarted run, cancellation is confirmed without external I/O.
For a partially executed run with known receipts and no uncertain requests,
cancel remaining categories and label it `cancelled_after_partial_execution` in
the link audit/UI. Do not claim the earlier work was undone. Unknown external
execution takes precedence over the legacy Red Team cancelled status in the
agent projection. Completion races are settled by locked invocation/link state,
not whichever worker reports last. Existing worker credential/safety rechecks
still apply at actual invocation. Never fabricate cleanup evidence.

## Verification and release

Focused red/green tests cover each changed contract. One feature batch covers
definition/API/client, registered worker planner/admission, crash/replay,
expiry-during-wait, tenant isolation, completion and cancellation. Database-owning
fixtures run serially. Independent Superpowers review precedes acceptance.

Browser acceptance uses the real mounted API and worker with an owned controlled
target: create/select existing test, configure and activate responder, trigger,
observe pending test, finish real execution, inspect exact linked before/after
evidence and history, reload and confirm tenant-scoped IDs. A foreign principal
must not read/control those links. Include a no-baseline pass and engine failure.
This is local composed acceptance, not live production/provider proof.

Publication still requires the full release gate, runnable UI and fresh approved
dependency-advisory evidence. Deployed queue/storage/credentials, actual provider
canary and production load remain separately recorded external evidence. Promote
M7A-21 only when the ledger's production criterion has been met, not on parser,
SQL or controlled-fixture success alone.
