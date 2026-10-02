# Security Agent Attack Lab action design

Status: selected architectural design for original M7A-22. Implementation has
not started. Compliance56 deployment remains the active implementation batch.
The user authorizes autonomous routine design decisions and feature-batched
verification, with no reduction of the728-task scope.

## Product contract

Connect `start_attack_lab` to the existing Attack Lab admission, outbox,
controller, isolated execution, evidence and cleanup lifecycle. The action is
available only through current database-backed preflight and explicit operator
approval. Production environments and production-write credentials must fail
before any job/outbox/effect enqueue. Model-supplied `preflight=approved` or
`target_class=test` is never authority.

Reuse the existing exact-version test picker and `existing_test` reference
shape on single-action Security Agent definitions. Permit this reference for
`start_attack_lab` only with `verification_kind=attack_lab_run`; retain the
existing `test_run` contract for `run_test`/`rerun_test`. No arbitrary prompt,
URL, target, credential, safety, limit or source-run override is accepted.
The definition remains scoped to one existing TestDefinition ID/version.

Draft creation resolves that reference under current scope. Activation also
checks current enabled test, non-production environment, fresh target and
dedicated active credential binding. A failed source run is resolved when a
triggered agent run prepares this action; its absence produces a visible
preflight-unavailable outcome, never an empty success or a new test implicitly.

## Architecture and alternatives

Select a private shared admission core with separately authorized API and
lease-bound Security Agent entry points. Preserve the API wrapper's registered
principal guard. Reuse the existing Attack Lab controller and outbox; do not
create a second sandbox launcher or give an agent worker API-role membership.

Calling the public API from the worker would require authority impersonation.
Copying its admission/enqueue logic would create two safety implementations.
A shared private core keeps one transaction while each caller proves its own
authorization. No application principal gets direct EXECUTE on that core.

Use an additive release57 after the current56 integration. Preserve all
published/predecessor SQL, checksums and semantic pins. Save the exact replaced
function definitions and ACLs for controlled rollback; old binaries refuse57.
Rollback refuses once any new-format definition/history/plan/approval/link or
effect exists, including terminal records. Retained evidence is not deleted to
make rollback succeed. Deployment compatibility, CLI and read-only readiness
must be extended with the new release as part of the same feature batch.

## Selecting and freezing source authority

Resolve the latest eligible completed failed Red Team run for the configured
exact-version test in the same organization/workspace/environment. Order by
completion timestamp then canonical run ID, and require its terminal attempt
and exact evidence identity. There is no cross-scope or older-definition
fallback. Failure to find an eligible source returns preflight unavailable.

The alternative of permanently pinning a source run on the agent definition
would make the reusable action stale after subsequent tests. Selection at
planning retains reusable definitions, but the chosen run must then be frozen:

1. Resolve source, terminal attempt, target and credential safety in the trusted
   planner context. The model still selects only its configured action and
   target ID. It cannot select source IDs, attempts, preflight decisions or
   change safety fields.
2. Bind source run/attempt, selected definition version, target identity,
   evidence tuple, preflight digest and expiry to the planner request/context
   digest. Recompute before reservation and plan acceptance. A changed source
   or safety decision invalidates that proposal; do not reinterpret the reply.
3. Accepted plan/step stores the full private authority snapshot. After that
   point, validate the stored source directly. A newer failed run does not
   silently replace the approved one or invalidate it merely by existing.
4. Approval shows the exact source run/attempt, target, bounded side effects,
   execution limits and expiry through current tenant-authorized product reads.
   Bind approval to the exact plan hash and step. Private credential references
   and secrets are not exposed to the model or browser.

The existing source preflight uses transaction-start freshness predicates.
The new shared admission core must check wall-clock freshness after all blocking
prerequisite waits. Lock scope/definition, source run/attempt, environment,
target and credential rows in a documented consistent order under organization
admission and agent run/step locks. Recheck worker lease, budget, stop controls,
definition activation, current operator authority, approval, target freshness,
credential validity and decision expiry immediately before committing effects.
An expired or changed decision needs a new plan and approval, not a renewed
timestamp attached to the old approval.

## Approval is a product boundary

Keep risk moderate, approval floor operator and verification kind attack_lab_run.
Support supervised and autonomous definitions under their existing tenant controls,
but both must create a pending approval for this mandatory-floor action. This
matches `securityagent/planner.go` authorization: a non-none metadata floor
requires approval regardless of definition autonomy. Do not copy the existing
low-risk test path's autonomous no-approval branch. Requester and approver remain distinct,
current scoped permissions and fresh authentication are required, and approval
must not survive revocation or authority drift during a database wait.

The user's instruction that implementation should proceed autonomously concerns
development workflow. It does not approve future customer sandbox executions
or remove the product's approval requirement.

## Durable action link and replay

Create a private forced-RLS link keyed by full scope plus agent run/step. Store
the action/input/plan digests, source run/attempt and evidence tuple, exact test
version, target identity, safety snapshot/digest/expiry, linked Attack Lab run,
correlation/receipt identities and reconciliation/cancellation state. Use
scope-complete foreign keys; revoke direct application table access.

Derive one linked Attack Lab run ID from full scope, agent run, step and action.
Reserve the step/effect, insert the durable link, and create the Attack Lab
run/outbox/audit/receipt in one transaction. Every replay compares the complete
stored intent. Lost-response recovery reads the existing link and never starts
another run. Link retention outlives the public request receipt's replay window.

The persisted definition-version actor is provenance, not authorization to
impersonate that browser user. Worker lease, scoped policy and exact approval
authorize the operation. Preserve both agent and approving-principal provenance
in audit records without copying credentials.

## Execution, uncertainty and cleanup

Dispatch returns pending. The existing Attack Lab controller owns provision,
run, artifact publication and sandbox destruction. Validate its actual provider
reconciliation/retry behavior for linked runs: uncertain create/run outcomes
must resolve the same deterministic attempt or remain Inconclusive. They must
not launch a fresh externally side-effecting attempt simply because the agent
worker restarted. No controller permission is granted to the agent reconciler.

Source-audit constraint for the implementation plan: the current production
provider's `Reconcile` calls `Cluster.Create`, not the cluster's read-only
`Reconcile` method. An existing exact Job can be recovered through its conflict
path, but a disappeared Job can be created again. Job manifests currently set
`TTLSecondsAfterFinished=60`. A deterministic name alone does not prove that a
completed, deleted Job cannot execute again. However, current SQL authorizes
proxy egress only in durable `running` state, and recovery of that state takes
the observation path without Create/Reconcile. A lost create response while
the database remains `leased` is not evidence that external execution occurred.
The connected regression must test both sides of the durable running transition:
lost create reply while leased (zero authorized external requests), then lost
running-transition reply after commit (observe the same UID, no second POST or
external invocation). Include completed/deleted Jobs and expiry. Preserve an
unresolved identity and cleanup obligation when prior execution cannot be
excluded. Do not translate repeated GET404 alone into proof of no prior execution.
Do not prohibit a proven pre-execution recovery merely because its Kubernetes
operation is a POST; the safety assertion concerns authorized execution and
durable identity, not the method name in isolation.

The generic controller also sends provisioning-not-found to `RetryAttackLabRun`;
the current SQL clears provisioning intent and increments the attempt at the
next queued/retryable claim. Test this path through actual registered authority,
not only a recording fake. Any linked-run protocol change belongs in additive57
and must preserve existing API behavior or explicitly strengthen its safety with
regression evidence. The existing provider test explicitly expects Create during
expired provisioning recovery, while the proxy rejects expired capabilities.
Changing that expectation needs connected evidence, not only a recording fake
with a different desired call count. This source audit identifies a verification
gap; it is not a reproduced live duplicate-execution incident.

Stop/cancel prevents new dispatch immediately and requests cancellation through
a separately guarded shared cancellation core. A canceled parent cannot cause
cleanup tracking to disappear. Pending cleanup and uncertain external execution
remain visible after agent duration/budget expiry; cleanup reconciliation is
permitted to drain existing resources, never to start new execution.

A scoped polling reconciler consumes the linked run's exact terminal attempt,
durable cleanup checkpoint and immutable artifact identity. It validates stored
object version/checksum/size and decoded scope/source/attempt/input bindings.
Cleanup complete requires the controller's confirmed provider destruction path,
not process exit, queue acknowledgement or a pending checkpoint. Keep immutable
settlement receipts so a lost settlement reply can replay without rereading or
reexecuting mutable work. Conflicting receipts fail closed.

Deploy a dedicated `security-agent-attack-lab-reconciler` worker mode and service
account. Its separately registered database login receives only a new fixed
`zasp_security_agent_attack_lab_reconciler` capability through bounded registration.
That capability can claim/read/settle linked reconciliation work through guarded
functions, not execute actions or query arbitrary tables. Its cloud role has
only versioned Attack Lab artifact reads, matching KMS decrypt and its own DSN
secret read. No provider invocation, Kubernetes mutation, SQS publish, object
write/delete, unrelated artifact bucket or other worker DSN authority. Use the
existing process health, bounded lease, network and CSI conventions.

## Outcome semantics

Attack Lab `verified` means the unsafe criterion was observed and the isolated
canary was touched. It does not mean protected, contained or remediated.
`EvaluateRunOutcome` currently converts generic verified results into a response
goal outcome, so this action requires its explicit settlement path and must not
pass an Attack Lab verdict through that generic shortcut.

| Authoritative linked result | Agent presentation and outcome |
| --- | --- |
| Complete/verified, valid artifact, cleanup complete | Verification action completed; unsafe condition reproduced; Needs human |
| Complete/not_reproduced, valid artifact, cleanup complete | Verification action completed; not reproduced in this bounded run; Needs human, no remediation claim |
| Engine/provider failure, missing/mismatched artifact or uncertain execution | Inconclusive; cleanup state remains separately visible |
| Definitive pre-execution refusal with no external execution | Failed with bounded safe reason; zero new work |
| Confirmed cancellation and provider cleanup | Cancelled, retaining any partial execution/evidence |
| Queued/running/cleanup pending | Pending; no terminal verification or cleanup claim |

Never close a finding or mark it safe based on this action. Existing Attack Lab
evidence may update its established risk pathway, but the Security Agent step
does not invent a new remediation assertion. Render source-run, execution-run,
attempt/evidence and cleanup links through current tenant-scoped APIs.

## Connected verification and release boundary

Use focused RED/GREEN while coding and one connected batch for this feature.
Actual registered-role PostgreSQL and mounted API/worker tests must cover valid
preflight/operator approval, foreign scope, production target/credential,
forged labels, stale/version drift, revocation and expiry after observed locks,
zero enqueue on refusal, exact replay, lost reply/restart, stop/cancel races,
provider uncertainty, artifact mismatch and cleanup lag. Test both verdicts
above against the generic outcome shortcut; neither may become Remediated.

Browser acceptance uses a real mounted local API, agent worker/reconciler and
owned controlled provider: select the existing test, trigger, inspect exact
preflight and approval, execute, inspect source/result/cleanup, reload and try
foreign-scope access. Controlled provider evidence is labelled local, never a
live isolated Fargate or hostile-code proof. Full UI/types/lint/build and
independent feature review precede any verified push.

Do not publish the production action catalog until admission, lifecycle,
reconciliation, UI and deployment are connected. Do not accept an intermediate
SQL grant that an old worker can use before the required safety protocol exists.
Keep the original M7A-22 ledger row component-only until actual deployment,
approved provider scope/credentials, sandbox canary, exact-source CI/advisory
and production acceptance evidence satisfy its production criterion.

Ruling: select a current failed source during planning and freeze it before
approval, preserving reusable exact-version definitions. Cost if wrong: source
selection/UI rework, not silent execution against a different approved target.
Ruling: use a dedicated reconciliation capability and version-read cloud role,
keeping execution/cleanup authority with the existing controller. Cost if
wrong: extra deployment/registration work, without broadening worker authority.
Ruling: reproduced and not-reproduced results both require human interpretation;
neither asserts remediation. This preserves Attack Lab's existing verdict
semantics and the original requirement for evidence-backed response outcomes.
