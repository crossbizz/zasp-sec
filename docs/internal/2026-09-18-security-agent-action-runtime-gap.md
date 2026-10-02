# Security Agent action runtime gaps

September 18, 2026. Read-only source audit at shipping worktree HEAD
`8733b16f8d939d38a8157dd2519e57fc6f630542`, including its inherited uncommitted
implementation. These findings do not describe a live deployment or a new test
run. M7A-22, M7A-23 and M7A-24 remain component-only.

## Confirmed next product work

M7A-22 `start_attack_lab` is not mounted for production execution. The component
metadata in `services/platform/securityagent/builtin_actions.go` accepts
`test_definition_id`, `target_class` and `preflight` strings. Its validation
does not resolve persisted preflight authority. The mounted catalog test in
`services/platform/agentsec-api/existing_test_composition_test.go` explicitly
rejects publication of this action. `action_readiness.go` keeps it disabled.
Simply enabling that catalog entry would not implement the original task.

The existing service has a real admission boundary:
`services/platform/apiserver/attack_lab_repository.go` exposes
`PreflightAttackLabRun`, taking a scoped **source run ID**, not merely a test
definition ID. Migration26's preflight requires a completed failed Red Team
run and attempt, the exact enabled test definition/version, a matching
non-production environment, a fresh active target and active dedicated
credential binding. It hashes the resolved safety decision. Creation
re-resolves those rows and compares the decision digest before inserting the
run, outbox, audit and receipt. The public wrapper requires the registered API
principal. The Security Agent worker must not impersonate that API principal.

This means the integration needs a persisted, scoped source-run association and
an independently authorized worker admission path. Caller labels such as
`preflight=approved` are not authorization. The existing-test action design
provides a precedent for private shared admission with separately guarded API
and worker entry points, durable step links and restart-safe reconciliation.
It is a precedent, not evidence that Attack Lab is already connected.

M7A-23 `create_evidence_export` is also disabled. Its component prefix check
does not establish membership of actual evidence in the current tenant/run.
The current compliance export repository takes framework/control selection,
so pointing the action at it without an explicit run-evidence adapter would
change the requested contract. Required work includes exact run-evidence
resolution, durable export linkage and scoped receipt/download acceptance.

M7A-24 `send_response_webhook` remains a subsequent dependent action. Component
signing and an in-memory result cache do not prove configured-destination
authority, durable signed acknowledgement or restart-safe delivery.

## Connected acceptance, not microtask-wide suite repetition

Follow-up controller inspection found a required restart boundary for M7A-22.
`attack_lab_kubernetes_provider.go:115` implements provider `Reconcile` using
`Cluster.Create`; the separate cluster `Reconcile` at
`attack_lab_kubernetes_api.go:596` is GET-only. The same API validates a60-second
completed-Job TTL. Recovering an existing Job through a create conflict is not
proof against recreating a completed/deleted Job after a lost response.
`attack_lab_runtime.go` also sends provisioning-not-found to the retry function;
migration26 clears provisioning intent and permits a later attempt increment.
The next feature batch must cover disappearance after uncertain execution,
preserve unresolved cleanup, and assert no second external execution. This is
current-source risk evidence, not a reproduced live incident or a claim that
the connected action already exists.

Further tracing narrows that risk: migration26's egress resolver requires
durable `running` state; its running transition stores the sandbox UID and
cleanup checkpoint atomically. The controller's `running` recovery skips
Create/Reconcile and the production provider's Run only collects that UID.
`TestProductionAttackLabProviderEnsuresExpiredProvisioningIntentIdempotently`
already expects a provisioning Create, while capability expiry prevents expired
external requests. The next connected proof must distinguish lost create replies
while leased from lost running-transition replies after commit. A recording
test that simply prohibits every recovery POST would discard this existing
authorization boundary without establishing a product defect. No such code
change is selected from source inspection alone.

For M7A-22, retain quick RED/GREEN checks during implementation, then run one
connected batch across actual mounted API, registered worker and owned isolated
database. Include an authorized preflight control; production-write target and
credential rejection despite forged caller labels; foreign scope; revoked or
stale authority; expiry during lock waits; exact replay; lost response/restart;
stop/cancellation; and linked outcome/evidence/cleanup. Denials must leave
jobs/outbox unchanged. A queued run is not completed verification.

PRD9.3 requires fresh isolated execution, explicit success criteria, bounded
resources/egress and dedicated test credentials. Infrastructure/engine failure
is Inconclusive. A local provider cannot prove hostile-code Verified status.
PRD11.9 forbids claiming Contained/Remediated from enqueue or HTTP success.
Actual Fargate/provider acceptance remains a separate external gate.

Keep M7A-21's accepted existing-test path and all predecessor migration pins
unchanged. Do not expose the new action before its entire safety lifecycle is
connected. API/client/UI changes receive one full runnable-UI boundary check
before publication, plus independent review of the complete feature batch.

## Work order and evidence limits

The bounded M1A-04 staging queue contract repair runs first while this source
mapping is recorded. Its connected suite then exposed the local deployment
blocker in `2026-09-18-compliance-deployment-gap.md`, which takes priority after
queue review. M7A-22 is the next new action integration; M7A-23 and M7A-24
follow their original dependencies. No action implementation or new runtime
acceptance is claimed by this document. The selected architectural design is now
`2026-09-18-security-agent-attack-lab-design.md`; its executable plan is now
`2026-09-18-security-agent-attack-lab-plan.md`. Compliance deployment has local
independent acceptance. Task1 of the Attack Lab plan is the active implementation
assignment; no connected action acceptance is claimed yet.

Do not reopen accepted local M7A-21/M7A-49 work based on historical pending
text. The September17 planner-request-binding checkpoint supersedes that old
text; current provider pricing, advisory, cloud and publication gates remain
explicitly open.

## Admission and outcome design constraints from current source

Follow-up source inspection while compliance deployment is implemented confirms
three constraints for the architectural action design. This is source evidence,
not a newly executed Attack Lab acceptance test.

1. `migrations/sql/0026_attack_lab_execution.up.sql:241` preflight binds the
   exact completed failed Red Team run and attempt, enabled definition version,
   target, credential binding and safety decision digest. The creator at282
   locks those prerequisite rows and recomputes the digest before writing the
   run/outbox/receipt. Its freshness predicates currently use transaction-start
   time. A new shared worker admission path must explicitly recheck wall-clock
   target/credential/decision expiry and current worker/approval authority after
   blocking waits. Do not copy stale-time predicates into the new entry point
   or grant the worker API membership. Existing predecessor SQL/pins stay intact.
2. `agentsec-worker/attack_lab_runtime.go:460` accepts `verified` only with
   criterion observed and canary touched. This means the unsafe condition was
   reproduced. It is not a Red Team protected/pass result and must never be
   mapped to Security Agent Remediated or Contained. `not_reproduced` also cannot
   prove a security control improved without separate comparable before/after
   evidence. Engine/transport/uncertain outcomes remain Inconclusive.
3. Cleanup is durable and separate: the runtime records a checkpoint before
   destroying the sandbox, then requires terminal state plus cleanup complete
   (`attack_lab_runtime.go:307..362`). SQL finish at550 records the exact attempt
   and immutable evidence tuple only after controller-authorized completion.
   A new agent link/reconciler must consume that exact scoped attempt/checkpoint
   and provider evidence. Queue acknowledgement, a worker's local cancellation
   or a pending cleanup checkpoint is not terminal cleanup proof.

The selected design resolves a scoped failed source for the configured exact-version
test during planning, then binds its run/attempt/safety digest before operator
approval. Dispatch cannot silently replace it. A fixed source-run reference was
considered but would make reusable definitions stale. This is a design decision,
not an implemented capability. No Attack Lab action source edits have been made
during this audit.
