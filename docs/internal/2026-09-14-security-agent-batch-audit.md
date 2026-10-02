# B02 Security Agent batch: original requirements and evidence audit

Status: read-only evidence audit recorded below; no completion credit.
September 15 follow-up: M7A-94 now has reviewed local composed
planner/processor/PostgreSQL foreign-asset acceptance and an explicit-target
authority fix. See [the current checkpoint](2026-09-15-planner-tenant-boundary-evidence.md).
It remains component-only and unpublished. The audit table below is the earlier
source baseline, not the latest execution result for this row.
September 15: M7A-84 display implementation is locally tested, pending combined
independent review and selected real API/browser no-execution-effect acceptance.
All original availability classifications remain unchanged. The following audit
instructions describe the completed read-only assignment, not a fresh dispatch.
This contains15 original IDs, not15 invented prerequisites. Audit current code,
tests and shipped evidence for each requirement below. Return exact per-ID
acceptance/test mapping, missing product behavior, shared prerequisites,
dependency-safe implementation order, affected-file ownership and external gates.
Do not treat existing component tests as production evidence. M7A-23 depends on
M7-40: preserve that cross-stream gate rather than pretending it is independent.
No product edits, external calls with side effects, test suite runs, Git mutation
or child agents are authorized by this audit. Root will dispatch implementation
after the findings. Report at the end of this file with evidence-backed rows.

Source: agent_security_platform_Technical_Implementation_Plan_v1.5.md.

**M7A-21 - Action: run existing test**  
Depends on: `M7A-20,M5-35`  
Deliverable: Register `run_test`/`rerun_test` against an existing TestDefinition.  
Verify: Action cannot create arbitrary new target/prompt content.  
Timebox: <=15 minutes.

**M7A-22 - Action: start Attack Lab verification**  
Depends on: `M7A-21,M5-35`  
Deliverable: Register `start_attack_lab` only for a preflight-approved non-production/test target.  
Verify: Production-write target fails before job enqueue.  
Timebox: <=15 minutes.

**M7A-23 - Action: evidence export**  
Depends on: `M7A-22,M7-40`  
Deliverable: Register `create_evidence_export` using existing export service.  
Verify: Export references only run-scoped evidence IDs.  
Timebox: <=15 minutes.

**M7A-24 - Action: signed webhook handoff**  
Depends on: `M7A-23`  
Deliverable: Register `send_response_webhook` using configured allowlisted webhook destination.  
Verify: Arbitrary URL argument is rejected; payload is redacted and signed.  
Timebox: <=15 minutes.

**M7A-84 - Security Agent builder Simulate UI**  
Depends on: `M7A-83,M7A-69`  
Deliverable: Show matched evidence, proposed plan and approval points without side effects.  
Verify: E2E simulator shows authorization result per proposed step.  
Timebox: <=15 minutes.

**M7A-86 - Security Agent run plan UI**  
Depends on: `M7A-85`  
Deliverable: Show trigger/evidence, AI rationale summary and ordered plan with deterministic authorization labels.  
Verify: Rationale is visually distinct from authorization/evidence.  
Timebox: <=15 minutes.

**M7A-87 - Security Agent run action UI**  
Depends on: `M7A-86`  
Deliverable: Show each step state, redacted arguments, result, TTL/rollback and verification.  
Verify: Protected arguments never render.  
Timebox: <=15 minutes.

**M7A-88 - Security Agent Approvals list UI**  
Depends on: `M7A-87`  
Deliverable: Add Protect -> Approvals list with action, agent, target, expiry and requester/run context.  
Verify: Unauthorized approvals are absent.  
Timebox: <=15 minutes.

**M7A-89 - Security Agent Approval detail UI**  
Depends on: `M7A-88`  
Deliverable: Show reason, evidence, expected side effect, risk, reversibility/TTL and Approve/Deny/Cancel.  
Verify: Sensitive approval invokes fresh-auth flow before decision.  
Timebox: <=15 minutes.

**M7A-90 - Security Agent activity links**  
Depends on: `M7A-89`  
Deliverable: Link finding/path/session/audit records to Security Agent run and back.  
Verify: E2E navigation preserves scoped entity IDs.  
Timebox: <=15 minutes.

**M7A-94 - Cross-tenant planner reference test**  
Depends on: `M7A-93`  
Deliverable: Seed planner output with another Organization's valid-looking asset UUID.  
Verify: Plan is rejected before authorization/execution.  
Timebox: <=15 minutes.

**M7A-95 - Security Agent action budget test**  
Depends on: `M7A-94`  
Deliverable: Exceed action/time/cost budget in fixture.  
Verify: No step starts after budget stop.  
Timebox: <=15 minutes.

**M7A-96 - Security Agent auto-response E2E**  
Depends on: `M7A-95`  
Deliverable: Trigger injection responder, auto-create temporary Block and re-test.  
Verify: Run ends Contained/Remediated only after policy evidence plus re-test verification.  
Timebox: <=15 minutes.

**M7A-100 - Security Agent single-tenant profile E2E**  
Depends on: `M7A-99`  
Deliverable: Execute the same responder flow in dedicated single-tenant profile.  
Verify: Same API/UI/action contracts pass without topology-specific product behavior.  
Timebox: <=15 minutes.

**M7A-101 - M7A gate**  
Depends on: `M7A-100`  
Deliverable: Write Security Agent MVP gate result covering automatic trigger, simulate, plan, authorize, auto-act, approval, execute, temporary-control expiry cleanup, verify, Home attention UX, audit, outage and tenant isolation.  
Verify: PASS only when all preceding Security Agent E2E/security/degraded checks pass.  
Timebox: <=15 minutes.

## Audit, 2026-09-14: the batch isn't ready for a blanket promotion

I inspected the current worktree, original requirements above, availability
ledger, component tests, production API/worker/UI code, migration authority and
recorded shipped evidence. No suites ran. No Git operation, provider request,
credential lookup or product edit occurred. Only this report changed. The
export-contract review and its files remain outside this audit.

All 15 original IDs have `Complete / component-only` rows in
`implementation_production_availability_v1.5.tsv` (lines 500-503, 567,
569-573, 581-583 and 587-588). Historical completion is not production
acceptance. Don't promote a row from source inspection alone.

There is useful shipped work to retain. `M7A-20`, `M7A-69`, `M7A-83`,
`M7A-85`, `M7A-93`, `M7A-97`, `M7A-98`, `M7A-99` and `M5-35` already
have production-available ledger rows. The current action-readiness manifest
allows four production actions: finding response can be autonomous; temporary
policy, session isolation and connection revocation are supervised. Test,
Attack Lab, export and response-webhook actions remain unavailable to a
production Security Agent.

### What each original ID still needs

Paths below are repository-relative. Named existing tests were read, not run.
The required checks are acceptance targets for implementation, not newly
invented task IDs or claimed passing evidence.

| Original ID | Current implementation and evidence | Missing behavior and exact acceptance/test boundary |
| --- | --- | --- |
| **M7A-21** | `services/platform/securityagent/builtin_actions.go:146-147,174` registers ID-only `run_test`/`rerun_test`; `TestBoundedResponseActionSet` in `automation_test.go:178` rejects a supplied prompt. This uses `fakeBuiltinBackend`. `action_readiness.go:27,29` keeps both actions component-only. Existing production Red Team enqueue is `apiserver/red_team_repository.go` / `zasp_red_team_run_test`; it is not wired into this action. | Add the durable Security Agent-to-existing-TestDefinition adapter, with authoritative tenant/environment/definition-version binding, exact replay and completion verification. Test extra prompt/target/URL inputs, nonexistent and other-tenant definitions, disabled/stale definition, revoked target credential, replay after worker restart, and zero new target/definition rows. A real scoped test run and evidence receipt must link back to this exact agent step. Reuse Red Team authority; do not let planner strings grant target access. Gates: G1 and G2 below. |
| **M7A-22** | Component metadata accepts `target_class` of `non_production` or `test` and `preflight=approved`; `TestBoundedResponseActionSet` rejects `production`. Those are caller strings, not proof of production preflight. `action_readiness.go:31` disables the action. Standalone Attack Lab production authority and `M5-35` are already recorded as available. | Wire an existing TestDefinition to actual scoped Attack Lab preflight/admission, with the live environment and registered credential checked before enqueue. Test production environment disguised as test, production-write credential, stale/revoked binding, changed preflight authority, replay and sandbox cleanup. Assert unchanged queue/outbox/job counts on every denial, including the direct action executor path. A real composed local sandbox run is required; managed-cluster canary remains separate. Depends on M7A-21. Gates G1/G3. |
| **M7A-23** | Component registration and run-prefix validation exist in `builtin_actions.go:149,178-191`; the fixture rejects `other-run:evidence`. A prefix is not a durable evidence membership check. The action is component-only. No export-contract acceptance was inferred or reviewed here. | Keep this row blocked on **M7A-22 and M7-40**. After the export owner accepts the existing service, wire only canonical evidence IDs resolved from the current tenant/run, bind the export receipt to the action, and verify missing/foreign/run-prefix-forged evidence is rejected before enqueue. Require restart-safe replay and artifact expiry behavior through the accepted service. Gate G4; this audit neither changes nor approves the export implementation. |
| **M7A-24** | `builtin_actions.go:75-92,192` constructs a fixed redacted HMAC payload using a configured destination ID; `TestBoundedResponseActionSet` checks exact bytes/signature and rejects a URL argument. The backend and idempotency cache are in-memory fixtures. Production Generic Webhook exists separately; its closure document explicitly excludes this Security Agent adapter. | Add tenant-bound destination/configuration/version authority, durable delivery identity and result, secret-reference resolution only after authorization, fixed redacted payload signing and bounded reconciliation. Test arbitrary URL, foreign destination, changed/revoked destination, redirects/private addresses, duplicate/restarted dispatch, and ambiguous delivery. A receiver's HTTP acknowledgement is not proof it validated the signature. Dependency stays M7A-23; independent transport reuse can be prepared, but this ID cannot be accepted ahead of it. Gates G1/G4/G5. |
| **M7A-84** | `apps/web/api/decoders.ts:498` already validates matched evidence and per-step authorization/approval flags. `SecurityAgentsView.tsx:313` renders only summary, plan hash, zero-effects text and expiry. Existing UI test `validates, simulates, and queues a supervised finding run from exact durable activation authority` and handler test `TestSecurityAgentPublicHandlerPersistsAZeroEffectSimulation` cover the underlying path. | Render `matched_evidence_ids`, ordered steps, deterministic authorization and approval points from the simulation result. Extend the named UI test to assert each label/evidence ID and a browser check to assert the same from the real API. Compare before/after action, approval and effect counts: simulation may persist its audit/receipt, but must create no execution side effect. No API shape expansion appears necessary. M7A-83/M7A-69 are available. Export-independent; G1 only for release claims. |
| **M7A-86** | `SecurityAgentsView.tsx:328-334` shows evidence IDs and ordered action/authorization/state, but no trigger context or AI rationale. `SecurityAgentPlanSummary` and `SecurityAgentRunDetail` in generated API types omit rationale. The planner receipt stores `planner_summary` in SQL v32; it is not exposed by the run-detail UI contract. Existing UI test `shows redacted run and approval detail, gates decisions on fresh auth, and cancels with the listed version` is a regression base. | Add a bounded redacted rationale projection and typed trigger context from authoritative run/receipt data, then render rationale in a distinct labeled section outside authorization/evidence. Test injected/secret-bearing planner summary, empty/unavailable rationale, stable step order, and visual/semantic separation in component plus real-browser tests. Do not render raw provider output. Depends on available M7A-85. Export-independent. |
| **M7A-87** | The same run view shows action/state/outcome ID and run-level verification only. `SecurityAgentPlanStep` has no safe argument projection; `SecurityAgentExecutionStep` does not supply the full original arguments/TTL/rollback display. The repository/decoder reject fields outside their narrow contracts. | Add server-produced allowlisted redacted arguments, per-step result/verification and TTL/rollback status; do not spread internal parameters or lease/approval tokens into JSON/JSX. Test protected values are absent from HTTP, DOM, error and retained-mutation storage; assert pending, failed, inconclusive, cleanup-pending and cleaned states show truthful per-step results. Reuse `SecurityAgentsView.test.tsx`, `decoders.security-agent.test.ts`, `security_agent_repository_test.go` and a composed browser flow. Depends on M7A-86. Export-independent. |
| **M7A-88** | `/protect/approvals` is routed in `app/components/ZaspProductionApp.tsx:41,64`. `SecurityAgentsView.tsx:392` lists expected effect, run ID and expiry. `SecurityAgentApproval` exposes neither agent/requester nor explicit target/action context. Repository pages are tenant-scoped; that does not alone prove the original unauthorized-approval visibility requirement for every role. | Extend the approval projection/list with action, agent, target, requester and run context. Check authorized visibility explicitly across principal role and tenant, including a direct detail request and pagination; don't merely hide Approve while returning unauthorized list rows. Preserve identity-admin-only irreversible decisions, fresh-auth and exact version/idempotency checks. Existing `TestSecurityAgentPostgresRepositoryReadsExactScopedRunsAndApprovals`, `TestSecurityAgentPublicHandlerRequiresIdentityAdministratorForIrreversibleApproval` and UI irreversible-approval test are the bases. Depends on M7A-87. Export-independent. |
| **M7A-89** | `ApprovalDetail` (`SecurityAgentsView.tsx:340-358`) displays effect, evidence, reversibility, TTL and expiry, with Approve/Reject behind reauthentication. It has no reason/risk projection and no Cancel control, although the API type already accepts `cancelled`. `TestSecurityAgentPublicHandlerApprovesWithFreshSeparateBrowserAuthority` covers server-side fresh-auth. | Add reason/risk from safe authoritative fields and the Cancel decision, with clear Deny semantics (the wire state remains `rejected`). Test stale/future/missing auth, self-approval constraints, unauthorized irreversible action, expiry/CAS race, exact retry and each terminal decision through the UI and API. Fresh-auth must precede sensitive decisions, not just set a caller header. Depends on M7A-88. Export-independent. |
| **M7A-90** | Run evidence is plain text; `SecurityAgentsView` has no entity-link callback or initial run selection. The production router accepts list routes, and Home links go to those lists. Inspected production views do not establish a round trip from finding/path/session/audit to a selected run and back. | Add typed entity/run activity relations and route selection bound to the current organization/workspace/environment; render bidirectional links only for visible entities. Browser-test all four entity kinds, browser back/reload, scope switch, foreign same-looking IDs and removed/forbidden targets. A bare ID in text or a list-only link is insufficient. This can use existing audit-read records without accepting audit-export. Don't edit frozen audit-export files; coordinate any shared public-contract edits with their owner. Depends on M7A-89. |
| **M7A-94** | `TestSecurityAgentPlannerFailsClosedWithoutRetryRedirectOrProviderLeakage` has a `foreign target` subtest with a syntactically valid product ID, but uses a mocked provider transport and does not seed that ID in another organization. `TestSnapshotPlannerAuthorizationAndRunBudget` tests `env-b` in-memory. SQL v32 candidate acceptance re-resolves the scoped allowed target before `prepare_run`; v33 adds verified attack-path support. | Seed a real second organization's valid asset/target and submit it through the planner/worker into the scoped database acceptance path. Assert rejection precedes prepare/authorization: zero plans, steps, approvals, effects and target mutation for the rejected candidate, while a redacted rejected-planner receipt/audit is allowed. Include same-looking IDs in separate tenant scopes and an authorized control case so an unavailable planner cannot make the test pass. Likely a test-first slice; change product code only if this reproduces a gap. M7A-93 is available. Export-independent. |
| **M7A-95** | `securityagent/planner.go:166-243` has in-memory action/time/token/cost/concurrency budgets. `TestSnapshotPlannerAuthorizationAndRunBudget` combines a step/token/cost breach; it doesn't isolate elapsed-time breach or prove a later executor call cannot start. Production SQL carries configured budgets in simulation but the inspected execution authority has no durable budget ledger. SQL v32 requires exactly one allowed action and one candidate step; worker planner config supplies a fixed token ceiling. | Add durable per-run budget accounting/reservation at the execution boundary, tied to lease/CAS authority, with explicit elapsed-time, action count and cost accounting; a fixed provider token cap is not a run cost budget. Separate tests must cross each limit and prove zero subsequent starts, including concurrent claims, replay, crash/restart, approval delay and time boundary. Preserve cleanup of already-created temporary controls after a budget stop. This is security/concurrency work, not a test-label-only closure. Depends on M7A-94. Export-independent. |
| **M7A-96** | `templates.go` defines `prompt_tool_injection` as temporary policy plus `run_test`, but the production planner only accepts one step and `run_test` is unavailable. `action_readiness.go` limits temporary policy to supervised mode. Existing autonomous PostgreSQL/browser evidence performs `update_finding_response` and reaches `remediated` after the finding changes to `under_review`; supervised temporary-policy evidence verifies gateway readback and cleanup. Neither proves this task's injection/Block/re-test flow. | Support the bounded original multi-step responder, including policy-authorized automatic temporary Block, actual existing-test execution and outcome linkage. Require both policy-enforcement evidence and a completed safe re-test before Contained/Remediated; unknown/failed/no re-test stays non-success. Test trigger deduplication, no autonomous escalation beyond allowed scope/TTL, verification ordering, expiry cleanup, and restart. Depends on M7A-95 and practical prerequisite M7A-21. Approval-policy changes require dedicated security review; don't relabel supervised work as automatic. Gates G1/G2/G6. |
| **M7A-100** | `TestSecurityAgentAttentionAndMVPGate` sets `SingleTenantParity: true`; this is a boolean fixture, not deployment evidence. `scripts/production-combined-e2e.mjs` exercises local multi-tenant composed flows. `docs/operations/production-deployment.md:7` says the supported hosted profile is `values-saas.yaml` and single-tenant needs its own release evidence. | Run the same accepted responder/API/UI/action assertions in an isolated dedicated single-tenant profile, record the release/config/image/schema identity, and compare contracts without topology-specific product branches. Local disposable dedicated-profile evidence can be built independently of export; actual hosted single-tenant acceptance requires a provisioned approved deployment. M7A-99 is available, but the original "same responder" also needs M7A-96's full flow. Gates G1/G6/G7. |
| **M7A-101** | `mvp.go` evaluates caller-supplied booleans; `mvp_test.go:30` supplies all true and flips one to false. `app/quality/m7a-mvp-gate-batch-contract.test.ts` mainly searches source/tracker strings. These checks cannot prove all original Security Agent journeys passed. Existing M7A-97/98/99 shipped rows remain useful independent evidence. | Write an evidence-backed gate with a result and artifact per required capability: trigger, simulate, plan, authorize, auto-act, approval, execute, TTL cleanup, verify, Home, audit, outage, tenant isolation and dedicated-profile parity. Require all preceding original E2E/security/degraded checks at the reviewed release; missing/skip/external cannot become PASS. M7A-100 is the explicit dependency, and M7A-23/24 retain their unresolved export dependency in the all-preceding gate. Gates G1-G7 as applicable. |

### Shared work, with file ownership kept explicit

The small UI work can start now. I would give M7A-84 its own focused TDD
slice, then keep M7A-86 through M7A-90 together under one UI/API owner so their
shared projections don't fight each other. M7A-94 can start independently;
M7A-95 and the action adapters deserve smaller security/concurrency slices.
These are subdivisions of the 15 approved IDs, not extra completion credits.

| Work boundary | Likely changed files and ownership |
| --- | --- |
| M7A-84 display-only slice | `app/features/securityagents/SecurityAgentsView.tsx`, its `.test.tsx`, and the Security Agent section of `scripts/production-combined-e2e.mjs`. Existing simulation result already contains the required fields. |
| M7A-86/87 run projection | The same view/tests; `services/platform/apiserver/security_agent_surface.go`, `security_agent_repository.go` and tests; `apps/web/api/decoders.ts`, `decoders.security-agent.test.ts`; Security Agent schemas in `openapi/openapi.yaml`, generated API types through normal generation; a new forward migration for safe run/step projection if needed. Do not rewrite historical v18/v32 migrations. |
| M7A-88/89 approval projection and decisions | Same UI/API owner; `security_agent_handler.go` and handler tests, approval repository validators, Security Agent-only OpenAPI/decoder fields, a forward projection/visibility migration. Approval `cancelled` already exists in the wire contract. New projection fields still need server/decoder/UI agreement. |
| M7A-90 links | `app/components/ZaspProductionApp.tsx`, `app/features/securityagents/SecurityAgentsView.tsx`, existing production entity view files (including `app/features/agents/ProductionAgentSecurityView.tsx`), their tests and a typed scoped activity-link projection. Existing audit-read integration must stay separate from the frozen export work. Root should reserve shared router/OpenAPI/generated/decoder/harness edits before dispatch. |
| M7A-94 isolation proof | New dedicated `services/platform/apiserver/security_agent_planner_postgres_test.go` is a likely clean home; `services/platform/agentsec-worker/security_agent_planner_test.go`, `security_agent_runtime_test.go` and, only for an observed defect, the matching planner/repository code. Current v32/v33 source provides the acceptance-boundary baseline. |
| M7A-95 and M7A-96 execution authority | `services/platform/agentsec-worker/security_agent_runtime.go`, `security_agent_planner.go`, `security_agent_action_runtime.go` and tests; `services/platform/apiserver/security_agent_worker_repository.go`, action repository/surface and tests; `services/platform/securityagent/planner.go`, templates/readiness and tests; new forward migrations with registration/readiness tests. The current one-step authority needs an explicit design before multi-step execution. |
| M7A-21/22 adapter boundary | New Security Agent action adapters beside the worker/repository files above, using existing `red_team_repository.go`, `red_team_execution_repository.go`, `attack_lab_repository.go`, `attack_lab_execution_repository.go` APIs as the source authority; dedicated PostgreSQL/worker replay tests. Touch existing Red Team/Attack Lab implementations only for a demonstrated integration need. Action readiness/manifest promotion waits for composed proof. |
| M7A-23/24 deferred integration | Security Agent adapters/readiness plus tests, after the export owner supplies the accepted service boundary. For M7A-24 reuse `services/platform/apiserver/integration_webhook.go` and `finding_ticket_webhook.go` transport/security contracts, not their test-delivery endpoint as a substitute for response delivery. No frozen export file is assigned by this audit. |
| M7A-100/101 evidence | Dedicated-profile harness/fixtures, `scripts/production-combined-e2e.mjs` under one owner, release evidence/gate document, and per-ID ledger updates only after acceptance. `deploy/staging/product` and `docs/operations/production-deployment.md` need changes only if dedicated-profile support is actually added. Gate boolean fixtures can remain unit checks but aren't the gate report. |

Any new migration must keep exact checksum/fingerprint, principal grants,
tenant fencing, rollback refusal and current supported-schema readiness. Root
owns migration numbering, release selectors, shared generated files and the
combined harness. Don't let two sub-slices edit those concurrently.

### Order that doesn't hide the export gate

Start independent lines at **M7A-84**, **M7A-86**, **M7A-94** and
**M7A-21** using their already-available prerequisites. Then follow these
acceptance chains:

```text
M7A-83 + M7A-69 -> M7A-84
M7A-85 -> M7A-86 -> M7A-87 -> M7A-88 -> M7A-89 -> M7A-90
M7A-93 -> M7A-94 -> M7A-95 -> M7A-96 (also needs M7A-21)
M7A-20 + M5-35 -> M7A-21 -> M7A-22
M7A-22 + M7-40 -> M7A-23 -> M7A-24
M7A-99 + accepted same-responder flow -> M7A-100 -> M7A-101
```

M7A-100's extra same-responder condition comes from its original deliverable,
not a renumbered dependency. M7A-101 also requires all preceding original
checks, so its PASS cannot sidestep M7A-23/24. **M7-40 itself is still
component-only** in the authoritative ledger. Audit-export acceptance alone
must not silently become M7-40 acceptance.

M7A-84, M7A-86-90, M7A-94-96 and M7A-21/22 can be implemented and verified
without audit-export acceptance. M7A-100's dedicated-profile work can also
proceed, subject to the responder and deployment gates. Keep M7A-23/24
acceptance and the M7A-101 final PASS closed until their real dependencies pass.

### Exact external gates, not generic "needs production"

| Gate | Required evidence / authority |
| --- | --- |
| **G1: release boundary** | Fresh focused TDD results, actual PostgreSQL/worker/browser checks for changed boundaries, independent security review where scope/authorization/leases change, shared regressions and reviewed main CI. Live release claims also need exact built-image SBOM/scans/signatures/provenance, approved release values/schema, public DNS/TLS and deployment health/canary. Recorded old CI is background evidence only. No live credentials are needed for the initial synthetic/disposable checks. |
| **G2: real test target** | Approved existing non-production TestDefinition and discovered target, authoritative environment, active scoped credential binding and exact version, dedicated Red Team outbox/worker/adapter identities, adapter token/TLS, queue/DLQ, evidence bucket/KMS and approved target CIDRs. Run the pinned production Promptfoo runner through the actual adapter and record the normalized test/evidence receipt linked to the Security Agent step. Customer/provider credentials or a managed deployment require explicit supplied authority; a fake backend is not this proof. |
| **G3: Attack Lab** | Existing M5-35 authority plus a provisioned isolated sandbox target, current preflight/credential registration, dedicated controller/proxy/outbox roles, image-pinned jobs, namespace/egress/resource limits and verified cleanup. Local composed Kubernetes-provider fixtures establish only that boundary; an actual approved cluster run and canary are needed for cluster/deployment claims. Production-write denial must be proved before job enqueue, not after sandbox startup. |
| **G4: export dependency** | Explicit handoff from the separate export owner accepting the existing export service, original **M7-40** gate acceptance, and M7A-22 acceptance. Then require this action's run-scoped membership/replay/receipt proof. No export implementation, schema or artifact was accepted by this report. |
| **G5: response destination** | A saved allowlisted tenant destination, approved public CIDRs, provisioned signing secret reference/version, reviewed egress and trusted TLS receiver. Prove exact response-event bytes/signature, stable delivery ID and recorded acknowledgement; if receiver signature validation is claimed, retain receiver-side verification evidence too. M3-48h Generic Webhook test delivery does not close M7A-24. |
| **G6: automatic containment** | Authorized bounded automatic policy behavior, ready signed gateway deployment/readback with current control switches, exact target and TTL, actual linked re-test after the policy, and expiry cleanup through a worker restart/outage. Both policy and re-test evidence are needed before success. Broadening temporary-policy autonomy without these proofs would bypass the current supervised safety contract. |
| **G7: dedicated profile** | An approved isolated single-tenant release with its own schema, image digests, configured service principals, target/worker dependencies and browser/session scope, then the same responder contract suite and artifact set. The deployment runbook currently supports hosted SaaS and explicitly withholds single-tenant use pending release evidence. A boolean `SingleTenantParity` fixture or a second tenant in SaaS is not this gate. |

Recorded shipped context: `docs/product/security-agent-action-readiness.tsv`;
`docs/internal/2026-09-08-m5-red-team-production-closure.md` (Red Team safety,
invocation and actual-image progress); `docs/internal/2026-09-08-m3-48h-production-webhook.md`
(PR #8/main `7677cf2f`, with response adapter explicitly excluded); and
`scripts/production-combined-e2e.mjs:2225-2516` (local automatic finding response,
supervised policy/session/revocation, TTL cleanup and planner outage coverage).
Those are reusable regression boundaries. They do not replace the missing
injection/Block/re-test, dedicated-profile or export-dependent acceptance.

Dispatch the small simulation UI and seeded cross-tenant planner proof first.
Keep the multi-step/budget/automatic-policy work under a separate security
review boundary; leave every availability row unchanged until its own proof
is recorded.
