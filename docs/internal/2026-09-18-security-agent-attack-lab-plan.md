# Security Agent Attack Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Execute the tasks in order. The user authorizes routine decisions and feature-batched verification without an approval pause.

**Goal:** Complete original M7A-22 by connecting start_attack_lab to current scoped preflight, mandatory operator approval, the existing execution controller, immutable evidence and confirmed cleanup.

**Architecture:** Add release57 around a private shared Attack Lab admission/cancellation core, with separate API and lease-bound agent wrappers. Keep existing execution authority with the controller; a separately registered read-only-artifact reconciler settles durable agent links. Enable the product catalog only when the connected path and its deployed configuration are available.

**Tech Stack:** Go1.25.6, PostgreSQL, Node22.23.1, React, OpenAPI, Helm, Terraform declarations and existing AWS SDK clients.

**Spec:** `docs/internal/2026-09-18-security-agent-attack-lab-design.md`. Read it in full. Source findings and historical compatibility are in `2026-09-18-security-agent-action-runtime-gap.md`.

## Global Constraints

- Work in `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`, existing isolated branch codex/cached-runtime-ship-20260917, HEAD8733b16f8d939d38a8157dd2519e57fc6f630542. Preserve unrelated dirty changes.
- Preserve original728 scope and all published release1..56 SQL/checksums/fingerprints. Release56 checksum is f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1; fingerprint8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced.
- Keep default49 and accepted55/56 behavior. Add57 explicitly; reject58. Preserve supported legacy reads; only unsupported authority/migration paths must refuse57.
- Single configured action uses existing_test `{definition_id,definition_version}` and verification_kind=attack_lab_run. No caller/model URL, prompt, credential, target-class, preflight-approved or source-run override is authority.
- Both supervised and autonomous definitions retain mandatory operator approval; requester and approver differ and current scoped permission/fresh authentication are required.
- Production environment/write credentials fail before enqueue. Denial leaves effects, links, jobs, outbox and receipts unchanged.
- Verified Attack Lab means unsafe behavior reproduced, never Remediated/Contained. Reproduced and not-reproduced bounded results both require human interpretation.
- No network/provider/advisory call, secret provisioning, provider/image download, host PostgreSQL, Terraform init/apply or full production-release script. Offline Go: GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off. Local Go/cache paths belong in invocation environment, not committed portable harnesses.
- Owned PostgreSQL uses only the cached image postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba with --pull=never --network none. Join all processes and clean owned containers.
- One implementation writer. Focused RED/GREEN while coding; shared connected integration/race and independent feature review. Do not repeat fullUI/fullGo per microtask. No push until exact-source UI/tests/types/lint/build and applicable publication gates pass.
- Freeze task-only before/after patches and hashes under docs/internal/security-agent-attack-lab-20260918/. Do not broad-stage inherited work. Components remain component-only until matching deployed evidence exists.

## Task 1: Durable admission, source binding and release57

**Create:**

- `services/platform/migrations/sql/0057_production_security_agent_attack_lab.up.sql` and `.down.sql`: release-owned objects, saved predecessor functions/ACLs and guarded rollback.
- New fragments under `services/platform/migrations/sql/fragments/`: `security_agent_attack_lab_definition.sql`, `security_agent_attack_lab_planner.sql`, `security_agent_attack_lab_admission.sql`, `security_agent_attack_lab_links.sql`. Reconciliation and settlement fragments are allocated to Task2 with their implementing runtime, not empty Task1 placeholders.
- `services/platform/migrations/security_agent_attack_lab_release.go` and `production_security_agent_attack_lab.go`: embedded release, compiled pins, exact-state/readiness and registration transaction.
- `services/platform/apiserver/security_agent_attack_lab_repository.go`: release probe and guarded query routing; `security_agent_attack_lab_postgres_test.go` and `security_agent_attack_lab_reference_test.go` for actual authority tests.

**Modify:** migration registry/CLI dispatch, `services/platform/agentsec-migrate/main.go`; `services/platform/apiserver/security_agent_repository.go`, `security_agent_worker_repository.go`, `security_agent_existing_test_reference.go`, `workflow_handler.go`; relevant database capability implementation. Locate owning registry and capability files with rg before editing, not a new parallel registry. Preserve older wrapper signatures and SQL bytes.

**Interfaces:**

```go
// New migration package exports; Metadata is the existing migration type.
func ProductionSecurityAgentAttackLab() Metadata
func SecurityAgentAttackLabFingerprint() string
func (runner *Runner) UpProductionSecurityAgentAttackLab(ctx context.Context) error
func (runner *Runner) DownProductionSecurityAgentAttackLab(ctx context.Context) error
func (runner *Runner) RegisterSecurityAgentAttackLabReconciler(ctx context.Context, principal string) error

// Capability is checked on operations, not cached forever across cutover.
func (repository *PostgresRepository) SecurityAgentAttackLabAvailable(ctx context.Context) (bool, error)
```

CLI commands: `up-to-57`, `down-from-57`, `register-security-agent-attack-lab-reconciler`.
The new registration input is `ZASP_SECURITY_AGENT_ATTACK_LAB_RECONCILER_DB_PRINCIPAL`.
Its pre-created canonical non-zasp_ login receives only the fixed capability
`zasp_security_agent_attack_lab_reconciler`, without SET/ADMIN option.

New SQL prefix is `zasp_sa_attack_lab_` to stay below PostgreSQL's identifier
limit. `zasp_sa_attack_lab_readiness(expected_checksum text, expected_fingerprint text)`
checks the compiled release and every protected function/ACL/table policy.
Registration takes `(principal text, expected_checksum text, expected_fingerprint text)`.
Planner/admission wrappers use the existing55 wrapper parameter types/order,
with names mapped to this prefix: planner_context, reserve_planner, prepare_run,
accept_planner, fail_planner and execute_run. Existing repository methods route
only matching attack_lab definitions to these57 wrappers; existing tests retain
their55 paths. Reconciliation signatures are fixed in Task2 below.

- [ ] Capture before bytes and current pins. Add a failing mounted/registered API case for a valid exact-test start_attack_lab definition and a failing agent dispatch case which cannot yet produce a durable linked Attack Lab run. Keep positive run_test/rerun_test controls.
- [ ] Retain the exact closed reference decoder. Add action/verification pairing tests using literal bodies, including these independent intended values:

```json
{"allowed_actions":["start_attack_lab"],"verification_kind":"attack_lab_run","existing_test":{"definition_id":"pid_8a000002-0000-4000-8000-000000000002","definition_version":1}}
```

  Reject the same action with test_run; mixed run_test/start_attack_lab; missing reference; duplicate/aliased JSON keys; reference URL/prompt/target/source overrides. The full definition test uses the existing required name/trigger/environment/autonomy/budget/version fields, not a relaxed public decoder.
- [ ] Add57 using existing release embedding/checksum conventions. Restore exact saved predecessor definitions and ACLs on downgrade only when no57-format definition/history/plan/approval/link/effect remains. Test refusal with both active and terminal records; never delete history to make downgrade pass.
- [ ] Extract one private admission/cancellation core through additive57 definitions. API wrapper still proves registered API authority; agent wrapper proves full scope/run/step/current worker lease, exact plan and approval. Revoke direct EXECUTE on private cores from PUBLIC and every application role. Do not impersonate the definition actor.
- [ ] Resolve the newest eligible completed failed Red Team source for the configured exact test version. Use completion time descending and runID descending as tie-breaker; require exact terminal attempt/evidence identity and same organization/workspace/environment. No source is a preflight-unavailable result, not implicit test creation.
- [ ] Bind the trusted source/attempt/test/target/evidence/preflight digest and expiry into planner context/request hashing. Recompute at reservation and acceptance. After acceptance, resolve the stored exact source; a newer run cannot retarget the approved step. The model candidate remains action/index/targetID only.
- [ ] Reuse the current operator-floor planner behavior. Both autonomy modes enter pending approval. Project exact source/attempt, destination, bounded side effects/limits and expiry, excluding private credentials. Approval binds exact plan hash/step and current distinct approver authority.
- [ ] Create forced-RLS `zasp_sa_attack_lab_links`, keyed by full scope plus agent run/step, with scope-complete foreign keys. Store complete input/plan/source/evidence/safety identity, linked executionID, approval/provenance, reconciliation generation/lease and immutable settlement receipt. Derive executionID with the existing canonical-ID function and full scope/run/step/action, never a random new replay ID.
- [ ] Hold organization admission, agent run/step, definition, source/attempt, environment, target and credential locks in one documented consistent order. After observed waits, use clock_timestamp checks for lease, budget, activation, stop, permission, auth freshness, safety and preflight expiry. An expired proposal needs a new plan/approval.
- [ ] In one transaction reserve effect, insert link, call private Attack Lab admission and create the existing run/outbox/audit/receipt. On replay compare complete stored intent. Retain link replay after public receipt expiry. Changed scope/source/input/approval conflicts instead of launching again.
- [ ] Test actual registered roles: positive nonprod control; production/write refusal despite forged labels; foreign/stale/version drift; missing source; permission/auth/lease/preflight expiry after observed waits; replay/lost acknowledgement; concurrent same-step dispatch; zero-mutation denial. Registration/CLI preflight must reject invalid principal before opening DB and preserve fixed public errors.
- [ ] Run focused GREEN, then freeze this authority unit for review. Do not expose the production catalog or publish57 before Tasks2/3 connect its consumer and acceptance path. Update only local component evidence.

## Task 2: Existing controller proof and dedicated settlement runtime

**Create:** `services/platform/agentsec-worker/security_agent_attack_lab_reconciler.go`, `security_agent_attack_lab_client.go`, `security_agent_attack_lab_config.go` and corresponding focused tests. Add runtime integration coverage in `security_agent_attack_lab_runtime_test.go` and registered tests in `services/platform/apiserver/security_agent_attack_lab_settlement_postgres_test.go`.

Create `services/platform/migrations/sql/fragments/security_agent_attack_lab_reconcile.sql` and `security_agent_attack_lab_settlement.sql` here, implementing the exact interfaces and evidence semantics below. This corrects the earlier Task1 file-list allocation; neither file nor its functionality is removed from scope.

**Modify:** existing worker mode/config/polling/readiness dispatch; `attack_lab_runtime.go` and provider files only if connected RED proves a required correction. Deployment uses new `deploy/production/attack-lab-reconciler-rollout.mjs`, matching fixture/tests, chart `attack-lab-reconciler.yaml` and network/operations templates, plus `deploy/staging/attack_lab_reconciler.tf` with source/mock assertions. Extend existing release contracts, phases, operational command dispatch and migration chain to57 without erasing56 controls.

**Interfaces:** Worker mode/service account `security-agent-attack-lab-reconciler`;
fixed DB capability `zasp_security_agent_attack_lab_reconciler`. Process no more
than one claimed link per iteration,60-second renewable lease and30-second
operation timeout. Reuse process health/shutdown conventions.

SQL functions use prefix `zasp_sa_attack_lab_` and return closed jsonb envelopes:

```sql
-- Full scope is o,w,e; r,s identify the parent agent run and step.
-- All functions require the registered reconciler capability plus compiled57 pins.
reconcile_scopes(after_o text, after_w text, after_e text, worker text, checksum text, fingerprint text)
reconcile_claim(o text, w text, e text, worker text, lease bytea, seconds integer, batch integer, checksum text, fingerprint text)
reconcile_heartbeat(o text, w text, e text, r text, s text, worker text, lease bytea, version bigint, generation uuid, seconds integer, checksum text, fingerprint text)
reconcile_cancel_stopped(o text, w text, e text, r text, s text, worker text, lease bytea, version bigint, generation uuid, checksum text, fingerprint text)
reconcile_evidence(o text, w text, e text, r text, s text, worker text, lease bytea, version bigint, generation uuid, checksum text, fingerprint text)
reconcile_release(o text, w text, e text, r text, s text, worker text, lease bytea, version bigint, generation uuid, delay integer, checksum text, fingerprint text)
reconcile_settle(o text, w text, e text, r text, s text, worker text, lease bytea, version bigint, generation uuid, snapshot jsonb, proof bytea, checksum text, fingerprint text)
```

Claims contain scope/run/step, link version, generation and lease expiry; heartbeat
returns replacement values. Evidence envelope contains the exact linked Attack
Lab run/attempt, source and input bindings, cleanup state, versioned artifact
key/version/checksum/size and cancellation/uncertainty state. The client strictly
decodes these, never treating missing fields as completed proof. Settlement
proof schema is `security-agent-attack-lab-verification-v1`; its fields are
outcome, reason, verdict, exact execution/attempt identity, artifact identity,
cleanup_complete and SHA256 digest. JSON bytes and exact snapshot are retained
for retry; a new receipt cannot overwrite a conflicting previous settlement.

- [ ] Add focused restart tests against the current controller before changing it. Distinguish lost Create reply while DB remains leased from lost MarkRunning reply after commit. Proxy egress requires durable running; running recovery must observe the same UID without Create. Include disappeared/expired Jobs and cleanup retries. Do not substitute a fake call-count assertion for actual database/proxy authority.
- [ ] Keep dispatch pending until the existing controller reaches authoritative terminal/cleanup state. Stop blocks new dispatch and requests cancellation through a guarded shared core. Parent stop/duration/budget expiry must not discard unresolved execution or cleanup tracking.
- [ ] Implement the dedicated client/poller with replacement heartbeat lease state, fair scope iteration, bounded backoff and exact settlement retry. Read only the pinned artifact version; verify checksum, length and decoded scope/source/run/attempt/input bindings before proving a verdict.
- [ ] Encode the outcome table from the design directly. Complete/verified and complete/not_reproduced both settle to Needs human with distinct safe explanations, never generic EvaluateRunOutcome remediation. Unknown/mismatched evidence is Inconclusive; cleanup status stays visible. Confirmed cancellation plus cleanup is Cancelled; pre-execution denial is Failed; queued/running/cleanup-pending remains pending.
- [ ] Grant only versioned Attack Lab artifact reads, matching KMS decrypt and own DSN secret. No SQS, Kubernetes/provider invocation, writes/deletes, other buckets or other DSNs. Give DB role no action-execution/core/table access. Reject ambient worker authority mixing in actual config loaders.
- [ ] Add explicit57 rendering/CLI coexistence with audit, test reconciliation and compliance. Render own CSI DSN, projected token, health/readiness, bounded resource/replica/HPA/PDB settings, DNS, explicit database/STS/S3 network scope and monitoring. Validate additive policies/RBAC and exact startup commands, not only expected resource names. Keep56 and default49 controls; reject58.
- [ ] Use registered-role PostgreSQL and actual client/provider transport for lost settlement reply, lease expiry, worker restart, source/artifact drift, foreign scope, revoked permissions, cancellation races and cleanup lag. Unknown external state must retain obligations and never start a new agent execution.
- [ ] Run one affected integration/race batch covering admission and settlement, actual rendered Go loaders and full migration/registration command chain. Freeze evidence; infrastructure source/mock declarations are not provider evaluation or live proof. Do not run uncached Terraform mocks.

## Task 3: User workflow, connected acceptance and publication gate

**Modify:** `app/features/securityagents/SecurityAgentsView.tsx`, `ActionDetails.tsx`, existing run/approval views; `openapi/openapi.yaml`, generated `apps/web/api/generated.ts`, strict `decoders.ts`; mounted API composition/catalog checks and connected browser harness under `scripts/`. Add `services/platform/agentsec-api/attack_lab_action_composition_test.go` and focused UI tests alongside the touched views. Use repository generators for generated contracts.

**Consumes:** exact reference,57 capability, projected approval snapshot and linked execution/evidence/cleanup from Tasks1/2. **Produces:** the real user flow and catalog availability only when its required runtime path is configured and ready. No new arbitrary-input action endpoint.

- [ ] Extend the exact-test picker to start_attack_lab with verification kind attack_lab_run. Show unavailable preflight safely, exact approved source/version/attempt and nonprod target. Keep both autonomy modes' explicit operator approval. Remove demo-only success paths for this action.
- [ ] Render linked source/execution/attempt/evidence and cleanup states using current tenant-authorized product reads. Label reproduced unsafe behavior and not-reproduced bounded results honestly; never claim a finding was remediated. Reloads and stopped-parent views retain cleanup obligations.
- [ ] Mounted real repository tests cover draft/activate/trigger/approval/dispatch/poll/detail, capability absent/malformed, stale source/version, foreign scope and both mandatory-floor autonomy modes. Assert production-write refusal leaves the actual job/outbox/effect tables unchanged.
- [ ] Run a composed local browser flow with actual mounted API, worker, dedicated reconciler, registered database roles and controlled provider: choose test, trigger, inspect approval, approve as distinct authorized principal, execute, inspect outcome/evidence/cleanup, reload and attempt foreign-scope access. Capture provider call count across restart and lost acknowledgements. Mark controlled provider evidence local, not live Fargate/hostile-code acceptance.
- [ ] Enable production catalog only after connected availability checks and the preceding paths are implemented. Preserve legacy client/API compatibility. A present but corrupt57 capability fails closed; absence can preserve historical supported behavior without enabling the new action.
- [ ] Run one final connected feature batch and independent spec/quality review. Fix findings with focused RED/GREEN and one affected re-review; reuse unchanged evidence. Full UI/test/type/lint/build is mandatory against exact publication sources before any push.
- [ ] Update original M7A-22 evidence in the authoritative TSV/status files and run `node scripts/implementation-status-check.mjs`. Keep component-only until approved provider scope/credentials, deployed sandbox canary, hosted exact-source CI/advisory and production acceptance are verified. Continue M7A-23 and M7A-24 afterwards; do not substitute this feature for the remaining728-task goal.

## Coverage check and execution ruling

Task1 implements definition/preflight/source/approval/durable admission and
release safety. Task2 implements actual execution recovery, stop/cleanup,
immutable evidence, settlement and deployment authority. Task3 implements the
user workflow, full connected proof and publication boundary. Every design
section maps to one of these tasks. Fixed interfaces above travel with each
task brief; files may be split further by responsibility, but not into weaker
acceptance claims. The source-audit restart concern is a test requirement,
not permission to replace the controller without a reproduced defect.

Execution choice is already authorized: one implementer at a time with
independent review. Use inline execution if agent capacity is unavailable.
Plans and tests do not constitute live production completion.
