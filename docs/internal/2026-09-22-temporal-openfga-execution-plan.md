# Temporal OSS and OpenFGA Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` for grouped execution with checkpoints. The user's instruction to execute this change is authorization; no additional architecture approval round is needed. Do not test Temporal or OpenFGA internals. Use TDD for our application behavior only.

**Goal:** Replace custom durable orchestration and permission evaluation with Temporal OSS and OpenFGA while retaining Stytch and every original product requirement.

**Architecture:** Temporal controls execution; existing executors perform actions through scoped transactional adapters. OpenFGA evaluates product permissions backed by synchronized identity/grant data. Product PostgreSQL retains tenant isolation, transactional authorization fences, receipts, audit and API projections.

**Tech Stack:** Existing Go 1.25 platform and React UI; official Temporal Go SDK/server/chart; official OpenFGA Go SDK/server/CLI; PostgreSQL; Stytch; existing OPA and provider clients.

**Spec:** `docs/internal/2026-09-22-temporal-openfga-design.md`.

## Global constraints

- Preserve all 728 IDs and acceptance requirements in the original v1.5 plan. This is an architecture amendment, not a replacement product scope.
- Keep the existing authoritative ledger and its production-available, component-only and blocked/external distinctions. This plan's packets are implementation groupings, not 728 new task rows.
- Keep the UI runnable on every push to main under the existing release rules.
- No vendor internals, conformance, repeated lease-expiry, or exhaustive upstream failure matrices. Test our model, adapters and product contracts only.
- One RED/GREEN/refactor cycle per meaningful behavior group. Review the complete deliverable. Repeat checks only for changed code, failures or unresolved concerns.
- Current working tree has extensive user-owned changes. Do not reset, blanket-stage, overwrite, or create a clean checkout that silently omits required uncommitted dependencies.
- No reset/drop of shared DB state. Use disposable test databases; preserve applied historical migrations and evidence.
- Versions must be pinned from actual compatible releases in P1. Do not assume every feature on current docs exists in an older deployed version.
- No implementation or acceptance claim has been made by this planning handoff.

## Task and status ledger

| Packet | Deliverable | Dependencies | Initial status |
| --- | --- | --- | --- |
| P0 | Baseline, original-task crosswalk and deletion inventory | none | pending |
| P1 | Pinned Temporal/OpenFGA runtime and configuration | P0 | pending |
| P2 | Product-to-Temporal start/message boundary | P1 | pending |
| P3 | Ordered Security Agent execution and cleanup | P2 | pending |
| P4 | Discovery/sync schedules and remaining workflow routing | P3 | pending |
| P5 | FGA model and stable principal/resource mapping | P0, P1 | pending |
| P6 | Grant synchronization and revocation fence | P5 | pending |
| P7 | FGA enforcement across production API and workers | P3, P6 | pending |
| P8 | Product UI/API acceptance and workflow coverage | P4, P7 | pending |
| P9 | Remove obsolete implementations and tests | P8 | pending |
| P10 | Deployment, external acceptance and final ledger | P9 | pending |

Main thread owns execution. Temporal P2-P4 is the first critical path. FGA P5-P7 is a separate bounded track; avoid overlapping edits to shared files. Other unaffected work can continue. Stop adding features to scheduler64 and worker63 immediately after recording their checkpoint.

## P0: reconcile scope once

**Files:** read original v1.5 PRD/plan, `docs/internal/implementation_status_v1.5.md`, both `implementation_production_availability*_v1.5.tsv` files, old ordered-multistep design/plan and `.superpowers/sdd/2026-09-20-security-agent-ordered-multistep-plan/progress.md`. Create `docs/internal/2026-09-22-temporal-openfga-crosswalk.tsv` and `docs/internal/2026-09-22-temporal-openfga-retirement.tsv`.

- [ ] Record current branch/HEAD and changed paths. Reconcile pending review findings once; carry product bugs forward, retire findings solely about code being removed.
- [ ] Build crosswalk columns `original_id`, `requirement`, `packet`, `existing_evidence`, `new_acceptance`, `production_class`. Include each of the original 728 IDs exactly once; use `unaffected` where appropriate. A task may map to several packet IDs in one cell. Do not silently drop queue/provider requirements that Temporal does not satisfy.
- [ ] Explicitly map M2 role/grant/auth requirements, M3 discovery/sync, M7/M7A approvals/actions/exports, deployment/recovery and all affected owner groups. In particular M7A-23 export and M7A-49 ordered execution do not become available from the platform installation alone.
- [ ] Build retirement inventory columns `path_or_symbol`, `callers`, `replacement`, `domain_invariants_to_keep`, `retire_after`, `status`. Trace Go callers AND stored procedure calls, grants, migration fingerprints, CLI routing and deployment config. Separate shared helpers from scheduler-only helpers.
- [ ] Mark unfinished custom scheduler implementation tasks superseded by these packets, retaining their evidence and original acceptance criteria. Add links to the main status ledger. Do not change production totals on planning evidence.

Verification: existing status validator and a set comparison of crosswalk IDs against the original task ledger. No new test framework or docs snapshot tests. Commit only this amendment and required ledger changes.

## P1: supply dependencies with the consuming configuration

**Files:** modify `services/platform/go.mod`, `go.sum`, `build/dependencies.lock.yaml`, worker/API runtime config; create `deploy/local/temporal-openfga.compose.yaml`, `deploy/staging/temporal-openfga.values.yaml`, `docs/operations/temporal-openfga.md`; connect existing staging manifests and secret references.

- [ ] Select and pin compatible stable server, SDK, CLI and chart releases from official releases; record exact versions/digests and supported configuration in the operations document. Use the official Go SDKs; no home-grown service clients.
- [ ] Configure Temporal persistence plus SQL visibility and a separate OpenFGA datastore/role. Development may share a PostgreSQL instance with separate databases; record resource isolation choices for staging/production. Use upstream migration tools for their databases.
- [ ] Add private authenticated endpoints, TLS outside local development, secret references, readiness, metrics, backup ownership, retention and operator-only service UIs. Keep credentials and resource bodies out of service logs/history. Assign concrete resource requests and pool limits after sizing the target; previous chat estimates are not a measured capacity plan.
- [ ] Add configuration for Temporal namespace/task queues and FGA endpoint/store/model. Production cannot default to fake implementations or an unauthenticated local endpoint.

Verify manifest rendering, dependency checks and one connection/readiness smoke per configured service. Do not test upstream migration algorithms or retry machinery. Missing external credentials remain recorded gates, with local work continuing.

## P2: close the SQL-to-Temporal delivery gap

**Files:** create `services/platform/orchestration/{contracts,temporal_client,outbox}.go` and `outbox_test.go`; add the next unused additive product migration through the existing registry; modify `apiserver/security_agent_manual_start.go`, admission entry points, `agentsec-api/production_runtime.go`, `agentsec-worker/production_runtime.go`.

New package contract (reuse equivalent existing domain types when possible):

```go
type RunRef struct { OrganizationID, WorkspaceID, EnvironmentID, RunID string }
type StartRequest struct { Ref RunRef; DefinitionVersion int64; InputDigest string }
type Message struct { Ref RunRef; EventID, Kind, DecisionID string }
type Engine interface {
    Start(context.Context, StartRequest) error
    Notify(context.Context, Message) error
}
```

`Start` returning nil means accepted or the identical existing execution, not business completion. A conflicting input digest is a product error. `Notify` is duplicate-safe at the product decision boundary.

- [ ] RED: product admission persists exactly one command in the same transaction; two deliveries of it target one workflow identity; same business key/different digest is refused; tenant mismatch cannot dispatch. Test our outbox/client request mapping, not Temporal dedup internals.
- [ ] GREEN: implement deterministic scoped workflow IDs, explicit reuse/conflict policy, finite RPC deadlines and idempotent outbox acknowledgement. Keep the outbox relay small and independently able to deliver when Temporal recovers. Map Temporal results to existing API status/receipt contracts.
- [ ] Route approvals and cancellation using committed product decision IDs and an outbox notification. Temporal receives wake-up hints; Activities read and validate the authoritative decision. Requests must not imply cleanup is complete.
- [ ] Group the new adapter tests with affected admission/API tests; review once and record evidence.

## P3: move the current Security Agent critical path

**Files:** create `services/platform/orchestration/{security_agent_workflow,activities,cleanup}.go`, `security_agent_workflow_test.go`, `activities_test.go`; extract reusable business executors from `agentsec-worker/security_agent_release61_loop.go`, `security_agent_action_runtime.go`, release61 runner/application/cleanup files; add narrow activity repository operations under `apiserver` or a shared repository package. Modify runtime composition.

`SecurityAgentWorkflow(workflow.Context, StartRequest) error` owns ordering. Activities load/admit the plan, await validated approval through product decisions, apply a policy, run the existing test, persist verified receipts and clean up. Inputs reference product objects and immutable plan versions. Effect identity is product scope/run/step/generation.

- [ ] RED group: unapproved or stale plans perform no external action; only a verified predecessor unlocks its successor; cancellation still reaches cleanup; permission loss blocks a new effect; cleanup cannot target another scope; repeating our executor with the same effect key does not duplicate the effect.
- [ ] Use SDK workflow test environment/time skipping for these product choices. Use existing bounded provider fakes to verify our requests and receipts. Do not reproduce Temporal scheduling, persistence, retry, replay-engine or timer correctness tests.
- [ ] GREEN: implement deterministic workflow control flow, explicit Activity timeouts/retry policies and heartbeats for long work. DB, provider, FGA, secrets and signing calls belong in Activities. Classified permanent validation/permission errors must not retry forever.
- [ ] Extract legacy executor functionality without requiring scheduler64/worker63 lease tokens. Retain atomic tenant/version/approval/budget/effect validation and receipts. For providers without effect-key support, use existing lookup/reconciliation or mark an ambiguous result for recovery before allowing another effect.
- [ ] Implement cancellation cleanup using a disconnected context and a narrow compensation authority; preserve cleanup-pending and failed/unknown outcome semantics. Keep budget release idempotent.
- [ ] Wire one complete actual API -> Temporal worker -> product receipt -> API read path. Disable the old selector for migrated runs so two executors cannot own the same run.

Review this behavior packet once. Run focused race tests only where we changed shared-memory code; run relevant product PostgreSQL tests once for the packet.

## P4: auto-discovery/sync and workflow family coverage

**Files:** create `services/platform/orchestration/{discovery_workflow,schedules}.go` and `discovery_workflow_test.go`; modify `agentsec-worker/{scheduler_runtime,discovery_composition,discovery_queue,discovery_cloud}.go`, `apiserver/discovery_execution_repository.go`, schedule API composition and the workflow inventory from P0.

- [ ] RED group: two tenants with identically named connectors cannot share schedule/run identity; disable stops future sync; manual and periodic sync retain required overlap behavior; repeated collection pages do not duplicate product inventory; checkpoint resume preserves provider cursor and tenant.
- [ ] GREEN: use Temporal Schedules and explicit overlap/catch-up choices; reconcile schedule desired state from product configuration; reuse actual discovery collectors and scoped inventory writers. Service-principal authority must survive the login session that originally created the connector while still honoring connector revocation.
- [ ] Route all existing trigger forms into the common product admission path: manual, scheduled, finding/event, webhook, attack-path and approved action. Preserve specialized behavior and budgets from the original plan.
- [ ] For each remaining family in P0 (red-team/tests, exports, cleanup/recovery), either migrate its custom durable job orchestration with the same adapters or record the concrete still-needed engine and why. Do not declare the orchestration replacement complete with migrated Security Agent flows but stranded jobs. Retain required SQS/event-stream uses with an explicit original-task mapping.

Run our scheduling/configuration and discovery contract tests as one group. One real-dependency product sync scenario proves the registration and wiring; no separate vendor Schedule conformance suite.

## P5: permissions model and identity mapping

**Files:** create `services/platform/authorization/{checker,openfga,mapping}.go`, `mapping_test.go`, `model.fga`, `model.fga.yaml`; read `identity/roles.go`, `apiserver/{production,router,middleware,repository}.go`, identity-administration SQL and original PRD permission requirements.

```go
type CheckRequest struct {
    PrincipalKind, PrincipalID string
    OrganizationID, WorkspaceID, EnvironmentID string
    ResourceType, ResourceID, Permission string
}
type Decision struct { Allowed bool; ModelID string }
type Checker interface { Check(context.Context, CheckRequest) (Decision, error) }
```

Only trusted server code constructs scope/resource bindings. Provider references remain in the existing principal mapping; FGA subjects use canonical product principal IDs. Do not invent Stytch memberships for agents or PATs.

- [ ] RED: encode expected business allow/deny examples from the PRD for six roles, two organizations, workspace/environment boundaries, direct resource access and delegated agents. These are tests of our model, not OpenFGA's evaluator. Resolve known map disagreements before activation, with a short written rationale.
- [ ] GREEN: implement the model and mapping with one validated parent per resource, a pinned model/store, canonical IDs and no cross-organization grants unless explicitly in scope. Ensure all operation permissions in production router and capabilities have a model relation.
- [ ] Publish/seed only to a development instance initially, record model ID, then run the grouped application permission examples using the supported CLI/SDK. Do not generate exhaustive relationship-graph engine tests.

## P6: permission changes, synchronization and revocation

**Files:** create `services/platform/authorization/{projection,reconcile}.go`, `projection_test.go`; add additive product migration for desired/applied authorization revisions and tuple outbox; modify `apiserver/identity_administration_repository.go`, bootstrap/grant writes and existing Stytch webhook integration.

- [ ] RED group: grant is unavailable until projected; pending/revoked membership is denied immediately; reordered events cannot restore a deleted membership; crash between tuple write and acknowledgement is replayable; the applied revision never advances over missing work; switching model requires a matching projection generation.
- [ ] GREEN: serialize desired-state reconciliation per organization using existing transactional/outbox primitives. Increment desired revision on permission-affecting changes. Set applied revision only after all writes for that revision/model succeed. Replays converge on current desired state. Do not implement a second generic workflow scheduler for tuple delivery.
- [ ] Reconcile provider events with authoritative Stytch membership where necessary. Keep immediate SQL session/PAT deactivation. Record unsupported/unverified provider event delivery as a gate; a signed local fixture is not live Stytch proof.
- [ ] Provide a one-time bootstrap/reconcile command with progress and retry, without destructive reseeding. Reuse it for repair. Monitor pending revision age and blocked organizations.

One grouped PostgreSQL/adapter test run verifies our revision and outbox contract. Do not test OpenFGA replication, cache eviction or persistence internals.

## P7: enforce through the live production boundaries

**Files:** modify `apiserver/{repository,middleware,router,production,composition,identity_administration_repository}.go`, relevant list/search/export handlers and mutation SQL, API/worker composition; create `apiserver/authorization_openfga.go` and `authorization_openfga_test.go`.

- [ ] RED group: direct API calls cannot bypass UI permissions; PAT permissions intersect current user grants; revocation after Check invalidates a mutation before commit; dependency failure fails closed; list/search/export counts and objects obey scope; queued actions recheck current authority before an effect; compensation remains narrowly authorized after user deactivation.
- [ ] GREEN: invoke the checker in actual request and Activity paths. Use HIGHER_CONSISTENCY initially and no stale positive cache. Verify desired=applied revision/model, Check outside the DB transaction, then revalidate revision and resource version under the transaction lock used by grant updates. Preserve CSRF/fresh-auth, PAT restrictions and RLS.
- [ ] Derive UI permissions from the same active decision policy. Preserve API error and pagination contracts. Resolve authorization list filtering before exposing counts or cursors.
- [ ] Compare the new model with intended permissions on a bounded fixture/staging matrix. On mismatch fix our model or mapping. After switching, remove old allow fallback and union logic. Leave product relational data and row guards in place.

Review all API and worker paths together. Do not use passing `identity/authorization.go` unit tests as proof the production router uses FGA.

## P8: one application acceptance batch

**Files:** adapt `scripts/production-combined-e2e.mjs` or add a focused mode; update generated API contracts only if changed; update actual UI capability/status handling in `app/api/APIProvider.tsx`, Security Agent and integration screens; extend the existing application tests.

- [ ] Login through Stytch, select scope, connect an integration, discover/sync inventory, start an agent run, approve the exact action, observe receipts, cancel another run, and observe cleanup. A second tenant must fail direct API/resource access.
- [ ] Include one bounded worker restart during our application flow to check activity registration and durable product status mapping. Check duplicate provider request handling at our executor boundary. Do not kill/rebuild Temporal clusters to re-prove vendor durability.
- [ ] Exercise a permission revoke and an FGA outage through our API, checking fail-closed behavior and recovery after projection catches up. Reuse real FGA model examples; do not build a vendor failure matrix.
- [ ] Use fixtures for unavailable external providers during local development and label evidence accurately. Repeat the relevant flow with real providers in P10. The UI must report pending/unavailable honestly without demo fallbacks.

Run this batch once per completed candidate; repeat affected scenarios after a material fix. Short summaries link to artifacts and commits, without copying thousands of log lines into the ledger.

## P9: delete superseded code

**Files:** retirement candidates include `agentsec-worker/security_agent_scheduler64.go`, `security_agent_worker63.go`, `security_agent_release61_loop.go`, their caller loops, scheduler-specific Go/PostgreSQL tests and runtime wiring. Release61 SQL requires operation-by-operation analysis. Historical `0061`/`0063`/`0064` migrations stay if applied; add a new retirement migration and update readiness/registration accordingly.

- [ ] Require every retirement inventory row to name a working replacement and retained domain assertions. Retire application-level obsolete tests only after those assertions exist at the new boundary.
- [ ] Remove active polling/lease orchestration and unreachable helpers; revoke retired SQL worker privileges and disable old selectors. Keep domain admission, budgets, RLS, receipts and provider-specific safety. No blanket deletion by filename prefix.
- [ ] Remove obsolete custom role evaluation from active paths after P7. Keep role metadata/source grants and transactional revision validation. Remove old runtime selectors/config flags that would allow accidental dual execution.
- [ ] Verify fresh database install and supported development upgrade once. Retain historical migration regression coverage appropriate to migrations still shipped; do not call historical bytes deletion necessary for runtime code removal.
- [ ] Inspect reference searches, compile, grouped product tests and runnable UI on the staged candidate. Commit only scoped changes; preserve unrelated dirty files.

## P10: production and authoritative completion

**Files:** existing staging/production manifests, `docs/operations/temporal-openfga.md`, release gates and authoritative status/evidence ledgers.

- [ ] Configure durable storage, backups, service auth/TLS, limited worker credentials, restricted administrative UIs, metrics, alerts, connection pools and deployment/version policy. Allocate isolated production datastores and verify required operations access.
- [ ] Run actual Stytch login, real permitted connector sync, Security Agent action/approval/cleanup and tenant isolation through the deployed UI/API. Record endpoint, artifact references, code/model/image versions and exact unavailable external prerequisites.
- [ ] Keep pending external gates distinct from local component completion. Reclassify original tasks only against their acceptance criteria. Preserve 728 IDs and milestone coverage; list every unmet gate.
- [ ] Push verified changes to main under the user's existing authorization. Each push gets runnable-UI build/typecheck plus affected tests and the existing required CI checks. Do not bypass required release checks; revise obsolete scheduler-only gates with the same reviewed replacement packet.

## Revised TDD and command policy

Use representative product cases, not one test/review round for every line or configuration field. Existing domain tests count; do not duplicate them to satisfy a new packet label.

During iteration run the selected behavior tests only, for example after the named packages/tests exist:

```sh
go test -C services/platform ./orchestration -run 'Test(StartDelivery|SecurityAgentWorkflow|DiscoveryWorkflow)' -count=1
go test -C services/platform ./authorization -run 'Test(PrincipalMapping|PermissionProjection)' -count=1
go test -C services/platform ./apiserver -run '^TestAuthorizationOpenFGA' -count=1
```

At a packet boundary run affected package tests and changed-SQL integration cases together. Use focused race testing for shared-memory changes. At each push run the actual repository build/typecheck commands and required CI. At final integration run existing `npm run verify` plus the new product integration batch, using project-supported environment setup. Handle legitimate missing credentials explicitly; do not mark skipped acceptance green.

Workflow timers use the SDK test environment's time skipping. SQL/real-provider tests use bounded relevant cases and synchronization barriers where appropriate; do not fake the clock for a DB guarantee whose behavior we changed. Preserve a direct tenant isolation assertion even when testing with a real FGA instance.

Trust the OSS dependency. Verify what we wrote: our workflow branching, our model, our service configuration and registration, our API enforcement, our transactions, our provider effect handling and our UI. No Temporal/OpenFGA internal tests are authorized or required by this plan.

## Plan self-review and handoff

Design coverage: orchestration P1-P4; identity/model/sync/enforcement P5-P7; user acceptance P8; retirement P9; live gates P10. Original-task completeness is checked by P0 and P10. Runtime security/OPA, tenant SQL, audit and provider correctness are explicitly retained.

All packet statuses are pending. The side conversation created this design/plan only. Main thread must update actual status as it executes and preserve the original status ledger as the completion authority. Start with P0/P1 and the current Security Agent critical path; do not spend another full gate cycle finishing custom scheduler composition before beginning this approved replacement.

## Main-thread goal

Complete and verify all 728 original microtasks in `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md` without reducing product scope, using the approved Temporal OSS/OpenFGA architecture amendment. Retain Stytch for identity. Implement Temporal orchestration and discovery/sync scheduling, OpenFGA permission enforcement in the actual production API and workers, and safely retire superseded custom orchestration and permission-evaluation code after equivalent product behavior is verified.

Preserve multi-tenancy, SQL isolation, automatic agent discovery/sync, security actions, approvals, budgets, audit/evidence, runtime policy and every original milestone. Use grouped Superpowers TDD and review for Zasp-owned behavior only; trust Temporal/OpenFGA and do not write tests of their internals. Keep the UI runnable and backed by real APIs on every verified push to main.

Maintain the existing authoritative docs/internal ledger with exact original-task mappings, production-available/component-only/blocked-external status and evidence. Completion means all original acceptance criteria and deployed end-to-end product flows are verified, including real Stytch and provider integrations. Local fixtures and component tests cannot satisfy live gates. Record external prerequisites honestly, continue independent authorized work, and report a concrete blocker when no safe in-scope progress remains. Never mark the goal complete with unmet requirements or blocked production gates.

Planning review boundary: source seams, upstream contracts, packet dependencies and retained safety requirements were checked. The main thread subsequently produced the exhaustive 728-ID crosswalk at `docs/internal/2026-09-22-temporal-openfga-crosswalk.tsv`. Current implementation and acceptance status is maintained in `docs/internal/implementation_status_v1.5.md` and its availability TSV; this planning checkpoint does not establish deployed acceptance.
