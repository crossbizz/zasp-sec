# Production Automatic Discovery and Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to execute this plan,
> `superpowers:test-driven-development` for every behavior change,
> `superpowers:verification-before-completion` before completion claims, and
> `superpowers:requesting-code-review` after each task.

**Goal:** Promote every v1.5 microtask from proof/component status to an
authorized, durable, deployable product behavior and finish the automatic
discovery, sensor/runtime, and Security Agent workflows users need.

**Architecture:** PostgreSQL v10/v11/v12 is the transactional authority; S3 stores
immutable evidence; SQS transports deterministic jobs through a transactional
outbox; OpenSearch and Neo4j are rebuildable projections. Separate least-
privilege API, discovery worker, runtime worker, event-ingest, and runtime-
gateway workloads serve one capability-gated, API-backed production UI.

**Design:**
`docs/superpowers/specs/2026-08-19-production-auto-discovery-and-response-design.md`

## Delivery Rules

- The 728-task v1.5 plan remains the source-of-scope. Every task retains its
  historical implementation evidence and gains a separate production-
  availability classification.
- Execute one coherent task at a time through implementer, specification
  review, quality review, correction, and verification. Do not parallelize
  implementation against the shared worktree.
- Start behavior changes with a focused failing test and retain the regression.
- Use immutable forward migrations, exact semantic fingerprints, and guarded
  down migrations. Never edit a released migration.
- Do not add a production UI affordance until its durable operation and every
  dependency are composed and ready.
- Do not store credentials or product authority in browser storage, memory
  repositories, fixtures, queues, logs, or derived projections.
- Commit atomic slices and push reviewed, fully green batches to `main`.

## Dependency DAG and Capability Barriers

| Task | Depends on | Produces | Capability barrier | Rollback boundary |
| --- | --- | --- | --- | --- |
| 1 | audited base | exact 728-row ownership/evidence manifest | none | documentation/validator only |
| 2 | 1 | v10 discovery/runtime authority | no new public capability | guarded v10 schema down |
| 3 | 2 | first-party connector and credential adapters | authorization only when exact provider dependency is ready | revoke reference/session; no snapshot mutation |
| 4 | 2, 3 | outbox, scheduler, discovery/projection workers and their inert deployment slice | sync/history/schedule per dependency readiness | last-good snapshot preserved |
| 5 | 2, 4 | v11 backfill/validate/cutover and typed inventory | inventory only after equivalence validation | app rollback to compatible reader; guarded schema down |
| 6 | 2, 4 | sensors, ingest, runtime worker/gateway and their inert deployment slice | sensor/runtime capability per workload readiness | revoke device/token; preserve archived evidence |
| 7 | 2, 5 | inert v12 SA authority, activation and kill switches | simulation only; execution stays killed | guarded v12 down before effects |
| 8 | 4, 7 | structured planning, supervised low-risk action and inert action-worker deployment | one action at a time after verifier/readiness | action reconciliation/compensation |
| 9 | 6, 8, 14 | supervised containment, per-action deployment, and evidence-backed autonomy | per-action owned canary and kill switch | TTL cleanup + effect reconciliation |
| 10 | 3–9 | API-backed discovery/runtime/SA UI | server capability plus dependency readiness | hide control; durable state retained |
| 11 | 1, 2 | production SSO/SCIM/group administration | each provider/webhook after live dependency readiness | local session deprovision reconciliation |
| 12 | 2, 4 | Red Team test worker/artifacts/UI and inert deployment slice | isolated target and artifact readiness | cancel/reconcile job; retain evidence |
| 13 | 2, 4, 12 | Attack Lab sandbox worker/UI and isolated deployment slice | isolated Fargate/network/cleanup readiness | destroy owned sandbox only |
| 14 | 2, 4, 11–13 | exports, retention, deletion, external flow, AI/telemetry and their worker slices | per-operation provider/policy readiness | deletion epoch/audit and artifact grants |
| 15 | 2–14 | consolidated release topology, hardening and shared infrastructure | deploy ready does not auto-enable actions | Helm/app rollback within schema window |
| 16 | 2–15 | backup/restore/upgrade/DR proof | consumers held until reconciliation | restore epoch; never undo external effects |
| 17 | 1–16 | complete owned E2E and final ledger | only externally validated features claim release-ready | reviewed commits and documented external gates |

---

### Task 1: Correct the 728-task production-availability ledger

**Outcome:** The repository reports historical component completion and actual
production availability separately, with machine-checked exact coverage of all
728 source IDs.

**Primary files:**

- Modify: `docs/internal/implementation_status_v1.5.md`
- Create: `docs/internal/implementation_production_availability_v1.5.tsv`
- Create: `scripts/implementation-status-check.mjs`
- Create: `scripts/implementation-status-check.test.mjs`
- Modify: `package.json`
- Modify: `.github/workflows/runnable-ui.yml`

**Microtask promotion scope:** all 728 tasks are classified; no task is
declared production-available from a component-only or external proof.

**Steps:**

1. Add a failing validator test for missing, duplicate, unknown, invalid-state,
   and count-drift rows.
2. Add one TSV row for every exact plan ID with milestone, historical status,
   production class, owning production task, and current evidence.
3. Correct the ledger headline and milestone matrix to the audited
   `229 production-available / 425 component-only / 61 external / 13 missing`
   baseline.
4. Wire the validator into local verification and required CI.
5. Review the map against source composition, UI capability inventory,
   executable behavior, migrations, chart, and release contract.

**Gate:** focused validator tests, validator execution, root type/lint checks,
`git diff --check`, independent ledger review.

---

### Task 2: Add v10 discovery/runtime authority and transactional outbox

**Outcome:** Integrations, syncs, snapshots, canonical inventory, evidence,
sensors, runtime batches, jobs, and outbox events are durable and exactly
scoped in the production migration chain.

**Primary files:**

- Create: `services/platform/migrations/sql/0010_production_discovery.up.sql`
- Create: `services/platform/migrations/sql/0010_production_discovery.down.sql`
- Modify: `services/platform/migrations/migrations.go`
- Create: `services/platform/apiserver/discovery_repository.go`
- Create: `services/platform/apiserver/discovery_repository_test.go`
- Create: `services/platform/apiserver/discovery_postgres_test.go`

**Microtask promotion scope:** exactly the manifest rows owned by
`T02-discovery-authority`. Other milestone tasks are dependencies, not shared
promotion ownership.

**Steps:**

1. Define exact canonical IDs, source ownership, complete-snapshot semantics,
   state transitions, lease rules, idempotency, and outbox envelopes in failing
   repository and migration tests.
2. Add v10 tables, RLS, constraints, indexes, typed functions, checksum,
   semantic fingerprint, readiness, locked upgrade, and data-aware down guard.
3. Implement strict PostgreSQL repositories for integration, sync, snapshot,
   inventory, evidence, sensor, runtime job, outbox, and distinct gateway
   device/enrollment/credential/policy-subscription operations.
4. Implement atomic complete-snapshot apply with last-good preservation,
   source-owned tombstones, cursor commit, and derived-projection work records.
5. Prove replay, concurrency, restart, stable keysets, hostile data, drift,
   rollback, and cross-scope nondisclosure on disposable PostgreSQL.

**Gate:** focused and full migration/repository race tests plus disposable-
PostgreSQL lifecycle and `git diff --check`.

---

### Task 3: Implement first-party launch connectors and credential lifecycles

**Outcome:** Users can authorize AWS, Kubernetes, GitHub, and the launch IdP
through first-party paths, while explicitly catalogued long-tail connectors use
private Nango without becoming a core readiness dependency.

**Primary files:**

- Create: `services/platform/connectors/nango/*`
- Create: `services/platform/connectors/awsdiscovery/*`
- Create: `services/platform/connectors/kubernetesdiscovery/*`
- Create: `services/platform/connectors/githubdiscovery/*`
- Create: `services/platform/connectors/idpdiscovery/*`
- Modify: `services/platform/apiserver/composition.go`
- Modify: `services/platform/apiserver/production.go`
- Modify: `services/platform/agentsec-api/production_runtime.go`
- Modify: `openapi/openapi.yaml`

**Microtask promotion scope:** exactly the manifest rows owned by
`T03-launch-connectors`. Queue/storage components owned by Task 4 are inputs,
not shared promotion scope. Evidence that inherently requires live credentials
retains its typed external gate.

**Steps:**

1. Define a connector matrix for first-party AWS, Kubernetes, GitHub, and the
   chosen launch IdP: auth, collection, normalization, evidence, health,
   degradation, and provider-specific scopes.
2. Add a credential-class matrix covering creator, metadata reader, resolver,
   rotation/revocation, KMS/storage, TTL, audit, deletion, and prohibited sinks.
3. Add a public state-bound OAuth return with PKCE, one-time replay protection,
   current session/scope reauthorization, safe redirects, and no URL token.
4. Implement bounded first-party adapters and strict parsers. Keep Nango
   private and limited to long-tail Auth + Proxy connectors.
5. Prove core connectors continue to authorize/collect when Nango is unhealthy,
   and prove connection-create unknown outcomes reconcile without duplicates.

**Gate:** provider contract tests, callback security tests, exact secret-leak
matrix, runtime configuration/readiness, OpenAPI parity, and no ambient
credentials.

---

### Task 4: Compose outbox, discovery scheduling, storage, and projection workers

**Outcome:** Authorized integrations run durable manual or scheduled syncs;
complete snapshots become authoritative before independently retryable derived
projections.

**Primary files:**

- Create: `services/platform/jobqueue/sqsdriver/*`
- Create: `services/platform/artifactstore/s3driver/*`
- Create: `services/platform/eventstore/opensearchdriver/*`
- Modify: `services/platform/agentsec-worker/*`
- Modify: `services/platform/apiserver/composition.go`
- Modify: `openapi/openapi.yaml`

**Microtask promotion scope:** exactly the manifest rows owned by
`T04-discovery-worker`.

**Steps:**

1. Promote production SQS/S3/OpenSearch/Neo4j drivers with exact ack, timeout,
   cancellation, checksum, scope, and failure contracts.
2. Add outbox publication, visibility heartbeats, retry/DLQ classification,
   bounded fair claims, per-organization quotas, and graceful drain.
3. Implement provider collection, raw evidence upload, strict complete-snapshot
   parsing, atomic reconciliation, completion, and ACK-last.
4. Persist deterministic projection-work rows with the snapshot transaction;
   run risk/graph/search projection asynchronously without recollection.
5. Implement a multi-replica discovery scheduler with leases, deterministic
   keys, cadence/time zone/missed-run behavior, and disable/delete races.
6. Mount sync/history/freshness/schedule operations only when their exact
   worker/dependency readiness is true.
7. Inject crashes and unknown outcomes at every stage; prove no duplicate
   effects and last-good retention.
8. Build and render inert discovery/outbox and projection worker images,
   workload-specific identities, queues, secrets, private networking, drain,
   metrics, and alerts before the first owned canary.

**Gate:** driver contracts, worker race/integration tests, real PostgreSQL plus
production-equivalent queue/storage/index/graph proof, OpenAPI parity, full Go
race, and secret scan.

---

### Task 5: Cut over generic records to typed discovery inventory

**Outcome:** Overview, agents, tools, identities, runtimes, findings, and paths
are derived from the authoritative discovered snapshot rather than seeded JSON
payloads.

**Primary files:**

- Modify: `services/platform/apiserver/production.go`
- Create: `services/platform/apiserver/inventory_repository.go`
- Modify: `services/platform/reconciliation/*`
- Create: `services/platform/migrations/sql/0011_discovery_cutover.up.sql`
- Create: `services/platform/migrations/sql/0011_discovery_cutover.down.sql`
- Modify: `scripts/production-combined-e2e.mjs`

**Microtask promotion scope:** exactly the manifest rows owned by
`T05-inventory-cutover`. Search and ticket behaviors owned by Task 14 remain
dependencies rather than overlapping scope.

**Steps:**

1. Add failing expand/backfill/equivalence/cutover tests for generic integration
   workflow records and inventory payload rows; define the minimum compatible
   application version and read-only compatibility projection.
2. Add failing typed repository and handler tests for all current inventory
   response shapes, source observations, evidence, confidence, freshness, and
   exact-scope keysets.
3. Replace `zasp_core_payloads` inventory reads with typed v10 queries while
   retaining unrelated compatibility payloads during migration.
4. Project complete snapshots into the existing v9 risk model and graph/search
   retry records without dual authority.
5. Add hostile multi-source add/change/remove tests, malformed projection
   fail-closed tests, and restart/cross-tenant coverage.
6. Update the combined browser proof to obtain inventory only through an
   actual sync, never direct inventory seed insertion.

**Gate:** focused repository/handler/decoder tests, 1,002-row stable pagination,
browser sync-to-inventory proof, full Go race and frontend verify.

---

### Task 6: Ship sensor enrollment, event ingest, runtime processing, and enforcement

**Outcome:** A sensor enrolls once, heartbeats, submits bounded runtime events,
and produces durable archived/indexed/correlated evidence while the runtime
gateway enforces signed policy from its local cache.

**Primary files:**

- Modify: `services/platform/sensor/*`
- Modify: `services/event-ingest/*`
- Modify: `services/platform/runtimeevent/*`
- Modify: `services/runtime-gateway/*`
- Modify: `services/platform/agentsec-worker/*`
- Modify: `openapi/openapi.yaml`

**Microtask promotion scope:** exactly the manifest rows owned by
`T06-runtime-data-plane`.

**Steps:**

1. Replace memory sensor state with the v10 repository and test one-time token,
   hash-only persistence, rotation, revocation, heartbeat, coverage, and scope.
2. Mount public sensor management APIs and the separate private ingest listener
   with server-side token-to-scope resolution and strict rate/body/type bounds.
3. Publish runtime batches transactionally and compose archive, index,
   correlation, projection, completion, and ACK-last worker stages.
4. Compose runtime-gateway enrollment, signed policy fetch/cache, HTTP/MCP
   evaluation, metadata evidence, offline behavior, and bounded drain.
5. Inject failures after each stage and prove deterministic replay, no duplicate
   event/audit, no cross-scope token use, and immediate rotation/revocation.
6. Build and render inert event-ingest, runtime-worker, and runtime-gateway
   images with separate identities, private APIs, queues, policies, resources,
   drain, metrics, and alerts before the owned runtime canary.

**Gate:** real PostgreSQL plus queue/S3/OpenSearch proof, gateway and worker race
tests, private-auth abuse tests, browser sensor journey, and full release checks.

---

### Task 7: Add inert v12 Security Agent authority, activation, and APIs

**Outcome:** Simulations, plans, runs, steps, approvals, verification, cleanup,
and audit survive restart and are authorized at each state transition.

**Primary files:**

- Create: `services/platform/migrations/sql/0012_security_agent_execution.up.sql`
- Create: `services/platform/migrations/sql/0012_security_agent_execution.down.sql`
- Modify: `services/platform/migrations/migrations.go`
- Create: `services/platform/apiserver/security_agent_repository.go`
- Create: `services/platform/apiserver/security_agent_handler.go`
- Modify: `services/platform/apiserver/composition.go`
- Modify: `openapi/openapi.yaml`

**Microtask promotion scope:** exactly the manifest rows owned by
`T07-security-agent-authority`.

**Steps:**

1. Add failing migration tests that quarantine every legacy `enabled=true`
   definition into exact persisted `draft` state and cannot execute on deploy.
2. Add global, organization, environment, and per-action kill switches plus an
   explicit fresh-auth audited `draft -> validated -> supervised -> autonomous`
   activation state machine.
3. Add failing lifecycle tests for definition versions, simulation, plan hash,
   triggers, run/step state, approval freshness/expiry, cancellation, replay,
   and terminal invariants.
4. Add immutable v12 schema, RLS, typed functions, fingerprint/readiness, and
   locked data-aware rollback.
5. Backfill/validate/cut over generic Security Agent definition records without
   dual authority; retain only an inert compatibility projection.
6. Implement exact-scope PostgreSQL repositories and atomic request/receipt/
   audit/outbox boundaries.
7. Mount definition/activation/simulation metadata operations; keep every
   execution action absent while the global execution kill switch is active.
   with current capability/fresh-auth/CSRF/PAT semantics.
8. Prove restart, true concurrent same-key replay, role/scope loss,
   authorization-before-replay, hostile plan/evidence references, and cleanup.

**Gate:** focused and full race tests, real PostgreSQL lifecycle/concurrency,
OpenAPI/generated-client parity, and composition inventory.

---

### Task 8: Ship structured simulation and one supervised low-risk action

**Outcome:** Production supports durable simulation and one explicitly selected
supervised internal low-risk action, with no other action advertised.

**Primary files:**

- Modify: `services/platform/securityagent/*`
- Modify: `services/platform/agentsec-worker/*`
- Modify: `services/platform/policy/*`
- Create: `services/platform/securityagent/postgres_*`
- Create: `services/platform/securityagent/provider_*`

**Microtask promotion scope:** exactly the manifest rows owned by
`T08-supervised-agent`. Policy/runtime/Red Team/Attack Lab/data-workflow tasks
remain explicit dependencies owned by their verticals.

**Steps:**

1. Port memory engine contracts to v12 repository interfaces and add a separate
   structured planner adapter; do not weaken the free-form AI governor.
2. Implement deterministic trigger dedupe, planning, evidence binding,
   authorization recheck, lease/heartbeat, action idempotency, cancellation,
   approval pause/resume, verifier, cleanup, and terminal audit.
3. Implement one supervised internal low-risk adapter with fixed destinations,
   secret references, dry-run/simulation boundaries, bounded timeouts, and
   explicit retry/unknown-outcome handling.
4. Add a dedicated Security Agent action-worker process/queue/identity plus
   scheduler loops for triggers, approval expiry, lease recovery,
   verification, and cleanup; drain without abandoning unsafe work.
5. Prove simulation has zero effects; then prove the one action's mandatory
   supervision, role loss, provider
   ambiguity, replay, cancellation, cleanup precedence, and cross-tenant
   isolation against real durable state.

**Gate:** engine/worker race tests, real PostgreSQL and provider-contract
integration, failure injection, audit-chain validation, and no-secret scans.

---

### Task 9: Promote reversible containment and remaining actions individually

**Outcome:** Each Security Agent action becomes visible only after its own
authorization, idempotency, reconciliation, verification, cleanup, dependency,
deployment, and canary evidence is green.

**Primary files:**

- Modify: `services/platform/securityagent/*`
- Modify: `services/platform/agentsec-action-worker/*`
- Modify: `services/platform/policy/*`
- Modify: `docs/product/security-agent-action-readiness.tsv`

**Microtask promotion scope:** exactly the manifest rows owned by
`T09-agent-actions`, with cross-task dependencies on Red Team, Attack Lab,
export, webhook, ticket, connector revocation, and runtime policy owners.

**Steps:**

1. Add a server-enforced action readiness manifest; unsupported actions are
   absent from catalog, planner schema, capability, and UI.
2. Promote one supervised reversible TTL-bounded containment action only after
   runtime policy distribution, independent verification, compensation, and
   cleanup are deployed.
3. Promote test, Attack Lab, export, webhook/ticket, and connection-revocation
   actions only after Tasks 11–14 complete their corresponding verticals.
4. Add separate per-action provider keys/digests, unknown-outcome reconcilers,
   approval floors, fresh-auth separation of duties, verifiers, compensators,
   kill switches, alerts, and canaries.
5. Allow autonomous mode only for a separately canaried reversible action with
   quotas, durable budgets, TTL cleanup, and immediate kill-switch proof.
6. Each promoted action owns its exact action-worker image/role/network/secret
   delta and must deploy inert before its owned canary; Task 15 only consolidates
   and hardens the already-proven slices.

**Gate:** one independent review and owned canary per action; unsupported
actions remain unadvertised; full cross-scope and failure-injection matrix.

---

### Task 10: Connect every production discovery and response UI workflow

**Outcome:** Users can complete connector, sync, inventory, sensor, simulation,
approval, run, and verification workflows from the production frontend.

**Primary files:**

- Modify: `app/features/connectors/*`
- Modify: `app/features/workflows/*`
- Modify: `app/features/sensors/*`
- Modify: `app/features/agents/*`
- Modify: `app/components/ZaspProductionApp.tsx`
- Modify: `docs/product/ui-api-map.yaml`

**Microtask promotion scope:** exactly the manifest rows owned by
`T10-product-ui`.

**Steps:**

1. Add strict generated-client adapters and decoders with bounded pagination,
   cancellation, exact cache keys, and durable receipt recovery.
2. Implement connector authorize/test/sync/schedule/history/freshness and
   last-good/degraded UI.
3. Implement typed inventory observation/evidence/change detail.
4. Implement sensor one-time enrollment, copy/ack, rotation/revocation,
   heartbeat, coverage, drop, and degraded UI.
5. Implement Security Agent simulation, plan, approval, progress, cancel,
   verification, cleanup, and audit backlinks.
6. Prove capability/permission/fresh-auth loss synchronously hides and
   transport-blocks actions; abort every obsolete request.
7. Remove corresponding production demo/store imports and reject them in the
   source and compiled dependency graphs.

**Gate:** focused accessibility/security/state tests, 3 viewports, strict
type/lint/build, source/compiled graph checks, and installed-browser journeys.

---

### Task 11: Compose SSO, SCIM, group mapping, and identity administration

**Outcome:** The component identity administration work is a durable,
provider-faithful production workflow, including deprovisioning and group
authorization effects.

**Microtask promotion scope:** exactly the manifest rows owned by
`T11-identity-admin`.

**Steps:** implement typed provider connections, verified callbacks/webhooks,
SCIM lifecycle, atomic deprovision/session revocation, validated group mapping
effects, provider revalidation/degraded behavior, durable API/UI, restart and
cross-scope tests, and honest external provider gates.

**Gate:** real PostgreSQL/provider-contract/browser proof plus fresh-auth,
replay, deprovision, and tenant-isolation tests.

---

### Task 12: Ship Red Team tests and the isolated test worker

**Outcome:** Users can configure, run, cancel, retry, and inspect supported Red
Team tests through durable queued execution and immutable evidence.

**Microtask promotion scope:** exactly the manifest rows owned by
`T12-red-team`.

**Steps:** add durable schema/API, bounded Promptfoo/test runner, queue/outbox,
artifact evidence, idempotent replay/cancel/reconcile, least-privilege worker,
API-backed UI, and real browser/restart/cross-scope proof. No arbitrary targets,
shell, prompts, or egress are accepted.

The task also builds/renders its inert worker image, queue, role, network,
resources, drain, metrics, and alert slice before the owned canary.

**Gate:** worker failure matrix, S3 evidence checks, provider budget/redaction,
browser journey, owned deployment/canary, and security review.

---

### Task 13: Ship Attack Lab isolated sandbox execution

**Outcome:** Attack Lab runs only inside an owned disposable sandbox with exact
network, identity, cleanup, evidence, and cancellation boundaries.

**Microtask promotion scope:** exactly the manifest rows owned by
`T13-attack-lab`.

**Steps:** add durable run state and outbox, exact Fargate profile/task identity,
fixed image/argv, non-production target guard, default-deny plus declared egress,
bounded lifetime, independent cleanup, evidence artifacts, API/UI, and hostile
escape/cross-tenant tests.

**Gate:** owned sandbox execution with complete cleanup and zero production-
write identity, plus full API/browser/deployment gates.

---

### Task 14: Ship exports, retention/deletion, external flows, telemetry, AI, search, and tickets

**Outcome:** Remaining M4/M7 workflows use durable bounded jobs, grants,
providers, and truthful production UI instead of component-only proofs.

**Microtask promotion scope:** exactly the manifest rows owned by
`T14-data-workflows`.

**Steps:** implement signed artifact grants and export jobs; retention/deletion
epochs across PostgreSQL/S3/OpenSearch/Neo4j with audit/holds; guarded external-
flow mutation; bounded consent-aware telemetry; provider-safe AI explanations;
typed search/ticket APIs and UI; replay/expiry/revocation/restart/security tests.
Build and render each required inert worker/provider deployment slice before
its owned canary.

**Gate:** real durable/provider contracts, no-secret/PII/PHI egress tests,
browser workflows, lifecycle cleanup, and independent review.

---

### Task 15: Deploy every production data-plane workload with least privilege

**Outcome:** The release chart and infrastructure consolidate and harden the
already owned/deployed vertical slices into one exact production topology.

**Primary files:**

- Create/modify: `deploy/production/Dockerfile.*`
- Modify: `deploy/staging/product/templates/*`
- Modify: `deploy/staging/*.tf`
- Modify: `deploy/production/release-contract.*`
- Modify: `deploy/production/release-gates.*`
- Modify: `docs/operations/*`

**Microtask promotion scope:** exactly the manifest rows owned by
`T15-deployment`.

**Steps:**

1. Verify every vertical's separately buildable, non-root, read-only compatible,
   digest-pinned image and reject any missing or duplicate workload authority.
2. Consolidate private workloads/services with exact probes, resources, drain,
   PDBs, topology, autoscaling, default-deny networking, and workload-specific
   service accounts.
3. Add least-privilege Terraform roles for each workload and exact queue,
   object prefix, KMS, secret, index, database, Nango, and Neo4j access.
4. Deploy or bind private durable Nango and Neo4j dependencies and the
   customer-edge sensor/gateway profile without control-plane credentials.
5. Add bounded metrics, SLOs, queue/DLQ/sync/freshness/drop/correlation/action
   alerts, runbooks, backup/restore, and release/preflight validation.
6. Prove public ingress exposes only web and `/api/v1`, while internal/provider
   services remain unreachable externally.

**Gate:** image definitions and owned builds, SBOM/license/CVE/signature gates,
Helm lint/render, Terraform fmt/validate/static IAM, release contracts,
NetworkPolicy tests, full secret/history scans, and clean rollback proof.

---

### Task 16: Prove backup, restore, upgrade, rollback, and operational recovery

**Outcome:** Recovery preserves authority and never replays a completed queue
publication or external effect.

**Microtask promotion scope:** exactly the manifest rows owned by
`T16-recovery-ops`; truly live/customer/cloud observations retain typed
external gates.

**Steps:**

1. Define backup manifests binding PostgreSQL recovery position, S3 versions,
   schema/app compatibility, projection rebuild cursors, and expected counts.
2. Restore only to disposable/authorized targets with all consumers and queues
   held; assign a new restore epoch.
3. Reconcile published/completed outbox rows, action effects, approval resumes,
   unknown outcomes, leases, and temporary controls before any worker starts.
4. Prove completed effects never replay, unknown effects require reconciliation,
   cleanup remains scheduled, and projections rebuild from authority.
5. Prove forward upgrade, compatible app rollback, data-guarded schema down,
   provider-effect non-rollback, backup/restore RPO/RTO, diagnostics, canary,
   and operator runbooks.

**Gate:** disposable recovery rehearsal, crash matrix, exact counts/evidence,
no external side-effect replay, clean independent cleanup, and review.

---

### Task 17: Prove the complete platform and finish the 728-task ledger

**Outcome:** One owned production-equivalent environment proves automatic
discovery, sensor/runtime processing, and Security Agent response through the
built UI; every v1.5 task has truthful final evidence or an exact external gate.

**Primary files:**

- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `deploy/production/release-gates.mjs`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/internal/implementation_production_availability_v1.5.tsv`
- Create/modify: production runbooks and release evidence

**Microtask promotion scope:** proof and ledger closure only. Task 17 cannot own
an unimplemented product behavior. External tasks move only when their named
real evidence is obtained.

**Steps:**

1. Build an owned production-equivalent topology with real migrated
   PostgreSQL, queue, S3-compatible evidence, OpenSearch, Neo4j, Nango, all Go
   workloads, built web, TLS, and installed browser.
2. Prove connect/authorize/sync, immutable evidence, last-good failure,
   1,002-row pagination, multi-source removal, restart, and cross-scope denial.
3. Prove sensor enroll/heartbeat/ingest/archive/index/correlation, rotation,
   revocation, replay, and gateway enforcement.
4. Prove Security Agent simulate/plan/fresh-auth approval/run/action/verification/
   cleanup, ambiguity recovery, cancellation, audit, and role/scope loss.
5. Inject crashes after every durable boundary; prove resume, ACK-last, no
   duplicates, no leaks, and complete owned cleanup.
6. Run full Go race, frontend verification/build, OpenAPI/client/UI-map parity,
   migrations, release render, source/compiled graph, audit, SBOM/license,
   Gitleaks, accessibility, responsive browser, and diff/status gates.
7. Obtain independent whole-range review, repair every finding, and rerun the
   affected plus final gates.
8. Update every ledger row with exact commit/test/deployment evidence and its
   single production owner. External rows record authority/owner, input,
   environment, safe procedure, expected evidence URI/digest, expiry, and
   recheck rule. Keep
   legitimately external cloud/provider/public-release gates explicit until
   exercised; do not translate them into false completion.
9. Merge/push reviewed batches to `main` and verify remote CI after each push.

**Final gate:** zero Critical/Important/Minor review findings, clean tracked
tree, exact ledger coverage, all local production gates green, main pushed, and
remote CI green. Live external gates must either be green with references or
remain visibly blocked with the exact authority/input required.
