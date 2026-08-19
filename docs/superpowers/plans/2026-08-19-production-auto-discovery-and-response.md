# Production Automatic Discovery and Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to execute this plan,
> `superpowers:test-driven-development` for every behavior change,
> `superpowers:verification-before-completion` before completion claims, and
> `superpowers:requesting-code-review` after each task.

**Goal:** Promote every v1.5 microtask from proof/component status to an
authorized, durable, deployable product behavior and finish the automatic
discovery, sensor/runtime, and Security Agent workflows users need.

**Architecture:** PostgreSQL v10/v11 is the transactional authority; S3 stores
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

**Microtask promotion scope:** `M3-03`–`M3-13`, `M3-23`–`M3-44`, the
discovery/storage portions of `M1-11`–`M1-16`, `M1-22`, `M1-30`–`M1-34`,
`M2-20`–`M2-33`, and their production persistence dependencies.

**Steps:**

1. Define exact canonical IDs, source ownership, complete-snapshot semantics,
   state transitions, lease rules, idempotency, and outbox envelopes in failing
   repository and migration tests.
2. Add v10 tables, RLS, constraints, indexes, typed functions, checksum,
   semantic fingerprint, readiness, locked upgrade, and data-aware down guard.
3. Implement strict PostgreSQL repositories for integration, sync, snapshot,
   inventory, evidence, sensor, runtime job, and outbox operations.
4. Implement atomic complete-snapshot apply with last-good preservation,
   source-owned tombstones, cursor commit, and derived-projection work records.
5. Prove replay, concurrency, restart, stable keysets, hostile data, drift,
   rollback, and cross-scope nondisclosure on disposable PostgreSQL.

**Gate:** focused and full migration/repository race tests plus disposable-
PostgreSQL lifecycle and `git diff --check`.

---

### Task 3: Compose provider authorization, queues, storage, and discovery workers

**Outcome:** A user can authorize a provider and request a real asynchronous
sync whose evidence is archived and whose complete snapshot becomes durable
inventory.

**Primary files:**

- Create: `services/platform/jobqueue/sqsdriver/*`
- Create: `services/platform/artifactstore/s3driver/*`
- Create: `services/platform/eventstore/opensearchdriver/*`
- Create: `services/platform/connectors/nango/*`
- Create: `services/platform/connectors/awsdiscovery/*`
- Modify: `services/platform/agentsec-worker/*`
- Modify: `services/platform/apiserver/composition.go`
- Modify: `services/platform/apiserver/production.go`
- Modify: `services/platform/agentsec-api/production_runtime.go`
- Modify: `openapi/openapi.yaml`

**Microtask promotion scope:** `M3-09`–`M3-21`, `M3-45`–`M3-47`, provider
driver and queue/storage component tasks from M0–M2, excluding only evidence
that inherently requires externally supplied live credentials.

**Steps:**

1. Add contract tests for SQS, S3, OpenSearch, Neo4j, Nango, AssumeRole,
   Cartography, and Prowler production adapters, including acknowledgements,
   deadlines, cancellation, redaction, and no ambient credentials.
2. Promote proof drivers into production packages and add strict runtime
   configuration and secret-reference loading.
3. Add transactional outbox publisher, visibility extension, bounded
   concurrency, retry classification, drain, DLQ inspection, and redrive.
4. Implement discovery collection, immutable evidence upload, strict parsing,
   atomic reconciliation, graph/search/risk projection, completion, and ACK-last.
5. Mount authorize, callback/connection status, sync, history, freshness, and
   redacted failure operations with exact OpenAPI/runtime/client parity.
6. Prove failures after every durable stage resume without duplicate effects
   and preserve last-good inventory.

**Gate:** driver contracts, worker race/integration tests, real PostgreSQL plus
production-equivalent queue/storage/index/graph proof, OpenAPI parity, full Go
race, and secret scan.

---

### Task 4: Replace generic inventory payloads with typed discovery reads

**Outcome:** Overview, agents, tools, identities, runtimes, findings, and paths
are derived from the authoritative discovered snapshot rather than seeded JSON
payloads.

**Primary files:**

- Modify: `services/platform/apiserver/production.go`
- Create: `services/platform/apiserver/inventory_repository.go`
- Modify: `services/platform/reconciliation/*`
- Modify: `services/platform/migrations/sql/0010_production_discovery.up.sql`
- Modify: `scripts/production-combined-e2e.mjs`

**Microtask promotion scope:** component-only reconciliation, capability,
inventory, risk, search, and graph tasks in M2/M4/M5 that are required by the
public production inventory and posture routes.

**Steps:**

1. Add failing typed repository and handler tests for all current inventory
   response shapes, source observations, evidence, confidence, freshness, and
   exact-scope keysets.
2. Replace `zasp_core_payloads` inventory reads with typed v10 queries while
   retaining unrelated compatibility payloads during migration.
3. Project complete snapshots into the existing v9 risk model and graph/search
   retry records without dual authority.
4. Add hostile multi-source add/change/remove tests, malformed projection
   fail-closed tests, and restart/cross-tenant coverage.
5. Update the combined browser proof to obtain inventory only through an
   actual sync, never direct inventory seed insertion.

**Gate:** focused repository/handler/decoder tests, 1,002-row stable pagination,
browser sync-to-inventory proof, full Go race and frontend verify.

---

### Task 5: Ship sensor enrollment, event ingest, runtime processing, and enforcement

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

**Microtask promotion scope:** `M3-27`–`M3-44`, `M3-50`, `M3-51`, `M6-19`–
`M6-25`, and required runtime evidence/correlation tasks.

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

**Gate:** real PostgreSQL plus queue/S3/OpenSearch proof, gateway and worker race
tests, private-auth abuse tests, browser sensor journey, and full release checks.

---

### Task 6: Add v11 durable Security Agent execution authority and APIs

**Outcome:** Simulations, plans, runs, steps, approvals, verification, cleanup,
and audit survive restart and are authorized at each state transition.

**Primary files:**

- Create: `services/platform/migrations/sql/0011_security_agent_execution.up.sql`
- Create: `services/platform/migrations/sql/0011_security_agent_execution.down.sql`
- Modify: `services/platform/migrations/migrations.go`
- Create: `services/platform/apiserver/security_agent_repository.go`
- Create: `services/platform/apiserver/security_agent_handler.go`
- Modify: `services/platform/apiserver/composition.go`
- Modify: `openapi/openapi.yaml`

**Microtask promotion scope:** `M7A-05`–`M7A-14`, `M7A-29`–`M7A-49`,
`M7A-61`–`M7A-76`, and their exact authorization, audit, receipt, and migration
dependencies.

**Steps:**

1. Add failing lifecycle tests for definition versions, simulation, plan hash,
   triggers, run/step state, approval freshness/expiry, cancellation, replay,
   and terminal invariants.
2. Add immutable v11 schema, RLS, typed functions, fingerprint/readiness, and
   locked data-aware rollback.
3. Implement exact-scope PostgreSQL repositories and atomic request/receipt/
   audit/outbox boundaries.
4. Mount simulation, plan, action, run, approval, status, and audit operations
   with current capability/fresh-auth/CSRF/PAT semantics.
5. Prove restart, true concurrent same-key replay, role/scope loss,
   authorization-before-replay, hostile plan/evidence references, and cleanup.

**Gate:** focused and full race tests, real PostgreSQL lifecycle/concurrency,
OpenAPI/generated-client parity, and composition inventory.

---

### Task 7: Compose Security Agent triggers, actions, approvals, and verifiers

**Outcome:** The production worker can safely execute the supported Security
Agent response catalog and prove or fail each outcome without fabricated
success.

**Primary files:**

- Modify: `services/platform/securityagent/*`
- Modify: `services/platform/agentsec-worker/*`
- Modify: `services/platform/policy/*`
- Create: `services/platform/securityagent/postgres_*`
- Create: `services/platform/securityagent/provider_*`

**Microtask promotion scope:** `M7A-15`–`M7A-28`, `M7A-35`–`M7A-60`,
`M7A-91`–`M7A-101`, plus M5/M6 policy and runtime triggers required by the
execution path.

**Steps:**

1. Port the memory engine contracts to repository interfaces and v11 records.
2. Implement deterministic trigger dedupe, planning, evidence binding,
   authorization recheck, lease/heartbeat, action idempotency, cancellation,
   approval pause/resume, verifier, cleanup, and terminal audit.
3. Implement the supported provider action adapters with fixed destinations,
   secret references, dry-run/simulation boundaries, bounded timeouts, and
   explicit retry/unknown-outcome handling.
4. Add scheduler loops for triggers, approval expiry, lease recovery,
   verification, and cleanup; drain without abandoning unsafe work.
5. Prove reversible containment, mandatory approval, role loss, provider
   ambiguity, replay, cancellation, cleanup precedence, and cross-tenant
   isolation against real durable state.

**Gate:** engine/worker race tests, real PostgreSQL and provider-contract
integration, failure injection, audit-chain validation, and no-secret scans.

---

### Task 8: Connect every production discovery and response UI workflow

**Outcome:** Users can complete connector, sync, inventory, sensor, simulation,
approval, run, and verification workflows from the production frontend.

**Primary files:**

- Modify: `app/features/connectors/*`
- Modify: `app/features/workflows/*`
- Modify: `app/features/sensors/*`
- Modify: `app/features/agents/*`
- Modify: `app/components/ZaspProductionApp.tsx`
- Modify: `docs/product/ui-api-map.yaml`

**Microtask promotion scope:** `M3-48c2`–`M3-51`, `M7A-84`, `M7A-86`–
`M7A-90`, and any remaining component-only production frontend tasks in M4/M7.

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

### Task 9: Deploy every production data-plane workload with least privilege

**Outcome:** The release chart and infrastructure deploy the exact runtime that
implements discovery, sensors, runtime processing, and Security Agent actions.

**Primary files:**

- Create/modify: `deploy/production/Dockerfile.*`
- Modify: `deploy/staging/product/templates/*`
- Modify: `deploy/staging/*.tf`
- Modify: `deploy/production/release-contract.*`
- Modify: `deploy/production/release-gates.*`
- Modify: `docs/operations/*`

**Microtask promotion scope:** `M8-09a`–`M8-14`, `M8-57a`–`M8-57`, and the
component-only deployment/observability/operations tasks required by the new
workloads.

**Steps:**

1. Add separately buildable, non-root, read-only compatible, digest-pinned
   images for discovery/outbox worker, runtime worker, event-ingest, runtime
   gateway, and isolated provider tools.
2. Render private workloads/services with exact probes, resources, drain,
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

### Task 10: Prove the complete platform and finish the 728-task ledger

**Outcome:** One owned production-equivalent environment proves automatic
discovery, sensor/runtime processing, and Security Agent response through the
built UI; every v1.5 task has truthful final evidence or an exact external gate.

**Primary files:**

- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `deploy/production/release-gates.mjs`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/internal/implementation_production_availability_v1.5.tsv`
- Create/modify: production runbooks and release evidence

**Microtask promotion scope:** all remaining component-only and missing tasks;
external tasks move only when their real named evidence is obtained.

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
8. Update every ledger row with exact commit/test/deployment evidence. Keep
   legitimately external cloud/provider/public-release gates explicit until
   exercised; do not translate them into false completion.
9. Merge/push reviewed batches to `main` and verify remote CI after each push.

**Final gate:** zero Critical/Important/Minor review findings, clean tracked
tree, exact ledger coverage, all local production gates green, main pushed, and
remote CI green. Live external gates must either be green with references or
remain visibly blocked with the exact authority/input required.

