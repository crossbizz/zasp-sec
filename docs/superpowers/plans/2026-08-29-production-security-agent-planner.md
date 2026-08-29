# Production Security Agent Planner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compose the shipped Security Agent worker with a typed OpenRouter planner and prove planner outage records one bounded failure without executing actions or weakening runtime enforcement.

**Architecture:** PostgreSQL exposes a lease-fenced redacted planner context and remains the final action/target validator. The worker performs one bounded OpenRouter-compatible call, then submits either the strict candidate or a stable failure classification to new v32 database authority before releasing its lease.

**Tech Stack:** Go 1.24, PostgreSQL/PLpgSQL, AWS Secrets Manager CSI, Helm, Terraform, Node 22 production contract tests.

**Spec:** `docs/superpowers/specs/2026-08-29-production-security-agent-planner-design.md`

## Global Constraints

- Do not add a new service or action type.
- Never send raw evidence, credentials, PII, arbitrary URLs, or foreign-scope references to the planner.
- PostgreSQL must revalidate every returned action and target under the current live lease before creating plan state.
- Planner failure must create no plan, step, approval, effect, or action job.
- Use one provider attempt, no proxy, no redirect, bounded request/response bytes, and stable redacted errors.
- Existing runtime-gateway enforcement must remain independent of planner availability.
- Follow RED, verified RED, minimal GREEN, verified GREEN for every behavior change.

---

### Task 1: Typed OpenRouter planner boundary

**Files:**
- Create: `services/platform/agentsec-worker/security_agent_planner.go`
- Create: `services/platform/agentsec-worker/security_agent_planner_test.go`

**Interfaces:**
- Produces: `securityAgentPlanner.Plan(context.Context, apiserver.SecurityAgentPlannerContext) (apiserver.SecurityAgentPlannerCandidate, securityAgentPlannerFailure)`.
- Produces: `newProductionSecurityAgentPlanner(securityAgentPlannerConfig) (securityAgentPlanner, error)`.

- [ ] Write failing tests proving exact system/operator/untrusted separation, fixed purpose/model/policy, bearer token, 64 KiB response cap, strict candidate JSON, no redirect/proxy/retry, cancellation, and stable unavailable/rejected classification.
- [ ] Run `go test ./agentsec-worker -run SecurityAgentPlanner -count=1` and verify the missing planner implementation causes the RED.
- [ ] Implement the one-attempt hardened TLS client, request encoder, strict decoder, validation, and credential zeroization.
- [ ] Run `go test -race ./agentsec-worker -run SecurityAgentPlanner -count=1` and verify GREEN.
- [ ] Commit the two files as `feat(worker): add bounded security agent planner`.

### Task 2: v32 planner database authority

**Files:**
- Create: `services/platform/migrations/sql/0032_production_security_agent_planner.up.sql`
- Create: `services/platform/migrations/sql/0032_production_security_agent_planner.down.sql`
- Create: `services/platform/migrations/production_security_agent_planner_test.go`
- Modify: `services/platform/migrations/migrations.go`
- Modify: `services/platform/migrations/migrations_test.go`
- Modify: `services/platform/agentsec-migrate/main.go`
- Modify: `services/platform/agentsec-migrate/main_test.go`

**Interfaces:**
- Produces: `zasp_security_agent_planner_context(...)`, `zasp_security_agent_accept_planner_candidate(...)`, and `zasp_security_agent_fail_planner(...)`.
- Produces: migration accessors `ProductionSecurityAgentPlanner()` and `ProductionSecurityAgentPlannerSemanticFingerprint()`.

- [ ] Write migration and real-PostgreSQL REDs for exact context scoping/redaction, fail replay, accept replay, malformed/cross-tenant candidates, lease loss, one-row receipt authority, and zero plan/action state on unavailable failure.
- [ ] Run focused migration and PostgreSQL tests and verify missing v32 authority causes the RED.
- [ ] Implement v32 tables/functions/ACL/readiness/fingerprint/down restoration and repin the computed fingerprint only after semantic tests pass.
- [ ] Run focused migration, empty/v31-to-v32/down/re-up migrator, and real-PostgreSQL tests under race where supported.
- [ ] Commit the migration slice as `feat(migrations): add security agent planner authority`.

### Task 3: Repository and worker lease integration

**Files:**
- Modify: `services/platform/apiserver/security_agent_worker_repository.go`
- Modify: `services/platform/apiserver/security_agent_worker_repository_test.go`
- Modify: `services/platform/agentsec-worker/security_agent_runtime.go`
- Modify: `services/platform/agentsec-worker/security_agent_runtime_test.go`
- Modify: `services/platform/agentsec-worker/production_runtime.go`
- Modify: `services/platform/agentsec-worker/production_runtime_test.go`

**Interfaces:**
- Produces: `SecurityAgentPlannerContext`, `SecurityAgentPlannerCandidate`, `SecurityAgentPlannerFailure`, and authority methods `LoadSecurityAgentPlannerContext`, `AcceptSecurityAgentPlannerCandidate`, `FailSecurityAgentPlanner`.
- Consumes: Task 1 planner and Task 2 v32 SQL functions.

- [ ] Write failing repository and processor tests proving the planner runs only for unprepared claims, heartbeat stays active, unavailable and malformed results durably fail once, lease loss blocks mutation, accepted candidates enter existing prepare authority, and prepared claims never call the planner.
- [ ] Run the focused repository/worker tests and verify the new interface requirements cause the RED.
- [ ] Implement strict repository decoding and worker orchestration with panic-safe stable failure classification.
- [ ] Compose the production planner only for the v32 repository and reject earlier schema modes for `security-agent` startup.
- [ ] Run focused race tests and `go vet ./apiserver ./agentsec-worker`.
- [ ] Commit as `feat(worker): plan security agent runs through openrouter`.

### Task 4: Production configuration and deployment authority

**Files:**
- Modify: `services/platform/agentsec-worker/runtime_config.go`
- Modify: `services/platform/agentsec-worker/runtime_config_test.go`
- Modify: `deploy/staging/product/values.yaml`
- Modify: `deploy/staging/product/templates/workloads.yaml`
- Modify: `deploy/staging/product/templates/secrets.yaml`
- Modify: `deploy/staging/product/templates/resilience.yaml`
- Modify: `deploy/staging/main.tf`
- Modify: `deploy/production/release-contract.mjs`
- Modify: `deploy/production/release-contract.test.mjs`
- Modify: `deploy/staging/gate.mjs`
- Modify: `deploy/staging/gate.test.mjs`

**Interfaces:**
- Consumes: Task 1 production planner constructor.
- Produces: exact endpoint/model/token-file/timeout/token-limit/policy configuration and CIDR-bounded TCP/443 egress.

- [ ] Write failing runtime and rendered-release tests for every required planner field, exact token mount, two-secret CSI authority, exact Secrets Manager/KMS policy, endpoint/model binding, and bounded public CIDRs that cannot overlap database ranges.
- [ ] Run focused worker and Node release tests and verify the missing configuration/rendering causes the RED.
- [ ] Implement strict runtime parsing, Helm resources, Terraform secret/IAM authority, and network policy.
- [ ] Run focused race/vet, Node release/gate/preflight, Terraform fmt/validate/offline plan, Helm lint/render, and diff-check.
- [ ] Commit as `deploy(worker): authorize security agent planning`.

### Task 5: Source-complete degraded E2E and ledger promotion

**Files:**
- Modify: `services/platform/agentsec-worker/production_combined_e2e_test.go`
- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `scripts/production-combined-e2e.test.mjs`
- Modify: `docs/internal/implementation_production_availability_v1.5.tsv`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `scripts/implementation-status-check.mjs`
- Modify: `scripts/implementation-status-check.test.mjs`

**Interfaces:**
- Consumes: shipped v32 worker composition and local fake OpenRouter-compatible endpoint.
- Produces: honest production-available evidence for M7A-40, M7A-41, M7A-51, and M7A-91; hosted OpenRouter remains external-blocked.

- [ ] Write the E2E/static/ledger RED proving the current journey lacks a real composed planner-outage run and runtime-policy continuity assertion.
- [ ] Run focused Node and Go E2E tests and verify RED.
- [ ] Add a local 503 planner fixture, run the actual composed worker, assert one `failed|planner_unavailable` run, one redacted audit/receipt, zero plan/step/approval/effect rows, zero action-provider calls, and unchanged runtime block decision.
- [ ] Promote only the four exact rows with accurate local-versus-hosted evidence notes and audited counts.
- [ ] Run full combined installed-Chrome/disposable-PostgreSQL E2E, full focused Go race/vet, release contracts, ledger validator, secret scan, and diff-check.
- [ ] Request independent pre-landing review, fix all findings, commit as `feat(security-agent): fail closed when planner is unavailable`, and push `HEAD:main`.

## Self-review

- Every spec requirement maps to Tasks 1-5.
- The external planner is the only mocked boundary; all worker, database, action, runtime-policy, and release composition remains real.
- Type names and method signatures are consistent between Tasks 1-3.
- There are no placeholders or deferred implementation steps; hosted credential/live-provider proof remains an explicit external gate rather than implementation debt.
