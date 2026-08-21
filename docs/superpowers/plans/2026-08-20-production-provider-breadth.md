# Production Provider Breadth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete production collection and normalization for AWS, Kubernetes, GitHub, and Okta so an authorized sync cannot report complete until every required launch-provider phase has produced exact source-scoped entities, relationships, and evidence.

**Architecture:** Extend the existing job-bound provider clients and subject-bound cursor protocol. Go owns bounded AWS pagination, authorization failures, and completion. Two isolated Python 3.13 environments run exact-pinned Cartography transforms and fixed Prowler checks through separate closed length-delimited subprocess boundaries. Cartography never owns a shared Neo4j staging graph, and Prowler runs against the exact native snapshot through guarded in-memory clients. All results continue through the existing immutable raw-page, manifest-last, checkpoint/resume, complete-snapshot, posture-evidence, and independent projection path.

**Tech Stack:** Go 1.25, Python 3.13, Cartography 0.139.1, Prowler 5.39.1, AWS SDK v2, Kubernetes client-go, bounded HTTPS clients, PostgreSQL v16 authority, S3 artifact manifests, SQS discovery jobs.

**Spec:** `.superpowers/sdd/2026-08-19-production-auto-discovery-and-response/task-4-brief.md`

## Global Constraints

- Preserve exact Organization, Workspace, Environment, integration, provider subject, job, attempt, parser, tool, and cursor authority on every page.
- Never persist credentials, provider response headers, raw provider errors, Kubernetes Secrets, GitHub tokens, Okta tokens, or AWS session material.
- A provider returns Complete only after all required phases complete; byte/item/time exhaustion returns a durable Partial checkpoint.
- Raw pages are immutable and manifest-last; only a complete manifest may replace current inventory.
- Live provider and managed AWS evidence remains typed NOT RUN until real credentials and infrastructure are supplied.
- Do not amend migrations v10 through v16.
- Preserve the original provider breadth. Upstream isolation and pin corrections may expand implementation files, but may not remove inventory phases, findings, multi-tenant authority, or automatic sync behavior.

---

### Task 1: Expand the closed normalized provider schema

**Files:**
- Modify: `services/platform/connectors/internal/providercollection/client.go`
- Modify: `services/platform/connectors/internal/providercollection/client_test.go`
- Create: `services/platform/connectors/internal/providercollection/provider_schema_test.go`

**Interfaces:**
- Consumes: exact provider page `entities`, `relationships`, and evidence objects.
- Produces: closed allowlists for AWS policy/resource authority, Kubernetes identity/RBAC/workload authority, GitHub app/workflow/permission authority, and Okta membership/assignment/privilege authority.

- [ ] Write failing table-driven tests that submit each newly required kind and relationship through the real provider client, plus unknown-kind, unknown-field, secret-shaped, duplicate, dangling-edge, and cross-subject hostile cases.
- [ ] Run `go test ./connectors/internal/providercollection -run 'TestProviderSchema' -count=1` and confirm the required kinds fail because the current allowlists reject them.
- [ ] Add only the exact new kinds, scalar fields, relationship kinds, and evidence schema required by M3-17 through M3-20.
- [ ] Rerun the focused package test and `go test -race ./connectors/internal/providercollection ./connectors/collection -count=1`.

### Task 2: Complete Kubernetes, GitHub, and Okta phase machines

**Files:**
- Modify: `services/platform/connectors/kubernetesdiscovery/collection_api.go`
- Modify: `services/platform/connectors/kubernetesdiscovery/collection_api_test.go`
- Modify: `services/platform/connectors/githubdiscovery/collection_api.go`
- Modify: `services/platform/connectors/githubdiscovery/collection_api_test.go`
- Modify: `services/platform/connectors/idpdiscovery/collection_api.go`
- Modify: `services/platform/connectors/idpdiscovery/collection_api_test.go`

**Interfaces:**
- Consumes: `collection.PageRequest` with exact subject-bound cursor lineage and remaining budgets.
- Produces: `collection.Page` sequences that remain partial until the final provider phase and emit only canonical product-owned kinds.

- [ ] Write failing Kubernetes tests for namespaces, service accounts, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, deployments, StatefulSets, DaemonSets, Jobs, CronJobs, workload-service-account edges, and RBAC subject/role edges.
- [ ] Verify the Kubernetes RED against the current namespace/deployment-only implementation, then implement one bounded API call per phase with opaque continuation binding and explicit Secret rejection.
- [ ] Write failing GitHub tests for installation, organizations, repositories, GitHub Apps, Actions workflows, environment/repository permissions, and exact app/workflow/repository edges.
- [ ] Verify the GitHub RED, then implement bounded fixed-endpoint phases with installation-subject attestation and no write-capable token acceptance.
- [ ] Write failing Okta tests for users, groups, group memberships, applications, app assignments, admin roles/privileges, and service principals.
- [ ] Verify the Okta RED, then implement bounded tenant-pinned phases with exact Link parsing and subject-bound continuation tokens.
- [ ] Run race and vet for the three provider packages and the shared collection registry.

### Task 3: Add the production Cartography and Prowler runner boundary

**Files:**
- Modify: `workers/security-python/pyproject.toml`
- Create: `workers/security-python/security_worker/protocol.py`
- Create: `workers/security-python/security_worker/cartography_aws.py`
- Create: `workers/security-python/security_worker/prowler_aws.py`
- Modify: `workers/security-python/security_worker/__main__.py`
- Create: `workers/security-python/tests/test_protocol.py`
- Create: `workers/security-python/tests/test_cartography_aws.py`
- Create: `workers/security-python/tests/test_prowler_aws.py`
- Create: `services/platform/connectors/awsdiscovery/security_runner.go`
- Create: `services/platform/connectors/awsdiscovery/security_runner_test.go`
- Modify: `deploy/production/worker.Dockerfile`
- Modify: `scripts/build-repo.mjs`
- Modify: `scripts/build-repo.test.mjs`
- Modify: `scripts/validate-dependencies.mjs`
- Modify: `scripts/validate-dependencies.test.mjs`
- Modify: `build/dependencies.lock.yaml`

**Interfaces:**
- Produces Python commands `security-worker cartography-aws-v1` and `security-worker prowler-aws-v1`. Each reads one canonical length-delimited request from stdin and writes one canonical length-delimited response to stdout from its own dependency environment.
- Produces Go `SecurityRunner.Collect(context.Context, CollectionSecurityRequest, []byte) (CollectionSecurityResult, error)` with cloned/cleared credential bytes, bounded child lifetime, fixed executable/arguments, and stable typed failures.

- [x] Write Python RED tests for exact protocol keys, version binding, scope/subject/job binding, byte/count limits, timeout/cancellation, unknown output, duplicate objects, secret-bearing output, and redacted errors.
- [x] Add isolated, hash-locked Python 3.13 dependency environments for `cartography==0.139.1` and `prowler==5.39.1`; prove clean install and exact import/version identity for both.
- [x] Import only reviewed Cartography pure transforms. Reject any Cartography sync/load/cleanup/Neo4j/socket path.
- [x] Execute fixed Prowler checks over the exact bounded native IAM/EC2 snapshot using guarded clients; never invoke Prowler's eager provider scan or swallowed-error collection path.
- [x] Write Go RED tests for stdin-only credentials, no environment credential propagation, exact executable/arguments, bounded stdout/stderr, cancellation, panic, malformed output, and zeroized request material.
- [x] Implement the Go runner adapter and map failures to `collection.FailureCancelled`, `FailureRetryable`, `FailureRateLimited`, `FailureDenied`, or `FailureMalformed`.
- [x] Run Python unit tests, dependency validation, Go race, vet, and focused secret-safe subprocess gates for the runner boundary.
- [ ] Build the production worker image with two non-root Python environments and prove exact interpreter, package, SBOM, license, and CVE authority.

### Task 4: Complete AWS collection and normalization

**Files:**
- Modify: `services/platform/connectors/awsdiscovery/collection_api.go`
- Modify: `services/platform/connectors/awsdiscovery/collection_api_test.go`
- Modify: `services/platform/agentsec-worker/discovery_clients.go`
- Modify: `services/platform/agentsec-worker/discovery_clients_test.go`

**Interfaces:**
- Consumes: exact STS-attested AWS account subject and `SecurityRunner` output.
- Produces: account, roles, policies, resources, services, trust/attachment/ownership edges, and Prowler evidence; identity-only output is Partial, never Complete.

- [ ] Write failing tests proving identity-only output is partial and exact complete output requires Cartography graph plus Prowler evidence.
- [ ] Write two-Organization tests with identical native ARNs proving distinct product IDs and zero cross-scope edges.
- [ ] Implement the AWS phases, canonical normalization, Prowler relevance filter, cursor lineage, and budget-aware partial completion.
- [ ] Extend raw pages, checkpoint/resume, complete snapshots, and risk input projection with first-class source-owned Prowler findings bound to entity ID, check ID, severity, status, observation time, and immutable artifact evidence.
- [ ] Add hostile stale-subject, wrong-account, unknown-resource, missing-edge, evidence/resource mismatch, timeout, rate-limit, denied, and malformed-output tests.
- [ ] Run AWS/shared connector race and vet gates.

### Task 5: Add immutable v17 provider catalog authority

**Files:**
- Create: `services/platform/migrations/sql/0017_provider_inventory_catalog.up.sql`
- Create: `services/platform/migrations/sql/0017_provider_inventory_catalog.down.sql`
- Modify: `services/platform/migrations/migrations.go`
- Modify: `services/platform/migrations/migrations_test.go`
- Modify: `services/platform/apiserver/postgres_database.go`
- Modify: `services/platform/apiserver/discovery_execution_postgres_test.go`
- Modify: `services/platform/agentsec-migrate/main_test.go`

**Interfaces:**
- Consumes: the frozen Go provider entity catalog, relationship matrix, product kinds, and digest from Tasks 1 through 4.
- Produces: exact v17 database catalog rows, live fingerprint/readiness authority, and reversible v16 restoration without changing migrations v10 through v16.

- [ ] Write migration REDs for every new provider kind, product kind, required typed field, relationship endpoint matrix, and exact Go/database catalog digest parity.
- [ ] Add immutable v17 up/down migrations with exact owner/ACL/readiness/fingerprint guards and no mutation of v10 through v16.
- [ ] Add hostile missing/extra/drifted catalog rows, wrong product kind, wrong endpoint direction, down guard, down/re-up, and PostgreSQL process-restart tests.
- [ ] Update exact constructors and principal readiness so provider composition refuses pre-v17 or drifted authority before claiming work.
- [ ] Run migration, migrator, repository race/vet, and real PostgreSQL gates before any runtime composition or ledger promotion.

### Task 6: Compose and deploy the expanded discovery runtime

**Files:**
- Modify: `services/platform/agentsec-worker/discovery_composition.go`
- Modify: `services/platform/agentsec-worker/discovery_composition_test.go`
- Modify: `services/platform/agentsec-worker/discovery_dependencies.go`
- Modify: `services/platform/agentsec-worker/discovery_dependencies_test.go`
- Modify: `deploy/staging/product/templates/workloads.yaml`
- Modify: `deploy/staging/product/values.yaml`
- Modify: `deploy/production/release-contract.mjs`
- Modify: `deploy/production/release-contract.test.mjs`
- Modify: `build/dependencies.lock.yaml`

**Interfaces:**
- Consumes: job-scoped resolver, four expanded provider clients, exact runner versions, and existing artifact/queue repositories.
- Produces: one readiness-gated discovery runtime that rejects narrow providers and does not claim before every configured provider dependency is ready.

- [ ] Write production-composition REDs requiring exact collector versions, security runner version/readiness, and no ambient provider fallback.
- [ ] Compose the expanded clients and runner while preserving one factory per claimed job and idempotent destroy/zeroization.
- [ ] Render exact immutable image/tool versions, worker-only secret access, required egress, resource limits, readiness, drain, and no public runner surface.
- [ ] Run worker race/vet, dependency validator, release contract, Helm render, Terraform validate/plan, and Gitleaks.

### Task 7: Prove full multi-tenant sync and promote exact rows

**Files:**
- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `scripts/production-combined-e2e.test.mjs`
- Modify: `docs/internal/implementation_production_availability_v1.5.tsv`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `.superpowers/sdd/2026-08-19-production-auto-discovery-and-response/task-4-report.md`

**Interfaces:**
- Produces installed-browser and backend evidence for public sync through immutable artifacts, complete snapshot, projections, freshness, and typed inventory for AWS, Kubernetes, GitHub, and Okta.

- [ ] Write static REDs that forbid direct snapshot/projection seeds and require every provider phase in the deterministic production boundary.
- [ ] Extend the disposable two-tenant journey so identical native identifiers never collide and stale/foreign scope cannot apply.
- [ ] Prove partial checkpoint/reclaim union, complete-empty source removal, last-good preservation on failure, and independent projection freshness.
- [ ] Run OpenAPI/generated/typecheck, platform/provider race and vet, real PostgreSQL migration/restart tests, pinned Node release gates, dependency/ledger validation, and the installed-Chrome combined E2E.
- [ ] Request independent zero-finding review. Promote exactly `M3-15` through `M3-20` only when source composition is approved; retain live AWS/Kubernetes/GitHub/Okta and managed-cloud gates as NOT RUN.
