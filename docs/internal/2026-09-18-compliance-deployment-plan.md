# Compliance56 Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkboxes for tracking. The user authorizes autonomous implementation and feature-batched verification; do not pause for routine approval.

**Goal:** Deploy the existing compliance API, export worker and exact-version cleanup worker with explicit registration and isolated cloud authority, preserving all original product scope.

**Architecture:** Extend the current optional release configuration and Helm chart, backed by dedicated Terraform storage and identities. Reuse release56 and existing runtime loaders; do not alter SQL or manufacture a second compliance implementation. Registration, storage declarations and connected chart acceptance are reviewable units, not one test/review cycle per original microtask.

**Tech Stack:** Go1.25, PostgreSQL, Node22, Helm, Terraform1.15.8, AWS S3/KMS/IRSA and Secrets Store CSI.

**Spec:** `docs/internal/2026-09-18-compliance-deployment-design.md`, with registration details in `2026-09-18-compliance-registration-brief.md`.

## Global constraints

- Work only in `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`; preserve unrelated dirty work.
- Schema56 checksum remains `f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1`; fingerprint remains `8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced`.
- Default schema49 compatibility and prior48..55 contracts remain intact;56 supports both precision phases;57 remains unsupported.
- Optional compliance configuration is disabled by omission in JS and `enabled: false` in chart defaults. Enabled configuration requires schema56.
- No provider downloads, infrastructure apply, hosted service calls, online vulnerability audit, raw cloud secrets or host PostgreSQL. Terraform commands use `CHECKPOINT_DISABLE=1`.
- Focused RED/GREEN, then connected affected tests and independent review. Reuse unchanged frontend evidence until the required full pre-push UI/types/lint/build gate.
- Keep authoritative ledger classifications unchanged until matching production evidence exists. Local registered PostgreSQL, mock providers and manifest tests are component evidence.
- One implementation writer at a time; root documentation and read-only review may proceed alongside it. Capture scoped before/after hashes and patches, never broad-stage the inherited worktree.

## Task 1: Explicit database registration bridge

**Files:** `services/platform/migrations/production_compliance.go`, focused registration tests under `services/platform/migrations/`; `services/platform/agentsec-migrate/main.go`, new registration config/helper and tests in that package. Exact detailed instructions and acceptance cases are in the registration brief.

**Interfaces:** `(*migrations.Runner).RegisterComplianceWorkers(ctx, executor, cleanup)` calls the existing parameterized SQL registration function within a transaction. CLI command `register-compliance-workers` reads only `ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL` and `ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL` as its added authority inputs. No implicit worker binding during `up-to-56`.

- [x] Capture focused RED for distinct canonical non-reserved logins, exact56 state/readiness and rollback/cancellation.
- [x] Implement the transactional call and CLI preflight before opening a database connection. Preserve fixed errors without principal/SQL/DSN leakage.
- [x] Run the actual built CLI against an owned network-none cached PostgreSQL container using a registered non-superuser migration identity. Prove idempotent replay and invalid/cross-authority rejection; join and remove owned resources.
- [x] Run one affected Go/race batch and freeze evidence in `docs/internal/compliance-registration-20260918/`. Independent review covers this bounded interface and actual CLI evidence, not future deployment.

## Task 2: Dedicated storage and least-privilege infrastructure

**Files:** create `deploy/staging/compliance_exports.tf`, `deploy/staging/tests/compliance_exports_iam.tftest.hcl`, and `deploy/staging/compliance-exports-contract.test.mjs`; add the source contract test to the existing staging gate script in `package.json`. Consult `audit_exports.tf`, `test-reconciler.tf` and their mock tests for repository conventions.

**Consumes:** existing account/region/cluster variables, EKS OIDC provider, and staging Secrets Manager encryption key. No new provider or module dependency.

**Produces:** optional `compliance_exports_deployment_metadata` containing the exact non-network fields accepted by `complianceExports` in Task3. It does not invent deployment CIDRs or secret values. Principal defaults are `compliance_export_runtime` and `compliance_cleanup_runtime`.

- [x] Add source-level regression checks for opt-in default, dedicated storage, scoped IAM actions and trust subjects. Include mutation controls so removing versioning, adding `s3:DeleteObject`, broadening a secret reference, or swapping a service account causes a failure. Source checks must be labelled as source checks.
- [x] Run the focused test before implementation:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/staging/compliance-exports-contract.test.mjs
```

- [x] Add the opt-in resource skeleton and then each policy from the design:

```hcl
variable "compliance_exports_enabled" {
  type    = bool
  default = false
}

locals {
  compliance_export_identities = var.compliance_exports_enabled ? {
    reader  = "agentsec-api"
    writer  = "zasp-compliance-export-worker"
    cleanup = "zasp-compliance-cleanup-worker"
  } : {}
}
```

  Bucket: `zasp-compliance-exports-${md5(var.account_id)}`, versioned, owner-enforced, public blocked, TLS-only, SSE-KMS and dedicated rotating key. Retain exact export object prefix. One-day current/noncurrent expiration and delete-marker cleanup are a backstop, never a claimed physical24-hour guarantee.

  Reader gets `s3:GetObjectVersion`; writer gets `s3:PutObject`, `s3:GetObject`, `s3:GetObjectVersion`; cleanup gets `s3:GetObject`, `s3:GetObjectVersion`, `s3:DeleteObjectVersion`. Constrain writer Put to exact KMS headers. Reader/cleanup get S3-context Decrypt; writer also gets GenerateDataKey. Worker roles each get only their own DSN secret and matching Secrets Manager KMS context. Trust pins OIDC provider, STS audience and exact service account.

- [x] Add mock-provider assertions against decoded policy JSON, covering disabled absence, enabled three-role isolation, two secret metadata entries with no versions, public/versioning/encryption/lifecycle settings and non-secret outputs. Example assertion shape:

```hcl
assert {
  condition     = aws_s3_bucket_versioning.compliance_exports[0].versioning_configuration[0].status == "Enabled"
  error_message = "Compliance objects require immutable versions."
}
```

  Keep resource names consistent with this assertion. If cached provider binaries remain absent, retain these tests as unexecuted and say so. Do not substitute regex checks for Terraform evaluation.
- [x] Run focused GREEN and pinned Terraform fmt/check. Freeze the patch and exact commands; obtain a scoped storage/authority review. No account plan is claimed.

## Task 3: Connected release rendering and runtime configuration

**Create:** `deploy/production/compliance-export-rollout.mjs`, `compliance-export-network.mjs`, `compliance-export-release-fixture.mjs`, `compliance-export-rollout.test.mjs`; chart `templates/_compliance-exports.tpl`, `compliance-exports.yaml`, `compliance-export-network.yaml`, `compliance-export-operations.yaml`.

**Modify:** `deploy/production/release-contract.mjs`, `session-search-rollout.mjs`, `audit-export-rollout.mjs`, `audit-export-network.mjs`, `test-reconciler-rollout.mjs`; chart `values.yaml`, `_session-search.tpl`, `migration.yaml`, `_audit-exports-migration.tpl`, `workloads.yaml`, `test-reconciler.yaml`, and the inherited DNS policy's owning template. Locate the latter with `rg -n 'NotIn|kube-dns' deploy/staging/product/templates` before editing. Update `deploy/staging/gate.test.mjs` only after genuine56 rendering works. Register new connected tests in `package.json`.

**Runtime compatibility files:** `services/platform/migrations/production_audit_exports.go` and `production_audit_exports_test.go`; add a connected CLI coexistence test under `services/platform/agentsec-migrate/`. Root's source check found that all three audit operational commands currently reject56 in their shared state helper.

**Interfaces:**

```js
normalizeComplianceExports(input, platformAccountID, schemaVersion, phase)
// undefined => undefined; otherwise a detached validated plain-data copy.
validateComplianceExportResources(resources, config, schemaVersion)
// throws Error("release rejected") on authority or resource mismatch.
complianceExportMigrationCommand(schemaVersion, auditExportsEnabled)
// complete fail-closed shell command; registration is last.
complianceExportReleaseFixture()
// fresh valid synthetic config, never production evidence.
```

  `renderRelease(value, options)` accepts `options.complianceExports`; append `expectedComplianceExports` as the seventh argument of `validateRenderedRelease`, preserving six-argument callers. Cross-product collisions require the complete `value` and normalized optional predecessors; enforce them in `renderRelease` and verify concrete resource authority in the rendered validator.

- [x] Add RED using actual Helm rendering, both precision phases, enabled/disabled compliance and all combinations of audit exports/test reconciler. Keep schema55 predecessor tests and reject57.

```js
test("compliance56 coexists with both optional predecessors", async () => {
  for (const phase of ["precision-consumers", "precision-intake"]) {
    const compliance = complianceExportReleaseFixture();
    const audit = auditExportReleaseFixture();
    const reconciler = testReconcilerReleaseFixture();
    const rows = await renderRelease(productionReleaseFixture, {
      schemaVersion: 56, sessionSearchPhase: phase,
      auditExports: audit, testReconciler: reconciler, complianceExports: compliance,
    });
    assert.doesNotThrow(() => validateRenderedRelease(
      rows, "123456789012", 56, phase, audit, reconciler, compliance,
    ));
  }
});
```

- [x] Implement closed input validation for the exact15 design fields. Reject accessors, symbols, unknown keys, newline-suffixed values, malformed/mismatched account/region, duplicate or predecessor roles/DSNs/principals/buckets, and invalid CIDRs. Snapshot before the first await. Direct Helm enabled validation must also fail closed.
- [x] Render the two isolated workers, own service accounts/CSI mounts/projected tokens, API's five reader env fields and migration's two principal fields. Both worker modes, DB authority names, resource/probe/grace/HPA/PDB/monitoring settings must match the design exactly. Reject extra containers, envFrom, host namespaces and cross-workload secret mounts.
- [x] Build migration command from fixed operations, preserving the legacy disabled path and audit-only path. Enabled compliance sequence is:

```text
load migration DSN && export DSN && up-to-56
  && [register-audit-export-api && register-audit-export-workers && configure-audit-exports]
  && exec /app/agentsec-migrate register-compliance-workers
```

  Brackets above describe optional fixed commands, not literal emitted shell. Compare the exact final command in tests; deleting or reordering registration must fail.
- [x] Extend only the audit operational configuration state/readiness dispatch to56, with focused RED/GREEN. Keep all52..55 cases and historical upgrade/down readers unchanged;57 must fail. The added dispatch is:

```go
case 56:
    return ProductionCompliance(), readProductionComplianceState(ctx, queryer)
```

  In `requireAuditExportConfigurationReadiness`, metadata56 uses `productionComplianceReadinessSQL`, its compiled checksum and `ComplianceFingerprint()`. Add a single owned PostgreSQL acceptance run executing the actual complete CLI chain after up-to-56, with pre-created separate audit/compliance logins, valid synthetic audit policy and registered non-superuser migration authority. Verify both systems' bindings/configuration and final56 readiness; invalid state/readiness must leave registration/configuration unchanged. Use Task1's cached network-none fixture conventions, no host DB. This is required in addition to rendered command assertions.
- [x] Add complete additive network/RBAC validation. Both workers receive kube-dns-only DNS, explicit DB5432 and STS/S3443, monitoring-only8081 ingress. Exclude them from inherited broad DNS. Validate unnamed additional policies and service-account group bindings as well as named expected objects; preserve predecessor network checks.
- [x] Add mutation tests to a single valid rendered fixture: swap roles/DSNs, remove version requirement, leak worker env to API, reorder migration, inject sidecar, broaden selector/egress/RBAC, weaken probes/resources or omit monitoring. Assert every mutation is rejected, and disabled resources cannot be smuggled into a legacy release.
- [x] Add Go tests in the existing API/worker packages which decode the rendered manifest environment and call the actual package-local config loaders. A Node orchestration test writes owned temp JSON, invokes pinned offline Go with an explicit fixture path, and joins it. Resolve `metadata.name` worker ID and synthetic DSN mounts in the test harness only; preserve original manifest fields in evidence. Never call cloud APIs. Cover disabled API and both enabled worker modes, plus swapped role/partial configuration negatives.
- [x] Run focused GREEN, then one connected release/staging suite and affected Go/race config suite. Do not run the unrelated full Go command suite or the production release script. Retain the former schema56!=55 failure and its new passing evidence.

## Task 4: Review, evidence and publication boundary

- [x] Freeze task-scoped final source hashes, patches, logs and command exit codes under `docs/internal/compliance-deployment-20260918/`; record provider-test skips as unavailable, not passing.
- [x] Request independent spec and quality review of the connected deployment batch, including runtime loader proof and Task1/2 interfaces. Re-review only changes addressing findings, plus affected connected tests.
- [x] Update `implementation_status_v1.5.md` and relevant TSV evidence without promoting component-only rows. Run `node scripts/implementation-status-check.mjs`; counts and original728 coverage must remain explicit.
- [ ] At an authorized publication boundary, run full UI/tests/types/lint/build against the exact staged sources, inspect a scoped staged diff, and publish only verified content. Follow existing external CI/advisory gates; do not claim a push or deployment happened if those gates remain open.

## Coverage and evidence limits

Task1 covers explicit registration and actual56 DB binding. Task2 covers declared storage/identity/lifecycle. Task3 covers configuration, rollout order, predecessor coexistence, workload/network isolation and actual runtime loader compatibility. Task4 covers review, source identity and honest ledger/publication status. Live IAM/S3/KMS cleanup canaries, provider plans, provisioned secrets, hosted rollout and exact-source advisory acceptance remain external requirements. None of these local tasks alone proves production readiness.
