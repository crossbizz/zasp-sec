# Production Recovery Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace caller-asserted backup JSON and fake restore runtimes with a tenant-scoped API, durable PostgreSQL authority, real workers, immutable signed artifacts, CLI/UI clients, and a full backup/restore rehearsal.

**Architecture:** The authenticated API creates scoped backup and restore jobs plus transactional outbox rows. Dedicated workers hold one tenant, capture a Neon LSN and immutable data references, publish a signed manifest, create an isolated Neon child branch for rehearsal, rebuild disposable projections, validate exact counts, and clean every temporary resource. SaaS and single-tenant releases use the same contract.

**Tech Stack:** Go 1.26, PostgreSQL 17, AWS SDK v2 for SQS/S3/KMS/STS/Secrets Manager, Neon HTTPS API, Kubernetes HTTPS API, OpenAPI 3.1, React 19, TypeScript, Vitest, Helm, Terraform.

**Spec:** `docs/superpowers/specs/2026-08-24-production-recovery-authority-design.md`

## Global Constraints

- Preserve Organization, Workspace, and Environment on every database key, artifact, job, API request, cursor, and audit record.
- Never accept tenant scope, cloud endpoints, object keys, DSNs, or credentials from a recovery mutation body.
- Every mutation uses exact idempotency, request digest, expected version, audit, receipt, and correlation authority.
- Every external call is bounded, single-attempt at the driver boundary, cancellation-aware, and redacts provider payloads.
- Artifact publication is descriptor-first and signed-manifest-last with exact S3 VersionID, SHA-256, size, media, and schema binding.
- Backup and restore claims are fair across Organizations and lease-fenced through final database acknowledgement.
- Every started restore attempts cleanup under an independent context; cleanup failure prevents success.
- Keep the web build and existing API contracts green at every commit.
- Ledger promotions require runtime-reachable evidence. Live-provider rows remain `blocked/external` until the named live gate passes.

---

### Task 1: Typed recovery manifest and signed envelope

**Files:**
- Create: `services/platform/recovery/manifest.go`
- Create: `services/platform/recovery/manifest_test.go`
- Create: `services/platform/recovery/canonical.go`
- Create: `services/platform/recovery/canonical_test.go`
- Modify: `services/platform/go.mod`

**Interfaces:**
- Consumes: `domain.Scope`, `domain.ProductID`, `domain.EvidenceRef`.
- Produces: `Manifest`, `ArtifactLocator`, `SignedManifest`, `BuildManifest`, `DecodeSignedManifest`, `ManifestSigner`, and `ManifestVerifier`.

- [ ] **Step 1: Write the failing canonical manifest tests**

```go
func TestBuildManifestBindsScopeLSNAndPinnedArtifacts(t *testing.T) {
	manifest, payload, err := BuildManifest(validManifestInput())
	if err != nil || manifest.SchemaVersion != "recovery_manifest_v1" {
		t.Fatalf("BuildManifest() = %#v, %v", manifest, err)
	}
	want := `{"schema_version":"recovery_manifest_v1","organization_id":"pid_71000001-0000-4000-8000-000000000001"}`
	if !bytes.HasPrefix(payload, []byte(want[:48])) {
		t.Fatalf("canonical payload = %s", payload)
	}
}
```

Add literal hostile cases for foreign scope, missing VersionID, checksum drift, unsorted duplicates, unknown resource count names, invalid LSN, expired retention, raw DSN/token text, and payloads over 64 KiB.

- [ ] **Step 2: Run the tests and observe the missing package failure**

Run: `go test -C services/platform ./recovery -run 'TestBuildManifest|TestDecodeSignedManifest' -count=1`

Expected: FAIL because `services/platform/recovery` and its exported contract do not exist.

- [ ] **Step 3: Implement the minimal closed manifest contract**

```go
type ArtifactLocator struct {
	Reference string `json:"reference"`
	VersionID string `json:"version_id"`
	SHA256Hex string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
	Schema    string `json:"schema"`
}

type Manifest struct {
	SchemaVersion string                     `json:"schema_version"`
	Scope         domain.Scope               `json:"-"`
	BackupID      domain.ProductID           `json:"-"`
	CapturedAt    time.Time                  `json:"captured_at"`
	ExpiresAt     time.Time                  `json:"expires_at"`
	NeonProjectID string                     `json:"neon_project_id"`
	NeonBranchID  string                     `json:"neon_branch_id"`
	PostgresLSN   string                     `json:"postgres_lsn"`
	Configuration ArtifactLocator            `json:"configuration"`
	Projection    ArtifactLocator            `json:"projection_rebuild"`
	Evidence      []ArtifactLocator          `json:"evidence"`
	Counts        map[string]uint64          `json:"expected_counts"`
}

type ManifestSigner interface {
	Sign(context.Context, []byte) (keyARN string, signature []byte, err error)
}

type ManifestVerifier interface {
	Verify(context.Context, string, []byte, []byte) error
}
```

Canonical JSON uses fixed struct field order, sorted evidence by reference, sorted count keys through a custom encoder, UTF-8 validation, a depth limit of 16, and a 64 KiB envelope limit. `DecodeSignedManifest` rejects unknown/duplicate fields and verifies the signature before returning typed content.

- [ ] **Step 4: Run package race and vet gates**

Run: `go test -C services/platform -race ./recovery -count=1`

Run: `go vet -C services/platform ./recovery`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/platform/recovery services/platform/go.mod services/platform/go.sum
git commit -m "feat(recovery): define signed manifest authority"
```

### Task 2: PostgreSQL v27 recovery authority

**Files:**
- Create: `services/platform/migrations/sql/0027_production_recovery.up.sql`
- Create: `services/platform/migrations/sql/0027_production_recovery.down.sql`
- Create: `services/platform/migrations/production_recovery_test.go`
- Modify: `services/platform/migrations/migrations.go`
- Modify: `services/platform/migrations/migrations_test.go`
- Create: `services/platform/apiserver/recovery_postgres_test.go`
- Modify: `services/platform/apiserver/postgres_database.go`
- Modify: `services/platform/apiserver/repository.go`
- Modify: `services/platform/agentsec-migrate/main.go`
- Modify: `services/platform/agentsec-migrate/main_test.go`

**Interfaces:**
- Consumes: v26 schema, core scope tables, workflow receipts, audit, outbox conventions, ProductID generation.
- Produces: v27 metadata/readiness plus exact API, outbox, worker, capture, hold, and transition SQL functions.

- [ ] **Step 1: Add RED migration metadata and real-PostgreSQL behavior tests**

The real test must call these missing functions:

```sql
SELECT zasp_recovery_create_backup($1,$2,$3,$4,$5,$6,$7,30,$8,$9,$10);
SELECT zasp_recovery_claim_outbox('recovery-backup-jobs','worker-1','token-000000000001',30,10);
SELECT zasp_recovery_claim_operation('backup','worker-1','token-000000000001',30,10);
SELECT zasp_recovery_begin_hold($1,$2,$3,$4,'worker-1','token-000000000001');
SELECT zasp_recovery_capture_page($1,$2,$3,$4,'configuration',NULL,100);
SELECT zasp_recovery_finish_backup($1,$2,$3,$4,'worker-1','token-000000000001',$5::jsonb);
```

Cover exact replay, request-digest drift, cross-scope denial, one live operation per Organization, fair two-tenant claims, hold blocks a new scoped mutation, foreign tenant keeps mutating, heartbeat lease loss, terminal retry, attempt 100 exhaustion, cleanup-required restore transitions, ACL drift, unsafe roles, fingerprint drift, v27 down guard, and v26 down/re-up.

- [ ] **Step 2: Run RED gates**

Run: `go test -C services/platform ./migrations ./apiserver -run 'TestProductionRecovery' -count=1`

Expected: FAIL on missing v27 metadata and `zasp_recovery_*` functions.

- [ ] **Step 3: Implement v27 tables, functions, RLS, roles, and readiness**

Create tables with composite scope keys:

```sql
CREATE TABLE zasp_recovery_backups (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 1000000),
  state text NOT NULL CHECK (state IN ('queued','draining','capturing','publishing','succeeded','failed')),
  retention_days integer NOT NULL CHECK (retention_days BETWEEN 7 AND 90),
  actor_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  hold_epoch bigint,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100),
  worker_id text,
  lease_token text,
  lease_expires_at timestamptz,
  manifest jsonb,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  started_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (organization_id,workspace_id,environment_id,id),
  UNIQUE (organization_id,workspace_id,environment_id,idempotency_key)
);

CREATE TABLE zasp_recovery_restores (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 1000000),
  state text NOT NULL CHECK (state IN ('queued','verifying','provisioning','validating','rebuilding','cleaning','succeeded','failed','failed_cleanup')),
  actor_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  target_environment text NOT NULL,
  manifest jsonb NOT NULL,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100),
  worker_id text,
  lease_token text,
  lease_expires_at timestamptz,
  observed_counts jsonb,
  validation_evidence jsonb,
  cleanup_evidence jsonb,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  started_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (organization_id,workspace_id,environment_id,id),
  UNIQUE (organization_id,workspace_id,environment_id,idempotency_key)
);

CREATE TABLE zasp_recovery_holds (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  epoch bigint NOT NULL CHECK (epoch BETWEEN 1 AND 9223372036854775807),
  operation_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('requested','draining','held','released')),
  active_mutations integer NOT NULL DEFAULT 0 CHECK (active_mutations >= 0),
  requested_at timestamptz NOT NULL,
  held_at timestamptz,
  released_at timestamptz,
  PRIMARY KEY (organization_id,workspace_id,environment_id)
);

CREATE TABLE zasp_recovery_outbox (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  topic text NOT NULL CHECK (topic IN ('recovery-backup-jobs','recovery-restore-jobs')),
  deterministic_key text NOT NULL,
  payload jsonb NOT NULL,
  payload_digest bytea NOT NULL CHECK (octet_length(payload_digest)=32),
  state text NOT NULL CHECK (state IN ('pending','leased','published','retryable','exhausted')),
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100),
  available_at timestamptz NOT NULL,
  worker_id text,
  lease_token text,
  lease_expires_at timestamptz,
  provider_ack text,
  published_at timestamptz,
  error_code text,
  PRIMARY KEY (organization_id,workspace_id,environment_id,id),
  UNIQUE (topic,deterministic_key)
);

CREATE TABLE zasp_recovery_fairness (
  topic text PRIMARY KEY CHECK (topic IN ('recovery-backup-jobs','recovery-restore-jobs','recovery-operations')),
  last_organization_id text,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
```

Add these roles with exact NOLOGIN/NOINHERIT authority:

```text
zasp_recovery_worker
zasp_recovery_outbox_worker
```

Public API functions derive scope from their arguments under the existing API role. Worker functions require `current_user` membership in one exact role. Every state transition verifies operation ID, worker, lease token, request digest, state, and expected attempt.

Mutation entry functions call `zasp_recovery_scope_mutable(organization,workspace,environment)` before any tenant write. Recovery's own functions bypass this guard only through their dedicated principal.

- [ ] **Step 4: Wire migrator metadata and exact readiness**

Add `ProductionRecovery()`, `ProductionRecoverySemanticFingerprint()`, `UpProductionRecovery`, `DownProductionRecovery`, v27 CLI progression, and schema detection. Fingerprint tables, columns, checks, indexes, RLS policies, functions, owners, grants, and role membership in deterministic order.

- [ ] **Step 5: Run focused unit, race, and real-PostgreSQL gates**

Run: `go test -C services/platform -race ./migrations ./agentsec-migrate -run 'ProductionRecovery|ReachesV27' -count=1`

Run with the repository's PostgreSQL fixture: `go test -C services/platform -race ./apiserver -run 'TestProductionRecoveryPostgres' -count=1 -timeout=180s`

Run: `go vet -C services/platform ./migrations ./agentsec-migrate ./apiserver`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services/platform/migrations services/platform/apiserver/postgres_database.go services/platform/apiserver/repository.go services/platform/apiserver/recovery_postgres_test.go services/platform/agentsec-migrate
git commit -m "feat(recovery): persist v27 execution authority"
```

### Task 3: Public recovery API and generated client

**Files:**
- Create: `services/platform/apiserver/recovery_repository.go`
- Create: `services/platform/apiserver/recovery_repository_test.go`
- Create: `services/platform/apiserver/recovery_handler.go`
- Create: `services/platform/apiserver/recovery_handler_test.go`
- Modify: `services/platform/apiserver/production.go`
- Modify: `services/platform/apiserver/production_test.go`
- Modify: `services/platform/apiserver/router.go`
- Modify: `openapi/openapi.yaml`
- Modify: `openapi/openapi.test.mjs`
- Regenerate: `apps/web/api/generated.ts`
- Modify: `openapi/generated-client.test.mjs`

**Interfaces:**
- Consumes: v27 SQL functions, `RequestIdentity`, workflow mutation headers.
- Produces: `RecoveryPublicAuthority`, four OpenAPI operations, strict Go responses, and generated TypeScript types.

- [ ] **Step 1: Write RED OpenAPI and handler tests**

Assert these operation IDs and behaviors:

```text
startRecoveryBackup
getRecoveryBackup
startRecoveryRestore
getRecoveryRestore
```

Handler tests prove authenticated scope is passed to the repository, body scope/unknown fields are rejected, `retention_days` is 7..90, target is disposable/non-source, exact replay returns stable IDs, responses are `no-store`, and raw object keys/key ARNs/provider errors never appear.

- [ ] **Step 2: Run RED gates**

Run: `node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs`

Run: `go test -C services/platform ./apiserver -run 'TestRecoveryHTTP|TestRecoveryRepository' -count=1`

Expected: FAIL on missing operations and Go types.

- [ ] **Step 3: Implement repository and HTTP surface**

```go
type RecoveryPublicAuthority interface {
	StartBackup(context.Context, RequestIdentity, RecoveryBackupMutation) (RecoveryBackupMutationResult, error)
	GetBackup(context.Context, RequestIdentity, string) (RecoveryBackup, error)
	StartRestore(context.Context, RequestIdentity, RecoveryRestoreMutation) (RecoveryRestoreMutationResult, error)
	GetRestore(context.Context, RequestIdentity, string) (RecoveryRestore, error)
}
```

Use strict database result decoding and independently validate every ID, version, state tuple, timestamp, count, locator, audit, receipt, replay, and error code. Mount only when exact v27 readiness passes.

- [ ] **Step 4: Add exact OpenAPI schemas and regenerate**

Schemas are closed with `additionalProperties: false`. `RecoveryManifestLocator` exposes public reference, VersionID, SHA-256, size, media, schema, signing key ID, and signature. It never exposes the S3 key or full KMS ARN.

Run: `npm run openapi:generate`

- [ ] **Step 5: Run API gates**

Run: `node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs`

Run: `npm run openapi:check`

Run: `go test -C services/platform -race ./apiserver -run 'TestRecoveryHTTP|TestRecoveryRepository|TestProductionHandlers' -count=1`

Run: `go vet -C services/platform ./apiserver`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services/platform/apiserver openapi apps/web/api/generated.ts
git commit -m "feat(api): expose tenant recovery operations"
```

### Task 4: Recovery outbox and backup worker

**Files:**
- Create: `services/platform/agentsec-worker/recovery_outbox_runtime.go`
- Create: `services/platform/agentsec-worker/recovery_outbox_runtime_test.go`
- Create: `services/platform/agentsec-worker/recovery_runtime.go`
- Create: `services/platform/agentsec-worker/recovery_runtime_test.go`
- Create: `services/platform/agentsec-worker/recovery_artifacts.go`
- Create: `services/platform/agentsec-worker/recovery_artifacts_test.go`
- Create: `services/platform/agentsec-worker/recovery_signing.go`
- Create: `services/platform/agentsec-worker/recovery_signing_test.go`
- Modify: `services/platform/agentsec-worker/runtime_config.go`
- Modify: `services/platform/agentsec-worker/runtime_config_test.go`
- Modify: `services/platform/agentsec-worker/production_runtime.go`
- Modify: `services/platform/agentsec-worker/production_runtime_test.go`

**Interfaces:**
- Consumes: v27 worker repository, `jobqueue`, `artifactstore`, AWS KMS signing client.
- Produces: `recovery-outbox` and `recovery` worker modes with complete backup state handling.

- [ ] **Step 1: Write RED worker tests**

Tests cover one-Organization claims, hold-before-capture ordering, drain timeout, page bounds, descriptor-first writes, manifest-last write, KMS signature binding, lost Put reconciliation, lease heartbeat during calls, lease-loss cancellation, attempt exhaustion, hold release on every terminal path, and shutdown cleanup.

- [ ] **Step 2: Run RED gates**

Run: `go test -C services/platform ./agentsec-worker -run 'TestRecovery' -count=1`

Expected: FAIL on missing processors and modes.

- [ ] **Step 3: Implement bounded processors**

```go
type recoveryOperationAuthority interface {
	Claim(context.Context, string, string, time.Duration, int) ([]RecoveryClaim, error)
	Heartbeat(context.Context, RecoveryLease) (RecoveryHeartbeat, error)
	BeginHold(context.Context, RecoveryLease) (RecoveryHold, error)
	CapturePage(context.Context, RecoveryLease, string, *string, int) (RecoveryCapturePage, error)
	FinishBackup(context.Context, RecoveryLease, RecoveryManifestAuthority) error
	Fail(context.Context, RecoveryLease, string, time.Duration) error
}
```

The processor keeps the heartbeat active through manifest publication and final database transition. Cancellation after hold acquisition always uses a bounded hold-release path.

- [ ] **Step 4: Compose explicit AWS authority**

Require exact role ARN, projected token path, region, evidence bucket/account, asymmetric KMS signing key ID, queue ARN/name/DLQ, and recovery principal. Use anonymous base config plus explicit `AssumeRoleWithWebIdentity`, `NopRetryer`, no proxy, and fixed endpoints.

- [ ] **Step 5: Run worker gates**

Run: `go test -C services/platform -race ./agentsec-worker -run 'Recovery|WorkerRuntimeConfig' -count=1 -timeout=120s`

Run: `go vet -C services/platform ./agentsec-worker`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services/platform/agentsec-worker
git commit -m "feat(worker): collect signed recovery backups"
```

### Task 5: Neon rehearsal and disposable projection rebuild

**Files:**
- Create: `services/platform/recovery/neondriver/client.go`
- Create: `services/platform/recovery/neondriver/client_test.go`
- Create: `services/platform/agentsec-worker/recovery_restore.go`
- Create: `services/platform/agentsec-worker/recovery_restore_test.go`
- Create: `services/platform/agentsec-worker/recovery_kubernetes.go`
- Create: `services/platform/agentsec-worker/recovery_kubernetes_test.go`
- Modify: `services/platform/agentsec-worker/recovery_runtime.go`
- Modify: `services/platform/agentsec-worker/recovery_runtime_test.go`
- Modify: `services/platform/agentsec-worker/recovery_production.go`

**Interfaces:**
- Consumes: signed manifest, project-scoped Neon key, pinned project/branch, in-cluster Kubernetes authority, projection drivers.
- Produces: exact restore verification, provisioning, validation, rebuild, and cleanup.

- [ ] **Step 1: Write RED Neon and restore tests**

Use a local TLS server. Assert exact POST `/api/v2/projects/{project}/branches` with `parent_id`, `parent_lsn`, deterministic name, and one private read-write endpoint. Cover 401/403 denial, 423/503 retry classification, lost-response reconciliation, oversized/unknown JSON, redirect, timeout, cancel, and provider body redaction.

Restore tests prove no provider call before signature/locator validation, tenant-only SQL counts, disposable namespace ownership, projection digest equality, cleanup after every started path, and `failed_cleanup` when deletion cannot be proved.

- [ ] **Step 2: Run RED gates**

Run: `go test -C services/platform ./recovery/neondriver ./agentsec-worker -run 'TestNeon|TestRecoveryRestore' -count=1`

Expected: FAIL on missing driver and restore implementation.

- [ ] **Step 3: Implement fixed-origin Neon client**

```go
type Client interface {
	CreateBranch(context.Context, CreateBranchRequest) (Branch, error)
	GetBranchByName(context.Context, string, string) (Branch, error)
	DeleteBranch(context.Context, string, string) error
	Ready(context.Context) error
}
```

The production client owns its TLS transport, disables proxy and redirect, caps headers/body, and never returns provider strings in errors.

- [ ] **Step 4: Implement isolated restore orchestration**

Provision one namespace named `zasp-recovery-<restore suffix>` with labels binding restore ID and scope digest, one network policy, one PostgreSQL validation job, and disposable graph/search projection jobs. Delete only resources with exact UID and ownership labels.

- [ ] **Step 5: Run restore gates**

Run: `go test -C services/platform -race ./recovery/neondriver ./agentsec-worker -run 'TestNeon|TestRecoveryRestore|TestRecoveryKubernetes' -count=1 -timeout=120s`

Run: `go vet -C services/platform ./recovery/neondriver ./agentsec-worker`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services/platform/recovery/neondriver services/platform/agentsec-worker
git commit -m "feat(recovery): rehearse isolated tenant restore"
```

### Task 6: Production agentsecctl client

**Files:**
- Create: `cmd/agentsecctl/recovery_client.go`
- Create: `cmd/agentsecctl/recovery_client_test.go`
- Modify: `cmd/agentsecctl/release.go`
- Modify: `cmd/agentsecctl/release_test.go`
- Modify: `cmd/agentsecctl/main.go`
- Modify: `cmd/agentsecctl/main_test.go`

**Interfaces:**
- Consumes: four generated recovery API contracts over pinned HTTPS.
- Produces: `backup start/get` and `restore start/get` commands.

- [ ] **Step 1: Write RED command tests against a local TLS API**

Tests assert exact method/path/headers/body, tenant scope omission, stable JSON output, 202/200 decoding, no redirect/proxy, CA pinning, 64 KiB body cap, timeout, cancellation, and redaction of authorization/DSN/provider bodies.

- [ ] **Step 2: Run RED gates**

Run: `go test -C cmd/agentsecctl -run 'TestRecoveryClient|TestRecoveryCommands' -count=1`

Expected: FAIL because the new command grammar and client do not exist.

- [ ] **Step 3: Implement exact config and commands**

```go
type RecoveryClientConfig struct {
	Endpoint       string
	CredentialFile string
	CABundleFile   string
	Timeout        time.Duration
}
```

Only `https://` endpoints with a non-IP host are accepted. Credential and CA files require owned regular-file checks before/open/after read. Request IDs and idempotency keys come from explicit flags or cryptographic generation, never timestamps.

- [ ] **Step 4: Remove the demo command path**

Keep `DecodeRecoveryManifest` as an internal validator. Change the public `backup` command from stdin echoing to the subcommand grammar. An old bare `agentsecctl backup` invocation returns `errInvalidArguments` without reading stdin.

- [ ] **Step 5: Run CLI gates**

Run: `go test -C cmd/agentsecctl -race -count=1 ./...`

Run: `go vet -C cmd/agentsecctl ./...`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/agentsecctl
git commit -m "feat(cli): operate production recovery API"
```

### Task 7: Recovery administration UI

**Files:**
- Create: `app/features/recovery/api.ts`
- Create: `app/features/recovery/api.test.ts`
- Create: `app/features/recovery/RecoveryOperationsView.tsx`
- Create: `app/features/recovery/RecoveryOperationsView.test.tsx`
- Modify: `app/App.tsx`
- Modify: `app/navigation.ts`
- Modify: `apps/web/api/decoders.ts`
- Modify: `apps/web/api/decoders.discovery.test.ts`
- Modify: `apps/web/api/ui-api-map.ts`
- Modify: `apps/web/api/ui-api-map.test.ts`

**Interfaces:**
- Consumes: generated `RecoveryBackup`, `RecoveryRestore`, and mutation APIs.
- Produces: `/administration/recovery` page and strict client decoders.

- [ ] **Step 1: Write RED decoder, API, and browser-component tests**

Tests cover strict queued/running/succeeded/failed state tuples, start confirmation, idempotent retry, bounded polling, navigation cancellation, reload recovery, exact count mismatch, cleanup failure, empty state, and absence of raw refs/ARNs/tokens/provider text.

- [ ] **Step 2: Run RED gates**

Run: `npm exec vitest run app/features/recovery apps/web/api/ui-api-map.test.ts apps/web/api/decoders.discovery.test.ts`

Expected: FAIL on missing recovery feature and map entries.

- [ ] **Step 3: Implement generated-client-only API and UI**

```ts
export type RecoveryAPI = {
  startBackup(input: StartBackupInput): Promise<RecoveryBackup>;
  getBackup(id: string, signal?: AbortSignal): Promise<RecoveryBackup>;
  startRestore(input: StartRestoreInput): Promise<RecoveryRestore>;
  getRestore(id: string, signal?: AbortSignal): Promise<RecoveryRestore>;
};
```

The page displays public reference IDs and status evidence only. It does not decode or render internal object keys or provider payloads.

- [ ] **Step 4: Run UI gates**

Run: `npm exec vitest run app/features/recovery apps/web/api/ui-api-map.test.ts apps/web/api/decoders.discovery.test.ts`

Run: `npm run typecheck`

Run: `npm run build`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/features/recovery app/App.tsx app/navigation.ts apps/web/api
git commit -m "feat(web): operate tenant recovery"
```

### Task 8: Deployment identities and cleanup operations

**Files:**
- Modify: `deploy/staging/product/values.yaml`
- Modify: `deploy/staging/product/templates/workloads.yaml`
- Modify: `deploy/staging/product/templates/secrets.yaml`
- Modify: `deploy/staging/product/templates/resilience.yaml`
- Modify: `deploy/staging/product/templates/monitoring.yaml`
- Modify: `deploy/staging/main.tf`
- Modify: `deploy/staging/outputs.tf`
- Modify: `deploy/staging/preflight.mjs`
- Modify: `deploy/production/release-contract.mjs`
- Modify: `deploy/production/release-contract.test.mjs`
- Modify: `deploy/production/release-gates.mjs`
- Create: `docs/operations/recovery-runbook.md`

**Interfaces:**
- Consumes: recovery worker modes and exact runtime configuration.
- Produces: dedicated workloads, IAM, queues, signing key, network policy, metrics, alerts, and runbook.

- [ ] **Step 1: Write RED rendered-release and Terraform policy tests**

Assert separate recovery/outbox ServiceAccounts and DSNs, SendMessage/GetQueueAttributes-only outbox role, worker S3/KMS/Neon-secret/Kubernetes authority, KMS signing-only key, PostgreSQL/STS/SQS/S3/KMS/Secrets/Neon/Kubernetes egress, PDB/topology/HPA, private metrics services, hold-age/cleanup/lease/readiness alerts, and no public ingress.

- [ ] **Step 2: Run RED release tests**

Run: `node --test deploy/production/release-contract.test.mjs deploy/staging/gate.test.mjs deploy/staging/preflight.test.mjs`

Expected: FAIL on absent recovery render and Terraform authority.

- [ ] **Step 3: Implement Helm and Terraform release**

Create Standard SQS backup/restore queues plus DLQs, one asymmetric KMS signing key, exact IRSA policies, projected tokens, secret mounts, and namespace-scoped cleanup RBAC. Render workloads disabled by default until the recovery canary input is true.

- [ ] **Step 4: Add fixed-cardinality monitoring and runbook**

Alert on unavailable worker, driver readiness, queue age, hold older than 15 minutes, exhausted work, lease loss, and cleanup failure. The runbook gives exact inspect, retry, cleanup, and escalation commands without printing credentials.

- [ ] **Step 5: Run deployment gates**

Run: `npm run production:release:test`

Run: `npm run staging:gate:test`

Run: `terraform -chdir=deploy/staging fmt -check`

Run after isolated init: `terraform -chdir=deploy/staging validate`

Run offline: `terraform -chdir=deploy/staging plan -refresh=false -input=false -lock=false`

Expected: PASS with zero updates and zero deletes against an empty state plan.

- [ ] **Step 6: Commit**

```bash
git add deploy docs/operations/recovery-runbook.md
git commit -m "feat(deploy): ship isolated recovery workers"
```

### Task 9: Combined E2E, ledger promotion, review, and push

**Files:**
- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `scripts/production-combined-e2e-source.test.mjs`
- Modify: `docs/internal/implementation_production_availability_v1.5.tsv`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `scripts/implementation-status-check.mjs`
- Modify: `scripts/implementation-status-check.test.mjs`

**Interfaces:**
- Consumes: production API, outbox/recovery workers, local TLS Neon fixture, S3/KMS fixture, disposable PostgreSQL, built web, installed Chrome.
- Produces: source-complete end-to-end evidence and exact ledger changes.

- [ ] **Step 1: Write RED static and full E2E assertions**

The full run starts backup through the real CLI and API, drains the real outbox/worker, verifies signed manifest-last storage, reloads the browser, starts restore, creates an exact local Neon branch fixture, validates counts, rebuilds disposable projections, proves cleanup, rejects cross-tenant reads, and checks process/port/temp cleanup.

- [ ] **Step 2: Run RED harness checks**

Run: `node --test scripts/production-combined-e2e-source.test.mjs`

Expected: FAIL on missing recovery flow evidence.

- [ ] **Step 3: Implement the deterministic local-provider flow**

Use TLS fixtures with complete provider response shapes. The harness must invoke production binaries and repositories; direct SQL finish calls are forbidden. Lost API responses are retried with the same idempotency key.

- [ ] **Step 4: Run full verification**

Run: `go test -C services/platform -race ./... -count=1`

Run: `go vet -C services/platform ./...`

Run: `go test -C cmd/agentsecctl -race ./... -count=1`

Run: `npm run openapi:check`

Run: `npm run typecheck`

Run: `npm run build`

Run: `npm run production:release:test`

Run: `node --test scripts/production-combined-e2e-source.test.mjs`

Run: `node scripts/production-combined-e2e.mjs`

Run: `node scripts/implementation-status-check.mjs`

Expected: PASS with complete cleanup.

- [ ] **Step 5: Audit and promote only proven rows**

Promote M8-20a through M8-21 only when the combined E2E proves runtime composition. Leave live Neon/AWS/Kubernetes/graph evidence rows `blocked/external` until those exact live commands pass. Update summary counts from the ledger, never by hand without validator agreement.

- [ ] **Step 6: Run Superpowers review and fix every finding**

Use `superpowers:requesting-code-review`, then the repository review skill if its checklist exists. Re-run every affected gate after corrections. Zero unresolved Critical, Important, or Minor findings is required for freeze.

- [ ] **Step 7: Commit and push without bypassing hooks**

```bash
git add scripts docs/internal
git commit -m "feat(recovery): prove production rehearsal"
git push origin codex/production-auto-discovery
```

If the secret scanner exceeds its 1 MiB input ceiling, push already-scanned fast-forward commit batches below that ceiling. Never use `--no-verify` or the skip environment variable.
