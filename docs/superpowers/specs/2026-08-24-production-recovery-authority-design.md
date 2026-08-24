# Production Recovery Authority Design

**Date:** August 24, 2026

**Status:** Approved by delegated product authority. The user directed the implementation agent to make launch and scale decisions without another approval pause.

**Plan coverage:** M8-20a, M8-20b, M8-20c, M8-20, M8-21a, M8-21b, M8-21c, M8-21d, M8-21e, and M8-21. This design does not promote preflight, upgrade, load, or isolation rows owned by T16.

## The gap

`agentsecctl backup` currently accepts a complete recovery manifest on standard input. The caller asserts the Neon recovery point, graph reference, evidence references, and expected counts. Restore uses an injected runtime implemented only by tests. Those boundaries validate JSON well, but they do not collect or restore production state.

That cannot ship as recovery authority. A tenant administrator must be able to start a backup, receive a durable job identifier, inspect the completed immutable manifest, rehearse restoration, and see cleanup evidence without holding PostgreSQL, Neon, S3, Kubernetes, or graph credentials.

## Decisions

### One control-plane contract

SaaS and single-tenant installations use the same authenticated recovery API. `agentsecctl` is a client of that API. It never opens PostgreSQL directly and never receives cloud credentials.

The request identity supplies Organization, Workspace, Environment, and principal. The server ignores tenant identifiers in request bodies because none are accepted. Recovery operations require the existing administrator authorization boundary plus a new `recovery.write` capability. Reads require `recovery.read`.

### Tenant restore from a whole-database recovery point

Neon point-in-time branches operate on a database branch, not one Organization. The backup worker captures an exact parent branch and PostgreSQL LSN after the selected Organization enters a durable recovery hold and its in-flight tenant mutations drain. The hold prevents that Organization from moving while its counts and immutable references are collected. Other Organizations may continue writing.

Restore creates a new Neon child branch at that LSN. It never points an application at the branch until validation succeeds. SaaS validation and any later extraction query every table through the original Organization, Workspace, and Environment scope. A single-tenant deployment may promote the whole restored branch after the same checks.

Neon's supported Create branch endpoint accepts `parent_id` and `parent_lsn`; the worker uses an explicit project-scoped organization API key and a fixed `https://console.neon.tech/api/v2` origin. POST uncertainty is reconciled by a deterministic branch name and a bounded list/get operation before retrying.

### PostgreSQL is the inventory authority

Neo4j and OpenSearch remain projections. Recovery does not claim that an Aura snapshot is tenant-scoped. The backup worker writes a graph/search rebuild descriptor containing the exact committed discovery snapshots, generations, input digests, and version-pinned artifact locators needed to rebuild those projections.

The restore worker replays that descriptor into isolated projection targets after PostgreSQL validation. Production projection endpoints are never used during rehearsal.

### Immutable artifact chain

Every descriptor and the final recovery manifest is canonical JSON stored through `artifactstore` in the versioned evidence bucket. Every locator includes scope, ProductID reference, S3 VersionID, SHA-256, byte size, media type, and schema version.

The final envelope is signed by a dedicated KMS asymmetric signing key. The API returns the signature, key ARN, and pinned manifest locator. Restore verifies the signature and every pinned child object before provisioning anything.

Raw credentials, DSNs, bearer tokens, session material, provider response bodies, and presigned URLs are forbidden in every descriptor and public response.

## Public API

The OpenAPI surface adds four operations.

### `POST /api/v1/recovery/backups`

Required headers follow existing mutation rules: `Idempotency-Key`, `If-Match: "0"`, and correlation identity. The body is exact JSON:

```json
{
  "backup_id": "pid_...",
  "retention_days": 30
}
```

`retention_days` is 7 through 90. The transaction creates the scoped backup row, audit event, workflow receipt, and `recovery-backup-jobs` outbox row. Exact replay returns the original result. A changed body under the same key conflicts.

Response: `202` with `RecoveryBackup` in `queued` state.

### `GET /api/v1/recovery/backups/{id}`

Returns the scoped job. A succeeded response includes `manifest`; queued/running rows do not. Failed rows return one stable redacted error code. Foreign scope is indistinguishable from not found.

### `POST /api/v1/recovery/restores`

The body supplies a new `restore_id`, a pinned `RecoveryManifestLocator`, and an exact disposable target name. The target grammar is lowercase DNS text, 1 through 63 bytes, and it must differ from the source environment. SaaS production restore is rehearsal-only in this slice; `promote` is absent from the schema.

The transaction creates the restore row, audit event, workflow receipt, and `recovery-restore-jobs` outbox row. Response: `202` with `RecoveryRestore` in `queued` state.

### `GET /api/v1/recovery/restores/{id}`

Returns start, validation, projection rebuild, and cleanup states. Terminal success requires `validated=true`, `cleaned=true`, exact expected/observed counts, and immutable evidence locators for start, validation, and cleanup.

All four responses use `Cache-Control: no-store`. Mutation responses return audit, receipt, correlation, ETag, and idempotent replay headers through the existing workflow conventions.

## Durable state

Migration v27 owns these tables:

- `zasp_recovery_backups`: scoped backup identity, version, state, retention, request digest, hold epoch, lease, attempt, manifest authority, stable error, and timestamps.
- `zasp_recovery_restores`: scoped restore identity, version, state, pinned manifest authority, disposable target, lease, attempt, validation/cleanup evidence, observed counts, stable error, and timestamps.
- `zasp_recovery_holds`: one active Organization/Workspace/Environment recovery epoch with requested, draining, held, or released state.
- `zasp_recovery_outbox`: exact topic, canonical payload, digest, lease, provider acknowledgement, retry state, and tenant fairness cursor.

All tenant tables use a composite scope key and RLS. `SECURITY DEFINER` functions set and verify the three scope settings before data access. API functions can create/read operations only. Separate `zasp_recovery_outbox_worker` and `zasp_recovery_worker` roles receive only their exact functions.

The migration has live semantic fingerprinting, principal readiness, exact ACL checks, hostile pre-existing-role checks, guarded down migration, and no broad table grants.

## Backup state machine

1. `queued`: the API commits the row and outbox atomically.
2. `draining`: the worker acquires a scoped lease, creates a recovery epoch, and blocks new tenant mutations at shared mutation entry points.
3. `capturing`: active tenant work reaches zero. One repeatable-read transaction captures tenant counts, configuration identities, immutable evidence locators, committed discovery snapshot authority, source branch identity, current timestamp, and `pg_current_wal_lsn()`.
4. `publishing`: the worker writes child descriptors first, then the signed manifest last.
5. `succeeded`: the database stores the exact pinned manifest authority and releases the hold in the same fenced transition.

Failure before manifest publication releases the hold and retries. An unknown artifact-write outcome is reconciled by exact reference, checksum, and VersionID. Attempt exhaustion moves the row to `failed`, releases the hold, and records a redacted error. Lease loss cancels cloud calls.

Every normal mutation path checks the scoped recovery epoch. Read-only traffic and other Organizations continue.

## Restore state machine

1. `queued`: API commit plus outbox.
2. `verifying`: verify KMS signature, manifest digest, scope, retention, and every child VersionID/checksum/size/media/schema binding before cloud mutation.
3. `provisioning`: create a deterministic Neon child branch at `parent_lsn`, a private compute endpoint, an isolated Kubernetes recovery namespace, and disposable graph/search targets. Reconcile uncertain POST outcomes by deterministic names.
4. `validating`: connect with ephemeral credentials, run exact tenant-scoped counts and sampled evidence checks, and verify schema v27 compatibility.
5. `rebuilding`: replay the graph/search descriptor against disposable targets and compare resulting digests.
6. `cleaning`: delete compute, Neon branch, namespace, volumes, and temporary secrets under a bounded context independent of the request context.
7. `succeeded`: only after validation and cleanup evidence are durable.

Any started restore reaches `cleaning`, including cancellation, lease loss, dependency failure, and validation mismatch. Cleanup failure wins and leaves the operation `failed_cleanup` for operator action. The system never reports success while resources remain.

## Worker composition

Two new modes use the existing worker binary:

- `recovery-outbox`: topic-fenced SQS publishing with DB heartbeat through publish and acknowledgement.
- `recovery`: concurrent fair claims, lease heartbeat, backup/restore dispatch, provider calls, and bounded shutdown.

Production dependencies use explicit web identity, fixed AWS region/account/bucket/key authority, a project-scoped Neon token from Secrets Manager, fixed Neon project/parent branch, and a Kubernetes client pinned to the in-cluster API. Ambient AWS credentials, proxy environment variables, redirects, provider retries, and caller-selected endpoints are rejected.

Readiness checks database fingerprint/principal authority, exact SQS ARN/DLQ, S3 versioning/KMS ownership, KMS signing key usage, Neon project/branch identity, and Kubernetes recovery namespace authority before claims.

## CLI behavior

`agentsecctl` receives a production API base URL, opaque credential reference, pinned CA bundle, and timeout from its strict config. It resolves the credential through the existing local credential boundary and sends it only to the configured HTTPS origin.

Commands become:

```text
agentsecctl backup start --id <product-id> --retention-days 30
agentsecctl backup get --id <product-id>
agentsecctl restore start --id <product-id> --manifest-file <path> --target <name>
agentsecctl restore get --id <product-id>
```

The old standard-input manifest builder remains an internal decoder used to validate downloaded manifests. It is no longer the production `backup` command.

Output is exact JSON suitable for release evidence. Errors are stable and redact response bodies, headers, tokens, DSNs, and object paths beyond the scoped public locator.

## UI

The administration area adds a Recovery page backed only by generated OpenAPI clients. It shows backup/restore state, manifest creation time and retention, validation counts, cleanup state, and stable remediation text. It never displays credential references, KMS key ARNs, raw S3 keys, Neon identifiers, or provider errors.

Starting backup or rehearsal requires the same explicit confirmation and idempotency behavior used by destructive administration workflows. Polling is bounded, cancels on navigation, and resumes from durable state after reload.

## Scale and isolation

Claims select at most one operation per Organization and exclude Organizations with a live recovery lease. A durable fairness cursor prevents a deep tenant backlog from starving another tenant. Backup collection pages through database and artifact references with fixed limits; no Organization is accumulated unbounded in worker memory.

One Organization hold never blocks another Organization. The only global artifact is the Neon branch recovery point, which is used in an isolated restore target and always filtered through the authenticated scope during validation.

Metrics have fixed cardinality: queued age, active jobs, hold duration, lease loss, retry, exhausted, cleanup failure, and provider readiness. Alerts fire per worker service and for any hold older than the configured 15-minute backup bound.

## Verification

Source proof requires:

- Unit tests for exact API schemas, scope derivation, idempotency, manifest signature/locator binding, provider decoding, and CLI redaction.
- Real PostgreSQL tests for RLS, ACLs, cross-tenant denial, fair claims, recovery holds, mutation blocking, lease fencing, replay, attempt exhaustion, down/re-up, and hostile role/schema drift.
- Local TLS provider tests for Neon request paths, authentication, deterministic reconciliation, response limits, timeouts, cancellation, and redaction.
- Versioned artifact tests proving descriptor-first/manifest-last publication and exact readback.
- Installed-browser tests for start, reload, terminal state, failed cleanup, and secret/reference absence.
- A disposable-PostgreSQL plus local-provider combined E2E that runs the real API, outbox worker, recovery worker, CLI, and UI.

Production promotion still requires live Neon branch create/delete, managed S3/KMS/SQS, Kubernetes namespace cleanup, and disposable graph/search rebuild proof. Those stay `blocked/external` until the live evidence exists. Source completion alone does not promote them.

## Release order

Migration v27 lands first and remains inert. API read/write operations land next, then outbox and recovery workers, CLI, UI, deployment identities, and combined E2E. Workloads stay disabled until readiness and cleanup canaries pass. A rollback to v26 is allowed only when no recovery operation or hold exists.
