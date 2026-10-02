# The bytes still need one connected proof

DISPATCH-GATE: READY FOR A BOUNDED LOCAL INTEGRATION PACKET, NOT FEATURE ACCEPTANCE. Give one integration owner the test composition below after the controller freezes its planner/public-activation dependencies. Product upload, retrieval and cleanup paths already exist. The missing piece is a registered, public-created export that passes through those paths and reaches saved browser bytes. Don't commission another export service.

I inspected source and retained reports on 2026-09-19 at HEAD `8733b16f8d939d38a8157dd2519e57fc6f630542` in this dirty worktree. Current release58 fingerprint in `services/platform/migrations/security_agent_exports_release.go:38` is `67a4e601a5597f67a35f3be50f4a47a0a602b3097b3a9e4838e6fc09dcee6b72`. The latest Go handoff reports checksum `78e98a4f8ed1532f431e1f9f14aaf59770bd963faa37a3bb20a2c06ec86b9c05`; I did not recompute it or rerun its database fixture. Older report pins are historical.

This is a read-only audit except for this document. No test, container, provider request, network access, product edit, ledger edit, commit or push ran. I read `/Users/manishmaheshwari/.codex/writing-style.md` and the Superpowers planning guidance. The proposed REDs below haven't run.

## Where the current proof stops

| Evidence | What it reaches | Boundary left controlled or absent |
| --- | --- | --- |
| `security_agent_export_definition_http_postgres_test.go`, `TestSecurityAgentExportDefinitionHTTPPostgres` | Registered API database login; real public router/handlers/repositories; public definition create/update/delete, controls, activation, manual starts, receipts, replay, authority refusal. Its fixture checks that export definitions/history/action controls/runs start empty. | Identity and browser-security context enter through the fixture; this test does not run login or authentication middleware. Worker health is a Boolean override. Its router is `NewComposition`, with no export download surface attached. |
| `security_agent_manual_admission_postgres_test.go:142-274`, `assertManualExportConnected` | Registered worker claims, retained manual context, budget reservation/settlement, SQL planner acceptance, approval context/decision, reclaim, export dispatch, registered capture containing the original manual intent digest. | The helper builds the candidate itself, invents a fixed output digest and supplies `fixture-model`/`fixture-cost-policy`. Approval is through the registered SQL helper. No planner provider/runtime, renderer, prepared package, object write, download grant, HTTP download, or saved file. This is real capture with constructed planning inputs, not fabricated capture output. |
| `security_agent_export_worker_process_postgres_test.go`, `TestSecurityAgentExportWorkerProcessPostgres` | Registered dispatch, actual compliance polling worker child processes, capture/render/prepare, persisted object bytes, SIGTERM during PUT, unknown-write accounting, second-process replay/completion, Go settlement claim/settle/replay. | `runExportDBFixture` owner-seeds run/plan prerequisites. SDK calls use a controlled file-backed `RoundTripper`; credentials and STS identity are doubles. The parent moves `next_attempt_at` for the test. No public-created definition, retrieval HTTP or browser. |
| `security_agent_export_postgres_test.go`, lifecycle/authority/cancellation/two-scope groups | Registered SQL lifecycle, grants and final-authority checks, isolation and accounting branches. | Its prepare/finish calls construct package bytes and storage receipts. SQL cannot establish that the claimed provider version contains those bytes. |
| `security_agent_export_http_test.go` and `security_agent_export_download_test.go` | Real routing/middleware in the HTTP component tests, grant format mapping, read-before-consume-before-response, denied disclosure, strict package/manifest decoding and corruption/cancellation bounds. | Database and artifact reader are controlled. This is not registered SQL plus an SDK-backed object download. |
| `ExportPanel.test.tsx`, `export-api.test.ts`, public UI handoff | Mounted panel and real client adapter with controlled transport, lifetime/scope invalidation and download handoff behavior. | The notice only says the download was handed to the browser. It doesn't prove that a browser saved a file, or connect its bytes to a real worker-produced object. |

The latest registered HTTP receipt-fix checkpoint reports eight passing groups and clean database joins at pin67a4e601. Keep that result. It clears public setup, not upload/download composition. The decoder review accepted its component after coverage corrections; it explicitly left connected retrieval open. The process review also says equal before/after bytes alone cannot exclude deterministic re-rendering. Pair restart evidence with the worker's separate no-render prepared-replay test or add a counted capture/prepare oracle to the connected fixture.

## Follow the actual object

The run worker's `tryExecuteSecurityAgentExport` calls `zasp_sa_export_run_kind` then `ExecuteSecurityAgentExport`/`zasp_sa_export_execute_run`. The checked receipt is a scoped pending export, and the parent moves to `verifying`; it is not an available artifact. See `services/platform/apiserver/security_agent_export_dispatch.go` and `services/platform/agentsec-worker/security_agent_export_dispatch_runtime.go`.

Next, the shared compliance execute lane discovers and claims the `agent_run` job. `compliance_export_database.go` validates its independent run/step/selection binding. `compliance_export_runtime.go:26-160` calls `executeComplianceExportPackage`; `compliance_export_replay.go:52-112` either reloads already prepared bytes or captures, selects the origin-specific renderer and prepares those bytes before storage I/O. `security_agent_export_worker.go` routes agent jobs to `security_agent_export_render.go`. Agent revisions are `security-agent-run-evidence-v1` and `security-agent-evidence-envelope-v1`.

`composeComplianceExportWorkerRuntime` in `compliance_export_production.go` constructs `s3driver.NewExport` and `artifactstore.NewExport`. The package is an application/json envelope containing `version`, `id`, `json`, `csv`, `human`. PUT completion must match scope, reference, version, size, SHA-256 and the prepared bytes. Any failure after PUT begins retains unknown-write accounting. Cleanup has separate read/delete clients and no writer.

The API runtime already mounts `NewSecurityAgentExportProductionHandler` using the shared compliance storage configuration (`agentsec-api/production_runtime.go:251-276`). That handler builds a read-only S3 driver and artifact store, not a presigned browser URL. Release58 capability controls its presence. Public metadata contains the package digest/size but no storage key or provider version.

All retrieval uses browser-session authority:

```text
GET  /api/v1/security-agent-runs/{id}/steps/{stepId}/export
POST /api/v1/security-agent-runs/{id}/steps/{stepId}/export/download-grants
POST /api/v1/security-agent-runs/{id}/steps/{stepId}/export/download
```

The last two bodies are `{format}` and `{format,token}`. Public `human` maps to SQL `readable`. `security_agent_export_http.go` reads one scoped grant, fetches the pinned provider version, validates the entire package plus ordered run manifest and each content digest, then consumes the grant before writing response bytes. A storage GET completing after permission revocation must still lose at final consume. The handler sets `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, format-specific media type and `Content-Disposition: attachment; filename="agent-export-<export_id>.<extension>"`.

The shared grant lifecycle is cloned with agent-origin/source authority in `security_agent_export_links.sql:389-458`. Each operation checks the browser session, active membership, retained run/link authority and current source permissions. Grant lifetime is at most60 seconds; read lease at most30 seconds, each clipped to retrieval expiry. Token matching binds scope, export, principal, session and format. Repeated read and consumed-token reuse fail. A second authorized scoped reader is allowed; equating the viewer with the original requester would be the wrong test.

`security_agent_export_download.go` verifies the package digest against SQL and artifactstore, then returns only the selected format. This distinction matters: the metadata SHA-256 is the envelope hash, not the saved CSV/JSON/readable file hash. The oracle must retain both. JSON `content_sha256` hashes the exact `content_json` string; `association_digest` is a separate membership/version binding.

`SecurityAgentsView.tsx:419` mounts the existing `ExportPanel` on the original execution step. `export-api.ts` issues a new grant for each download, checks current scope/lifetime and returns a bounded Blob. The panel creates an object URL and clicks a filename-bearing anchor. It does not use response Content-Disposition to choose the filename, so test the HTTP header and browser filename separately. The panel refreshes status on mount/manual refresh, not continuous polling.

Cleanup runs `Maintenance`, then reconcile/cleanup lanes in `compliance_export_runtime.go`. Read leases block deletion. Reconciliation reads the prepared intent and verifies stored bytes without PUT. `artifactstore/s3driver/export_lifecycle.go:81-121` deletes only the pinned version and requires a typed `NoSuchVersion` from a follow-up GET before accounting can be released; a DELETE200/204 or generic404 is insufficient. SQL cleanup clears retained package/source data and retained bytes only after that receipt. Parent cancellation/revocation doesn't authorize publication, and doesn't remove the cleanup obligation.

## Smallest useful composition

Start with one registered PostgreSQL fixture and real public handlers. Keep the same public-created definition/run/step/export identities all the way through. Admit an export-only supervised definition through the existing APIs, call the actual planner worker against a bounded controlled model response, approve through the public route as a distinct authorized actor, and let the action worker dispatch. Then run the real compliance execute/settlement paths and mount the production download handler against the very object written by that worker. The planner/runtime owner supplies that upstream handoff; this storage packet must not call `assertManualExportConnected` and claim it exercised the runtime.

There is a small reusable seam already: `agentsec-worker/compliance_export_process_test.go` persists `Body`, headers and key in `object.json`; `agentsec-api/compliance_browser_process_test.go` has `complianceBrowserReadTransport` that reads that exact file using the real AWS SDK. Both refuse external provider access. Reuse their format and pin checks, but give the new test fixture an owned multi-object store keyed by full object key plus immutable version. The existing one-file transport rejects every second key; it can't honestly cover two successful tenants or preserve an unrelated object during cleanup.

A file-backed controlled SDK transport is enough for local composition. Label it precisely. It executes real rendering, storage drivers, bytes on disk, registered authority and HTTP; it doesn't implement AWS IAM, KMS, bucket versioning or real retention. No production endpoint override is required. Keep provider injection in test-only constructors/factories, and retain the production client role separation.

For browser acceptance, extend the existing owned-browser/process approach with an isolated export mode, compiled58, production frontend and the actual API process. Use the existing session/login flow with a controlled identity provider and two browser identities for requester/approver, or explicitly label an injected identity run as below-authentication integration. Run the unchanged `ExportPanel`, save all three formats in its owned downloads directory, and compare saved bytes with the persisted worker envelope. A React object-URL assertion is not the final oracle.

## Give the files one writer

The controller owns dependency freezes and dispatch. A single storage/download integration owner should own these proposed additions; paths below do not exist yet unless stated otherwise:

| Owner | Exact files and purpose |
| --- | --- |
| Storage/download integration | Create `services/platform/apiserver/security_agent_export_storage_download_postgres_test.go`: registered public-created flow, real production export handler, grants and exact-byte assertions. Create `services/platform/agentsec-worker/security_agent_export_storage_process_test.go`: test-only execute/reconcile/cleanup process entry with existing production runtime construction. |
| Same integration owner | Create `services/platform/internal/exportfixture/store.go` and `store_test.go`: explicitly test-only imported controlled SDK transport, bounded disk persistence, version/key isolation, fault barriers and request log. If existing fixture transport is refactored, it also owns `agentsec-worker/compliance_export_process_test.go` and `agentsec-api/compliance_browser_process_test.go` for that packet. Do not share-write these files. |
| Browser integration, after API fixture | Create `scripts/security-agent-export-mounted-browser.mjs` and its test; modify `scripts/production-combined-e2e.mjs` and `.test.mjs` for a separate compiled58 export mode. Reuse `scripts/owned-browser-postgres.mjs`; don't silently change compliance56 or Attack Lab57 acceptance. |
| Planner/runtime owner | Real public-created run -> bounded planner call -> public approval -> action dispatch handoff. It supplies run/step/selection identity, failure limits and joined process evidence; this packet consumes those identities. |
| SQL single writer, only if a behavioral failure requires it | `migrations/sql/fragments/security_agent_export_links.sql`, related release58 fragments and `security_agent_exports_release.go`. Any SQL/pin change invalidates the fixture binaries and requires catalog/predecessor regressions. No speculative SQL fix is identified here. |
| API/UI product owners, only on reached RED | `security_agent_export_http.go`, `_production.go`, `_download.go`, `_status.go`, `security_agent_exports_repository.go`, `ExportPanel.tsx`, `export-api.ts`. Existing wiring is present; the audit does not assert a product defect in these files. |

Configuration needs no new production storage backend. API requires the current compliance bucket/owner/KMS key, reader role and web-identity token-file settings plus enabled evidence-export workflow. Executor and cleanup use distinct registered database principals, worker modes `compliance-export`/`compliance-export-cleanup`, and separate role credentials. Real readiness checks target the Security Agent planner/action and compliance execute/cleanup services (`export_workflow_readiness.go`). The local harness must map those readiness probes to its actual child processes through a controlled test transport; copying `workersReady=true` preserves only admission test coverage. Capture config, authority registration, source hashes and release pins with the result.

## Proposed RED, and the assertions that count

Write the connected test first. The old public HTTP composition has no export handler, and its helper leaves the job captured without a package; expecting a completed downloadable export exposes that fixture gap. That is a composition RED, not evidence of a production handler bug. Compilation errors, missing PostgreSQL binaries or a test that selects zero cases don't count as behavioral RED.

The executable test contract is:

1. Public setup starts with zero export definitions/runs/links/jobs. Submit the bounded draft and manual intent through the public API, plan through the real runtime using controlled provider output, approve publicly, then dispatch. Assert exactly one scoped link/job and the original run/step in the worker-produced manifest. A sibling run and foreign tenant must have distinguishable source content; neither can leak into the selected manifest.
2. Actual stored bytes. Let the real renderer/prepare/store path write the owned disk store. Independent observation reads the stored envelope and hashes it, comparing SQL package digest/size and immutable provider version. Do not construct expected bytes with the renderer under test. Compare each downloaded format to the corresponding stored envelope member, and assert selected record identity/content against seeded source facts.
3. Mounted GET status, POST grant and POST download must succeed through registered API SQL and the production artifact reader. For JSON/CSV/human assert exact bytes, media type, full Content-Disposition filename, no-store, nosniff and no private object locator/version in metadata or errors. Browser saved-file checks use a separate per-format SHA-256 and size.
4. Refusal matrix: foreign organization/workspace/environment, sibling run/step, another session, wrong format, changed token, expired grant, repeated read, repeated consume and concurrent token reuse. At most one request returns the file. Source/membership/session revocation after the storage GET barrier must make final consume refuse before any file bytes are written. Assert failed pre-read checks cause zero storage GETs. Bearer CRUD remains supported upstream, but export retrieval is browser-only.
5. Corruption. Return a wrong version/key, altered package bytes, swapped ordered selection or malformed content with internally recomputed hashes; no response may contain artifact content. Verify the integrity-failure grant bookkeeping/audit is single-use. Keep ordinary provider timeout distinct from integrity failure.
6. Kill/restart after disk PUT succeeds but before SQL finish. Retain prepared bytes, retained quota and unknown-write state, then join the first child and start a second. Verify immutable version/bytes, no extra capture/render, one durable export and bounded attempts. Log PUT attempts separately from object versions: a conditional retry may legitimately issue another PUT without creating another version. Restart the API between grant issue and download too; persisted grants must survive and still be single-use.
7. Cleanup. Block a real version-pinned GET at a controlled barrier, prove a live read lease prevents cleanup claim/deletion, then release or let the bounded lease expire. Accelerating expiry via owner SQL is acceptable only as a labeled fault injection; never replace the product claim/cleanup functions. Exercise parent cancel, requester revocation and retrieval expiry. Denied delete, lost delete response and generic404 keep accounting; exact-version `NoSuchVersion` permits one deletion audit and zero retained bytes. Confirm the sibling/foreign stored objects are unchanged. Restart cleanup while deletion remains pending; cleanup/reconcile must issue zero PUTs.

Use two successful scopes, not just a foreign-scope request that dies before storage. And keep browser-origin compliance regression in the same affected batch: release58 shares its tables, worker and grant mechanics.

## Commands for the implementation owner

These are proposed verification commands, not runs performed by this audit. Run from `services/platform` with the cached toolchain:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^(TestSecurityAgentExport(HTTP.*|Download.*)|TestCompliancePersisted.*)$' -count=1 -v
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-worker -run '^(TestSecurityAgentExportWorker.*|TestComplianceReplayOutcomes|TestComplianceWorker.*|TestComplianceRuntime(RendersFrozenSnapshot|CandidatesRejectUnsafeWire|Configuration|ComposedLifecycle))$' -count=1 -v
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -list '^TestSecurityAgentExport(StorageDownload|WorkerProcess|Lifecycle|Cancellation|TwoScopes|AfterLockRevocation|Release)Postgres$'
```

After adding the proposed registered test, compile fresh apiserver/API/worker test binaries offline for the approved owned PostgreSQL environment. Use the retained bounded runner recipe in `database/public-activation-commands.md` with explicit mounted binaries; the process fixture requires `/compliance-worker.test`. Proposed registered selector:

```text
^TestSecurityAgentExport(StorageDownload|WorkerProcess|Lifecycle|Cancellation|TwoScopes|AfterLockRevocation|Release)Postgres$
```

Demand every named test in enumeration and output, zero unexpected skips, joined database/worker lifetimes and exact candidate source hashes. A standalone `TestComplianceRuntimeProcess` SKIP without its owning parent is not restart proof. If the new fixture is split into named tests, freeze the new explicit selector before running it. This audit does not run or authorize containers.

From the worktree root with cached Node22.23.1 on PATH:

```sh
node node_modules/vitest/vitest.mjs run app/features/securityagents/ExportPanel.test.tsx app/features/securityagents/export-api.test.ts app/features/securityagents/SecurityAgentsView.test.tsx
node --test scripts/compliance-browser-bytes.test.mjs scripts/production-combined-e2e.test.mjs scripts/owned-browser-postgres.test.mjs
npm run typecheck
npm run build
git diff --check
```

The new mounted browser runner needs a documented, bounded command after implementation; there is no existing M7A-23 storage/download browser mode to truthfully invoke today. Retain request traces, object hashes, downloaded files/hashes, process exits, authority/pin checks and cleanup receipts. Redact session/grant tokens from durable reports.

## What stays outside this gate

Local GREEN can establish connected product behavior using registered local PostgreSQL and a controlled model/storage boundary. It cannot establish actual AWS bucket versioning, IAM executor/reader/cleanup isolation, web-identity trust, KMS decrypt/encrypt authorization, retention/legal-hold behavior, lifecycle deletion, cloud networking or provider operational availability. Those need approved provider/deployment evidence with exact configuration and production build identity. Controlled model output doesn't establish live model quality, latency, cost or provider account access. Controlled identity-provider login doesn't establish the deployed identity provider.

The exact-source hosted CI, release/SHIP-GATE, independent integrated review and native browser file proof remain separate checks. Existing component reports are dependencies, not substitutes for this packet. M7A-23 remains component-only. Dispatch the test composition with one storage owner and the planner/runtime handoff frozen.
