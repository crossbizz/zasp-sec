# Browser acceptance still needs its own runner

Read-only source audit, 2026-09-19. M7A-23 / R2. I did not run tests, browsers, containers, network requests or providers. Only this document changed.

The fastest honest route is a new, isolated release-58 mode in the existing combined browser harness. Keep the real HTTPS origin, session callback, mounted API, registered PostgreSQL authorities, React UI and worker composition. Replace only the external identity/model/storage transports with bounded local fixtures. Then record a public-created export-only definition reaching approval, persisted export bytes and a Chrome download.

That is controlled local acceptance. It does not prove live Stytch, OpenRouter, AWS or a deployed environment.

**Goal:** One authenticated, supervised, source-free manual export, created and enabled through the UI, with an independently authenticated approver and exact saved-file evidence.

**Architecture:** Reuse `scripts/production-combined-e2e.mjs` for process ownership, TLS, OAuth callback, proxy, compiled UI and CDP. Add a small export flow module and test-only API/worker processes; the latter call existing production composition and registered SQL. External fixtures do not write definitions, histories, controls, runs, plans, approvals, links, packages or completion state.

**Inputs:** `docs/internal/launch-execution-20260919/README.md`, its M7A-23 card in `tasks.md`, and the four public-activation reports in this directory. Planning/TDD skills informed the packet boundaries and first failure below. This audit is a dispatch recipe, not permission to execute it.

## The old blocker is gone

The initial `public-activation-audit.md` predates accepted SQL/API/UI work. Don't rebuild public CRUD or the export builder from that snapshot.

The current SQL report records eight passing registered groups, including HTTP, lifecycle, authority waits, predecessor behavior, release restoration and manual admission. Its latest receipt correction supersedes the earlier 83416842 pin:

```text
HEAD:        8733b16f8d939d38a8157dd2519e57fc6f630542
fingerprint: 67a4e601a5597f67a35f3be50f4a47a0a602b3097b3a9e4838e6fc09dcee6b72
checksum:    78e98a4f8ed1532f431e1f9f14aaf59770bd963faa37a3bb20a2c06ec86b9c05
```

HEAD is not a complete identity for this dirty worktree. I checked the current release Go file, export HTTP test, SecurityAgentsView and decoder hashes against their latest report entries; all four match. Before implementation, the integrator must recheck the full producer manifests in `database/public-activation-sql-report.md`, `go-public-activation-progress.md` and `ui-public-activation-progress.md`, record a task-only diff and hash the built binaries/UI. Any later producer change invalidates the affected evidence.

Current UI evidence is 147 focused tests, with an explicit integer cost budget required for export drafts and enabled/version-0 export controls rejected. The reports still reserve independent review and connected browser/deployment acceptance. This audit makes no status promotion. Original M7A-23 acceptance still depends on M7A-22 and M7-40, plus SHIP-GATE for publication; R3's ordered multi-step work stays outside this packet.

## DISPATCH-GATE

Observable output: a candidate-bound evidence directory containing the browser-created definition, manual-run provenance, approved typed selection, export link/capture/storage receipt, original mutation receipts, screenshots and three native saved files whose bytes match persisted JSON/CSV/readable formats.

| Seat | Exclusive files to edit | Consumed contract and handoff |
| --- | --- | --- |
| Browser integration owner, L3/L5 | `scripts/production-combined-e2e.mjs`, `scripts/production-combined-e2e.test.mjs`; create `scripts/security-agent-export-mounted-browser.mjs` and `.test.mjs` sibling | Own the new mode, identity fixture extension, release registration, UI flow, artifacts and all process cleanup. Consume frozen API/worker fixture environment below. No other writer touches the combined harness concurrently. |
| Controlled API fixture owner | Create `services/platform/agentsec-api/security_agent_export_browser_process_test.go` | Build through `buildRuntimeDependenciesWithReadinessTransport`; actual session middleware, separate Security Agent DB and export retrieval. Storage factory is controlled. Only the four approved readiness hosts are routed to the owned worker listener. |
| Controlled worker fixture owner | Create `services/platform/agentsec-worker/security_agent_export_browser_process_test.go` | Compose planner, action, compliance writer and cleanup under separate registered logins; real admission/accounting/dispatch/capture/render/settlement. Bounded model/S3 transport is test-only. Supplies `/readyz` and bounded phase controls. |
| Independent reviewer and publication owner | No product write set in this packet | Review task-only diff plus evidence and cleanup. Keep the authoritative ledger unchanged until original acceptance requirements pass. |

These are seats, not agent assignments. The controller must name the implementer(s), one independent reviewer and cleanup owner before dispatch. One person can own all three code seats. Parallel work is safe only after the fixture contract is frozen; the shared harness has one writer.

Do not edit migrations, release pins, accepted SQL/HTTP fixture files, OpenAPI/generated code, product UI, deployment files or the ledger in this packet. If a focused test exposes a product defect, stop at that boundary and ask the controller to give its existing owner a narrow reproduction. Don't grow the harness packet's write set silently.

**Implementation input:** The supplied producer reports and current source have the public contract. Named ownership, current hash reconciliation and review disposition remain dispatch checks.

**Local execution input:** Cached Node 22.23.1, local Go toolchain/cache, Chrome, Docker daemon plus the already-cached pinned PostgreSQL image, `pg_config`/`psql`, OpenSSL and a fresh UI build. This audit did not check runtime availability. Missing cache/tooling is a prerequisite failure, not permission to install or pull.

## What can actually be reused

| Existing code | What it proves or supplies | Limit to preserve |
| --- | --- | --- |
| `scripts/production-combined-e2e.mjs` | Real callback at `/auth/callback`, durable product session, Secure `__Host-zasp_session`, browser bootstrap, expected-scope/CSRF headers, HTTPS proxy and Chrome | The identity endpoint is a local Stytch-shaped fixture. It returns controlled session JWT text, not a real provider JWT. |
| `scripts/attack-lab-mounted-browser.mjs` and API/worker `attack_lab_browser_process_test.go` files | Public create/activate/start pattern, actual production composition with controlled transport, bounded worker phase controls and fresh owned DB | Its current mode stops at57. Don't copy source/run fixtures or seeded approval sessions. |
| `scripts/existing-test-mounted-browser.mjs` | UI labels, independent approval UI, run-detail receipts and screenshots | Lines106-108 insert a `zasp_product_sessions` row and inject its cookie. That cannot prove approver login. Mode stops at55. |
| `services/platform/apiserver/security_agent_export_definition_http_postgres_test.go` | Public CRUD/control/activation/manual admission on registered58, replay/CAS and outage withdrawal | Injects `RequestIdentity` and a `workersReady` boolean. `assertManualExportConnected` calls registered SQL for planning/approval/dispatch/capture, not composed workers or download. |
| `services/platform/agentsec-api/compliance_browser_process_test.go` and worker `compliance_export_process_test.go` | Real API/storage factory and AWS SDK, persisted object across process restarts, exact version/KMS/owner pins | Current browser mode migrates56, has no export workflow configuration/readiness routing and serves compliance UI. The short-lived worker fixture cannot remain healthy for the four-service catalog check. |
| `scripts/production-combined-e2e.mjs:2246` and `scripts/compliance-browser-bytes.mjs` | Native Chrome download events plus filesystem bytes, all three formats and API restart | Compliance filenames and envelope shape must be replaced with the Security Agent export contract. A displayed success notice is insufficient. |
| `scripts/owned-browser-postgres.mjs`, `isolated-postgres-bridge.mjs`, `owned-command.mjs`, `bounded-signal-cleanup.mjs` | Pull-never pinned container, exact ownership labels/IDs, network-none relay option, bounded joins and cleanup | The relay is currently selected only for Attack Lab. Extend that branch for the new mode; don't boot host PostgreSQL. |

The simulation runner is not an execution substitute. Its intended result is zero execution side effects. The large audit-export browser runner is a different export family.

One more missing piece: `newCombinedE2EOpenRouterPlanner` in `agentsec-worker/production_combined_e2e_test.go:57` does not construct an export candidate. It targets the first untrusted evidence ID for export and omits typed `evidence_ids`. Reusing it unchanged will not produce the required parent-run target and retained selection. Add an export-specific provider fixture in the new worker file; leave this shared helper alone.

## Freeze the local fixture contract first

Proposed mode: `ZASP_COMBINED_E2E_SECURITY_AGENT_EXPORT=true`. It does not exist today. Reject combinations with every other selected combined mode; don't fall through to the broad discovery/runtime scenario. Add this branch before generic `seedPostgres`, building API and worker with `go test -c`, and migrate with `agentsec-migrate up-to-58`. Assert max version58, the compiled checksum/fingerprint, installed admission and settlement readiness through the appropriate registered principals.

Register compliance logins with the existing `agentsec-migrate register-compliance-workers` command and `ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL=compliance_executor`, `ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL=compliance_cleanup`. Reuse the harness's existing migration principal registrations for `zasp_e2e_api`, `zasp_e2e_security_agent_api`, `zasp_e2e_security_agent_worker` and `zasp_e2e_security_agent_action`. Runtime requests must never use owner `zasp_e2e`.

Existing shared API settings come from `combinedAPIEnvironment`: loopback listener, trusted loopback proxy, SaaS test mode, secure cookies, local identity URLs and separate Security Agent DSN. Add:

```text
ZASP_EXPECTED_SCHEMA_VERSION=58
ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW=enabled
ZASP_COMPLIANCE_EXPORT_BUCKET=zasp-compliance-exports
ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER=123456789012
ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111
ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN=arn:aws:iam::123456789012:role/compliance-api-reader
ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
```

Those AWS values are fixture configuration. Factories must replace external credential/storage transports, so the local path does not read a real IRSA token or contact AWS. Writer and cleanup composition use separate roles and the existing worker `ZASP_COMPLIANCE_EXPORT_ROLE_ARN` setting; never put that writer variable into API configuration.

New process names: `TestSecurityAgentExportBrowserAPIProcess` and `TestSecurityAgentExportBrowserWorkerProcess`. Proposed shared fixture environment is `ZASP_SA_EXPORT_BROWSER_API=true` or `ZASP_SA_EXPORT_BROWSER_WORKER=true`, plus `ZASP_SA_EXPORT_BROWSER_PG_PORT`, `ZASP_SA_EXPORT_BROWSER_WORKER_PORT`, `ZASP_SA_EXPORT_BROWSER_DEADLINE` (absolute, at most 30 minutes away), and `ZASP_SA_EXPORT_BROWSER_OBJECT` (canonical path in this invocation's owned root). Worker also takes `ZASP_SA_EXPORT_BROWSER_DSN` with the worker login. Strictly validate these values before opening sockets or files; they are not production switches.

All ports are selected by `reservePort`, not hardcoded. Existing eight: PostgreSQL bridge, identity HTTP, policy-history fixture, API public, API health, web, TLS proxy, Chrome CDP. Add one worker-control/readiness port and a separate Chrome CDP port/profile for the approver. Record the actual numbers in the evidence manifest. Public origin stays `https://zasp.production-e2e.test:<proxyPort>` with the existing Chrome loopback host mapping and owned one-day certificate.

The API's fixed readiness names remain unchanged:

```text
agentsec-security-agent:8081
agentsec-security-agent-action:8081
zasp-compliance-export-worker:8081
zasp-compliance-cleanup-worker:8081
```

Route only their GET `/readyz` calls to the owned worker listener, retaining the original Host so it can invoke each actual composition's `Ready` function. Unknown hosts fail. Don't return a constant healthy response. Export dispatch occurs in the Security Agent processor; action-worker readiness is still an explicit admission requirement.

The worker fixture can host four real compositions in one test process. `/plan`, `/dispatch`, `/capture` and `/settle` are test-only bounded loopback operations that call the relevant `Processor.RunOnce`; they must not call owner SQL to synthesize results. `/plan` and `/dispatch` advance the same Security Agent processor on opposite sides of public approval. `/capture` advances the compliance writer, and `/settle` lets the Security Agent reconciliation consume completed export facts. Keep cleanup composition available for readiness and explicit cleanup tests. Reuse the existing strict SDK object transport pattern, persisting object key, version, headers and bytes to the owned file.

The provider fixture reads the actual planner context and returns exactly one step: index0, action `create_evidence_export`, target=parent run, and a nonempty subset of supplied `export_selection` with all four tuple fields intact. Include bounded usage/cost so production reservation and settlement stay active. Preserve the real model request parser, candidate validation and SQL admission. No hand-authored accepted plan row.

## Two sessions, both through the callback

Seed Organizations/workspaces/environments, membership and scope grants only. Use the identity-only pattern in `seedAttackLabBrowserIdentity`, without calling its downstream source fixture. Author scope can use the existing Staging IDs ending `0001/0022/0023` and actor ending `0004`; author needs `view`, `manage_workflows`, `manage_identity`. Add a distinct approver membership with `view` and `manage_workflows` in that exact scope. A foreign Organization with no access supplies the tenant-negative case. Global execution state comes from the migration; read and record it, never patch it to make the test pass.

Current `startIdentityServer` recognizes admin and group-reader identities only. Extend its controlled OAuth/authenticate/session responses with a fixed approver identity and a foreign identity, selected by test orchestration before each sequential login. The author, approver and foreign-user profiles each visit `/api/v1/session/start?return_to=...`, receive the real callback, and let product code persist their sessions. Don't insert `zasp_product_sessions`, set browser cookies, inject middleware identities or share the author's cookie with the approver. Separate profiles prevent one login replacing the other.

Record callback/bootstrap success, principal/scope IDs and fresh-auth state. Never retain session cookies, JWTs, CSRF secrets, grant tokens or credentials in evidence. If the session loses freshness during the flow, use the real reauthentication path and retained operation retry; a SQL timestamp update would invalidate that proof.

Before the first user mutation, count definition/history/run/plan/approval/export-link/job rows and scoped export action controls. Require zero. After login, product session rows are expected, but they must come from the callback.

## The browser steps that matter

1. Open `/protect/security-agents` as author. Assert the exact eight current controls and the catalog-backed `Run-scoped evidence export` choice. Save a definition with budget `1000000`, one step, verification `export`, only `create_evidence_export`, no `existing_test` and `enabled=false`. Capture POST body, receipt, audit ID and ETag, redacted.
2. Update its name through `Save definition`; retain the PATCH receipt/version. Enable environment automation and `create_evidence_export` through their UI buttons. Validate, then click `Enable supervised execution`. These are real fresh-auth/CAS mutations. Do not enable autonomous mode for this approval proof.
3. Empty Evidence ID. Click `Start supervised run`. Keep the original returned run ID, definition version, receipt and `manual_trigger`; legacy evidence IDs must be `[]`. The manual intent is already a valid run-scoped export source, so this shortest path needs no discovery/finding/test run fixture.
4. Advance the real planner composition once and reload the run. Assert `waiting_approval`, one typed export step, target=that run, settled planner accounting and a selection from its actual context. Record both screenshot and durable IDs. A second author-created manual run can supply an unselected same-tenant canary; don't plan it.
5. Approver login. Open `/protect/approvals`, select the generated approval, approve through the UI and retain its public receipt/version and principal. Author self-approval must fail in a separate negative assertion if this is the configured independent approval boundary. Don't use direct decision SQL.
6. Advance dispatch, then the compliance writer. Observe the same run's `verifying` state and the pending export link before upload, followed by captured package, versioned stored artifact and `completed` export status. Advance settlement and assert the actual recorded terminal reason. Current code maps available exports to `needs_human` / `export_available`; never claim remediation from export creation.
7. Author opens the original run detail. `section[aria-label="Security Agent evidence export"]` must show selection, artifact hash/size, expiry and cleanup state. Click `Refresh export status` as needed; ExportPanel does not continuously poll job status.
8. Configure native Chrome download behavior on the current target. Click `Download JSON`, `Download CSV`, `Download readable`; require actual saved files and completed download events. Restart API/worker against the same database and persisted object, reopen the same run, then repeat one download without another upload or export job.

This sequence proves manual intent exports. The broader source families keep their registered source/authority regressions; don't claim that one manual browser run proves finding, attack-path, runtime, existing-test and Attack Lab browser journeys.

## Start with an honest RED

No new test ran here. The names below are proposed.

First add `TestSecurityAgentExportBrowserPlannerSelection` in the new worker fixture file. Feed a real export-only manual context through the existing controlled planner helper and production parser. Assert an accepted candidate targets the parent run and carries the original `{source_kind,source_id,source_version,association_digest}` selection. The current helper cannot meet that contract: it omits selection and targets the manual evidence digest. Capture that behavioral failure before adding the export-specific transport. A missing file/import or unreachable service is setup failure, not RED.

```sh
# From services/platform, offline and without PostgreSQL/browser startup:
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-worker -run '^TestSecurityAgentExportBrowserPlannerSelection$' -count=1 -v
```

For browser acceptance, write the happy-path assertions before filling in the new harness mode. Once it boots, retain the first real product-boundary failure with request/status and screenshot. If the product path already works, a GREEN integration test is new evidence, not a fabricated historical RED. Any product fix needs its own focused failing regression first.

Add behavior tests in the new JS test module for missing/mismatched saved bytes, foreign selection, absent approval receipt and incomplete download; test actual assertions with controlled values. Add isolation/cleanup tests to the existing combined test file only where this new mode changes its behavior. Don't grep source for proof of execution.

## One grouped verification pass

After focused RED/GREEN, freeze all packet files and run one coherent batch. Below are commands to use after implementation; none has run for this audit.

```sh
# Worktree root; cached toolchain only.
export PATH="/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache
node --test scripts/security-agent-export-mounted-browser.test.mjs scripts/production-combined-e2e.test.mjs scripts/browser-prerequisites.test.mjs scripts/owned-browser-postgres.test.mjs scripts/browser-e2e-helpers.test.mjs
node node_modules/vitest/vitest.mjs run app/features/securityagents/SecurityAgentsView.test.tsx apps/web/api/decoders.security-agent-lifecycle.test.ts app/features/securityagents/ExportPanel.test.tsx app/features/securityagents/export-api.test.ts
npm run typecheck
npm run build
ZASP_COMBINED_E2E_SECURITY_AGENT_EXPORT=true node scripts/production-combined-e2e.mjs
git diff --check
```

The last browser command is proposed, not a currently supported invocation. Require a mode-specific completion marker, actual exit0 and every declared stage in the manifest. An unknown environment variable currently does not establish a selected export test.

Run the new non-process Go tests with `-race -count=1` and the affected existing API/workflow/planner/dispatch/render tests on the frozen source. The process tests have opt-in skips outside their parent runner; invoke their exact `-test.run` selectors in that runner and require zero skips there. Don't use a broad native Go selector that accidentally starts host PostgreSQL. Reuse the latest registered eight-group proof only if its exact source/pin inputs remain valid; otherwise rebuild the offline Linux binary and use the owned runner recipe in `database/public-activation-sql-report.md`.

The grouped browser negatives should include sibling-scope/foreign-Organization status and download refusal, revoked current membership between grant and download, replay of an already consumed grant, stale CAS or retained-response retry, and worker-health loss refusing fresh setup while retained reads/control disable remain usable. Restore only this fixture's scoped identity changes. Keep source-family rejection and release-drift matrices in the existing registered tests unless changed inputs require a rerun.

The independent reviewer maps each assertion to M7A-23's run-scoped evidence criterion. Publication still has its own exact-candidate SHIP-GATE; this command block doesn't replace it.

## Saved bytes, not a toast

Create a retained evidence directory outside the disposable process root. Save a manifest with source hashes, UI/API/worker binary hashes, schema checksum/fingerprint, actual ports/process IDs, redacted public request receipts, SQL read-only witnesses, provider request counts, stage timestamps, exit status and cleanup results.

Screenshots: disabled saved draft; enabled controls/activation; waiting approval and its typed selection; distinct approver decision; pending export; completed ExportPanel; download confirmation; one tenant denial. Use existing `Page.captureScreenshot` and visually inspect the captures before accepting them. A screenshot alone cannot establish durable authority.

Files are `agent-export-<export_id>.json`, `.csv` and `.txt`, as defined by `ExportPanel.tsx`. Capture download GUID, suggested filename, completed state and received bytes; bounded filesystem checks must see nonempty final files and no partial `.crdownload`. Hash each file. Compare JSON with the exact stored JSON-format bytes, CSV with the persisted CSV string bytes, and readable with persisted human string bytes. Use independently parsed storage envelope data; don't generate expected bytes by rerunning the renderer under test.

The artifact SHA-256 shown by ExportPanel is for the stored package. It is not automatically the downloaded JSON hash. Record both the package hash/size and per-format hashes/sizes, plus object key/version and exact run/step/export tuple. Check the downloaded content contains only the retained selected sources, original manual digest/version and expected scope; reject a foreign marker and the unselected same-tenant run. Verify disclaimer text without making a certification or remediation claim.

## Cleanup owns the last word

The integration owner registers every child before awaiting startup. Reuse bounded signal cleanup, but include both browser profiles and the new API/worker process. Stop and join workers/API/browser, close proxy/identity/policy-history listeners, then stop the PostgreSQL bridge and its exact labeled container. Verify the container is absent and ports/processes are gone. Never kill a shared browser or all PostgreSQL processes.

The existing PostgreSQL image is `postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`, with `--pull=never`, read-only root and owned tmpfs. Use the network-none relay option from Attack Lab for this mode. No LocalStack, Neo4j, discovery provider or AWS account is needed for the controlled manual-export path.

Do not down-migrate a database containing retained exports. Dispose only of this invocation's owned container/state. Retain screenshots, redacted logs and downloaded bytes outside the temporary root; delete the owned process root only after every join succeeds. On cleanup failure, retain it and report the exact resource identity. Avoid broad `rm`, container pruning or shared-worktree cleanup.

## What remains external

| Claim | Evidence still required |
| --- | --- |
| Real identity-provider authentication | Authorized Stytch test/deployed project, approved callback origin, actual author and independent approver accounts, real provider session/fresh-auth observations. Local callback proof does not close M0-02/M0-03. |
| Real model execution | Approved OpenRouter credentials, model/data policy, current pricing and bounded spend; original provider/accounting receipts on the candidate. Controlled usage numbers are not live charges. |
| Real export storage | Authorized S3/KMS/IRSA identities and bucket/versioning policy; real write/read/cleanup and current-actor denial evidence. SDK transport proof is not AWS authorization proof. |
| Deployed product | Authorized reference environment, deployed candidate/image identities, actual four-service health and public TLS/browser run. Local same-process health routing is not service DNS, Kubernetes or network-policy acceptance. |

M7A-23's card has no standalone external gate on its row. That doesn't erase inherited acceptance prerequisites, SHIP-GATE, or the separate inputs needed for any live claim. This packet can produce useful controlled browser proof without waiting for those accounts, but it cannot label that result production-available.

Assign the harness owner and freeze the three fixture interfaces before starting the first RED.
