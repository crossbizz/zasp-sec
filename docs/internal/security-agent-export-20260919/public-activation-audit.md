# Export still stops at public setup

Read-only audit, 2026-09-19. M7A-23 / R2. The next observable result is a user-created, updated, activated and enabled single-action export definition reaching the existing manual start, planner, approval, export and download path. Definition, run and plan must all come from product APIs. Not proved yet.

I inspected the dirty shipping worktree at HEAD `8733b16f8d939d38a8157dd2519e57fc6f630542`. HEAD alone does not identify these unpublished bytes. Paths and line numbers below are worktree-relative; they identify this audit snapshot, not a deployed revision.

The original task remains component-only, with M7A-22 and M7-40 acceptance prerequisites. Its criterion is run-scoped evidence, and the launch plan explicitly requires public setup without seeded runs/plans (`docs/internal/launch-execution-20260919/tasks.md:2438`, `:2458`; `README.md:65` in that same directory). R3 owns ordered multi-step execution. This report does not design it.

## DISPATCH-GATE

| Packet / owner | Actual input and gap | Produced contract / one observable output | Dispatch disposition |
| --- | --- | --- | --- |
| SQL admission / single migration writer | Exact58 settlement/manual authority exists. `zasp_sa_export_workflow_readiness(text,text)` does not exist in migration SQL. Existing lifecycle/control paths have no dedicated export admission contract. | Installed admission probe; closed export-only definition lifecycle; scoped eight-action control read/mutation; retained definition actor/version/digest and ordinary mutation receipts. Preserve predecessor restoration and live fingerprint coverage. | Preparation ready. Implementation must freeze the SQL mutation/read signatures and pin with Go owner before consumers change. |
| Go API / one named API owner | Accepted capability interfaces exist, but only catalog uses connected workflow readiness. Body validation, activation decoding and controls still exclude export. | Existing HTTP CRUD/activation/control routes accept valid export intent only under the agreed capability rules, preserve original receipt/CAS semantics and reject stale/foreign/disabled authority. | RED preparation ready; SQL-backed GREEN depends on SQL producer. No fallback to older authority on missing/drifted58. |
| OpenAPI, client and UI / one integrator | Download, manual start and approval displays exist. Control enum/decoder stop at seven actions; builder only creates templates, all export-bearing templates are composite. | Closed eight-key controls plus a bounded export-only creation choice using the catalog; real public create/update/activate/enable/start and existing export panel. | Prepare focused tests now. Integrate after API shape is frozen. Do not enable composite templates. |
| Connected verification / integration seat, then independent reviewer | New public prerequisites plus unchanged planner/approval/export consumers and configured local runtime. | Original definition/run/approval/export/grant receipts and matching downloaded bytes from one public flow, with tenant and authority-loss refusals. | Blocked on the three packets. One frozen feature batch and independent review, not a new review per microtask. |

These are ownership slots, not dispatched agents. The controller must name each implementer and an independent reviewer before coding. SQL owns disposable database cleanup; integration owns any browser/runtime fixture cleanup. No deployment files belong to these packets. The active deployment work remains separate.

## Where it stops, exactly

| Boundary | Current source evidence | Remaining gap |
| --- | --- | --- |
| Installed admission / catalog | `services/platform/apiserver/security_agent_export_workflow_capability.go:43` probes the exact function and passes release58 checksum/fingerprint; absent is false, installed false/error is unavailable. `workflow_handler.go:142` consumes workflow capability; `:880` conditionally adds export metadata. `services/platform/migrations/sql/0058_production_security_agent_exports.up.sql:66` installs sources/jobs/links/planner/accounting/manual fragments, and `:90` defines only the settlement readiness function. | Implement and grant the distinct admission probe only when the public lifecycle/control contract exists. Settlement readiness is not a substitute. Current real installation cannot advertise export through this probe. |
| Create / update | `services/platform/apiserver/workflow_handler.go:640` probes existing-test and Attack Lab authority only. `:819` special-cases those actions; `:836` sends export through the static served-action guard. That guard calls `ProductionActionAvailable` at `:964`; `services/platform/securityagent/action_readiness.go:24` marks export component-only/autonomy none. | Add an explicit capability-bound export-only branch: `allowed_actions=["create_evidence_export"]`, `verification_kind="export"`, no `existing_test`, draft `enabled=false`, exact authorized environment and existing bounds. Keep static production classification unchanged. |
| Definition persistence / replay / deletion | `services/platform/apiserver/workflow_repository.go:169` defaults to legacy mutation; `security_agent_existing_test_reference.go:17` only recognizes existing-test/run_test/rerun_test/Attack Lab. The versioned mutation route appends55 pins at `workflow_repository.go:179`; replay routing repeats that distinction at `:462`. Delete has `{}` body and needs retained-resource classification, not body-only inference. Generic list/detail use the retained definition readers at `:100` and `:140`. | Freeze export write/replay/read authority with SQL. Prove current definition/history/workflow receipt agree after create/update, safe delete and replay. Don't infer export authority solely from an incoming body or lose retained reads when runtime health drops. |
| Activation | `services/platform/apiserver/security_agent_repository.go:207` uses the same static action guard for activation reads, with exceptions only for existing-test/Attack Lab at `:208`. Activation writes select the55 wrapper at `:276`; `security_agent_existing_test_read_repository.go:9` and `:12` show its14 parameters and55 pins. | Export activation reads must decode saved valid states. Fresh enabling must require installed export admission and connected runtime, current scope, fresh auth, version, budget and controls. Retained reads and disabling must not depend on healthy workers. |
| Execution controls | Go read expects six or seven actions (`security_agent_repository.go:84`); write whitelist ends at Attack Lab (`:99`). HTTP validator allows six/seven (`security_agent_handler.go:386`), and PUT rejects export at `:432`. SQL builds six keys in `security_agent_existing_test_controls.sql:27`;57 only adds Attack Lab (`security_agent_attack_lab_definition.sql:49`). | Exact sorted eight-key response including export, absent export control disabled/version0, scoped enable/disable with original receipts, fresh auth and CAS. Preserve read-only global control and fail-closed enabling; allow safe withdrawal during runtime outage. |
| Browser surface | `app/features/securityagents/SecurityAgentsView.tsx:50`, `:83`, `:196` exclude export controls. `apps/web/api/decoders.ts:505` caps controls at seven and `:517` rejects an export result. OpenAPI control enums omit it at `openapi/openapi.yaml:3720`, `:3737`, `:3745`. Builder requires a selected template (`SecurityAgentsView.tsx:272`, `:278`, `:281`). | Regenerate client after schema edits; extend strict decoders and actual control adapter. Add a catalog-backed single-action creation choice. Existing export composites in `services/platform/securityagent/templates.go:73` remain filtered by `workflow_handler.go:866`; catalog availability alone cannot populate the present builder. |

Older SQL does not equal an export admission contract. But the ceiling is not simply stuck at57: release58 deliberately rewrites predecessor `count(*)=57` / `version>57` and compatibility limits to58 (`0058_production_security_agent_exports.up.sql:24-50`). The public lifecycle wrappers still take55 pins (`security_agent_existing_test_lifecycle.sql:199-208`), and their special action fences recognize only run_test/rerun_test plus57's start_attack_lab (`security_agent_attack_lab_definition.sql:30-59`). Release58 currently adds neither export definition fences nor an export control key.

Some generic predecessor mutation/activation code accepts broad bodies and inserts action controls (`0018_security_agent_execution.up.sql:391-400`, `:487-503`). I have not executed those calls in this audit. Claiming that every direct SQL export create/activate call fails would be wrong; what is missing is a dedicated, pinned, permission-checked public contract, including legacy-entrypoint bypass refusal. Test that boundary explicitly.

## Contracts we already have

HTTP uses the existing `/api/v1/security-agents`, `/{id}`, `/{id}/activation`, `/api/v1/security-agent-execution-controls` and `/{id}/runs` routes. `services/platform/apiserver/composition.go:162-171` keeps controls under `manage_identity`, definitions/start under `manage_workflows`, and activation/control mutations browser-only. Preserve exact CSRF, fresh-auth, idempotency and `If-Match` checks; don't add a setup endpoint.

The new SQL producer must freeze its public mutation/read signatures before Go integration. Existing mutation outputs already have the required shapes: definition body/version/audit/correlation/receipt/replay; activation `{id,activation,enabled,version,audit_id,correlation_id,receipt_id,replayed}`; controls `{target,action_key,enabled,version}` and mutation receipt fields (`security_agent_repository.go:113-115`, `:287-289`). A decision to extend existing wrappers or add export-specific wrappers is not implemented or implied by this audit.

The downstream input is concrete. `services/platform/migrations/sql/fragments/security_agent_manual.sql:3-24` requires matching current/original definition version, actor, digest and activation, enabled global/environment/action controls and current effective scope. `:27-58` exposes13-argument `zasp_sa_manual_run(o,w,e,d,actor,key,v,run,audit,correlation,receipt,checksum,fingerprint)` to the registered API role. Its response has `manual_trigger={kind:"manual",intent_digest:"sha256:...",version:1}` and empty legacy `evidence_ids`; it creates the run, trigger, audit and request receipt atomically. Preserve the scheduled definition trigger.

Export planning already consumes an exact original export-only definition (`security_agent_export_planner.sql:82`), target=parent run and typed selection; its context still has `maximum_steps=1` (`:106`). Selection tuples are closed `{source_kind,source_id,source_version,association_digest}`, unique, bounded1..100 (`security_agent_export_sources.sql:1-12`). Existing provider reservation/settlement and approval controls still apply. The current SQL actor guard checks active membership and effective `view` plus `manage_workflows` (`security_agent_export_links.sql:6-13`); source-specific retrieval checks must remain in place, with no `view_compliance` substitution.

The registered connected manual test already reaches claim, planning, approval, dispatch and capture. Its fixture still owner-writes activated definition/history and export control (`services/platform/apiserver/security_agent_manual_admission_postgres_test.go:29-36`), so reuse the downstream assertions, not that setup. HTTP proof has the same limit (`docs/internal/security-agent-export-20260919/manual-http-progress.md:3-13`). Run-detail already mounts `ExportPanel` at `SecurityAgentsView.tsx:413`; don't rebuild it.

Runtime composition also exists. `services/platform/agentsec-api/export_workflow_readiness.go:10-45` checks admission, settlement and four fixed private `/readyz` services. `production_runtime.go:140` requires retrieval configuration and separate Security Agent DB for enabled mode; `:266-271` installs the health callback only with mounted export retrieval. The newer deployment checkpoint is reflected at `docs/internal/implementation_status_v1.5.md:83`; this audit does not repeat that work or claim a live deployment.

## Write ownership, kept narrow

| Sole writer | Exact edit set for this packet | Leave alone / handoff |
| --- | --- | --- |
| SQL writer | New `services/platform/migrations/sql/fragments/security_agent_export_definition.sql`; `services/platform/migrations/security_agent_exports_release.go`; `services/platform/migrations/sql/0058_production_security_agent_exports.up.sql`; `.down.sql` sibling if cleanup/restoration needs it. New `services/platform/apiserver/security_agent_export_definition_postgres_test.go`; extend `security_agent_export_release_postgres_test.go` in that directory. | Apply additive58 amendments with saved predecessor bodies/owners/ACLs; don't edit historical55/57 migrations. Preserve accepted `security_agent_manual.sql`, accounting/planner/links fragments unless a focused failure requires reopening that owner boundary. Supply exact SQL signatures, new checksum/fingerprint and registered evidence to Go owner. |
| Go API owner | `services/platform/apiserver/workflow_handler.go`, `workflow_repository.go`, `security_agent_repository.go`, `security_agent_handler.go`; new `security_agent_export_definition.go`, `security_agent_export_definition_test.go`, `security_agent_export_definition_http_postgres_test.go` in the same directory; extend `security_agent_export_catalog_test.go`. | New export-specific routing helper avoids rewriting accepted existing-test helper semantics. No migration, pin, OpenAPI or UI edits. Existing capability/production readiness files are inputs; reopen only on a reproduced defect. Own the new HTTP test, not SQL writer's fixture file. |
| OpenAPI/client/UI integrator | `openapi/openapi.yaml`, `openapi/identity-admin.test.mjs`, generated `apps/web/api/generated.ts`, `apps/web/api/decoders.ts`, `apps/web/api/decoders.security-agent-lifecycle.test.ts`, `app/features/securityagents/SecurityAgentsView.tsx`, `SecurityAgentsView.test.tsx` sibling. | One writer for all schema/generated changes. No global static readiness promotion or composite template edits. Existing export API/panel/download transport remain consumers. |

`0058...up.sql:12-18` already saves original function definitions and ACLs; `:76-97` fingerprints live export/manual functions plus predecessor ancestry. Down migration refuses retained export definitions/history/controls and manual receipts before restoration (`0058...down.sql:4-17`, `:26-36`). A new helper must be covered, private helpers must remain private, and empty down/up must restore57 exactly. These aren't optional cleanup details.

## Make the next RED small

No test ran for this audit. The names prefixed `ExportDefinition` below are proposed new tests, not existing passing coverage.

| New test location | Focused behavior to fail first |
| --- | --- |
| `services/platform/apiserver/security_agent_export_definition_postgres_test.go` | Registered exact58 admission probe absent today; create/update/read/replay and activate export through public SQL with zero preseeded export definitions/history/controls. Prove disabled/version0 control, enable/disable, current group/direct authority loss after waits, fresh-auth expiry, foreign scope, CAS/replay conflict, budget refusal and legacy bypass refusal. |
| `services/platform/apiserver/security_agent_export_definition_test.go` | Ready export draft currently rejected by real body/handler route; activation reader rejects saved export state; control PUT/read rejects eight keys. Pair ready positives with absent/drifted admission, down workers and malformed definitions. Retained reads/disable during outage remain available. |
| `services/platform/apiserver/security_agent_export_definition_http_postgres_test.go` | Real router/repository/registered API role creates, updates and activates the definition, sets controls, then starts manual run. Verify original receipts/ETags and no owner-seeded definition/run/plan. Reuse downstream consumer assertions without fixture activation writes. |
| `app/features/securityagents/SecurityAgentsView.test.tsx` and `apps/web/api/decoders.security-agent-lifecycle.test.ts` | Native export-only choice, strict eight-key control shape, fresh-auth and retained retry, update resetting activation, authority withdrawal, public manual start and existing export panel. Unsupported composites remain absent. |

Focused native command from `services/platform` after adding the test:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -run '^TestSecurityAgentExportDefinitionBoundary$' -count=1 -v
```

One feature batch, frozen at the new pin: affected Go API/runtime/worker race checks, the registered public setup-to-capture test plus manual claim/accounting/permission/release regressions, then UI/schema/generator checks and one independent review. Existing database test names are in `security_agent_export_planner_postgres_test.go:63`, `:261`, `:528`, `security_agent_export_postgres_test.go:589`, `:710` and `security_agent_export_release_postgres_test.go:33`. Use the exact selectors below, not a broad native pattern that silently starts host PostgreSQL.

```sh
# services/platform, native boundary checks only
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver ./agentsec-api ./agentsec-worker -run '^Test(SecurityAgent(ExportDefinitionBoundary|ExportDefinitionsRequireAdmissionRelease|ExportCapabilityReleaseChecks|ExportCatalogRequiresConnectedReadiness|AttackLabCatalogRequiresConnectedReadiness|TemplateIdentifiersPreserveExistingBoundary|ManualStart|ExportDispatchProcessor|ExportPlanner(ProcessorPreservesSelectionThroughAdmission|RetainsExactSubsetAndOrder|RejectsInventedOrMalformedSelection|FreezesSelection|RefusesCrossActionOrParentAuthority|SupportsAllReferenceKindsAndBounds|RequiresTrustedSelectionBeforeProviderCall))|ExportWorkflow(ConfigurationIsClosed|ProductionCatalogRequiresWorkersAndAdmission))$' -count=1 -v

# services/platform, offline registered-test binary
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-public-export-activation.test
```

Run that fresh binary with the retained network-none, pull-never, read-only disposable PostgreSQL command in `database/manual-claim-report.md:36-52`, using a new owned container name and binary mount. Registered selector:

```text
^TestSecurityAgent(ExportDefinition(PublicLifecycle|HTTP)Postgres|Export(Release|Sources|Authority|PlannerAdmission|PlannerRefusals|PlannerAccounting)Postgres|Manual(Admission|HTTP|ClaimIsolation)Postgres)$
```

Require every named group to appear across the selected packages and zero skips. Add affected existing-test/Attack Lab cases if shared lifecycle wrappers change, and settlement regressions if their dependencies change. Worker names above are declared in `security_agent_export_dispatch_runtime_test.go:35`, `security_agent_export_planner_runtime_test.go:45` and `security_agent_export_planner_test.go:49-192`. Full composed browser/runtime proof still needs a dedicated controlled fixture; this audit does not invent an existing runner command for it.

From worktree root, with cached Node22.23.1 on PATH:

```sh
node node_modules/vitest/vitest.mjs run app/features/securityagents/SecurityAgentsView.test.tsx apps/web/api/decoders.security-agent-lifecycle.test.ts app/features/securityagents/ExportPanel.test.tsx app/features/securityagents/export-api.test.ts
node --test openapi/openapi.test.mjs openapi/internal-health.test.mjs openapi/generated-client.test.mjs openapi/identity-admin.test.mjs
npm run typecheck
npm run openapi:lint
npm run openapi:check
```

The publication owner still runs exact-candidate UI build and SHIP-GATE. Local fixture storage/model responses do not establish external provider, browser authentication or native saved-file proof. The complete public flow must retain those separate observations when the required environment is authorized.

## Pins and limits

Current58 fingerprint is `0d5ce2f2b6a6252ee8bc5e675b2776a5c23c03fb50754f7c46345f8fbae906f3` (`services/platform/migrations/security_agent_exports_release.go:34`). Predecessor57 is `f44bc966ef77ab523a80ace71b59defbe709c1fdbefd69ccfc40cacaf16d7ba8` (`docs/internal/implementation_status_v1.5.md:116`). The58 checksum is the output of `ProductionSecurityAgentExports().Checksum()`, computed from expanded fragments, predecessor checksum/fingerprint and down SQL before compiled placeholder substitution (`security_agent_exports_release.go:38-51`). I did not execute a checksum-printing program or calibrate a database pin here.

Source SHA256 observed in this audit:

```text
813a6bf7f11ddd1e0d9246a2581690a60d0fe4a5c518dc8390ab4a3184c994fc  services/platform/migrations/security_agent_exports_release.go
30df8924c0dc32cc861363bb39fe8dd722cf8c83ce0e33cbae0def1c9c43cee1  services/platform/migrations/sql/0058_production_security_agent_exports.up.sql
2e68048c8b0ac75cf987871692a8b1789d1a2a2c89d5550859b9fa1791bc57d0  services/platform/migrations/sql/0058_production_security_agent_exports.down.sql
cb4106ae08975d8b4ba38bfefc975a05d28aca8839ce5433745b8a75a4982bc4  services/platform/migrations/sql/fragments/security_agent_manual.sql
389140cf914eaead1723680444a2bc7c179398a45fa48dcea2d3d2c175e77f51  services/platform/apiserver/workflow_handler.go
31552ddd1a2cc4ee22a82b807aa1103f7b05e69f162e6c0adb83d9297e4d5b78  services/platform/apiserver/security_agent_repository.go
7a08cb2ed3ac09392fd8489529903f6190ec4a2ecb13e50af9edabc842cd866c  services/platform/apiserver/workflow_repository.go
4505639e2bb05692cc8d302ba0121bc984ed458355798eb4b652f2b468720622  services/platform/apiserver/security_agent_handler.go
1169fefc4fee8421dd3873df321e501a581815792109bb16f2279defbbafc882  app/features/securityagents/SecurityAgentsView.tsx
```

The status record accepts the claim-isolation correction after re-review (`docs/internal/implementation_status_v1.5.md:58-68`); older manual reports still say pending. Don't reopen that resolved P2 from stale text. Readiness acceptance remains bounded to its nine-file component (`workflow-readiness-progress.md:106-115`). Existing receipts, manual accounting and download evidence stay useful only while their relevant source and pin dependencies remain unchanged.

Only this report was written. No product edits, tests, external requests, containers, staging, branch changes or task reclassification. Next: freeze the SQL public-admission contract with its single writer before dispatching a consumer implementation.
