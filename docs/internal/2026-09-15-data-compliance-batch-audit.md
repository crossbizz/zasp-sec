# B03 data/compliance evidence audit

Status: source/evidence audit complete, September 15, 2026. All 16 B03 IDs
remain component-only or unavailable in the product. No implementation,
availability promotion, test execution or release proof occurred in this audit.

Requirements: all 16 B03 rows in implementation_batches_v1.5.tsv, checked against
agent_security_platform_Technical_Implementation_Plan_v1.5.md. Preserve the exact
original IDs, deliverables, acceptance criteria and dependencies. The batch is
an execution index, not a replacement for the original plan.

Read-only assignment: inspect current product handlers, production composition,
store/worker adapters, UI, tests, readiness contracts and existing evidence.
For each ID report the actual production path, exact named tests and what they
prove, missing behavior, dependencies outside B03, and exact external gates.
Separate component evidence from actual deployed-provider evidence. Do not infer
that a dependency is installed in the product merely from a package or unit test.
Identify dependency-compatible implementation groups and precise file ownership.

Pay particular attention to compliance export versus audit export, mandatory
Stytch/Neon service controls, per-tenant settings, approved outbound data and AI
purpose/model/provider policy, durable or request-local budget semantics, and
UI unavailable behavior. Trace M7-40's relation to the Security Agent export
action without treating existing audit exports as compliance/evidence exports.

Only this report may be edited. No product edits, Git writes, provider calls,
credential inspection, database/process operations, test suite execution or
subagents. Another agent owns Security Agent UI and selected browser harness.
Root owns ledger updates and subsequent implementation authorization.

## Findings

I checked the 16 batch rows against the original plan, lines 3246-3394. IDs,
deliverables, acceptance criteria and direct dependencies agree. The exact
requirements are retained below. Existing tests were read, not run; a named test
here means its source checks the stated condition, not that this audit produced
a passing run.

The product boundary is decisive. `services/platform/apiserver/composition.go`
mounts compliance reads, data-control GET/PATCH and External Data Flows GET.
It doesn't mount either compliance export operation, external-flow PATCH or AI
explanation POST. `openapi/openapi.yaml` and `apps/web/api/generated.ts` agree
on those missing operations, even though some unused schemas still exist.
`TestBatchThreeCompositionExposesOnlyCompleteDurableOperations` in
`services/platform/apiserver/composition_test.go` explicitly excludes the export
and external-flow writes; `TestCoreCompositionHasExactProductionSecuritySurfaceWithoutUnimplementedOverclaims`
excludes AI explanations. `docs/product/ui-api-map.yaml` retains planned actions.
The helper constructors for `NewGovernor`, `NewFlagCache`, `NewRetentionWorker`
and `WriteComplianceExportArtifact` have no non-test product caller in the Go
tree inspected here. A helper's presence isn't an installed adapter.

## The original 16, unchanged

| ID | Depends on | Deliverable | Acceptance criterion |
| --- | --- | --- | --- |
| M7-12 | `M7-11` | Implement OpenAPI operation `createComplianceExport` for `POST /api/v1/compliance/exports` using the existing service/store contract. | Handler test covers authorized success plus one stable product error. |
| M7-13 | `M7-12` | Implement OpenAPI operation `getComplianceExport` for `GET /api/v1/compliance/exports/{id}` using the existing service/store contract. | Handler test covers authorized success plus one stable product error. |
| M7-14 | `M7-13` | Create JSON/CSV plus human-readable evidence package in S3. | Package links evidence IDs/timestamps and avoids certification language. |
| M7-15d | `M7-15c` | Add evidence export trigger and job-status UI. | Queued/completed/error states render. |
| M7-19 | `M7-18` | Delete/expire product-controlled event/evidence references according to data class policy. | Fixture deletes expired test data and audits admin policy change. |
| M7-22 | `M7-21` | Implement OpenAPI operation `updateExternalDataFlows` for `PATCH /api/v1/settings/external-data-flows` using the existing service/store contract. | Handler test covers authorized success plus one stable product error. |
| M7-22a | `M7-22` | Prevent the External Data Flows API from disabling required Stytch or Neon dependencies while allowing optional PostHog, OpenRouter and remote OTLP changes. | Required-service disable fixture is rejected; optional-service disable fixture succeeds and is audited. |
| M7-23 | `M7-22a` | Create allowlist-only product event serializer. | Prompt/tool args/secrets/IP/raw evidence fixtures fail serialization. |
| M7-24 | `M7-23` | Implement server-side flag cache with explicit code defaults/max age. | PostHog outage returns deterministic defaults. |
| M7-25 | `M7-24` | Redact prohibited fields for approved AI explanation purposes. | Seeded secret/PII/PHI fixture is absent at fake endpoint. |
| M7-26a | `M7-25` | Reject AI requests whose purpose, model or provider is not allowlisted. | Unapproved purpose/model/provider fails before egress. |
| M7-26b | `M7-26a` | Enforce per-request token, cost, deadline and concurrency limits. | Over-limit fixture is rejected before provider request. |
| M7-26c | `M7-26b` | Attach configured data-policy/ZDR requirement metadata to provider selection. | Provider selection excludes a fixture that violates the required data policy. |
| M7-26 | `M7-26c` | Wire AI governance checks into the AIGateway request path. | Approved request passes all guards and records governed request metadata. |
| M7-27 | `M7-26` | Implement OpenAPI operation `createAIExplanation` for `POST /api/v1/ai/explanations` using the existing service/store contract. | Handler test covers authorized success plus one stable product error. |
| M7-28 | `M7-27` | Create evidence-aware Explain with AI panel and unavailable state. | E2E displays sent-field notice and deterministic content stays usable on failure. |

## Per-ID source findings

### M7-12 and M7-13: the local map isn't a product export service

M7-12's only handler is `sessioncontrol.HTTPHandler.dispatch` in
`services/platform/sessioncontrol/http.go`. It assembles constructor-supplied
controls/evidence, calls `BuildComplianceExport`, writes `h.exports[input.ID]`
and immediately returns 201/completed. It doesn't persist a job, call an artifact
store, check real evidence ownership or enqueue work. There is no tenant key in
the map; an existing ID is overwritten. The production API doesn't use it.

M7-13 reads that same map and returns 200 or the helper's generic
`session_control_rejected` error. It has no durable status, download reference,
expiry, revoked-access recheck or recovery path. These are separate gaps: adding
the POST route alone doesn't make GET durable.

Named evidence for both: `TestHTTPHandlerPublishesBoundedAuthorizedRoutes` in
`services/platform/sessioncontrol/http_test.go` checks a 201 POST and a following
200 GET with a boolean bearer-token authorizer. Its stable 403 error assertion
targets `/sessions`, not either export operation. It doesn't meet the requested
per-handler error proof. The product composition tests above prove deliberate
absence, not export acceptance.

M7-12's outside dependency is M7-11. The actual read path is
`PostgresRepository.ReadAdministration` and `postgresListComplianceEvidenceSQL`
in `services/platform/apiserver/administration_repository.go`; it reads
organization-scoped `zasp_compliance_controls`/`zasp_compliance_evidence` from
migration `0007_production_administration.up.sql`. Evidence pagination has source
coverage in `TestAdministrationTimeAndEvidenceKeysetsTraverseBeyondResponseBoundsWithPostgres`
(`administration_fix_round2_postgres_test.go`). This doesn't prove every exported
ID resolves to current product evidence or a live provider. M7-13 depends on
M7-12, inheriting that dependency.

External gate E1 below applies to each operation. Before that, product tests need
exact scoped authorization, CSRF/fresh-auth where required, stable operation
errors, duplicate request behavior, cross-tenant denial, restart/readback and
expired/revoked access. These are missing product proofs, not credentials work.

### M7-14: bytes exist, S3 composition doesn't

`BuildComplianceExport` and `WriteComplianceExportArtifact` in
`services/platform/sessioncontrol/sessioncontrol.go` create a JSON envelope with
JSON evidence, CSV and human text, then validate the returned artifact's locator,
media type, size, digest and bytes. JSON has evidence IDs/timestamps. CSV contains
only `control_id,framework,freshness,evidence_count`; the human field is a generic
non-attestation sentence, not a readable account of the evidence. Make the
reviewer's evidence links/timestamps usable in the human-readable package too.

`TestSessionsComplianceAndDataControlBoundaries` checks nonempty formats, stale
evidence and no certification language. `TestComplianceExportPersistsExactArtifact`
checks IDs/timestamps in package bytes and rejects a mutated store response.
Both are in `sessioncontrol_test.go`. The latter uses `complianceArtifactStore`,
a fake with no S3 I/O. It does not prove S3 persistence despite the older ledger
wording about an "S3-backed ArtifactStore boundary".

No production export job/worker calls this function. Need a scoped evidence
snapshot, durable lifecycle, configured ArtifactStore adapter, exact stored/read
package and expiry/recovery proof. Direct dependency M7-13; outside dependency
M7-11 is inherited. Gate E1. Generic audit/S3 tests are reusable boundary
evidence, not acceptance for this payload and job type.

### M7-15d: unavailable is the current UI

`app/features/sessions/SessionsComplianceView.tsx` renders "Evidence exports
unavailable" and says durable job, artifact, one-time grant, expiry and recovery
are missing. `SessionsComplianceAPI` has no export methods. It doesn't render an
export trigger or queued/completed/error job states.

`renders local evidence and keeps exports unavailable` in
`SessionsComplianceView.test.tsx` proves the unavailable text and absence of an
export button using supplied API fixtures. The source-contract test
`implements durable session, evidence, and data controls while hiding exports`
in `app/quality/m7-session-compliance-batch-contract.test.ts` checks that export
calls stay absent. Neither is the requested three-state acceptance or browser
E2E.

Outside dependency M7-15c follows M7-15b and M7-15a, with M7-15a depending on
M7-14. Recheck these seams: current evidence rows display asset/source/ID as text,
without timestamp or clickable product evidence target, and freshness comes from
the first record per control. Then add lifecycle UI after the export service.
Gate E1 plus E5's selected product browser flow.

### M7-19: no actual deletion

`admincontrol.RetentionWorker.Apply` in
`services/platform/admincontrol/admincontrol.go` filters an input slice and
returns remaining records plus `RetentionAudit`. One retention-day value covers
`event`, `evidence` and `audit`; it doesn't load per-class settings, inspect
`DeletionEnabled`, delete a repository row/object/index reference, or write a
durable policy-change audit. Record inputs themselves lack tenant scope. There
is no caller in `agentsec-worker`.

`TestRetentionExternalFlowsSystemHealthAndHTTP` in `admincontrol_test.go` checks
that a 40-day evidence record is omitted while a one-day event remains and that
the returned audit names the expired ID. It doesn't delete stored data or assert
an admin policy-change audit. Current data-control changes do have a separate
durable path: `postgresUpdateDataControlsSQL` binds organization/workspace/
environment, version and audit correlation, called from production
`updateDataControls`. Wire the worker to that authority; don't substitute the
environment-only in-memory `DataControlStore`.

Direct outside dependency M7-18, with M7-16/17 upstream and M7-15 behind them.
Need per-class policy semantics, bounded scheduled work, transactional reference
expiry, repeat/restart behavior and durable policy-change evidence. Physical S3
and search cleanup must follow the approved class policy while preserving the
retained S3 archive's recovery role. Gate E2. Token-reveal-grant cleanup tests
elsewhere in `apiserver` don't prove event/evidence retention.

### M7-22 and M7-22a: required-service truth must be server-owned

M7-22 has a component PATCH in `services/platform/admincontrol/http.go`.
`ExternalFlowStore` is a mutex/map plus an audit slice, keyed only by flow ID.
No production tenant settings repository or PATCH route uses it. The real
`identityHTTPHandler.serveLocalAdministration` in
`services/platform/apiserver/production.go` returns exactly one flow,
`identity-provider`, marked required/enabled with health from live identity
verification. It omits Neon and every optional destination. `AdminOperationsView`
is a read-only inventory, with no toggle.

For M7-22a, `validateFlow` reserves helper IDs `identity` and `database` and won't
disable a currently required flow. Its category allowlist is global, not an
approved category set per provider. Client input can set `Required`, `Categories`
and `Health`. The special analytics/raw-evidence check is redundant with the
global category rejection. It doesn't establish the required Stytch/Neon versus
optional PostHog/OpenRouter/remote-OTLP product catalog or make optional switches
stop egress.

Both use `TestRetentionExternalFlowsSystemHealthAndHTTP`. It checks successful
helper PATCH, rejects disabling `identity`, rejects `raw_security_evidence` for
`analytics`, and confirms an in-memory audit for disabling analytics. No Neon
disable fixture, optional OpenRouter/OTLP fixture or tenant persistence/restart
proof exists there. Its stable HTTP error check is GET `/system/status`, not
PATCH. Add exact per-service tests, including denied mutation with zero state or
audit side effect, successful optional disable with durable actor/scope/version
audit, and zero subsequent provider egress for the disabled tenant.

M7-22's outside dependency M7-21 follows M7-20 and M7-19. M7-22a depends on
M7-22 and inherits those prerequisites. Repair the incomplete read/catalog seam
before accepting either. Gates E3 and E4; Stytch/Neon must remain required even
if optional services are absent or unhealthy.

### M7-23: the serializer is tested, its product egress path isn't installed

`SerializeProductEvent` in `services/platform/producttelemetry/m7.go` permits
only `screen_viewed` and fields `screen,surface,action,result`, with source-token
grammar. `TestProductEventSerializerAndFlagFallback` in `m7_test.go` rejects
`prompt,tool_args,secret,ip,raw_evidence` and accepts a screen fixture. This is
the exact requested field rejection at component level.

The older `NewAllowlistSerializer`/`Telemetry.Track` in `producttelemetry.go`
implements a different `proof_completed` catalog with source/success and scope.
`TestAllowlistSerializerRejectsUnknownAndProhibitedFields` and
`TestTelemetryRejectsInvalidEventsBeforeDriverIO` in `producttelemetry_test.go`
check field rejection and zero driver I/O. These catalogs aren't wired together
or into an installed PostHog adapter by the B03 code.

Fake-endpoint evidence exists separately under `proofs/posthog-privacy`:
`serializer rejects each prohibited and unknown property before coercion`
(`serializer.test.mjs`) and `privacy rejection happens before transport I/O`
(`run.test.mjs`). These are local proof scripts, not production capture or hosted
PostHog. Need one approved product event catalog and an actual caller that
resolves tenant enablement before serialization/egress. Direct dependency
M7-22a, inherited outside M7-20/21. Gates E3/E4. No telemetry failure may block
the deterministic security path.

### M7-24: cache policy isn't selected by the server yet

`NewFlagCache`/`FlagCache.Resolve` in `producttelemetry/m7.go` accept caller-
supplied defaults/max age, call the provider on every resolve, reuse fresh cache
on error and return defaults when stale. State is keyed only by flag name.
The provider call runs while holding the cache mutex, with no internal timeout;
nil provider returns false before consulting a configured true default. An
unknown key can be cached, and backward clock movement can extend apparent
freshness. These details need an explicit product policy.

`TestProductEventSerializerAndFlagFallback` sets `ai_explanations=false`, gets
one true provider response, then simulates an error two minutes later with a
one-minute max age. It proves expired-cache fallback for that false default.
No true-default, fresh-cache outage, provider timeout, tenant separation or
production PostHog adapter test is present there. Need code-owned defaults and
max age plus bounded calls, tenant/config-generation keys where flags differ,
and optional-disable behavior. Direct dependency M7-23; inherited outside
M7-20/21. Gates E3/E4, with safe deterministic defaults usable before optional
provider approval.

### M7-25: field dropping isn't a full PHI egress proof

`RedactApprovedFields` in `services/platform/aigateway/m7.go` retains
`title,severity,finding_id,evidence_summary`; it removes email, SSN and `ghp_`/
`sk-` token patterns inside retained values and rejects `password=`. The helper
doesn't establish that free-text names, medical details, other secrets or raw
evidence embedded inside approved fields are excluded.

`TestGovernedExplanationBoundary` in `aigateway/m7_test.go` checks a dropped
`secret` field and regex replacement of email/token/SSN. Its provider closure
increments a counter and returns a result; it doesn't inspect the received
fields. It has no explicit PHI assertion. Separate loopback evidence under
`proofs/openrouter-privacy` includes `gateway deterministically redacts seeded
secret and PII values` (`gateway.test.mjs`) and `fake endpoint accepts exactly one
exact request and contains no seeded sensitive value` (`run.test.mjs`). That
proof script isn't the Go Governor's production path.

Need server-derived evidence summaries, approved per-purpose field policy and
seeded secret/PII/PHI assertions at the actual adapter's fake endpoint. Direct
dependency M7-24, inherited outside M7-20/21. Gate E4. Do not accept a caller's
claim that arbitrary summary text was redacted.

### M7-26a: independent lists need a configured provider policy

`Governor.Generate` rejects purpose/model/provider absent from its three
allowlists before calling the provider. Config is static per Governor and
contains no tenant/version or allowed purpose-model-provider tuple. The request
supplies the selection. `TestGovernedExplanationBoundary` proves an unapproved
model produces zero further calls, but doesn't exercise bad purpose/provider.
`TestGatewayRejectsUnapprovedPurposeBeforeIO` in `aigateway_test.go` rejects bad
purposes in the separate `Gateway`, whose request has no model/provider fields.
`TestSecurityResponsePlanPurposeRejectsFreeFormGovernor` prevents the structured
Security Agent purpose from entering this free-form helper.

Need one server-selected purpose/model/provider policy, exact three rejection
fixtures at the real egress boundary, tenant isolation and disabled-policy
handling. Keep Security Agent structured planning separate from free-form
explanations. Direct dependency M7-25; inherited outside M7-20/21. Gate E4.

### M7-26b: per-request bounds, no durable budget claim

Governor bounds caller-supplied `Tokens` and `CostCents`, uses one in-process
semaphore per instance and creates a context deadline. It doesn't compute a
server-side token/cost reservation, reconcile measured usage, enforce a tenant
quota across replicas or recover accounting after a restart. A provider that
ignores cancellation can continue while `Generate` waits. This is request-local
admission only, not a durable run/organization budget.

`TestGovernedExplanationBoundary` passes one below-limit request, with no
over-token, over-cost, occupied-slot or expired-request assertion. Separate
`TestGatewayCancellationAndTimeoutAreOneAttempt` proves cancellation/timeout
behavior of `Gateway`; `TestGatewayConcurrentCallsAreIndependent` proves call
isolation, not an admission cap. The required over-limit-before-provider fixture
is missing for Governor.

The original B03 deliverable is per-request limits. Don't quietly substitute
the broader Security Agent run budget requirement or claim it complete here.
Define trusted worst-case estimates/provider output caps, pre-egress rejection,
actual deadline behavior and the requested concurrency scope. If organization-
wide quota is claimed, join the shared quota authority (original M1-43) and the
Security Agent budget owner, with durable reservations/reconciliation tests.
`securityagent.BudgetManager` in `planner.go` is also process-local; it doesn't
close that gate. Direct dependency M7-26a; inherited outside M7-20/21. Gate E4,
including approved provider pricing/usage semantics before a live cost claim.

### M7-26c: no-storage assertion isn't provider selection

Governor requires `RequireNoStorage=true` and checks the provider's returned
`NoStorage` bit. It doesn't consult a provider capability registry or exclude a
nonconforming candidate before egress. `aigateway.DataPolicyMetadata` in
`aigateway.go` carries version, purpose, approved egress, excluded data classes
and `no_provider_storage`, but it is a separate contract supplied with the
request. There is no joined tenant policy-to-provider selection path.

`TestGatewayRejectsIncompleteDataPolicyBeforeIO` rejects unset policy claims and
unknown retention mode before fake-driver I/O. `TestGatewayGenerateExactContract`
checks exact metadata propagation. `TestGovernedExplanationBoundary` accepts
one true no-storage result. None tests selection among compliant and
noncompliant providers. Need that exclusion fixture and actual configured
request metadata sent through the selected provider adapter. Direct dependency
M7-26b; inherited outside M7-20/21. Gate E4. ZDR is not a BAA.

### M7-26: two gateways, no joined request path

`Gateway.Generate` in `aigateway.go` validates scope, finding purpose, text and
data-policy flags and calls `Driver.Generate`. It doesn't call Governor.
`Governor.Generate` in `m7.go` checks allowlists/limits/redaction but lacks
`domain.Scope`, policy version and durable governed-request recording. No
production composition joins them. The constructor search found no production
caller for either helper path.

`TestGatewayGenerateExactContract` and `TestGovernedExplanationBoundary` prove
their own fake-driver/provider contracts separately. No test sends a request
through every B03 guard and then verifies a governed request metadata record.
Need one composed entrypoint and metadata excluding evidence content: trusted
scope, request/subject, policy version, chosen purpose/model/provider,
reservation/actual usage, outcome and audit correlation as approved. Direct
dependency M7-26c; inherited outside M7-20/21. Gate E4.

### M7-27 and M7-28: don't publish the helper as the finished feature

For M7-27, `NewGovernedHTTPHandler` in `aigateway/http.go` accepts a boolean
authorizer and the full caller-controlled governed request. It has no production
identity scope, evidence lookup, tenant settings or metadata store. It's absent
from the real router and generated client. `TestGovernedExplanationBoundary`
checks 200 for the helper POST and 403/`ai_governance_rejected` for unauthorized
POST. This is the closest per-handler acceptance fixture in B03, but still
component-only. Need production auth/scope, stable product errors and exact
zero-egress rejection before publication. Dependency M7-26; gate E4.

M7-28 has no current Explain with AI panel or sent-field notice in the inspected
`app`/`apps` source. The old ledger says one exists. Current
`app/quality/m7-admin-ai-degraded-batch-contract.test.ts`, test `implements
bounded service and honest UI boundaries`, asserts that `AdminOperationsView`
doesn't contain "AI explanation unavailable". This is no evidence-aware panel
test. No current named M7-28 browser flow was found. Keep deterministic findings
and evidence usable, then add sent-field notice, consent/policy status, scoped
subject/evidence display, loading and unavailable states once M7-27 is installed.
Add the requested browser outage fixture with deterministic actions still
enabled. Direct dependency M7-27; inherited outside M7-20/21. Gates E4/E5.

## Gates that need external evidence

These gates are prerequisites for product/provider release claims, not permission
to contact services during this audit.

| Gate | Exact evidence still needed | IDs affected |
| --- | --- | --- |
| E1: compliance artifact lifecycle | Authorized selected deployment with scoped Neon/PostgreSQL export state, SQS worker delivery/retry where used, approved S3/KMS identity/bucket/prefix/encryption, readback of the exact compliance JSON/CSV/human package, access revocation/expiry, cleanup and worker restart/recovery evidence. A stored audit export or LocalStack receipt doesn't satisfy this payload/job gate. | M7-12, M7-13, M7-14, M7-15d |
| E2: retained data actually expires | Approved fixture tenant/environment and data-class retention policy; scheduled worker proof that expired product references and required storage/index artifacts are removed or expired, retained records survive, admin policy change is audited, retries/restarts are safe, and no other tenant changes. Confirm backend lifecycle and archive recovery behavior in the chosen deployment. | M7-19 |
| E3: service controls | Authorized Stytch/Neon deployment identity and current health evidence, complete required/optional catalog, approved per-tenant data categories, persistent optional switches; fixture proves both mandatory disable requests fail and PostHog/OpenRouter/remote-OTLP disable prevents corresponding egress without damaging mandatory services. | M7-22, M7-22a, M7-23, M7-24 |
| E4: approved optional egress | Owner-approved tenant/profile policy and destinations, purpose/model/provider combinations, data-policy/ZDR capability evidence, cost/token accounting semantics and caps. First run hostile/secret/PII/PHI rejection and accepted-request receipts against the actual adapter at a fake endpoint. A hosted-provider claim then needs explicitly authorized deployed receipt/selection evidence. Optional PostHog/OpenRouter/remote OTLP stay off in the HIPAA-oriented profile until explicit approval; AWS BAA, Stytch review/coverage if ePHI can reach identity, and Neon HIPAA/BAA configuration if ePHI can reach Neon remain separate contractual gates. | M7-23 through M7-28, with M7-22/22a controls |
| E5: product acceptance | Selected production-composed browser/API environment; compliance filter/export with live evidence/freshness, policy-change ingest effect, required/optional health distinction, AI outage with deterministic actions, and UI/API operation coverage. Record M7-40a-f separately, plus the five M7-39 degraded fixtures; M7-40 is PASS only if all required checks pass. | M7-15d, M7-28 and the M7/M7A release seam |

Original plan sections at lines 522-545 specify the regulated-profile defaults
and contractual conditions. Nothing in this audit establishes contractual
coverage or clears egress. `config/config.go` defines optional endpoint/secret-
reference configuration, but configuration capability alone doesn't install an
adapter or grant tenant approval.

## The M7-40 / Security Agent seam

Original M7A-23 depends on both `M7A-22,M7-40` and requires
`create_evidence_export` to use the existing export service with only run-scoped
evidence IDs. `services/platform/securityagent/builtin_actions.go` currently
checks string equality for run ID and the `run_id:` prefix on up to 100 IDs.
`TestBoundedResponseActionSet` in `automation_test.go` exercises a fake backend.
This isn't authoritative resolution of run evidence against tenant-scoped rows.

Both `docs/product/security-agent-action-readiness.tsv` and
`services/platform/securityagent/action_readiness.go` keep this action
`component-only`, maximum autonomy `none`, with durable worker/canary pending.
`TestProductionActionReadinessExposesOnlyVerifiedActions` and
`TestProductionActionReadinessManifestMatchesCodeAndCatalog` in
`action_readiness_test.go` protect that boundary.

Audit exports are different. `services/platform/apiserver/audit_export_composition.go`,
`audit_export_http.go`, `audit_export_repository.go`, worker `audit_export_*.go`,
and schema `0052_production_audit_exports.up.sql` implement audit-event export
plumbing. The conditional composition exposes `createAuditExport/getAuditExport`,
not compliance exports. `docs/internal/2026-09-12-audit-export-evidence.md`
explicitly separates local PostgreSQL/SDK-controlled-provider work from live AWS
and selected browser/provider acceptance. Its results cannot promote B03 or
M7A-23.

Before M7A-23 can use B03 output, its owner must join run-scoped authoritative
evidence lookup, durable job idempotency, artifact verification/expiry and the
canary to the accepted compliance/evidence export service. M7-40 stays a separate
six-check gate. Old August ledger statements and tests that search those
statements don't prove current product acceptance.

## Groups that respect the original graph

These are proposed ownership groups for later authorization, not changes made
here. Keep the dependency barriers; B03's row order doesn't erase outside IDs.

| Group | IDs and barrier | Precise file ownership for an implementation |
| --- | --- | --- |
| G1: compliance service | M7-12 -> M7-13 -> M7-14, after M7-11 evidence-source review | Own `services/platform/sessioncontrol/sessioncontrol.go` and `http.go` helper contracts plus new compliance-specific repository/handler/worker/migration files under `services/platform/apiserver`, `agentsec-worker` and `migrations`. Reuse `artifactstore` via an explicit adapter. Don't edit audit-export job semantics. Shared schema numbering, `apiserver/composition.go`, `agentsec-api` composition and OpenAPI need one integration owner. |
| G2: export interaction | Revalidate M7-15a -> M7-15b -> M7-15c after G1, then M7-15d | Own `app/features/sessions/SessionsComplianceView.tsx` and `.test.tsx`, export API/decoder additions under `apps/web/api`, scoped browser tests and relevant UI/API map entries. The generated client is regenerated only with the shared contract change. No Security Agent UI ownership. |
| G3: retention | M7-15 -> M7-16 -> M7-17 -> M7-18 must be valid before M7-19 | Own retention code split from `services/platform/admincontrol/admincontrol.go`, a new scoped retention repository and scheduled worker, associated migration/tests. Preserve `administration_repository.go` data-control version/audit semantics; shared integration owner handles its seams. Coordinate storage/index class-policy owners. |
| G4: external-flow authority | M7-20 -> M7-21 after G3, then M7-22 -> M7-22a | Own external-flow model/store/handler code, new tenant setting persistence, `serveLocalAdministration` read replacement and `AdminOperationsView` inventory/toggle tests. Shared auth/route/OpenAPI owner handles registration. Lock Stytch/Neon and approved categories server-side. |
| G5: telemetry | M7-23 -> M7-24 after G4 | Own `services/platform/producttelemetry/m7.go`, `producttelemetry.go`, their tests and a configured provider adapter; existing `proofs/posthog-privacy` remains explicitly synthetic. Scope flag keys/defaults and egress decisions before adapter wiring. |
| G6: governed explanations | M7-25 -> M7-26a -> M7-26b -> M7-26c -> M7-26 -> M7-27, after G5 | Own `services/platform/aigateway/m7.go`, `aigateway.go`, `http.go`, joined adapter/config/tests and governed metadata persistence. Shared integration owner handles production routes/OpenAPI. Coordinate, but don't edit, active Security Agent planner/executor work or broaden this into M7A run-budget acceptance. |
| G7: UI and release evidence | M7-28 after G6; downstream M7-29..M7-40 remain separately checked | Own a finding-scoped explanation panel and its API binding/component/browser tests. Root owns M7-40 evidence reconciliation and any availability/ledger changes. Security Agent owner separately handles M7A-23 and its M7A-22 gate. |

Safe independent preparation is possible for test design and isolated helper
work, but original acceptance is ordered through these barriers. Avoid concurrent
edits to `composition.go`, `production.go`, OpenAPI, generated clients, migration
registration, shared API providers and the readiness/ledger files. Assign those
to the integration owner.

The only file changed by this audit is this report. Product implementation,
selected browser acceptance, provider work and release promotion require the
next authorization.
