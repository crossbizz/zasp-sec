# Export API integration progress

2026-09-19. New plan: docs/internal/2026-09-19-security-agent-export-api-plan.md.
Added a scoped SecurityAgentExportsRepository with grantAction/readGrant. SQL
receives full scope, original run/step, principal, cloned real-session digest,
CSRF, token/format/operation and compiled58 pins. Source permission decisions
remain SQL-owned; no view_compliance substitution. Private immutable receipt
validates run/step/selection and nested closed JSON, not just artifact hash.

Focused RED from services/platform using cached Go environment:
`go test ./apiserver -run '^TestSecurityAgentExportGrants.*$' -count=1 -v`.
Exit1,1.154s: issue/read/consume/integrity_failure all refused by fail-closed
stubs. Implemented the grant repository and started focused native race GREEN.
No API route, public status or browser UI is claimed yet. Malformed response,
caller refusal and SQL error tests still required before independent review.
No original task reclassified and no publication.

GREEN command:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^TestSecurityAgentExportGrants.*$' -count=1 -v
```

Exit0,2.473s, TestSecurityAgentExportGrantsRepository PASS with all four
operation subtests PASS, zero SKIP. Controlled JSONDatabase verifies exact
query arguments/pins and typed receipt behavior; it is not source-permission,
registered-session or mounted HTTP proof. git diff --check exit0.

Expanded same-pattern native race: three top-level PASS, zero SKIP,exit0,2.830s.
Full output grant-repository-race.txt. Added wrong run/step, duplicate binding/
selection fields, unknown selection fields, null selection, expired deadline,
wrong renderer/size, invalid CSRF/digest/run/token/format/operation, null consumed
and SQL conflict cases. All characterize existing implementation; no additional
RED claimed. Public status and mounted HTTP are next, before a grouped API
review. Current repository hash e5e255092ade8c6a6885b38a3fd79c80580ac1c7e4ae893de2adf24a48547223;
test hash91f941483b1b638d8ba415cd3e79e766c951464311bafd756b4695b5fc21cf57.

## Scoped status repository

Added SecurityAgentExportStatus and Get in security_agent_export_status.go.
Status exposes lifecycle/cleanup state, frozen selection, optional snapshot
time and artifact checksum/size. No storage locator or immutable version field.
The exact registered query receives scope/run/step/principal/session/CSRF and
release pins. Expired retrieval remains visible as status; expiry is not
mistaken for permission to read bytes. Closed nested selection/artifact fields
and lifecycle enums are checked before returning the typed value.

RED: cached `go test ./apiserver -run '^TestSecurityAgentExportStatus.*$'
-count=1 -v` exit1,1.130s. Pending/completed/failed literal status all refused
by the stub. Implemented Get and decoded status validation.

GREEN from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^(TestSecurityAgentExportStatus.*|TestSecurityAgentExportGrants.*)$' -count=1 -v
```

Exit0,3.209s,four top-level PASS,zero SKIP. Full output status-grants-race.txt.
git diff --check exit0. Status rejection edge cases, registered repository
calls, mounted routes/OpenAPI, browser flow and independent API review remain
required. No task or live availability claim.

## Mounted HTTP checkpoint

Added optional NewCompositionWithSecurityAgentExports and three browser-only
scoped run/step routes. Existing default composition doesn't expose them.
Handler enforces one browser cookie, exact POST CSRF, bounded closed body,
supported format and token; uses the authorized immutable reference; performs
read then storage verification then consume before emitting attachment bytes.
Verified integrity mismatch alone triggers integrity_failure. Status and grant
issue branches are implemented but need mounted-case coverage.

RED: mounted download test returned404 for both branches,exit1,1.132s before
routes/handler implementation. GREEN command from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^(TestSecurityAgentExportHTTP.*|TestComposition.*|TestComplianceHTTPMountedPublicLifecycle)$' -count=1 -v
```

Exit0,2.483s,two top-level PASS,zero SKIP. Full output http-mounted-race.txt.
Actual matched tests: existing ComplianceHTTPMountedPublicLifecycle and new
SecurityAgentExportHTTPConsumeBeforeBytes (allowed/revoked). The TestComposition
pattern matched no composition-test names; do not claim those ran. New test
uses actual router/middleware/repository/decoder with controlled SQL and storage,
and verifies exact bytes or consume-time42501 with no artifact disclosure.
It does not establish real SQL permission revocation or production mounting.
Production API constructor/config wiring, OpenAPI/types/UI, broader failure
coverage and independent API review remain open. git diff --check exit0.

## Verification cadence confirmed by user

Group related microtasks into coherent feature batches. Keep focused failing
regression checks and targeted GREEN while implementing behavior. Run affected
native race, registered database, and browser checks at the completed feature
boundary; perform one independent feature review and scoped follow-up checks.
Reuse accepted evidence only while its code and relevant dependencies remain
unchanged. Run release-wide checks and the UI build before publication. Track
each original microtask separately against its batch evidence; batching does
not remove requirements or convert local evidence into production proof.

Collected existing session93235 without restarting it: native race command
matching TestSecurityAgentExportProduction.*, TestSecurityAgentExportHTTP.*,
and TestNewComposition.* exited1. Both composition tests and mounted download
test passed; production constructor ready case failed with configuration
rejected. Absent and drift cases passed. This checkpoint is not GREEN and
requires diagnosis before claiming production constructor completion.

## Production startup integration

Diagnosed constructor failure: fixture KMS key UUID used variant1, while the
existing s3driver validator requires RFC UUID variant8/9/a/b. Corrected fixture
to a version4, variant8 identifier; did not weaken production validation.

Added actual API startup composition coverage with separate ordinary and
security-agent database doubles. RED session78892 exited1 (1.136s): installed
route returned404 without querying status; installed catalog drift incorrectly
allowed startup. Absent and disabled routes correctly remained404. Corrected
the new status fixture's field names to source_kind/source_id/source_version
before GREEN (the earlier404 had not reached status decoding).

Wired the optional export handler through production startup using the traced
security-agent database, sharing the configured compliance read-only storage
client. Added capability forwarding and readiness checks. Installed drift fails
startup; absent release and disabled export configuration leave routes absent.

Grouped native race verification, session81923, exit0:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-api ./apiserver -run '^(TestSecurityAgentExportAPIProductionComposition|TestComplianceAPIProductionComposition|TestSecurityAgentExportProduction.*|TestSecurityAgentExportHTTP.*|TestNewComposition.*)$' -count=1 -v
```

Six top-level PASS, zero SKIP: two startup composition tests (agentsec-api
2.543s), constructor release gate, mounted consume-before-bytes and two core
composition compatibility tests (apiserver2.055s). git diff --check exit0.
Controlled SQL/provider configuration only; no real provider requests, deployed
startup, registered session permission proof or production availability claim.
API batch still needs broader route/status refusals, registered SQL integration,
OpenAPI/types/UI and independent review. No commit, push or task reclassification.

## Mounted grants and closed status coverage

Added mounted grant issuance for json/csv/human, asserting returned token is
the SQL-issued token and human maps to SQL readable. Added unknown format,
duplicate format, unknown field, query, invalid token and duplicate CSRF
refusals, all before SQL/storage. Initial test run failed because its decoder
incorrectly expected a data wrapper; inspected writeJSONValue and corrected
the test to the existing direct JSON contract. No production defect or TDD RED
is claimed from that fixture mistake.

Native race session80506, `go test -race ./apiserver -run
'^TestSecurityAgentExportHTTP' -count=1 -v` with the cached environment above:
exit0,2.382s,two top-level PASS,zero SKIP. Nine new grant/refusal subcases plus
existing allowed/revoked consume-before-bytes cases passed.

Added13 malformed status cases covering private fields, duplicate fields,
invalid lifecycle/source binding/cleanup/failure/snapshot and artifact bounds.
Session10808, same environment and `-run '^TestSecurityAgentExportStatus'`:
exit0,2.865s,two top-level PASS,zero SKIP. Reworked null-selection case to avoid
an unrelated unknown-field rejection; scoped rerun session55031 using
`-run '^TestSecurityAgentExportStatusRefusesMalformedPayloads/null_selection$'`
exited0,1.897s. These characterize existing validation, not new implementation
RED/GREEN. git diff --check exit0. OpenAPI/types/UI is next; registered database
and independent batch review still required. No production reclassification.

## OpenAPI and generated client checkpoint

Added all three mounted run/step export operations with browser-only selected
scope security, exact CSRF/body format/token inputs and binary download media.
Added closed public status/selection schemas including manual digest vs product
ID sources, bounded versions/selection/artifact sizes and lifecycle phase rules.
No provider coordinates in public schemas. Reused the existing format/grant
schemas without reusing compliance authorization.

New behavioral schema-validation test in openapi/identity-admin.test.mjs first
failed because the status path was missing (exit1,213ms). After implementation,
it validates literal public status and rejects private fields, bad bounds and
malformed download bodies; scoped GREEN exit0,234ms. Regenerated generated.ts
with the pinned local openapi-typescript7.13.0 and existing generation flags.

Full four-file OpenAPI test batch initially had40PASS/1FAIL due to the old
operation-count assertion157 vs160. Updated that contract assertion and added
explicit operation-presence checks. Final session88876:
`node --test --test-reporter=spec openapi/openapi.test.mjs
openapi/internal-health.test.mjs openapi/generated-client.test.mjs
openapi/identity-admin.test.mjs`, using cached Node22.23.1: exit0,41PASS,0SKIP,
2304.6ms. Includes generated-byte reproducibility and drift rejection. Local
Redocly lint of both OpenAPI documents exited0; git diff --check exited0.
No network dependency operation or provider call. UI adapter/panel, browser
proof, registered API SQL and independent batch review remain open.

## Browser API download adapter

Added app/features/securityagents/export-api.ts with real typed POST grant and
download calls. Token remains in the body and memory only. Checks current
session/scope and cancellation before dispatch, after grant and after bytes;
rejects expired/mismatched grants and empty/oversized artifacts.

TDD session31259:12tests,11failed against fail-closed stub,1passed (already
invalid authority). Initial implementation then exposed the missing binary
route in shared client.ts: valid requests were treated as ordinary JSON.
Extended its narrow attachment recognition to canonical agent run/step routes,
strict method/body, expected media/extension, canonical safe export filename,
no-store/nosniff and existing bounded response reader. Compliance attachment
validation remains exact. Corrected test response fixtures to actual attachment
headers so negative cases do not pass through unrelated header errors.

Final grouped session76230, cached Node22.23.1:
`node node_modules/vitest/vitest.mjs run
app/features/securityagents/export-api.test.ts
app/features/sessions/compliance-api.test.ts apps/web/api/client.test.ts`
exit0,3files,39tests passed,1.23s. Includes all formats, authority changes at
three boundaries, expired/wrong/malformed grants, revoked/empty/oversized bytes
and filename/media/cache/nosniff refusals. Uses real API client with controlled
fetch responses. No mounted UI, real browser Save, live server or provider proof.
Status decoder and mounted panel remain next; batch review not yet requested
for these changing API/UI files. Database-only frozen patch has been sent to
the independent reviewer, separate from this root-owned integration batch.

## UI status reader

Added a typed status GET on the exact run/step route and a closed runtime
decoder in apps/web/api/security-agent-export-decoders.ts. Preserves frozen
selection versions, rejects private/unknown fields and duplicate source IDs,
checks source-kind-specific IDs, safe version integers, association hashes,
calendar timestamps, lifecycle phases and artifact bounds. Checks current
authority before dispatch and after response; status expiry remains display
data, not retrieval authorization.

RED session33260:27tests,2failed against fail-closed status stub (successful
status and late-response dispatch),25passed including existing download cases.
GREEN session51950: cached Node22.23.1 Vitest across export-api.test.ts,
compliance-api.test.ts and client.test.ts, exit0,3files,50tests passed,1.28s.
Controlled transport only. Status/download adapter is ready for the next panel
integration step; no mounted panel or live deployment claim yet.

## Mounted export panel and UI build

Added ExportPanel to create_evidence_export execution steps in RunDetail,
backed by the real typed API adapter. Shows frozen selection/version, persisted
state, expiry, cleanup and artifact digest/size. Downloads require completed,
retained, unexpired status. Errors clear stale status and download controls.
Abort/lifetime checks discard responses after replacement/unmount. The save
action uses a temporary Blob URL and explicitly says browser handoff, not saved.

Panel RED session21737:5behavior tests failed against placeholder. Component
GREEN session13555:32tests passed. Mounted run-view RED32699:1failed/76filtered
tests; expected-scope/boundary RED80199:1failed/27filtered tests. Added optional
exports API for retained consumers, mounted panel, pinned expected-scope header
and production session/scope generation checks. Final grouped session93394:
ExportPanel.test.tsx, export-api.test.ts, SecurityAgentsView.test.tsx,
exit0,3files,110tests passed,4.39s,zero skips.

TypeScript noEmit session32580 exited0. UI vinext build session15148 exited0
through all five environments and produced dist/standalone. Build used cached
Node22.23.1, WRANGLER_SEND_METRICS=false and DO_NOT_TRACK=1. This is a local
build, not browser or deployed workflow proof.

UI/API coverage initially failed because new operations were unmapped. Added
three api_available entries (not full available), updated retained count tests,
and operation declarations. Ten coverage tests and coverage CLI passed; totals
planned2/api_available13/available147/public160 are map counts, not the728-task
production ledger. Scoped ESLint first reported one dependency warning; made
the query generation part of the actual captured boundary key, then reran
scoped ESLint session93903 with exit0 and no diagnostics. That small hook-key
and map/declaration delta followed the build and needs inclusion in final batch
verification. No commit, push or production reclassification.

Independent database review found one P2 possible concurrent settlement-lease
overwrite in links.sql183-188. Controller inspected the missing locked-row
eligibility recheck and returned it to the implementer for a controlled
reproducer and scoped fix. Database component acceptance remains pending.

## Run-detail action projection integration

Before browser inspection, source inspection found that the actual run-detail
request negotiates action details, while both Go and TS action decoders reject
create_evidence_export. The earlier mounted panel test used a supplied run
detail and did not prove that live decoder path. Registered SQL projection also
still needs its additive58 extension; controller notified its owner separately
from the P2 fix. Browser proof remains deferred, not replaced by component tests.

Added typed export action arguments {target_id,evidence_ids:[closed selections]}
in Go, with parent-run binding, bounded original selection, nested duplicate/
unknown-field refusal and no fabricated TTL or rollback support. Native RED
session4222 exit1,1.220s; argument and no-effect/pending/verified projection
cases refused the unsupported action. GREEN session53765:
`go test -race ./apiserver -run
'^(TestSecurityAgentExportAction.*|TestSecurityAgentActionArguments.*|TestSecurityAgentActionProjection.*|TestSecurityAgentActionDetailsHTTP.*)$'
-count=1 -v` under cached environment, exit0,2.081s. Existing projections and
HTTP negotiation checks included. This is not registered SQL projection proof.

TS RED51781: export action rejected by existing enum. Added action decoding with
parent target match and the shared closed export-selection validator. Added
OpenAPI argument union/action enum and regenerated types. Grouped GREEN64975:
four Vitest files (action decoder, export API, panel, SecurityAgentsView),
147tests passed,4.40s. TypeScript noEmit and diff check session68776 exited0.
SQL projection, approval/planner/dispatch and registered browser workflow remain
open. No status reclassification or publication.

## User-approved feature-batched verification

Group related microtasks into a feature batch. Keep focused failing/passing
regression checks during implementation, then run the affected integration,
race and browser checks once against the frozen batch. Request independent
review for that batch; follow-up verification targets the review delta and its
affected dependencies. Run the runnable-UI build and release gates against the
exact proposed push. Broaden tests for shared infrastructure changes.

Each original task retains its own acceptance criteria and evidence mapping.
Reuse accepted evidence only when its source and relevant dependencies remain
unchanged. Security boundaries, tenant isolation and authorization checks stay
mandatory. This changes verification scheduling, not the 728-task scope or
production-readiness standard. No measured speedup is claimed.

## Export action display and lifecycle projection batch

Added original selected source kind/ID/version to ActionDetails before an
artifact exists. RED60158 failed on missing accessible selection list; initial
GREEN7667 passed166 tests. Corrected the display fixture to use canonical
sha256-prefixed association digests and unavailable/none before effect.

Go and TS export action readers now accept only pending, succeeded,
known_failure and cleanup_pending effect states. Succeeded is not verified
security remediation. Cleanup_pending maps to inconclusive/effect_record,
without fabricating rollback or policy cleanup authority. The database owner
confirmed these semantics for the forthcoming registered read projection.
SQL projection, approval, public planner/dispatch and browser proof remain open.

Lifecycle RED20785: Go refused cleanup_pending and wrongly accepted verified,
leased and unknown_outcome. TS RED24798: four tests failed for equivalent
behavior. Grouped GREEN73700 ran12 native Go top-level tests with race enabled,
exit0,2.061s. GREEN9692 ran seven UI/decoder files,170 tests,zero skips,4.69s.
TypeScript78765 and scoped ESLint14340 both exited0 without diagnostics.
git diff --check passed. No new full UI build or production claim.

Database same-reviewer follow-up accepted the P2 locked-row guard at component
scope. Reviewer found a P3 coverage overclaim: settled-winner retained a live
lease, so that case did not independently exercise settled_at. Implementer is
correcting the fixture and report, with isolated mutation and affected tests.

Frozen root review source SHA256:
3d5613759067df0ed110cf62e292388a6c6156362fad1998cfec1814794dae70 action_projection.go
f59ceea33b094c9de94ab078d84acaa65a38d0385c37bbfc4ac5dd773639f90e action_validation.go
5dd3f55f0fd4082829bf82d1b5fb2157fe679fd6dcbdb5ccff3f618c28ba40c6 export_action_test.go
164756986f3ccfdf4f04fa06f903cf3275078e04376cbf94cef09fe087283eab ActionDetails.tsx
884147defc7b543990686c42990d46e7352271e6ab490fe5287d7306f2d2078f ExportActionDetails.test.tsx
90c71fbfcbc0cdc56943191c1c6c7f0e7762a4d5e093fca45638e2797d87b0a3 decoders.ts
70aa9482d8745ce52538dcaa22a6605df67fba2cf08518ef5c5a27f5373c9a4e decoders.security-agent-actions.test.ts

## Supervised export approval component batch

Previous root projection batch accepted by independent reviewer at component
scope, no actionable findings. Database P3 independently resolved with isolated
settled_at mutation RED and normal interleave GREEN, production SQL/pin unchanged.

Added Create run-scoped evidence export approval metadata with low catalog risk,
reversible=true and ttl_seconds=0, preserving builtin catalog semantics. This
does not change action rollback support. Public negotiated approval context
derives export_selection from validated original private arguments.evidence_ids,
requires parent target=approval.run_id, and refuses missing/invalid selections or
selections borrowed by other action contexts. UI shows the closed selection and
warns that expiry cannot recall downloaded files or verify security remediation.
Go and TS run detail now recognize this exact approval/action pairing.

Go context RED14001 refused export; run-detail RED2768 likewise refused export.
Grouped GREEN51710 (export approval, approval context, approval page tests) exited0
under native race,2.110s. UI RED13663 refused new effect; context/display GREEN84414
passed25 tests. Run-detail RED79147 exposed remaining action pairing gap. Final
UI GREEN86465: nine files196 tests,zero skips,4.67s. TypeScript and scoped ESLint
32582 exited0. OpenAPI closed-context test RED exited1; full four-file OpenAPI
suite55505 passed42 tests,zero skips,2.433s including generated reproducibility.

API lint flagged two conditional-schema property warnings. Added explicit
properties inside then/not, regenerated types, lint then exited0 without
warnings. Scoped schema/reproducibility/typecheck follow-up40043 and UI build
85928 pending at this record. Initial build command used nonexistent
vinext/dist/cli/index.js and did not run a build; corrected to package-declared
dist/cli.js. No dependencies installed or external provider used.

Approval SQL value/decision/detail/page routing remains open. The database
implementer is first completing registered run-detail projections. This batch
is component-only, not production, not pushed; independent approval review
pending. Full original scope unchanged.

Frozen approval review source SHA256:
b332a6681c8c23254c7b2ccbcdf8db26e6e6853c7f9907c8db8cbed5dc802e9e security_agent_approval_context.go
fe250653758d502b749fff0fcaf06f744aa0f081fa76b1d4d02386712d9769d1 security_agent_export_approval_test.go
9bcc769b63e48e19d2f44f26d948246325ed3fff3d7a0e1ccd148b2f8792902d security_agent_repository.go
fe5a7ea5dcb0c34030ec95c27486f0f86935b1758db3c84d99f83369eb5d0013 ApprovalContext.tsx
b3f24f839ef933e57afa89b4673f32f8c992888667ae007e092ddc509cefbc0d ExportApproval.test.tsx
e91385984b5126b9c66cb577f3c727e694c88bf6bf334cabc5b824896e0ff40c decoders.ts
17b37c067fcbf25652a8e26963615c92a5060f94336e04a3d01a52c702f76e12 openapi.yaml
b7fa9d3896fd64b499fbd3b4dc40e99cfadad821227635c501abe9f0649a5649 identity-admin.test.mjs
eefb6a05d3081787d452e867cd63cb4adb18c6ae86db4f805e554fbc4d31b843 generated.ts

Final batch follow-up:40043 exited0, two schema/generator reproducibility tests
passed with zero skips and TypeScript noEmit passed. Build85928 exited0 through
all five vinext environments and generated dist/standalone. This verifies the
local UI build only; no browser/live deployment claim. Approval component diff
sent to the same independent reviewer. Registered SQL projection owner now
verifying the next release58 pin7d10566a, not yet accepted at this checkpoint.

## Dispatch receipt integration checkpoint

Supervised approval batch independently accepted at component scope. The reviewer
verified all nine source hashes and no actionable findings; registered SQL paths
and composed browser proof remain open.

Added a distinct SecurityAgentExportDispatchResult and exact58 pinned Go dispatch
client. Closed receipt validates full scope/run, canonical step/export IDs,
pending state, original-claim version advancement and nonnull replay boolean.
It does not invent a result digest, completed artifact, or remediation. Inputs
require a prepared scoped claim, worker lease and audit/correlation IDs.

Initial test compile failed for missing method74278; minimal placeholder enabled
behavioral RED41474 (receipt refused, exit1). Implementation then passed grouped
race command19864,24.218s. That selector was too broad and also ran two existing
PostgreSQL groups on the host: table gate and two interleave cases. All three
owned PostgreSQL lifetimes joined with pg_ctl/server exit0. No shared daemon
restart or persistent database mutation was performed. This accidental extra
run does not replace the pending cached-container projection verification.
Subsequent native verification uses exact test names to prevent that expansion.

Dispatch source SHA2561278d1550d33451d64ccaf5c0109df15c73af1e7cc58a72f87afdf6cf76a6591;
test SHA2562754f4a49b8bd4cc2010a0890ba4a03ffb50c0d73a035fdcc2e74f0fb13ce218.
Worker routing and processor consumption remain open. Proposed trusted run-kind
probe must enforce registered worker plus current scoped lease, or original
dispatch worker/token for exact replay; missing/foreign/malformed is an error.
No scope-based guessing or current-definition fallback. The dispatcher retains
original receipt version even after settlement advances the parent.

Manual-parent integration gap: collector correctly uses the original64-hex
manual-intent digest, but legacy public run/approval and worker-claim decoders
expect product IDs. Follow-up must carry explicit typed manual provenance
(kind, original digest/version), with empty legacy evidence lists allowed only
when that provenance is validated. Do not turn a digest into a product ID or
substitute another source. This needs connected SQL/read/claim/Go/TS/OpenAPI
verification; finding-parent tests do not prove manual-parent workflows.

Registered projection runtime is pending at owned exec47277, CLI PID8143, with
no startup output and a separately timed-out daemon socket ping. Exact command,
binary/source hashes and draft patch are in database/projection-pending-runtime.md.
No restart or duplicate fixture launched; no projection GREEN claim.

Exact native follow-up28416 passed eight top-level dispatch/settlement unit
groups under race,zero skips,exit0,3.590s. No PostgreSQL lifetimes were launched
by this corrected selector. Dispatch client review will be grouped with its
worker routing/processor integration; the client alone is not an end-to-end
completion or production-available milestone.

## Worker dispatch consumer and routing batch

SecurityAgentExecuteResult now has an internal json-omitted ExportDispatch
receipt. Production ExecuteSecurityAgentRun probes installed export authority,
then the proposed registered zasp_sa_export_run_kind scope/run/worker/lease
function. False continues existing dispatch, true uses the exact58 export client;
malformed/null/duplicate/error never falls back. The resulting verifying wrapper
contains no fabricated security effect, outcome or digest. Registered run_kind
SQL is still pending, so this source snapshot cannot be published as a working58
workflow. A missing helper fails closed; component tests are not deployment proof.

Processor validates all wrapper/receipt scope/run/step/version bindings and only
pending admission, refusing fabricated completion/remediation or budget stops.
Confirmed lease-clearing heartbeat conflict is accepted, unrelated outage and
unconfirmed operation fail. RED82341 exposed refusal of three valid admission
cases and acceptance of two contradictory cases. GREEN93592: eight native worker
groups passed with race,zero skips,2.800s, including14 new dispatch cases and
existing completion/budget heartbeat coverage.

Routing RED2874 refused export; initial GREEN85840 passed five native groups.
Connected cancellation RED43472 then showed the real client discarded an
otherwise validated committed SQL receipt after heartbeat cancellation. Removed
the post-query context-only rejection, retaining initial context checks, SQL
error handling and full receipt validation. This matches existing committed
executor handling. GREEN70579 passed six exact native repository/routing groups
with race,zero skips,2.544s. No database process was launched. Diff check passed.

SQL routing must also preserve nonexport lost-reply dispatch: existing-test and
Attack Lab clear their parent leases on commit. False-family routing must prove
the corresponding original durable dispatch worker/token identity, not require
only a current lease or allow arbitrary family disclosure. Database owner has
this requirement and a registered regression queued after the held snapshot.

Frozen dispatch batch hashes:
b03d1b7d3c073332dde978e3fab4bdf602e5533ca973b7ae7d8fa13dab553479 apiserver/security_agent_worker_repository.go
b53e5049904ef00f00cb2df420e1a87319ab97839be0f35263f4acafa929104f apiserver/security_agent_export_dispatch.go
590d668d5e100148ab0b9c2e803175f0b3a8cd4b3af4216f128708790d7a7802 apiserver/security_agent_export_dispatch_test.go
d5e317f296f3b020c860eb3ded2559c6be02dd3ff42a5ade081a88108259d29a agentsec-worker/security_agent_runtime.go
1a8d32a01e06e1ac22c9e9089bd43c6b17f403c5ccc3949fe65f23def5ae0852 agentsec-worker/security_agent_export_dispatch_runtime.go
6924fd0d7c350add235121885dacdcf1d99a12f39412caf01539a78bf2528ed6 agentsec-worker/security_agent_export_dispatch_runtime_test.go

## Late-response UI boundary verification

Dispatch batch independently accepted at component scope with no findings. The
unimplemented registered run-kind helper still prevents publication acceptance.

Extended real ExportPanel + typed API adapter + response-decoder tests across
late grant and late binary responses, each after unmount, parent-run replacement,
disabled authority or scope-generation invalidation. Controlled fetch deliberately
ignores abort until released; the real adapter operation is awaited to rejection.
No stale Blob URL or browser save is created. A late grant never starts a bytes
request. The replacement run retains its own pending state, and stale download
controls disappear. This is local component evidence, not native browser-save
or live-provider proof. No production code changed in this test batch.

GREEN6062: ExportPanel/export-api/SecurityAgentsView,112 tests in three files,
zero skips,exit0,4.28s. Includes eight new boundary scenarios in two table groups.
TypeScript noEmit and scoped ESLint71080 exited0 without diagnostics.

Docker recovered without intervention. The original registered projection run
47277 joined exit0 (reported five groups/eight owned PG joins at7d10566a), so the
requested shared-runtime restart is no longer needed. No restart was performed.
Database owner retained that evidence and reproduced the additional stopped-
parent reader gap with actual contained/remediated/inconclusive settlements;
its narrow reader correction and affected verification are in progress.

## Batched continuation and routing decision

The previous user-facing batching discussion changed no product state. Resumed
against the current shipping worktree; preserved the inherited dirty tree.
Projection correction is now frozen at pin
46b69c98336c9a93c168e9b451ae8da69fb248ee1706d6d2c419f31707b6a998.
Root rechecked the three source hashes and projection.patch against
database/projection-report.md and dispatched independent read-only review of
that bounded delta. The report retains the actual final three-group registered
run, seven clean PostgreSQL joins, and the stopped-parent behavioral RED.
No live production acceptance follows from those fixtures.

Correction to the earlier routing requirement: source inspection found no
durable original parent dispatch token receipt for existing-test execution.
Its predecessor executor calls budget_can_start before replay and refuses a
cleared lease. Attack Lab does have a durable dispatch worker/token identity.
The additive export run-kind route must preserve the existing-test refusal and
test it, while admitting only exact proven Attack Lab/export replay identities.
Do not fabricate existing-test replay authority or weaken the current lease
check. A durable existing-test dispatch receipt protocol remains required
connected reliability work, not waived by this compatibility decision.

Planner integration is not only a missing Go action branch. Current
LoadSecurityAgentPlannerContext requires one step/action/target/evidence item,
and zasp_sa_export_authorize independently requires exactly one planned step
at index zero. The collector's existing_test/attack_lab selections require a
different same-run prerequisite step with its actual effect digest. Those
requirements cannot be met by the current one-step plan through the product
path. Multi-step planning/execution and typed manual-parent provenance must be
implemented before claiming the full export workflow; seeded collector proof
does not close either gap. No readiness flag or ledger classification changed.

Independent projection review accepted the three-file component delta with no
actionable findings. Reviewer checked actual code/tests, source/evidence hashes,
unchanged decoder/renderer dependencies and reverse-apply safety; no redundant
test rerun. Approval and run-kind SQL implementation resumed as the next
connected feature batch. Ledger validator remains green:728 rows,526 historical
production-available,141 component-only,61 blocked/external,0missing. These
historical labels are not a fresh production audit. No commit or push occurred.

## Planner candidate wire-contract correction

While tracing export planning, root found that model response decoding used
DisallowUnknownFields but still accepted duplicate keys, case aliases and a
missing/null first-step index as zero. This violates the existing exact schema
before adding export selection. New production helper
agentsec-worker/security_agent_planner_candidate.go checks the closed outer
and step keys using the existing duplicate-rejecting object reader, before
the existing typed decode and action/target validation. No authority expands.

New test security_agent_planner_closed_candidate_test.go drives the actual
planner through a controlled provider transport. RED23730 reproduced ten
accepted malformed candidates; two unknown-key controls already refused.
Exact native race follow-up58636 passed18 top-level planner/prepared/cost
groups,zero skips,exit0,2.121s. Existing successful candidates, usage retention,
one-shot dispatch, cancellation and immutable prepared context were included.
Initial group21428 was overly broad and selected the parent-DSN-gated planner
PostgreSQL test; its exit0 is not registered-database proof. The exact follow-up
excluded it. No provider request or new database process was needed for this
correction. Diff check passed; independent review requested for these two new
files and the single added guard in the inherited dirty planner.go.

Reproduce the accepted native selection from services/platform with cached Go:
```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-worker -race -run '^Test(ProductionSecurityAgentPlannerLoadsOnlyPinnedCredentialFile|SecurityAgentPlanner(RejectsAmbiguousCandidateFields|SendsOneSeparatedBoundedRequestAndAcceptsExactCandidate|FailsClosedWithoutRetryRedirectOrProviderLeakage|HonorsCancellationAndZeroizesCredentialOnClose|DoesNotExpandExplicitTargetAuthority|PreservesExactUsage|UsageUnknownIsNotZero|UsageRejectsAmbiguousResponse)|SecurityAgentPrepared(PlanValidationUsesOwnedContext|PlanFreezesContext|PlanRefusesDriftAndCancellation|PlanDispatchIsOneShot|PlanPreparationErrorsNeverReserve|PlanMissingAuthorityReachesReservation|PlanWorkerPermitRefusals|PlanDoesNotHoldPlannerLockDuringSend|CostAuthorityRefusesUnboundValues))$' -count=1 -v
```

SQL owner confirmed the next export planning contract: trusted export_selection
contains ordered closed typed references; model evidence_ids chooses a bounded
subset whose full tuples must match. The same version-bound context must be
recomputed for reservation and acceptance before freezing plan order. This
agreement is not implementation or proof of the manual/multi-step workflow.

Independent planner correction review accepted at component scope with no
actionable findings after inspecting code and boundary tests. Reviewer did not
rerun tests or independently inspect session output; root owns the observed
RED/GREEN evidence above. Frozen hashes:
```text
129033e6c635159a4c94bd7de44a96be0df963c80aca1598fa0bd21954712496 agentsec-worker/security_agent_planner.go
80f8437f926fd2d7326bf9734d574e12a2673a203165a9b9ec4e3b8394aa638b agentsec-worker/security_agent_planner_candidate.go
3577e1f7bba0a0cd4bae4b5f985c66d3be538133760b882b4c92047dfe55f19f agentsec-worker/security_agent_planner_closed_candidate_test.go
```

## Export planner typed-selection component

Implemented the agreed model boundary without enabling action readiness.
Trusted context carries ExportSelection and sends export_selection to the model;
export steps require evidence_ids with exact kind/id/version/association tuples.
Model selection must be a nonempty unique subset of those tuples, bounded100,
and target the parent run. Original candidate order is retained. Preparation
clones the selection so caller mutation cannot change the accepted authority.
Nonexport action wire format is unchanged and refuses export fields. Nested
duplicate/aliased/unknown keys are refused before typed decoding. An export-only
response schema requires the same tuple fields; independent validation remains
mandatory even if a provider ignores the schema.

RED66873 reproduced valid export refusal and four malformed/absent trusted
selection cases reaching the provider. GREEN10687 passed the initial grouped
cases. Final native race5704 passed24 exact top-level planner/prepared/cost/export
groups,zero skips,exit0,2.529s. No PostgreSQL/provider process was selected.
Tests cover exact subsets and reordering, version/digest/kind/ID substitution,
duplicate references/keys, private fields, parent and cross-action refusal,
immutable prepared selection, all seven reference formats and100/101 bounds.
All-kind selection is parser evidence, not manual-parent or linked-source
product-workflow proof. Independent review requested; diff check passed.

Frozen source hashes:
```text
a87b3bf992ad6c8d9e268059567d81c183f38803602fb38fc6ce2548e782a249 agentsec-worker/security_agent_export_planner.go
aa22d4af9e4d30ca909dbf04db7a2ac43fb37eaadbfd3c59814a72aa30471aa1 agentsec-worker/security_agent_export_planner_test.go
853956bafd0699c11a9c33d3bdf4d158530b43ea9547eefd9734e66e59ab49b7 agentsec-worker/security_agent_planner.go
ff431aa95ed340356b7741777d2848dd5bb5b1ae6c32588c40a2d3efe1986d22 agentsec-worker/security_agent_planner_candidate.go
12a110c33d1550ea4db07985760b1be958bd711fa9a468fcc68f083120896d03 agentsec-worker/security_agent_prepared_plan.go
```

Repository and processor do not supply this context yet. Next connected SQL
interface retains predecessor parameter arities/types under
zasp_sa_export_planner_context, zasp_sa_export_reserve_planner,
zasp_sa_export_accept_planner and zasp_sa_export_fail_planner. Selection belongs
inside canonical context/candidate JSON, not separate transport arguments.
Reservation and acceptance must recompute the same selection-inclusive,
version-bound context digest. Multi-step execution, manual-parent provenance,
configured runtime, actual API/browser/provider proof and publication gates
remain open. No task reclassification, commit or push.

Independent selection-batch review accepted at component scope with no
actionable findings. Reviewer inspected the actual code and tests, including
value-only slice cloning, schema boundaries and exact tuple membership, but
did not independently rerun root's race command. Full workflow gates above
remain unchanged.

## Processor selection forwarding

Added ExportSelection to repository planner-context type and EvidenceIDs to
planner-submission type. The worker processor clones trusted selection into
the real planner context and clones the chosen subset into submission. New
security_agent_export_planner_runtime_test.go drives the actual processor,
planner and response decoder through controlled provider/accounting boundaries.
The authority boundary receives exact ordered references and original input
digest; a changed-version model response records planner_rejected without
admission or execution. SQL source authorization is not mocked into proof.

Initial fixture runs39229/5819/29441/71919 were confounded by JSON-roundtripping
the entire repository context: nil AttackLab became raw null, triggering the
correct non-Attack-Lab refusal. The final fixture decodes only selection. An
intermediate request-token configuration hypothesis did not resolve it and was
reverted. Those fixture failures are not accepted behavioral REDs.

After fixture correction, isolated mutations proved both links: removing the
context copy failed54226 before provider dispatch; removing only submission
copy failed56196 with evidence_ids lost as null. Restored both copies. Final
native race2341 passed seven exact export/processor groups,zero skips,exit0,
2.341s. Includes existing approval/execution, budget stop, scheduling failures,
heartbeat and known-usage rejection. Diff check passed; independent follow-up
review requested. No production SQL, browser, provider or deployment claim.

Frozen bytes:
```text
7cc1b204c21557477fc2467e13137c33d6e469ad43d2929ffd58d6ec3a559d7e apiserver/security_agent_worker_repository.go
e2448e9e84775afaab181ad5bd9bfa610fe2c10466a683cb6703607795318a60 agentsec-worker/security_agent_runtime.go
cda37f6401bd7933c4775de3fac8d6c1aab5cfe0ce1eb767a74d09ebb6cc95d8 agentsec-worker/security_agent_export_planner_runtime_test.go
```

Next is repository context parsing, candidate JSON serialization and all four
release58 planner routes (load/reserve/accept/fail). Database owner confirmed
run_kind supports unprepared planning with a current scoped lease and the exact
run-bound definition version/digest, not a latest-definition inference. This
allows explicit export routing before a step exists. Current repository methods
still reject export context and do not serialize selection; this forwarding
component does not make the public workflow usable or close M7A-23.

Processor follow-up independently accepted at component scope with no
actionable findings. Reviewer verified all three hashes, inspected both copy
boundaries and test behavior; no independent test rerun or session-output
inspection. No ledger reclassification, commit or push.

## Connected repository planner admission routes

Implemented the four agreed Go routes as one batch: context, budget reservation,
candidate acceptance and planner failure. All select the exact export SQL
entrypoint only after the optional release capability and closed scoped
run-kind receipt. Export routing runs before predecessor family probes.
Unavailable/invalid capability or kind never falls back. Absent capability or
explicit false preserves existing planner families. Source authority remains
the registered SQL contract, not a model action name.

Export context adds closed export_selection parsing using the existing
selection validator, factored without changing download validation. It requires
the parent-run target and no existing-test/Attack Lab private context. Candidate
serialization preserves evidence_ids and rejects empty/duplicate/malformed
references or foreign parent targets before SQL. Nonexport submission refuses
selection fields. Acceptance requires the action to agree with the routed run
family, so unavailable export support cannot silently use predecessor SQL.

RED67185 showed the legacy context route could not load export authority.
GREEN8588 passed initial context/whole-admission cases. Native race43701 passed
21 exact top-level groups,exit0,3.221s: five new export repository groups, two
worker planner groups, durable-stop context, three budget groups, three
existing-test routing groups and seven immutable download groups. These are
local boundary tests, not registered SQL planner proof. No PostgreSQL test was
selected. Tests cover all four routing failures (null/duplicate/unknown/type,
capability error, query conflict and missing helper), context drift, submission
guards, retained scope/lease arguments, exact selected candidate JSON and
false/absent nonexport routing. Diff check passed.

Frozen hashes:
```text
17708cf8913afb2ba52c8feb28305cd8ec7509b75a02faa52edfe75bb0521f8c apiserver/security_agent_export_planner_repository.go
e6eb73ff2adf6cac7a8897e22165ab37fa5d2e8a59e3f607e505b1180d9de324 apiserver/security_agent_export_planner_repository_test.go
b4211dccab5f3a87d073dca0239f3c81ee89ff96058e1a9c2dbc9a0c0c1b5853 apiserver/security_agent_worker_repository.go
f858aecf2c8c0890d67962f1b426d503efe5a15d2a45952a2977837c67bba9de apiserver/security_agent_budget_repository.go
b9e3d2a20dfbd46c2d1914cd42bcbee594233de0aee69acbbab11711ab2f7f43 apiserver/security_agent_export_download.go
```

Database approval/route batch is also frozen at e60b91c5d4ecd09bd20617e12eca85bc139865c9532f71e6613e578a6a5bd676.
Root inspected approval-route-report.md and checked report/patch hashes.
Registered approval, route, atomic refusal and supervised admission groups
passed on the draft; a concrete Attack Lab SQL alias collision was corrected,
then nonexport routing/release passed at the final pin. Exact logs and limits
are in database/approval-route-report.md. One combined independent review now
covers that three-file SQL delta and the five-file Go repository batch.

The four SQL planner entrypoints are still absent. At release58 an export
planning attempt therefore fails closed; this checkout is not publishable as
a working export workflow yet. SQL context/reservation/acceptance/failure,
manual-parent provenance, original multi-step execution, real mounted browser
workflow and external production gates remain required. No readiness change,
task reclassification, commit or push.

## Planner receipt replay routing correction

The combined approval/route SQL and Go repository review was accepted at
component scope. Subsequent SQL integration analysis exposed a lost-reply
problem in the Go routing contract: successful acceptance or failure can clear
the lease, so a current-lease run-kind probe would refuse a legitimate retry.
This supersedes the preceding all-four-routes kind-gating description.

Context and reservation still require the scoped current-lease kind probe.
Acceptance and failure now use the release58 receipt-aware SQL wrappers for
all families whenever that capability is available. SQL must dispatch using
the original scoped definition/plan and preserve the predecessor's exact
request/receipt replay checks. Missing or invalid release support cannot admit
an export through an older route. No new dispatch-token authority is added.

RED25014 refused all four new export/nonexport accept/fail replay cases because
the old Go code attempted the lease-bound kind read. Restored implementation
passed native race session77690, exit0, 2.113s, covering the six export planner
repository groups, two worker planner groups, durable-stop context, three
budget groups and three existing-test routing groups. The test database omits
the kind response and requires exactly the receipt-wrapper call for replay.
These are local repository boundary tests, not registered SQL replay proof.

Corrected file SHA256 values:
```text
32b276d72d43a780f309d910ce34c7157d10028121cf05b9e4b175e1622f344f apiserver/security_agent_export_planner_repository.go
b12077ed2420255d5a25baac9bb65c30a94a3dab3902417c75cb2fb9df44ba91 apiserver/security_agent_export_planner_repository_test.go
69c4e7a629c9a8112af25e1870f8045f429e0d6694ccbb658f12de43a28adf3d apiserver/security_agent_worker_repository.go
```

Scoped independent review accepted this correction at Go component scope with
no actionable findings and all three hashes checked. Review confirms direct
receipt routing, retained request validation and closed failure behavior; it
does not establish actual durable SQL replay. Exact selector listing58963
confirmed 15 top-level groups (correcting the 14-group reviewer handoff count).
Registered planner
SQL implementation remains in progress, including a private immutable input
snapshot captured before provider dispatch. Manual provenance is design-only
in `2026-09-19-security-agent-manual-provenance-design.md`; no manual public
flow, multi-step workflow, production availability or milestone completion is
claimed. No commit or push.

## Manual worker-claim reader

Started the recorded manual provenance design at the existing Go worker claim
boundary. Optional manual_trigger carries exactly kind=manual, a lowercase
sha256 intent digest and version1..9007199254740991. A raw digest trigger_id
requires the matching typed object. Legacy ProductID claims omit it. The reader
rejects null, mixed identity, mismatched or prefixed trigger IDs, invalid kinds,
missing/unknown/duplicate/aliased fields and invalid versions. The claim reader
now checks closed outer keys with duplicate rejection. No global ProductID
validator or SQL entrypoint changed.

RED27669 failed the legitimate manual and maximum-version cases against the
old reader. GREEN1877 passed nine exact native race groups,exit0,2.042s: the
new 19-case reader test, two existing worker planner groups and six export
planner route groups. The tests exercise the repository reader against
controlled SQL response bytes and preserve typed provenance on serialization;
they do not prove actual SQL association authority. Diff check passed.

Frozen SHA256 values:
```text
a204b29ed1d6b7bacd1ed7763d3d0ad59b31041e1a905681d686d893575a3070 apiserver/security_agent_manual_trigger.go
301fa4f008feda8ff3699deb6e51a59c71a09b0dced50df2a2695a638bc2c039 apiserver/security_agent_manual_claim_test.go
39186959c71a65b6c40d0c79dd6737860c56c96ed7dc247139a574286b6e69fc apiserver/security_agent_worker_repository.go
```

Independent component review accepted with no actionable findings and all
three hashes verified. Registered claim producer and original
receipt/definition binding, public run/approval projections, planner canonical
context binding, OpenAPI/TS/UI and real manual admission remain required. The
manual workflow is not available end to end. No readiness or ledger-row change,
commit or push.

## Manual public Go read projections

Added typed manual_trigger to public Run and Approval reads. Closed decoders
reject unknown/duplicate/aliased outer fields and null manual provenance.
Manual evidence arrays must be explicit empty arrays; nonmanual evidence keeps
its prior ProductID contract. Embedded approvals must match their parent run's
manual digest/version. Negotiated run context requires the matching manual
trigger; only manual-kind trigger IDs use raw intent digests. Legacy reads may
omit negotiated context, but cannot invent manual identity. The context trigger
object now rejects duplicate keys.

RED89149 rejected legitimate manual detail. RED99701 also proved the previous
reader exposed a manual-labeled ProductID without provenance (HTTP200). The old
positive fixture for that invalid representation is now a refusal regression.
RED78161 caught duplicate trigger-kind acceptance. Final native race16793
passed20 exact groups,exit0,2.083s: manual read/claim2, run-context8,
export-approval3, approval-context7. New15-case read tests exercise the real
detail decoder, HTTP handler, run-list reader and standalone approval reader
against controlled SQL response bytes. No PostgreSQL fixture selected, and no
actual registered manual receipt association proved. Diff check passed.

Frozen SHA256 values:
```text
eca6a209e2ce1ab944c16ee8a2de45bf518719c82892d3e37cb1c2453068162a apiserver/security_agent_manual_read.go
7a0f3235ab320065689f1362a1f07fdeac19046a68368f2fc7b687eade6a9e80 apiserver/security_agent_manual_read_test.go
f828fb5927d7256911ebc0c67b96379d97eae83b9780ab2fc307122465e762a2 apiserver/security_agent_handler.go
8f8332d8a690f55745c2f4529f76bbda37c2be2a64449dcd863836de14284691 apiserver/security_agent_repository.go
b27c271c2c137e553a0b0aeb31ec543fb643d08cd2d98a76ce331c3184dc3558 apiserver/security_agent_run_context.go
6abea66e493d68aa5c623372e40130cce73269efd8529af42447c8d7d5333f90 apiserver/security_agent_run_context_test.go
2709d974a91451b126b7568a3b03fe648ccee86225af8830c757f6c592cfca68 apiserver/security_agent_run_context_envelope.go
16a07837e9e00029750dd7fbdb6b027f03d5475e0322eb7756cd2b40d0dfe601 apiserver/security_agent_attack_lab_repository.go
```

Independent review found a P2: permissive alias decoding inside the new
Approval.UnmarshalJSON bypassed nested unknown-field rejection. RED36633
reproduced all six paths (context/requester/reason/risk/rationale/selection),
with a valid control. The alias now uses decodeStrictDiscovery. Race19979
passed21 affected groups,exit0,1.932s. Scoped re-review accepted the correction
and the Go read component. Corrected SHA256 values supersede the two above:
```text
5f259dd9fe700aa0a20f3c5bc7606a686f1541646565849257044bdeafbbd93e apiserver/security_agent_manual_read.go
8968bef1c3c26a8224e2cf9ff22c97f634ad84b1642568af5e109094835b60eb apiserver/security_agent_manual_read_test.go
```

Mutation result
propagation (cancel/start/approval decision), registered manual receipt producer
and projections, planner canonical provenance, TS/OpenAPI/UI, real end-to-end
manual workflow and production gates remain required. No ledger reclassification
or claim that manual runs are production-available. No commit or push.

## Manual cancellation and approval-decision responses

Both mutation result types now retain manual_trigger. Repository cancellation
accepts the closed optional provenance field, validates the resulting manual
run with explicit empty evidence, and preserves existing scope/version/audit/
receipt checks. Cancellation and approval-decision HTTP projections copy the
same typed provenance. Approval result validation uses the same manual read
contract. No fresh-authentication, CAS, authorization, or replay rule changed.

RED75135 refused all four valid fresh/replay mutation paths with HTTP503.
GREEN75866 passed the four manual groups,2.046s. Final affected native race32693
passed17 exact groups,exit0,2.060s, covering manual4, existing public-handler4,
repository4, approval validation1, fresh-authentication1 and Attack Lab mutation
projection3. New15-case tests traverse the actual handler and repository with
controlled SQL bytes. Fresh/replayed receipts retain the manual digest, explicit
empty evidence, ETag and original mutation receipt; null/mixed evidence, wrong
version, foreign fresh receipt and missing fresh authentication refuse.
These do not establish registered SQL mutation or durable replay behavior.

Frozen SHA256 values:
```text
edb754626e4789477ff6d332c60928575dff6ccf36e12766f5b8382e5b8d182e apiserver/security_agent_handler.go
df29c84211d94ea23af6f87f2f990ce177a7449a845afcdffbc06261b95b1a0c apiserver/security_agent_repository.go
04edbf0a5b62bdedad53e6a70d3657abe3d39ccd46a779c52e9858d11f1efd9b apiserver/security_agent_manual_mutation_test.go
```

Independent review accepted this Go propagation component with no actionable
findings and all three hashes verified. Original M7A-70 explicitly requires manual
POST /api/v1/security-agents/{id}/runs with optional finding/path/session ref;
the current handler still requires such a ref. Public manual admission is a
remaining original-scope requirement, not a new endpoint request. Registered
provenance producers, planner propagation, TS/OpenAPI/UI and full production
gates remain open. No task reclassification, commit or push.

## Manual browser contract and display

OpenAPI now describes optional closed SecurityAgentManualTrigger and the
manual/nonmanual trigger-ID union. Run, run-detail and approval evidence arrays
are empty only with manual provenance, otherwise nonempty ProductID arrays.
Generated types were rebuilt from the schema. Browser decoders validate exact
kind/digest/safe version and parent context/approval agreement. Manual intent
digest and version are displayed in run detail and approval context without a
ProductID link. Original manual-start input is unchanged and still incomplete.

RED30297: valid manual and maximum-safe provenance refused, and the invalid
manual ProductID fixture accepted. UIRED3494: both intent displays absent.
GREEN76504: seven files212 tests,4.43s; OpenAPI/generator26 tests passed.
Final schema inspection found and corrected the outer detail array's old
minItems=1. Final schema lint passed and generator reproducibility58294 passed
three tests,2295.65ms. Types58464 and scoped lint70409 exit0. Vinext78380 built
all five environments and dist/standalone,exit0; the final schema-only array
constraint change does not alter runtime output. Diff check passed. These are
local decoded/component renders, not a live browser or actual SQL manual run.

Frozen SHA256 values:
```text
99e7d2098a49c916e50eac2656ec34762aab711d7b9b0d0c1697cc9c9e46a592 apps/web/api/decoders.ts
5006210ac892f49aa5eaf5a8c45c83409a9791a512c55ce2397688d9f89ffca8 apps/web/api/decoders.security-agent-manual.test.ts
18b2b5a0aabfe330f8d2553d8d09f3ab3e2ce8c27177448197400b5e432870ee apps/web/api/decoders.security-agent.test.ts
4fd3c59cfc3519569ee17fe185c6d46c692a34b7af9e6458b60271ee2048dff7 openapi/openapi.yaml
ca228cdd40bfff7ee4782943c6741a72f77c5c7717ca421d0cd16cd1d2785fc8 apps/web/api/generated.ts
de307439266bd01d1a25d39d0fc2237d7a0cd30a1c3a01786b5cbdd323b497d2 app/features/securityagents/SecurityAgentsView.tsx
f98ac9edf252aee911cce1dbed0a3a080442c76ac7905ac6595f724d23478161 app/features/securityagents/SecurityAgentsView.test.tsx
65f52d1f9cfc3fda18e23eb7ce6c289278393a9efcb8a6541068f0a6c4495c5a app/features/securityagents/ApprovalContext.tsx
```

Independent review accepted the browser contract/display component with no
actionable findings and all eight hashes verified. Registered manual producer/projections, planner
provenance, original multi-step workflow and end-to-end acceptance remain open.

SQL implementer reports an additional retained accounting gap in registered
tests: a worker with current planning lease can accept a permitted candidate
with a valid input digest without reserving/settling provider usage; an
outstanding reservation also does not prevent acceptance. Existing-test
predecessor behaves likewise. Attack Lab is inferred from cloned protocol but
not yet characterized. Explicit unknown settlement does durably stop the parent
as needs_human/budget_usage_unknown and refuses admission. This report still
needs root evidence/review inspection and an all-family closure batch before
production; it is not a waived requirement or safety acceptance. A prior
permission-wait report was invalid evidence because reducing direct scopes did
not revoke the admin role's effective view_audit; corrected effective-grant
fixtures are in progress. No production reclassification, commit or push.

## Manual planner provenance propagation

The repository accepts optional context.run.manual_trigger only when it equals
the claim's original typed identity. Closed run keys reject aliases/unknown
fields. Manual untrusted evidence uses the same raw intent digest and version;
nonmanual contexts cannot carry this provenance. The processor copies it into
planner input, Prepare owns a deep copy, and the model request includes the
typed identity. Candidate output cannot supply or override that identity.
Targets and export tuple subset validation retain their existing authority.

RED51049 refused valid manual repository context. WorkerRED23079 refused valid
manual preparation and accepted a nonmanual context after dropping unknown
manual metadata. RuntimeRED84697 refused both actual-processor manual cases
before provider dispatch. Fixture14364's wrong-kind wire injection was itself
rejected by the existing strict manual JSON decoder; it was corrected to test
an invalid in-memory kind and is not production defect evidence.

Repository race75864 passed12 exact affected groups,2.103s. Worker focused
race36190 passed5 groups,2.431s. Final worker race37035 passed20 exact groups,
2.374s,exit0, including retained export selection, prepared-input immutability,
provider refusal/cancellation and exact target checks. The new context test has
10 cases; prepared identity has7; actual planner/processor test now includes
valid and invalid manual selection paths. SQL and model transport are controlled
test boundaries, not registered manual receipt or live provider proof.

Frozen SHA256 values:
```text
ca56d2b8c233f52e1e7719b2e027e7963bff2a7737178130fadcd9da05439490 apiserver/security_agent_manual_planner.go
d7018166790c5c4ee10f67737191c4c83cefd12da7544f57ae92f2db27d912e3 apiserver/security_agent_manual_planner_test.go
c8bb6aae98edfe2684b6b16f2abeacb1ee1d7f163ac80b29860ee9fe6d5def61 apiserver/security_agent_worker_repository.go
825016a2ab1c71ad7955a5d11b5c64b5e24f97918fcd9fc06b664b414749081e agentsec-worker/security_agent_manual_planner.go
0226de988a60712201fa44d7c841d63d771e608f662a7b375f8d00cb4367b5be agentsec-worker/security_agent_manual_planner_test.go
4342b9f8aad8cf75c2f517460a4e8a6929caec838bb7040bfa8c71dc732d6322 agentsec-worker/security_agent_export_planner_runtime_test.go
4396641a20cd3be22ddba843b3d93153bcce174ffb1130149323972dec29ce6e agentsec-worker/security_agent_runtime.go
3111b28068dd1d9d5dd0bf4c9fa381e3feadf2676ad9a05eb1189a948aaa7610 agentsec-worker/security_agent_planner.go
4c2f097cbdcb52479414435d5b4e856f82c6d260fa7c9e7042b55e5cbe651540 agentsec-worker/security_agent_prepared_plan.go
```

Independent Go review accepted this component with no actionable findings and
all nine hashes verified. SQL owner confirmed this wire fits the private
snapshot, but registered manual context still refuses and plan preparation
still needs its manual legacy evidence-array correction. Public start and
registered receipt binding remain required.

Root read database/planner-report.md fully and verified report, patch and all
five product hashes at pin4f5dbcc24bcc51b39c3aff1fc019ffed8e15b3e4bd8278367e364c5fc9a1073c.
Independent SQL review found one P2: subset validation rejects valid candidate
reordering, contrary to the agreed Go/model contract. Owner is correcting this
with registered acceptance/replay proof. Review verified retained logs and the
corrected post-wait mutation proof; no other actionable findings in that patch.
Missing/outstanding provider accounting remains an explicit separate all-family
production blocker. SQL admission is not accepted for production. No task
reclassification, commit or push.

## Candidate-order correction accepted; feature-batched verification

Root verified the correction report, scoped patch and all three current product
hashes, and reverse-patch applicability. Independent re-review accepted the
bounded planner component with no new findings. The original P2 is addressed:
exact unique subset membership preserves candidate order; cleared-lease replay
returns the original result; changed order or subset refuses without mutation.

See [the correction report](database/planner-order-report.md), SHA256
269df2249c7544d2697b78cbcf399f63d71cdee45c8fb5c787f638fc907b94b1.
Current release58 pin:
49c9b2e421d80372470136ede8e9cced66ba34fa19dae1b72e88f6ee0b0cfecb.
Retained behavioral RED reproduces the former rejection. The affected registered
batch passes CandidateOrder (6.65s), Refusals (6.10s), and Release (6.74s), with
three clean owned PostgreSQL joins and no skips. Reviewer checked the log hashes.
Unchanged reviewed groups were reused, not rerun. This is registered local
component evidence, not a deployed or live-provider acceptance.

The user's feature-batching instruction applies to subsequent connected work:
focused behavioral RED/GREEN during coding; one affected integration/UI/race
batch and independent review before shipping; correction-only reruns when
unchanged source and evidence remain applicable. All728 tasks retain their own
status and proof requirements. This does not waive tenant/authorization cases,
production gates, or original scope.

Next local dependencies remain all-family settled-provider accounting and the
original M7A-70 optional-reference manual admission, followed by registered
manual projections and composed public workflow. Neither a passing correction
nor typed manual readers closes those gaps. No reclassification, commit or push.

### Next connected batch: all-family accounting closure

Read-only investigation identified worker-granted legacy and v33 accept/fail
entry points in addition to existing-test, Attack Lab and export paths. A guard
only in the new export wrapper would leave a bypass. Root checked the v33
grants and production planWithBudget sequence: prepare, reserve, dispatch,
settle known usage, then return model output. There is no production
zero-provider model acceptance path.

Implementation is authorized as an additive release58 correction. Fresh model
output must match the settled reservation's full scope/run/current attempt,
input/output digests, model and original worker/lease digest, with complete known
usage and no outstanding run reservation. Preserve existing committed receipt
replay before fresh-path guards. Preserve current lease, budget stop/deadline,
context and post-write checks. Missing/outstanding accounting must refuse without
consuming the attempt, so settlement and retry can recover. Explicit known zero
usage is valid; unknown usage retains its stop and reservation.

The narrow existing terminal-failure exception remains: planner_unavailable
with NULL output and no current-attempt or outstanding reservation. It cannot
accept a plan or hide an issued permit. Reservation cost_policy_version is not
the planner receipt policy_version. Deterministic preparation is not a model
acceptance and does not acquire a provider requirement. Existing unaccounted
committed receipts are not repaired by this future guard; their historical
proof limits remain recorded.

SQL owner is implementing behavioral RED, the shared private guard after
receipt-first replay, saved predecessor/ACL restoration, and one affected
registered batch. No completion or safety acceptance is claimed yet.

## M7A-70 source-free public API component

Go now decodes the existing run endpoint's environment-only request as a
server-derived manual intent request. Explicit finding/path/session references
retain their existing route. A closed custom request decoder rejects partial,
null, empty, duplicate, case-aliased and unknown fields, caller digests and a
foreign environment. Internal manual requests cannot supply trigger_id.

The repository uses the SQL-owner-confirmed zasp_sa_manual_run13-argument
contract with authenticated scope/principal, key, definition version, fresh
server IDs and compiled release58 pins. Absent/false/error capability fails
closed; there is no fallback to historical create_run. The response requires
valid manual version1 provenance, explicit empty legacy evidence, consistent
definition version and original replay or matching fresh receipt IDs. Public
responses retain manual metadata; only browser responses expose mutation
receipt headers. A null replay flag is refused, not coerced to false.

Superpowers TDD evidence from actual handler/repository with controlled SQL
bytes: session94628 RED (valid no-reference requests returned400); session51116
initial GREEN23cases1.503s. Expanded session60680 RED showed replayed:null
incorrectly returned202. The correction requires an explicit boolean.
Final session20740 affected native race batch passed14top-level groups in3.383s,
including all27manual-start cases, prior manual claim/read/mutation/planner
checks and explicit finding/session regression paths. Command from
services/platform, using GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
GOCACHE=/private/tmp/zasp-budget-go-cache:

```sh
/opt/homebrew/bin/go test -race ./apiserver -run '^TestSecurityAgent(ManualStart|ManualClaimBoundary|ManualMutationProvenance|ManualReadBinding|ManualReadPreservesNestedStrictness|ManualPlannerContextBinding|PostgresRepositoryRunsExactV24SessionTrigger|PostgresRepositoryRunsAndApprovesWithExactScopedAuthority|PublicHandlerQueuesExactTenantFindingRun|ExistingTestWriteUsesVersionedAuthority|ExistingTestReplayUsesVersionedAuthority|PostgresRepositoryReadsExactScopedRunsAndApprovals|PublicHandlerListsReadsAndCancelsTenantRuns|PublicHandlerApprovesWithFreshSeparateBrowserAuthority)$' -count=1 -v
```

Frozen SHA256 (paths below services/platform):

```text
f17627876dcc1db686d63e54faf354adbec7b96a604aa58a474ffdb47d65c15c apiserver/security_agent_manual_start.go
6e1f9f4e885b8eb79fe46ecddf35d97c49ae91c62702d9601f1afbbfefd25319 apiserver/security_agent_manual_start_test.go
28d7868bf457ff25d8454e1a078b5f5ca359ca8345192ae5c0c9196fbbaeb342 apiserver/security_agent_handler.go
31552ddd1a2cc4ee22a82b807aa1103f7b05e69f162e6c0adb83d9297e4d5b78 apiserver/security_agent_repository.go
```

Independent review accepted the bounded Go component with no actionable
findings and all four source hashes verified. The SQL helper is not implemented, manual SQL
projections are not complete, and OpenAPI/client/start-button contracts still
require explicit references. Thus this is not a functioning end-to-end manual
start or production acceptance. The UI was not changed in this batch. No push
or task reclassification.

## M7A-70 browser optional-reference component

The start form can now omit the evidence reference while simulation still
requires one. Its retained intent contains the exact request body. The real
API adapter accepts source-free responses only with manual version1 provenance
and empty evidence; explicit-source responses must retain the requested ID and
omit manual provenance. OpenAPI requires environment_id and makes the two
trigger fields mutually dependent. Generated types were regenerated locally.

The mounted browser-component test uses the real API client with controlled
HTTP responses, submits environment-only JSON, opens the returned run, and
renders its manual intent. A second case loses both the original and automatic
retry responses, then verifies explicit retry sends exactly the same body and
idempotency key while evidence edits remain disabled.

Behavioral RED10845 reproduced both the disabled no-reference start button and
the client's rejection of valid manual provenance. Earlier fixture missing
page_info and mismatched definition/activation versions were setup failures,
not production evidence. Retry RED65507 then exposed a real pre-existing bug:
the retry button disabled itself through its own retained-operation lock. The
button now permits its own retry while retaining other lock behavior. A prior
one-lost-response fixture recovered through the adapter's existing automatic
retry; it was corrected to lose both responses before testing explicit retry.

Final evidence:

- Session55632:188 tests across SecurityAgentsView.test.tsx,
  decoders.security-agent-manual.test.ts, decoders.security-agent.test.ts and
  workflows/api.test.ts passed in4.54s; no skipped cases in this affected batch.
- Session75687: tsc --noEmit exited0. ESLint for the two changed UI files and
  git diff --check exited0 on final bytes.
- OpenAPI lint passed both public and internal-health schemas;23 existing
  OpenAPI tests passed. Session51340:3 generator reproducibility tests passed.
- Cached Ajv2020 evaluated the actual manual request schema:10 semantic cases
  passed (source-free; finding/path/session; partial/null/manual-kind/unknown
  digest/missing environment refusals). No package or network request added.
- Session57091: Vinext built all five environments and dist/standalone, exit0.

Frozen SHA256:

```text
1169fefc4fee8421dd3873df321e501a581815792109bb16f2279defbbafc882 app/features/securityagents/SecurityAgentsView.tsx
665417ec5743b8221ac6dcc942338fc9b5aa64f8a01c3548dd0cf6a13abf3a3d app/features/securityagents/SecurityAgentsView.test.tsx
5d13108ea6ab90812540e3e3115d2461716a5d9b277aab5c1e775db5c19768b6 openapi/openapi.yaml
a67cfbf4ce711ce058bff474f15c977655e03a1ef3f8a9df749ad6dcc8032895 apps/web/api/generated.ts
```

Independent review accepted the bounded component with no actionable findings
and all four supplied hashes verified. Manual SQL admission/projections and a composed
mounted API/database/browser workflow are still absent. This controlled HTTP
test and build are component evidence, not live production proof. No task
reclassification or push.

## Registered accounting closure awaiting independent review

Root read [the accounting report](database/accounting-report.md) fully, verified
its SHA256112d31f55639b09d598f9c2619b17cceab828d02f99537a9a73f28939085f2cb,
the scoped patch d4776309df9ad4924bba679d5ea1bf259f6e4ec4161732437ccee3f46616012e,
all five product hashes, and reverse-patch applicability. Final candidate pin:
16d71c1f47360dc46b7fba40e0ab438d0f902a0a0683978c99cf8a88e4a42336.

Registered RED established missing/outstanding accounting bypass in export,
existing-test, Attack Lab, legacy and v33 accept/fail paths. The implemented
gate now has passing registered coverage across those families, including
zero-usage settlement, original receipt replay, identity mismatches, unknown
usage, no-provider terminal failure, private clone ACLs, existing planner
pipeline and exact release up/down/up. The main batch passed12of13groups with
35 clean owned PostgreSQL joins. The remaining stop fixture incorrectly tried
to inspect private receipts through worker authority; it correctly got42501.
Owner-only observation fixed that fixture, and only the five-family stop group
reran:35.78s, exit0, five clean joins. Product SQL/pin did not change. No skips.
Independent review accepted the bounded accounting component with no actionable
findings, verifying report/patch/product/log hashes and that the stop follow-up
changed only its fixture. This closes the missing/outstanding accounting gap at
this registered component pin. It does not repair historical unaccounted
receipts or prove new concurrent-settlement interleavings. Production acceptance
remains unproven.

## Manual admission registered RED

Root added security_agent_manual_admission_postgres_test.go. It applies actual
registered releases through58, seeds only activated definition/history,
membership/scopes and controls, and checks there are zero runs, trigger
receipts, request receipts and run audits before calling the deprivileged API.
Its specified assertions include atomic original manual provenance, unchanged
scheduled trigger configuration, original receipt replay despite fresh supplied
IDs, changed-version and foreign-scope refusal, revoked-requester refusal on
both replay/new intent, and distinct intent for a new key. Assertions after the
missing-function call have not executed and are not claimed as passing.

An initial fixture tried to update the protected global switch and correctly
failed42501 (session49286,4.69s), not behavioral RED. That write was removed;
the inherited fixture already configures global controls. Recompiled offline
Linux/arm64 binary /private/tmp/zasp-manual-admission.test exited0. Corrected
registered RED session80121 fails at the actual API call with42883:
public.zasp_sa_manual_run does not exist. Duration4.56s, container exit1;
owned pg_ctl/server Wait both exit0. Current test SHA256:
ae5d7dd6be70687d7a10ef69870fd0a0adc097d4824d4e3e769baa604684bc0c.

The run used the existing cached PostgreSQL digest with --pull=never,
--network none, --read-only, --user postgres, bounded CPU/memory/pids and owned
tmpfs. No external provider, image pull or host PostgreSQL was used. This RED
is the next implementation boundary, not a completed task or production proof.
