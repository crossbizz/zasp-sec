# P7 implementation progress — not accepted or production-enabled

The accepted P5/P6 components remain the basis for this batch. P7 is in progress;
the current source is not a complete enforcement deliverable and has not been
independently reviewed. No commit, push, deployment or shared reset occurred.

## Implemented checkpoints

- A current request authorizer consumes P6 CheckRevision, preserves the original
  PAT ceiling, rejects incomplete candidate enumeration, and supports a resource
  collection with no environment-wide allow.
- Explicit target-policy classification covers all160 operation IDs. This is
  manifest coverage, not evidence that every typed SQL resolver is implemented.
- The router can consume that authorizer in place of its old permission-array
  allow. Controlled deny, unavailable and revision-conflict tests prevent handler
  execution even when the old identity permission array contains view.
- JSONDatabase signatures remain unchanged. The production pgx driver has an
  additive Begin seam. Checked QueryJSON uses one transaction for the SQL fence
  and protected statement; stale proof rolls back before the statement executes.
- SQL80 has initial registered readiness, closed typed source resolution,
  revision lock, current membership/session/PAT row locks, ceiling/fresh-auth and
  target-version validation. A disposable installed PostgreSQL test passes a
  registered API role's current request and rejects its stale allow after actual
  session revocation. Repeated SQL80 installation succeeds.
- Risk list and count SQL80 reads place the allowed-key predicate before
  pagination or count. The installed finding fixture proves a denied first row
  does not consume a page slot, with correct authorized continuation and no stale
  version write. Other count/search families still need behavioral coverage.
- The final supported SQL80 predecessor is canonical61 plus registered79,
  independent of78. The full installed fixture verifies unchanged canonical61
  readiness after both extensions. Typed projection now uses inventory
  product_kind and required sensor/session/test/run/approval/recovery facts with
  source revision triggers. Audit append rows are not independently projected.
- Console session-* and validated native policy-* keys use the existing product
  canonical-ID derivation with exact organization/workspace/environment and a
  type-specific authorization prefix. SourceID retains the native key for SQL
  resolution, fencing and filters. Unknown kinds/IDs do not borrow environment
  permission. Native policy and hierarchy changes follow the last catalog GREEN
  and still require their affected installed checks.
- Parent-linked evidence requires every disclosed target's exact operation
  permission. The controlled two-parent case allows both-current targets and
  denies when only one is allowed; installed parent-link reads are in progress.

## Evidence so far

`go test ./apiserver -run '^TestP7AuthorizationRouterBoundary$' -count=1 -v`
was RED: deny, unavailable and conflict all called the handler with status200.
`TestP7AuthorizationTransactionBoundary` was RED: both cases used the direct
driver, bypassing the transaction fence. The grouped controlled boundary tests
then passed in0.937s. This does not attest installed production composition.

The first installed SQL80 check exposed a PL/pgSQL CASE-expression parse error;
the next exposed the row-share UPDATE privilege requirement on environments.
Both were corrected. `go test ./apiserver -run '^TestP7AuthorizationPostgres$'
-count=1 -v` then passed in2.821s (test1.89s), exercising the actual registered
principal, identity lock and rollback path. This precedes the subsequent risk
collection SQL additions and is not the final candidate verification.

Later installed/control terminal excerpts and exact commands are retained at
`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7/installed-checkpoints.txt`.
These include full61 GREEN9.203s, catalog RED9.614s/GREEN10.762s and the updated
controlled group GREEN0.934s. The early25+79+80 fixture is partial historical
evidence only; it is not a supported final installation precondition.

The full61 fixture first exposed a required discovery-principal registration
before52. It also demonstrated that the existing61 registered fingerprint is
owner-sensitive: default disposable zasp_test produced7c225146... and was refused;
the established zasp_e2e fixture produces the unchanged registered pin
`6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92`.
Only the owned fixture owner changed. Arbitrary/production migration owners are
not proved; deployed registered-owner and readiness verification remains a
release gate. No historical fingerprint, migration bytes or readiness check was
bypassed.

## Ownership and retained evidence

The immutable P5/P6 packets are unchanged. P7's starting bytes are captured in
`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7/baseline.json`.
Root released the five shared composition/database files and only the named
workflow list functions/constants; Temporal mutation, replay, worker andSQL78
paths remain excluded. No worker enforcement claim is made.

The accepted parallel search handoff is at `p7-search-filter/` in the same SDD
workspace. It includes its four-file baseline/diff and meaningful RED/GREEN;
those changes require the combined P7 review, not separate acceptance. The
unrelated two-file attack-lab vet repair likewise joins that review. The CLI
handoff is complete under `p7-authorization-cli/`: timestamp minor corrected,
eight actual executable calls, three reconciliation receipts, live FGA grant/
revoke and wrong-principal configure refusal. Its retained Temporal readiness
dependency remains explicit. The root verified both live source hashes.

The narrow organization identity model handoff is complete under
`p7-org-identity-model/`: nine changed/new source files, 25 new checker decisions
plus the existing93 checks, CLI DSL/JSON agreement and descriptor validation.
SQL80 supplies active human OrganizationRole; membership alone and machine
membership confer no organization identity-administration authority. No model
permission inherits from organization to descendants. Installed generation/
reprojection and production composition proof remain P7 work.

The session SQL fallback/detail lane is handed off under
`p7-session-authorization/`, using the fixed transaction-local allowed-key
contract. Its retained `green-bridge.log` is PASS15.832s (installed test15.02s):
console/runtime restricted pages, detail/events, source50 fields, explicit
unattributed access and four rollback drift gates. Root verified the five-file
candidate and two-file baseline hashes. All contributions join one P7 review.

## Registered predecessor compatibility checkpoint

Canonical61 intentionally leaves the old public readiness chain closed; only
its registered private predecessor chain understands61. SQL80 therefore owns
narrow new source41/50 and source52/56 read bridges, retaining literal release
pins, live registered61+79 readiness, and relevant owner/RLS/ACL/security checks.
Historical public functions, guards and fingerprints are unchanged. Readiness
does not grant product access.

Raw command, source hashes, terminal output, exit status and owned PostgreSQL
teardown are now retained by `p7/run-check.mjs`. The earlier
`installed-checkpoints.txt` remains explicitly excerpt-only. Subsequent evidence:

- `p7/parent-bridge-check.log`: RED audit clone guard found two readiness calls,
  not one. The exact-count guard was corrected against the installed source.
- `p7/parent-bridge-check2.log`: full installation and restricted native policy
  page passed; actual compliance constructor rejected the old public readiness
  path. Missing each of the three compliance permissions was independently denied.
- `p7/parent-constructor-check.log` and `.source.json`: PASS15.574s, installed
  test14.61s. Explicit enforced database mode uses fixed metadata queries for
  registered80 schema/source readiness, constructs the real compliance repository,
  denies a proofless query, and permits only the checked evidence page/detail.
  Native policy SourceID and pre-pagination restriction are exercised too.

The compatibility shape marker remains the existing API schema string; it is
returned only after current registered80 readiness succeeds, not as an installed
migration-number assertion. The source56 bridge retains its configuration-owner
and worker/security checks. Full production composition and the other source
families are still pending, as are installed parent mutation races and export
parity. No fixture-only repository bypass is used for this constructor evidence.

Further affected boundary evidence is retained in the same `p7/` directory:

- `csrf-red.log` reproduced a candidate80 gap: changing the current session's
  CSRF token after Check still allowed the evidence read. The proof now carries
  a CSRF hash and the transaction compares it with the locked current credential.
- `metadata-red.log` reproduced missing separate environment-view capability.
  `csrf-metadata-green.log` is PASS17.068s: resource-only session grants remain
  usable, while scope-wide metadata needs a separate environment view Check,
  PAT ceiling intersection and the same revision. The environment version joins
  the fence targets, never the session Allowed list.
- `hierarchy-red.log` was fixture setup only (duplicate environment names), not
  meaningful behavior evidence. Corrected `hierarchy-red2.log` showed the real
  foreign-workspace collection resolver returning no allowed environments.
  `hierarchy-green.log` is PASS16.798s: three actual environments in another
  workspace, first denied and next two allowed, resolve to their real ancestry
  and return only the allowed two before the one-item page's lookahead limit.
  Existing effective-scope admission is preserved. This is that exact scoped
  assertion, not complete hierarchy/UI/cursor coverage.

The additional `p7-session-search/` handoff is root-verified: four live paths,
one baseline, complete report and raw `green-installed.log` PASS21.128s. It covers
v1/source50 SQL hydration, exact native session keys, pre-aggregation provider
restriction, denied/empty metadata omission, separate environment-view metadata,
and a permission/revision change between index lookup and SQL hydration. Old
proof reuse fails; a fresh Check succeeds. The index is a controlled application
adapter, not evidence from a deployed OpenSearch cluster.

`repository-composition-final.log` and `.source.json` are PASS15.275s, with the
installed test14.22s. All14 real repository constructors pass on registered core
and security-agent API principals. Wrong compiled pins, wrong API principal,
arbitrary proofless SQL and an invalid present Temporal74 are refused. Earlier
`repository-driver-trace.log` identified a PostgreSQL generic-plan ACL issue:
a CASE expression naming both principal functions required both EXECUTE ACLs.
Two fixed role-specific metadata statements avoid that issue without granting
new privileges. The closed metadata adapter admits exact compiled statements
and arguments only; it grants no product capability. These constructor checks
remain distinct from actual supported operations and full runtime composition.

`cursor-red.log` reproduced changed-revision cursor reuse through the actual
administration and audit-export HTTP handlers. `compliance-cursor-red.log`
reproduced unsigned cursor acceptance with a current authorization proof.
`cursor-group-final.log` is PASS1.353s, covering those actual handlers and
compliance HTTP roundtrips. Same-proof cursors work; revision, generation,
credential and PAT-ceiling changes reject the signed compliance cursor.
Missing signing configuration fails closed for enforcing compliance handlers.
The existing workflow server key is passed by production composition, with no
new secret or client-derived signing key. Legacy non-enforcing fixture behavior
is retained. The broader affected run `cursor-group-green.log` also ran legacy
PostgreSQL grant/read-classification checks successfully, but found a date-literal
portability defect in the legacy freshness fixture (08:00Z versus intended00:00Z).
The controller approved explicit UTC for its two seed statements; the original
file and scoped diff are retained under `p7/timezone-fixture/`. No production
timezone or global PostgreSQL setting changes were made.
`cursor-timezone-final.log` and `.source.json` pass16.090s; the corrected actual
PostgreSQL freshness fixture passes14.96s, including its unchanged exact UTC
deadline assertion, and normal owned database teardown is recorded.

The controller approved a narrow sensor administration-event policy: all four
sensor.create/update/delete/token.rotate events use their own immutable mutation
receipt's recorded environment as event authority. SQL validates exact actor,
scope, sensor target, timestamp, deterministic event ID and sensor version before
resolving that environment. Delete also requires the retained deleted result.
Current view_audit (and the compliance permission intersection when applicable)
still applies. This declared event policy is stable after deletion, gives no
sensor product access, and never falls back from a denied sensor Check. The
sensor owner's installed baseline captured four expected public events missing
before the mapping. The owner reports its final installed group PASS44.297s;
its frozen `p7-sensor-authorization` packet was read and its five current plus
two baseline hashes verified by the controller. Audit export parity remains
pending in this lane.

Actual API construction now requires enabled runtime clients, current80 database
mode on both API principals and an injected request authorizer. It connects the
existing clients before constructing repositories, uses the reviewed P6 reader
and official SDK checker, and retains the Temporal readiness dependency.
`production-enforcement-red.log` reproduced enabled composition accepting absent
enforcement dependencies; `production-enforcement-green.log` passes1.206s.
`production-router-final.log` passes1.081s with the actual composition and four
mounted route families (core sensor, audit export, compliance, agent export):
current denial/unavailability/conflict produce403/503/409 even with no legacy
permission array. SQL and the authorizer are controlled in this test. This is
not a valid-installed80/live-FGA startup proof, and not a permission proof for
all product operations. Disabled compose helpers remain explicit non-enforcing
fixtures; the actual buildRuntimeDependencies path rejects disabled clients.

Concrete implementation gaps still owned by the P7 API lane:

- `inventory_repository.go`: relationship/session disclosure, home aggregates,
  and ownership mutation; the current inventory list is only one part of this.
- Risk detail and consequential finding/ticket mutations need actual installed
  operation evidence, including provider-return fences.
- Workflow/policy/integration/discovery admission, all typed detail/collection
  statements, stored group scopes and identity/PAT administration still need
  their current-proof SQL adapters. Existing mappings alone are insufficient.
- Bootstrap/capability and scope-switch reads must compute current decisions;
  permission-free credential lifecycle requires an exact separate SQL allowlist.
- Source-restricted export capture/manifests and post-artifact download fences
  remain open for audit, compliance and agent exports.
- The complete closed operation-to-statement/argument classifier, production
  installed80 plus live FGA construction, generation/reprojection proof and
  operation-wide integration coverage are not yet complete.

The controller owns the Temporal join: actual worker forward-effect checks and
SQL commit fences, retained compensation, plus the newly delivered78 approval
and run-context paths. Recovery's four public API operations are proposed as
the next disjoint slice after the sensor handoff; no recovery worker ownership
has been transferred to this lane. The recovery slice has since joined as
`p7-recovery-authorization`: controller-verified five current and two baseline
hashes, raw PASS21.246s (installed19.85s). The four API operations retain native27
receipts, audit and outbox, with exact-object sibling denial, current credential,
revision, freshness, PAT, rollback and source27/61/ACL drift cases. Its native
audit-to-public-export mapping remains a parent integration gate.

The actual production handler constructor is now exercised with registered
current80 API principals, the official FGA SDK and an owned model/store.
`p7/live-production-handlers.log` plus `.source.json` records PASS15.704s
(installed14.64s) through NewProductionHandlersWithSecurityAgent, NewComposition
and actual database authentication. Sensor HTTP200, empty legacy permission
arrays, org identity-role allow without sibling-environment view, old proof
conflict after role change, pending/reconcile denial, model generation
reprojection and credential-revoked HTTP401 are asserted. Owned store
01M3AX3PCQQ124W5MJF2WXXMNB and model generations
01M3AX3PD4JYSQRZ2MS379V65F / 01M3AX3SFGWZ45A67P2WHW3G6V are test-only; no
runtime pin was changed. Earlier diagnostic logs `live-model-installed*` are
retained, including the invalid active-sensor fixture corrected with a native
issued token. This does not prove full buildRuntimeDependencies with external
providers, all160 operations, or worker enforcement.

Home summary is the current grouped feature. The approved restricted wire
contract is required healthy:null and attention_required:null together, with
authorized-resource counts. Full status needs a separate current environment
view Check, PAT ceiling and revision fence. UI/schema work is controller-owned
in a separate slice; backend and UI verification must join before accepting
the new nullable wire shape.

### Home isolation and signed decision boundary checkpoint

`p7/home-red.log` reproduced a resource-only grant leaking two failed runs where
only one was authorized, with full-environment health booleans. The initial
subtest helper called its parent Fatal; later cases in that first log are not
evidence. Helpers now receive each subtest's testing.T. Paired-null strict decode
passed before the installed positive path did. Diagnostic failures remain under
`home-green1`, `home-diagnostic`, `home-attestation-check` and
`home-source-diagnostic`, each with normal owned PostgreSQL teardown.

The canonical source9 risk tables have no RLS; source10's legacy API loop grants
raw CRUD. Source14 expressly grants the existing nonlogin discovery authority
CRUD on all seven risk tables. This is a source contract gap, not fixture drift.
The approved additive80 correction enables/forces RLS on findings, finding
evidence/factors, attack paths, path nodes/evidence and break options. It preserves
their registered predecessor owner and ACLs, adds exact typed/native allowed-row
SELECT policy for API roles, and preserves guarded source function/projection
access through the existing nonlogin authority. There is no API write policy or
new role membership.80 fingerprints the seven tables and all their policies.

`risk-isolation-red2.log` captured three actual raw API failures: no-proof SELECT
returned three selected/foreign rows, a caller-set GUC did the same, and the API
could call fence with an invented allowed target. A SQL-only context seal cannot
prove an OpenFGA Check. The approved fix purpose-derives an HMAC key from the
existing server WorkflowSigningKey, attests only after all official Check calls
and the final revision read, and registers the verifier under the migration
principal in private forced-RLS80 storage. API SQL principals cannot read or
register that key. Exact signed bytes include scope, principal/credential/PAT,
operation, model/store/revision/generation, targets, permissions, key version and
a60-second lifetime. SQL checks the HMAC before parsing those bytes into the
authoritative proof; duplicate, oversized, parallel unsigned or malformed input
fails closed. Key versions are deterministic SHA256 identifiers of the derived
key; rotation touches organization revisions and never falls back to an old key.
Actual production construction checks both database principals have the matching
registered key. No deployed key or server configuration was changed.

Each SQL fence still rechecks current identity, revision and target versions.
It creates a separate session/transaction-bound context seal. A narrow decision
may be reused during its short lifetime for another legitimate fenced read;
copied database context cannot cross transactions. The raw SQL role still has
the trusted application's narrow signed decision, not an independently computed
SQL permission policy. Official OpenFGA remains the permission authority.

Home's first stricter guard also exposed source14's whole-package requirement
for exactly24 zasp_inventory_* functions. Source29 adds retained versioned home
functions, so that old guard is not valid on registered61. The80 replacement
retains original public guards, checks exact29 stored identities plus61/79/80,
the live cutover-table/scope-state owner/RLS/ACL, the original risk-authority CRUD
ACL contract, the three home tables' forced RLS and authority, and the original
home functions' owner/security-definer/search path/public ACL.80 fingerprints
the three original home source functions as well. This does not alter historical
source bytes or fingerprints.

`home-attestation-green2.log` passes26.191s (installed25.29s): restricted/empty
run counts with paired-null health, separate environment Check for full status,
current revision refusal, strict wire cases, three raw API refusals and the
transaction boundary. `risk-attestation-affected.log` passes20.454s
(installed19.12s): registered API exact authorized native rows across all seven
risk tables, hidden/foreign exclusion, raw write denial, copied-context refusal,
legitimate repeated narrow decision, tampered permission/version/MAC/unsigned
fields/duplicate fields/expiry/future/model/scope refusal, verifier isolation,
and six rollback owner/ACL/RLS/permissive-policy drift denials. These use a
controlled Check and signer, not live FGA.

An extra within-transaction expiry test reproduced disclosure after the signed
deadline in `context-expiry-red.log` (15.824s). Context validation now checks the
deadline too. `signed-session-expiry-green.log` passes45.848s: home28.68s and
sessions16.02s, with native seven-table reads, expiry during a transaction,
copied-seal refusal, API assume-role refusal, source security drift and the
restricted/full home cases. Sessions now obtain a fresh empty Check decision;
the prior test's direct modification of an already signed grant correctly
failed. Separate tamper assertions preserve kind/scope/native-key and emptied
allow-list refusal. No signed grant is edited to simulate legitimate denial.

`attestation-api-regressions.log` is a mixed result, not a green group:
live official OpenFGA13.39s, recovery15.36s, sensor44.71s and search23.81s pass;
only the now-corrected session fixture failed. The live test includes actual
production handlers, registered SQL, signed decisions, model-generation
reprojection and expected credential-revoked HTTP401. Owned FGA store
01M3AZ7C48TYYAHZPGAFBAT07E and model generations
01M3AZ7C559ZRWRA2P074P25HD / 01M3AZ7F0WAGV3VT43R9ME42GW are disposable
test evidence, not runtime pin changes.

Actual registered projection caller preservation is still pending. Retained
`risk-projection-compatibility`, `risk-projection-registered61`, and
`risk-projection-owner61` failures occurred in fixture/predecessor admission,
before writer assertions. The projection-only test now targets the native
source13 `zasp_execution_apply_risk_projection` boundary under registered61,
with an actual registered login; it does not need automatic-source77. Its first
build in `risk-projection-native61.log` was interrupted by concurrent finding
test helpers being added. No historical pin or principal guard was relaxed.

The go downloads in `home-red.log` were cache activity from ordinary go test.
This P7 lane did not edit go.mod/go.sum or invoke version changes. Their earlier
SDK/Temporal overlay remains; current hashes are
0d2451facec3bf6371d8ad6485b265dadb1d4d3c9dd025344af42684dfe48a7a and
5c97e3211711a2b9bc3854b336aeb993584afa60dfd84b1b7fd29e6d6c69cc4f.
Later retained runner checkpoints include both files and the inventory/runtime
composition files; earlier checkpoints are not retrospectively widened.

## Remaining completion gates

### Closed statement binding checkpoint, still in progress

The adapter now has an explicit operation/statement/argument contract. An
unknown query cannot use a valid signed decision as general SQL authority.
`statement-binding-red.log` reproduced ten controlled effects from wrong SQL,
operation, scope, native ID, actor or argument arity. The first focused
`statement-binding-green.log` passes1.061s. This is adapter evidence only.

The160-row `p7-operation-coverage.md` distinguishes registry entries from
admitted statements and working endpoints. At this checkpoint32 operation
names have statement rules. Unsupported operations refuse and remain incomplete;
that refusal is not P7 delivery. Collection selectors, remaining families and
exact credential lifecycle paths still need their own working contracts.

`statement-affected-installed.log` is mixed102.120s: sensor44.17s and
search20.80s pass. Recovery/session positives worked, but prior negative tests
expected the later SQL denial and saw the new earlier adapter refusal. Those
tests now keep both checks: pre-SQL ErrAuthorizationDenied and direct signed
fence plus native SQL sibling/kind denial. `statement-denials-native.log` passes
39.661s: recovery14.97s, native projection8.76s, sessions14.78s. Mounted session
hidden/missing404 preservation is a separate current check; no external status
change is accepted merely because an internal refusal became earlier.

That mounted check now passes in `p7/session-http-mounted-green.log`, package
11.435s, installed10.59s. It mounts the real session handler/router/current
authorizer against canonical61+79+80 with a controlled checker: visible detail200,
hidden/missing detail404, hidden event page404, and missing event404. Only these
three session resource operations map a denied or absent target to not-found;
PAT-ceiling and collection admission still deny403 before reads. The earlier
`session-http-hidden-green.log` is unit-only1.155s because its combined slash
regex did not select the installed subtest. No installed evidence is attributed
to that first command. `session-http-hidden-red.log` retains the meaningful
earlier403-vs404 failure.

Hierarchy request selection now has a signed `workspace_selector` separate
from the selected environment and allowed targets. `hierarchy-statement-red.log`
fails0.901s for both legitimate empty-list statements; the grouped
`hierarchy-statement-green.log` passes1.084s with exact operation/organization/
actor/workspace binding, sibling denial and signed-selector tampering refusal.
Installed `hierarchy-mounted-red2.log` fails10.925s because the old handler
returned404 for an authorized requested workspace different from the selected
one. Empty-page/native sibling/current-revision cases already passed. The handler
now accepts that request only with the exact private current signed selector;
legacy unproved requests retain the old check. `hierarchy-mounted-green.log`
passes21.806s: mounted hierarchy10.10s including pre-limit denial, legitimate
empty page, pre-SQL and native42501 sibling refusal, and changed-revision refusal;
the same command rechecks mounted session40410.73s after the signed proof shape
change. Its first new fixture run failed on duplicate seeded workspace names
before assertions, not product behavior. Data-controls ownership and source7 pins are in
`p7-data-controls-brief.md`; that disjoint batch includes the discovered raw API
table-isolation gap, not just wrapper admission. Hierarchy create seed callers
remain an explicit compatibility gate.

`parent-selector-red.log` fails1.186s because the adapter accepted a changed
event ID under the same session and a changed evidence selector under a checked
parent. The grant now copies and signs route parameters; exact event/evidence
statement arguments must match. `parent-selector-green.log` passes1.137s and
`workflow-selector-green.log` passes1.765s with route-map copy/private-map tamper
checks and exact workflow kind binding. These are controlled adapter checks.
The existing policy page's native SourceID mapping remains unchanged; a rule for
a generic security-agent page does not prove its production override works.

`session-native-operation-red.log` fails11.396s: actual registered API SQL can
reuse a valid `listSessions` proof on console/runtime detail functions for an
already-allowed session. Both operations use `investigate_sessions`; this is an
exact-operation binding failure, not evidence of a cross-permission or foreign
session disclosure. Native clone constraints now bind the exact operation and
signed route IDs. `p7/native-read-selector-green2.log` passes34.163s: the installed
enforcement group15.86s and session group17.25s cover native list-to-detail
refusal, exact event selectors, mounted404, filtered console/runtime pages,
source50 fields, and source/ACL/RLS/61 drift. The first green attempt failed at
installation on a new PL/pgSQL CASE-expression syntax error and rolled back;
it is retained as `native-read-selector-green.log`, not passing evidence.
Unknown SQL stays refused by the application adapter.

Data-controls local implementation is frozen in `p7-data-controls/report.md`.
`p7/data-controls-green-5.log` passes15.954s with eight installed subtests and
routing checks. Source7 table ACL/owner are retained, with additive forced RLS
and a registered migration-owner policy. Only the two checked, audited wrappers
retain that owner; the API cannot assume it. Real API raw CRUD and foreign or
proofless access refuse. The exclusively owned fixture uses a separate bootstrap
administrator so its registered migration login can be demoted to NOSUPERUSER
NOBYPASSRLS during mounted reads/updates, owner seeding and source56 helper checks.
Committed role flags are restored and verified before normal cluster teardown.
Earlier bootstrap-owner demotion failures are fixture-construction evidence,
not product failures. Existing hierarchy-create seed callers remain unsupported
and require checked wrappers; this compatibility gate has not been waived.

## Bounded foundation review checkpoint

The human/API foundation is being frozen for independent review while P7 remains
in progress. `p7-operation-coverage.md` distinguishes admitted statements from
working endpoints. The final affected source checkpoint is
`p7/native-read-selector-green2.source.json`; no product edits followed that run
before the foundation snapshot. Earlier feature groups are not an aggregate
all-green suite against this final source, and earlier live FGA/production
composition proofs predate some later classifier changes. The packet includes
their exact source checkpoints and failures without promoting them to current
full-production acceptance.

`p7-worker-authority-contract.md` is proposed integration, not implemented
machine authorization. Root approved distinct worker and compensation key
inputs with purpose-separated derivation and restricted per-purpose verifier
registration, exact disclosure/effect/control permissions, and a separate
explicit worker profile after combined-lineage proof. Base API80 stays valid
on61+79; absent78 is not worker support. No real secret provisioning is authorized.
The worker profile, credential lifecycle, unsupported operations, export effect
boundaries, hierarchy creates, full current production composition and release
gates remain open. Source/UI environment creation currently exposes name only;
the original production/staging/development class-selection gap is separately
tracked and is not included in the bounded hierarchy-create continuation.

The projection test proves additive risk RLS compatibility only. It connects
as the actual registered projection login, calls the unchanged source14
replacement for `zasp_execution_apply_risk_projection`, observes a new scoped
finding/path and exact replay, and verifies raw table access is denied for the
worker and the existing security-agent API role. The fixture already owns one
attack path; the new projection makes two, with one new finding. The source
function hash is identical before/after80. Registered principal readiness is
true and old source13 readiness false on both sides. Source13's marker/current
fingerprint/no-version-after13 guard and the constructor's legacy readiness
enumeration do not support canonical61 alone; intended Temporal72 retained
profile composition and P7 forward-effect authorization remain open.

`home-cutover-scope-ready.log` passes23.094s: installed cutover permits the
restricted summary, equivalent phase refuses, restored cutover permits it
again. `raw-legacy-risk-authority.log` passes10.548s: direct registered API
invocation of the historical risk mutation is rejected by its closed release
guard with55000, before effects. This61-only result does not establish the
same property on the future combined Temporal77/78 profile. No source policy
or historical fingerprint was relaxed to obtain either result.

Complete typed resource/projection facts (including session, export and hierarchy
semantics); installed collection/search/count/export parity; production
composition without fallback; capability and scope-switch results; current
identity/version/revision races on actual product mutations; cursor revision
binding; real FGA-connected evidence; controller-owned worker forward effects
and retained compensation; operation-wide integration coverage; migration CLI
dispatch; scoped vet and a frozen complete review packet. No item above replaces
these P7 gates or later UI/release gates.
