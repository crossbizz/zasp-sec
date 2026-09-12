# Sandbox database work in progress

Uncommitted and unpushed draft after local checkpoint `2c5de32e`. No new M3
task credit, production activation or complete release claim. The authoritative
counts remain 536 production-available, 131 component-only and 61 external.

The draft migration50 adds a nullable semantic sandbox column. Historical null
means the value wasn't retained. It doesn't backfill old observations or alter
the released v2 freeze function. The new v3 freeze derives its source from
admitted enrollment authority and its sandbox from the digest-bound archive.
It emits snapshot-v2, refuses old snapshot-v1 replay and retains unknown
observations alongside known bindings. SQL text validation now matches Go's
Unicode whitespace boundary and byte-length limit.

Actual PostgreSQL tests exercise the real closed repository decoder and v3
matcher after SQL admission. They cover known-plus-unknown ambiguity, distinct
source namespaces, conflicting sandboxes for one agent/session, exact frozen
replay after late admission, old-v2 backlog compatibility, private table denial,
immutable observations and atomic rollback on malformed/overflowing input.
These tests explicitly seed committed archive/index authority rows. They are
not authenticated ingestion, live provider or cloud deployment proofs.

Separate v3 claims retain the predecessor's locking and fairness rules. Old
public entrypoints and their private helper remain v1-only or v1/v2-only. The
new helper can drain v1/v2/v3 and declares v3 compatibility while mutating work.
The expanded trigger permits v2 under a v2/v3 marker and v3 only under v3, with
the same registered principal requirement. This marker isn't binary attestation.
The original claim helper's SQL and old snapshot serialization stay unchanged.

The draft has a pinned50 readiness function and a49 compatibility wrapper.
Review found that freeze lacked the new readiness check despite claims using
it. Direct admission/replay regressions reproduced that gap in all six cases.
The fix checks readiness before execution and again before either return, after
the last blocking operation and live execution check. A separate lock-wait test
changes readiness while admission waits on an enrolled sensor row.

The follow-on draft implements transactional runner Up/Down50 and Version50
recognition. Rollback takes the full NOWAIT lock set and checks pinned readiness
before any removal. It refuses non-v1/v2 correlate work, nonnull sandbox values,
and any snapshot schema other than v1. These evidence checks have independent
fixtures with no v3 work, without disabling constraints or immutable triggers.
Historical v2 work, null observations and exact snapshot-v1 bytes survive.
Rollback restores the original49 fingerprint and permits a subsequent install.

The investigate workflow found a reinstall defect in the initial reversal:
PostgreSQL retains a dropped attribute slot, so sandbox_id moves from physical
position22 to23. Schema50 now fingerprints only that new column by its live
ordinal, keeping every predecessor column's physical position unchanged. The
changed fingerprint function's body is explicitly pinned in50, and Down restores
its exact prior definition. No catalog writes or evidence-table rebuilds are used.
The new semantic pin is
`abe9048ab228d0de447fdeba68679f9bc43c0fc1e47efbe60b25c588ded21f09`.

## Worker pre-stage draft

The v3 executor now dispatches each claimed version without mutating shared
configuration. It keeps candidate authority when draining v2, leaves v1 receipt
bytes unchanged, and runs the sandbox matcher only for v3. V3 execution requires
the authorized lease path, rejects snapshot-v1, and checks cancellation/lease
validity after freeze and around graph/receipt effects. Production configuration
and the database-backed executor factory now accept this explicit capability.

The new reader checks compiled50 readiness before every poll. Only SQLSTATE42883
on that check can try independently pinned49; it never falls back to48. A failed
claim never downgrades. Returned leases must fit the negotiated entrypoint.
An actual PostgreSQL test uses the same repository before/after49-to50 upgrade,
settles its first v2 attempt with the real retryable finish path, claims v3, then
removes50 readiness and verifies both readiness/poll fail without changing work.
The first fixture left a tenant's v2 lease live and incorrectly expected another
claim; the existing tenant concurrency guard correctly rejected that expectation.
The fixture fix did not weaken the guard.

Worker tests exercise real receipt encoding for Exact semantic, Strong inferred
and Probable ambiguous results. Distinct sandboxes for the same agent/session
clear every identity field on the Probable receipt. Historical v1/v2 receipts
remain byte-equal under the upgraded executor. Database replies and graph/object
storage in these worker unit tests are explicit boundary doubles, not live
provider evidence. The separate PostgreSQL reader proof is real database work,
but not a complete composed v3 ingestion-to-browser proof.

The CLI now has explicit `up-to-49` pre-stage targeting and principal registration
classification. Default `up` still targets49, and the CLI does not activate50 yet.
Downstream projection still rejects v3 receipts. No deployment or producer
activation is authorized by these partial changes.

## Projection contract draft

`ProjectSandbox` now retains sandbox/source on projected items and binds them
into version2 effect hashes and risk IDs. Receipt schema2 is restricted to
`runtime-projection-v2`. Exact requires a known complete binding; Strong may
retain an unknown historical binding; Probable/Unattributed cannot carry any
identity fields. UTF8, byte bounds, whitespace and partial bindings are checked.
The historical Project entrypoint now rejects sandbox fields it used to discard,
and receipt encoding rejects unknown implementation versions.

The old projection receipt was captured before these changes. Its pinned effect
is `056ae915931b47d0698539ad3fd6a649a425b92c6e5b92305438a9ef7b248c9e`
and receipt SHA256 is
`e9412869f845f846df23631a70bb8f42a1a4df70db2a691791a7352d13cc43bb`.
Both remain unchanged. The new receipt rejects sandbox fields onv1 even when
an attacker recomputes the old digest. No worker, database or browser completion
claim follows from this pure contract.

## Recorded runs

- `/tmp/zasp-sandbox-sql-red.log`: new SQL entrypoint absent before implementation.
- `/tmp/zasp-sandbox-sql-history.log`: retained binding and old history tests pass.
- `/tmp/zasp-sandbox-sql-whitespace-red.log`: trailing tab and leading NBSP were
  incorrectly accepted by SQL. The matching green run rejects both.
- `/tmp/zasp-sandbox-sql-security-races.log`: new-entrypoint malformed-input,
  principal/scope/lease/delivery/enrollment, namespace and atomicity tests pass.
- `/tmp/zasp-sandbox-sql-overflow.log`: 500 admitted observations remain intact;
  the next 501-observation admission fails with SQLSTATE54000 and no residue.
- `/tmp/zasp-sandbox-sql-boundaries.log`: 256-byte multibyte text and allowed
  internal whitespace retain exact bytes through the database/Go decoder.
- `/tmp/zasp-sandbox-routing-red.log`: old workers reject the unfinished50
  readiness boundary before its implementation.
- `/tmp/zasp-sandbox-routing-races.log`: pending, retryable, expired, exhausted
  and final-attempt100 cases pass. Both old entrypoints leave v3 work untouched;
  the v3 reader claims or exhausts it. Six readiness drift checks pass.
- `/tmp/zasp-sandbox-sql-final-races.log`: broad old/new PostgreSQL selection
  passed in135.204s before the final freeze-readiness fix.
- `/tmp/zasp-sandbox-freeze-readiness-red.log`: all six admission/replay cases
  accepted work after missing fingerprint, checksum drift or future schema.
- `/tmp/zasp-sandbox-final-readiness-races.log`: final new sandbox suite passed
  in83.458s after the fix, including readiness drift during an actual database
  lock wait. All six direct admission/replay drift regressions pass.
- `/tmp/zasp-sandbox-sql-ui-build.log`: standalone production UI build passes.
- `/tmp/zasp-sandbox-sql-contract-races.log`: runtimeevent, runtimecorrelation,
  runtimeprojection and migrations race suites pass.
- `/tmp/zasp-sandbox-post-refactor-legacy.log`: the historical candidate
  replay/lease/enrollment/overflow suite passed again in8.238s after the shared
  test helper gained an explicit SQL-entrypoint parameter.
- `/tmp/zasp-sandbox-sql-verify.log` and
  `/tmp/zasp-sandbox-sql-source-gate.log`: FAILED. The staging contract expects
  chart schema49 to equal the latest embedded migration50. This is an unfinished
  rollout gate, not permission to activate an incompatible chart.
- `/tmp/zasp-sandbox-rollback-red.log`: safe historical rollback failed against
  the unconditional refusal stub. Drift/evidence denial tests passed the stub.
- `/tmp/zasp-sandbox-reinstall-diagnostic.log`: the first reversal restored49
  but reinstall failed its pin; catalog diagnostics showed dropped position22
  and new sandbox position23. The regression drove the ordinal fix.
- `/tmp/zasp-sandbox-runner-version-red.log`: Version rejected installed50.
  Exact50 and tampered49/50 cases now exercise version recognition.
- `/tmp/zasp-sandbox-rollback-full-races.log`: all sandbox PostgreSQL tests
  passed in116.915s, including round trip, independent evidence guards and
  twelve actual runner lock-contention cases across Up/Down and six tables.
- `/tmp/zasp-sandbox-rollback-runner-final.log`: final rollback/runner tests
  passed in35.626s after adding actual runner denial atomicity and both release
  checksum-tampering cases. Early fixture runs failed a foreign key because the
  independent snapshot fixture used the wrong batch generation; fixing that
  fixture preserved all database constraints.
- `/tmp/zasp-sandbox-rollback-contract-fresh.log`: uncached race tests passed
  for migrations, runtimeevent, runtimecorrelation and runtimeprojection.
- `/tmp/zasp-sandbox-rollback-ui-build.log`: fresh standalone UI build passed.
- `/tmp/zasp-sandbox-rollback-verify.log`: full verification still FAILED at
  staging gate49 versus50 after the UI tests, typecheck, lint and import checks.
  The rollout contract remains unfinished. No push followed.
- `/tmp/zasp-sandbox-worker-red.log`: v3 executor configuration rejected all
  three compatible job versions before implementation.
- `/tmp/zasp-sandbox-composition-red.log`: the production factory/composition
  rejected v3 before database factory and release negotiation wiring.
- `/tmp/zasp-sandbox-reader-worker-final.log`: reader/worker race selection
  passed, including cancellation and malformed/denied/missing release cases.
- `/tmp/zasp-sandbox-worker-inferred.log`: Strong and Probable runtime worker
  receipt cases passed with a nonempty qualified candidate snapshot.
- `/tmp/zasp-sandbox-reader-postgres-final.log`: actual49-to50 reader negotiation,
  version-bound retryable completion, v3 claim and missing50 refusal passed
  in5.993s after correcting the active-tenant-lease fixture.
- `/tmp/zasp-sandbox-worker-full-races.log`: uncached full worker, runtimeevent,
  runtimecorrelation, runtimeprojection and migrations race packages passed.
- `/tmp/zasp-sandbox-cli-prestage-red.log`: `up-to-49` was an invalid command
  before the explicit pre-stage command was registered.
- `/tmp/zasp-sandbox-cli-prestage-green.log`: full migration CLI race suite
  passed in91.979s, including pre-stage targeting and forward registration.
- `/tmp/zasp-sandbox-reader-all-postgres.log`: all sandbox PostgreSQL race tests
  passed in154.393s with the new same-reader upgrade/missing-authority proof.
- `/tmp/zasp-sandbox-worker-ui-build.log`: fresh standalone UI build passed.
- `/tmp/zasp-sandbox-worker-verify.log`: full verification still FAILED only
  after reaching staging chart49 versus embedded50. No publication followed.
- `/tmp/zasp-sandbox-projection-legacy-red.log`: captured the old receipt and
  reproduced silent sandbox-field loss in Project.
- `/tmp/zasp-sandbox-projection-interface-red.log`: compile failure while the
  new entrypoint/data members were absent, not a behavioral assertion.
- `/tmp/zasp-sandbox-projection-contract-red.log`: with declarations present,
  new projection behavior failed against the rejecting stub.
- `/tmp/zasp-sandbox-projection-version-red.log`: also reproduced acceptance
  of an unknown implementation version by the old receipt encoder.
- `/tmp/zasp-sandbox-projection-validation.log`: projection/correlation races
  passed, including confidence/identity, Unicode/size, canonical wire tampering
  and old-version laundering regressions.
- `/tmp/zasp-sandbox-projection-full-races.log`: uncached full projection,
  correlation, runtimeevent, worker and migrations race packages passed.
- `/tmp/zasp-sandbox-projection-ui-build.log`: fresh standalone UI build passed.
- `/tmp/zasp-sandbox-projection-verify.log`: full verification still FAILED at
  the known unfinished chart49/embedded50 rollout gate.

Superpowers is unavailable as an installed skill. The main agent read its
official upstream test-first, verification and requesting-code-review workflows
and required references. Independent read-only review found the missing freeze
gate and required new-entrypoint security tests. Final review confirmed the fix
and approved a local draft checkpoint only. No publication approval follows
from the partial draft.

The new SQL reversal, reinstall and Version regressions have recorded behavioral
RED runs. Runner transaction/lock tests were added after the runner methods, so
they are verification coverage, not claimed as a strict test-first sequence.
Independent review of the rollback/ordinal/runner code found no concrete defect;
its initial response withheld test approval while the race run was pending.
Follow-up review read the completed full/final/uncached logs and approved only
the local draft, including the final runner denial and version-tampering tests.
The next independent review found the live-tenant-lease test defect described
above. After its correction and the Strong/Probable receipt tests, review found
no production worker/routing defect and approved continuation of the local
draft. Full CLI and final all-sandbox PostgreSQL results were still pending at
that review; their completed logs are recorded above, not attributed to it.
The investigate learning helper failed because its installation lacks
`lib/jsonl-store.ts`; this document retains the root cause and verification.

## Projection worker consumer checkpoint

The local projection-v2 executor consumes only a bound correlation-v3 receipt.
Configured v2 workers can drain v1 projection leases using the unchanged legacy
contract. The versioned lease, predecessor effect, scope, batch and generation
must agree; v2 requires authorized execution and a live lease. Cancellation or
lease loss after graph or receipt writes cannot return a completion effect.

The composed fixture executes the actual correlation worker, then projection
through the stage processor. Its first green attempt failed because the
correlation-only artifact stub's fixed URI didn't match its actual receipt
locator. The fixture now uses that real locator, without loosening validation.
The next negative test reproduced acceptance of a nil predecessor digest;
the v2 executor now rejects a missing or mismatched predecessor before I/O.

Evidence: `/tmp/zasp-sandbox-projection-worker-green.log` passed in2.460s;
`/tmp/zasp-sandbox-projection-worker-fences.log` records the predecessor RED.
`/tmp/zasp-sandbox-projection-worker-final-races.log` passed uncached with
projection1.333s, correlation1.657s, runtimeevent3.664s, worker9.239s and
migrations1.430s. Tests cover invalid capabilities, canceled/expired leases,
predecessor version/digest/generation drift, cancellation after both effects,
lease expiry after graph apply and valid renewed leases. Independent review of
the pure projection contract and worker delta found no blocker. The reviewer
read the final race log and approved only a local checkpoint with stub
infrastructure, not production persistence or activation.
No production config or SQL producer/routing activation is included.

## Completion worker consumer checkpoint

The local completion-v2 worker accepts only projection-v2 receipts for v2 work.
It drains old v1 leases without changing historical completion bytes. Authorized
v2 execution validates the live lease and matching predecessor digest before
I/O, checks the receipt scope/batch/generation/effect, preserves the exact
projection body for database finish, and fences cancellation/expiry before and
after the terminal artifact write. This does not implement the database finish
consumer or activate any new work versions.

The tests compose actual correlation, projection and completion worker code
through the stage processor, with archive/artifact/graph/authority stubs.
They verify retained sandbox/source, risk IDs and the exact projection body;
negative cases cover version/digest/generation drift, credentials, expired and
renewed leases, cancellation after read/write, and expiry after read.
`/tmp/zasp-sandbox-complete-worker-red.log` records constructor rejection before
implementation; `/tmp/zasp-sandbox-complete-worker-green.log` passed in2.388s.
Final uncached `/tmp/zasp-sandbox-complete-worker-final-races.log` passed:
projection1.406s, correlation1.724s, runtimeevent3.649s, worker9.153s and
migrations1.392s. Independent review found no blocker and read the completed
five-package log. It approved a local checkpoint only, not SQL persistence or
deployment. The original 728-task counts are unchanged.

Fresh checkpoint verification: standalone UI build passed
(`/tmp/zasp-sandbox-consumer-ui-build.log`); ledger validation passed with
728 rows,536 production-available,131 component-only,61 external,0 missing
(`/tmp/zasp-sandbox-consumer-status-final.log`). Full `npm run verify`
passed all1188 UI tests across196 files, typecheck, lint and source-import gates,
then failed the known staging chart49/embedded50 contract
(`/tmp/zasp-sandbox-consumer-verify.log`). No new push, rollout or task credit.

## Search consumer and separate index checkpoint

`sessionsearch.BuildDocuments` now accepts digest-bound v1/v2 projection
receipts and reprojects with the matching contract before exact item comparison.
It retains sandbox/source from the committed projection, not from untrusted
semantic fields. Unknown/ambiguous identity stays empty. The historical document
hash captured before the edit is
`624b8e5470849d0e258da00ba869b9114aa2a09f68a76c714ee428d4b2c44b02`;
the regression pins those bytes.

`NewSandboxSessionIndex` selects a separate fixed `zasp-runtime-sessions-v2`
namespace with a strict mapping and v2 marker. All mapping, marker, bulk,
readback, refresh and query operations use that constructor-owned namespace.
The unchanged default v1 index rejects v2 projection receipts before provider
I/O. The v2 index can backfill historical documents without changing their body
or occurrence key, and accept sandbox-bound new receipts. This is not an
automatic backfill or read cutover: deployed historical coverage must be proven
before switching readers. No production factory selects v2 yet.

Behavioral RED: `/tmp/zasp-sandbox-search-red.log` records rejected v2 search
documents and the historical hash; `/tmp/zasp-sandbox-search-index-red.log`
records v2 work reaching the old index and the new constructor selecting the old
namespace. The separate interface compile failure isn't behavioral evidence.
`/tmp/zasp-sandbox-search-index-green.log` passed both packages. Final uncached
`/tmp/zasp-sandbox-search-final-races.log` passed sessionsearch2.206s,
runtimeindex1.672s, OpenSearch driver1.983s, projection1.937s, worker9.018s and
API3.195s. Negative tests cover mapping/marker drift, missing/changed binding,
foreign readback index and failed refresh, without false completion.

Independent initial review found no implementation blocker, limited to stub
provider evidence. Follow-up review confirmed the added negative boundaries and
six-package results, but correctly withheld real-provider approval after the
first local run failed. That failure and its resolution are recorded below.
No task counts, rollout status or main revision change.

### Actual local OpenSearch and clock diagnosis

The first run failed before schema initialization with `ErrDenied`
(`/tmp/zasp-sandbox-search-local-provider.log`). Following the investigate
workflow, reproduction inspected the owned provider: no cluster blocks, zero
shards, and no v1 index (`/tmp/zasp-sandbox-search-local-diagnostic.log`).
Tracing the transport found its UTC signing-clock guard; the new fixture passed
`time.Now`, whose local location is rejected before HTTP. A narrow test now
proves non-UTC returns denied with zero calls while UTC reaches the provider
(`/tmp/zasp-sandbox-search-clock-diagnostic.log`,PASS1.689s).

Only the fixture clock changed to `time.Now().UTC()`. The production guard is
unchanged. Actual OpenSearch3.8.0, started through the existing ownership-checked
disposable runtime dependency harness, then passed separate old/new schemas,
sandbox write/replay, a historical generation2 backfill, scoped old/new queries,
foreign-tenant zero results and unchanged old-index query behavior.
`/tmp/zasp-sandbox-search-local-provider-final.log` passed in15.10s (race package
16.687s); owned container cleanup completed. This proves local index behavior,
not PostgreSQL committed authority, deployed historical coverage or cloud IAM.
Final independent review read the successful provider log and fresh races,
found no issue, and approved only the bounded local checkpoint.

Fresh `/tmp/zasp-sandbox-search-reviewed-races.log` passed all six packages:
sessionsearch1.792s, runtimeindex1.325s, OpenSearch driver1.987s,
projection2.168s, worker9.355s and API2.192s. Standalone UI build also passed
(`/tmp/zasp-sandbox-search-ui-build.log`). Full verification passed all1188 UI
tests in196 files, typecheck, lint and source-import gates, then failed the
known chart49/embedded50 rollout contract
(`/tmp/zasp-sandbox-search-verify.log`). The ledger check still reports all728
rows,536 production-available,131 component-only,61 external and0 missing
(`/tmp/zasp-sandbox-search-status.log`). No draft push or task credit.
The investigate learning helper still fails because its installation lacks
`lib/jsonl-store.ts`; this document retains the diagnosis instead.

## Database session completion checkpoint

The draft adds nullable sandbox/source columns to the existing session-event
table. Historical rows stay null. It derives a separate
`zasp_runtime_finish_sandbox_session_projection` from the verified old finisher,
leaving the released v1 function unchanged. V2 binds complete-v2/project-v2,
scope/batch/generation/effect and the exact predecessor receipt digest. It checks
pair presence and JSON types, requires a binding for Exact, forbids agent/session
aliasing, and uses the table constraint for bounded sandbox values and known
confidence. Whole-row replay comparison includes the new fields. Readiness is
checked at entry, after blocking predecessor/work locks and before returning;
later failures roll back stage, event and receipt writes together.

The schema50 fingerprint now includes the new function and session-column ACLs.
The actual PostgreSQL secure fingerprint at this completion-only checkpoint was
`65a396847234cb2aae93ccf8d256f26532d355ab725eeda67a88c0b6e816c813`.
Rollback refuses project-v2/complete-v2 work or retained session bindings, locks
both session tables and removes only null new fields. The Up/Down runner now
also includes these tables in its NOWAIT preflight. The missing-lock regression
first hit the two-second cancellation and invalidated the migration connection
(`/tmp/zasp-sandbox-session-lock-red.log`); the expanded lock set passes all
sixteen controlled contention cases with an intact predecessor release.

The new `FinishStage` branch pins compiled schema50 readiness before calling
the new atomic SQL entrypoint with the exact receipt bytes. Missing, denied or
malformed authority cannot fall back to the old finisher. Production claim
routing and new worker configuration are still not activated.

Evidence: `/tmp/zasp-sandbox-session-red.log` reproduced the missing SQL function;
`/tmp/zasp-sandbox-session-green.log` passed in7.005s.
`/tmp/zasp-sandbox-session-boundaries.log` passed in19.770s, covering exact
SQLSTATE checks for partial/null/numeric/empty/oversize/whitespace/weak/aliased/
invalid-source binding failures on the final item, unchanged earlier writes,
historical v1 replay through two rollback/reinstall cycles, and changed readiness
while blocked. The later conflict regression and expanded rollback suite passed
in72.201s (`/tmp/zasp-sandbox-session-rollback-final.log`).
Repository routing RED is `/tmp/zasp-sandbox-session-repository-red.log`;
runtimeevent/worker/migration races passed in4.337s/10.045s/2.025s
(`/tmp/zasp-sandbox-session-repository-green.log`). Actual repository plus
PostgreSQL completion/replay passed in7.217s
(`/tmp/zasp-sandbox-session-repository-postgres.log`). These tests seed bound
predecessor/work rows and use the real projection encoder/database finisher;
they do not prove the full ingest/claim/worker deployment path.

Independent review found no concrete defect after the requested negative,
conflict, old-row and lock-wait tests. It approved only the local checkpoint.
The full all-sandbox PostgreSQL race selection passed in225.785s
(`/tmp/zasp-sandbox-session-all-postgres.log`). Final runtimeevent/worker/migration
races passed in3.951s/15.024s/1.494s
(`/tmp/zasp-sandbox-session-final-go.log`), including missing, denied and malformed
repository authority with no fallback. The two selected historical session
regressions passed in26.520s
(`/tmp/zasp-sandbox-session-legacy-regression.log`). This is a bounded selection,
not a claim that every PostgreSQL integration test ran.

The standalone UI build passed (`/tmp/zasp-sandbox-session-ui-build.log`). Full
verification passed1188 tests in196 files, typecheck, lint and source imports,
then failed the chart49/embedded50 release gate
(`/tmp/zasp-sandbox-session-verify.log`). Later verification steps did not run
through that command. The separate status check confirms728 rows:
536 production-available,131 component-only,61 blocked/external,0 missing.
No draft push, activation or task credit. Counts and main remain unchanged.

## Session API and UI retention checkpoint

Superpowers is now installed at
`/Users/manishmaheshwari/.agents/skills/superpowers`. After the user's correction,
the main agent read the installed using-superpowers (including Codex adaptation),
TDD and writing-good-tests, systematic-debugging, verification-before-completion,
and requesting-code-review/template instructions. Earlier steps in this turn
used the official upstream copies; subsequent work uses the installed skills.
This coupled SQL/API/UI change continues in the existing isolated worktree,
with an independent bounded review, not a new implementation-agent handoff.

Checklist for this checkpoint, not new plan microtasks or completion credit:

- [x] Reproduce missing API representation and skipped repository readiness.
- [x] Preserve sandbox/source pairs in strict browser decoding and both event views.
- [x] Add separate SQL event page/get functions with existing scope, principal,
  evidence-target and cursor predicates; leave released representations unchanged.
- [x] Pin new read functions/ACLs in schema50 readiness and guarded rollback.
- [x] Test actual SQL and HTTP reads, pagination, historical49-to50 behavior,
  revoked membership and missing50 authority.
- [x] Finish startup predecessor-metadata negative tests and the reproduced fix.
- [x] Run fresh broad races, UI build/verification and review the final delta;
  full verification still fails the unfinished chart49/embedded50 rollout gate.
- [ ] Composed browser/ingest proof and rollout remain outside this checkpoint.

The current schema50 fingerprint, including the new readers, is
`41a74d3c5da173809848918e99aac3d1b1f27afbb9d3dec783a865b3d2b25a40`.
The production search-enabled repository negotiates compiled50 readiness on
each event read, trying separately pinned49 only for a missing50 function.
A failed new read never retries the old representation. The initial HTTP test
found startup still rejected50; a separate pinned startup path now supports it
without changing the released six-argument startup SQL. A further actual
PostgreSQL RED (`/tmp/zasp-sandbox-api-startup-metadata-red.log`) showed the first
new startup path accepted consistently altered49 checksum metadata. The corrected
path shares the original compiled27/48/49 predicates and adds compiled50
readiness, binding all eight arguments. Only a raw no-rows result from the old
startup check can try it. Other provider errors do not trigger this path.

Browser RED: `/tmp/zasp-sandbox-api-ui-red.log` (six failures). Unicode RED:
`/tmp/zasp-sandbox-api-ui-unicode-red.log` (NUL accepted, BOM rejected). Decoder
now validates UTF-8 bytes and Go whitespace without rewriting values. Both
timeline and evidence views show the reporting sensor alongside sandbox identity,
and show unknown when no binding was recorded. Historical Exact events may omit
the pair; the decoder does not invent a binding from the session.
The first focused UI run passed117 tests in8 files
(`/tmp/zasp-sandbox-api-ui-final.log`). Additional whitespace-boundary cases were
added later. Full verification initially passed1213 tests then failed the new
control-character regex lint rule. The check now uses string membership for
control characters without disabling the rule; the fresh run passes lint.

SQL RED: `/tmp/zasp-sandbox-api-sql-red.log` (new function absent).
Repository RED: `/tmp/zasp-sandbox-api-repository-red.log` (old read skipped pinned
authority). SQL/repository GREEN passed6.589s
(`/tmp/zasp-sandbox-api-sql-repository-green.log`). The initial revocation test
changed explicit scope permissions while leaving a security_admin membership,
whose role still granted investigation permission. Tracing
`zasp_identity_admin_effective_scopes` identified the fixture error; the test now
revokes membership and production authorization is unchanged.

Actual HTTP/database tests passed14.987s
(`/tmp/zasp-sandbox-api-http-postgres-final.log`): source-qualified detail/page,
keyset continuation, same API instance on49 and50, unchanged historical response
bytes, and503/provider_unavailable when50 authority is missing. Search itself is
not exercised by this HTTP fixture. Its index double is unused by event routes;
the coordinator finisher, database, production repository constructor and HTTP
handler are real. Ingest, worker claiming and deployed browser behavior are not
proved by this fixture.

Final actual PostgreSQL/HTTP/startup tests passed14.289s, including both48 and49
metadata tamper rejection (`/tmp/zasp-sandbox-api-http-startup-final.log`). The
broader all-sandbox PostgreSQL race selection passed176.042s before that last
startup-only fix (`/tmp/zasp-sandbox-api-all-postgres.log`). Selected historical
session/evidence PostgreSQL regressions passed13.023s
(`/tmp/zasp-sandbox-api-legacy-postgres.log`). Runtimeevent/worker/migration/API
command races passed3.458s/9.504s/1.667s/2.370s
(`/tmp/zasp-sandbox-api-go-races.log`).

Full verification (`/tmp/zasp-sandbox-api-verify-final.log`) passed1238 tests in197
files, typecheck, lint and source imports, then failed the existing chart49 versus
embedded50 rollout gate. Later gates in that command did not run. The separate
fresh standalone UI build passed (`/tmp/zasp-sandbox-api-build-final.log`). The
ledger check still validates728 rows with536 production-available,131
component-only,61 blocked/external and0 missing.

Final independent review read the startup fix and terminal PostgreSQL/build
results, found no concrete issue, and approved spec/quality for this local
checkpoint. HTTP identity remains a fixture; no deployed/browser/ingest or task
completion claim follows. No draft push or task credit; production routing,
search cutover and broader acceptance remain open.

## Session-stage claim routing checkpoint

Installed Superpowers TDD, systematic-debugging, verification-before-completion,
requesting-code-review and receiving-code-review were used for this bounded
continuation. The first actual PostgreSQL RED showed the old claim consuming a
projection-v2 job (`/tmp/zasp-sandbox-stage-routing-red.log`). Schema50 now has
separate projection-v2 and completion-v2 claim entrypoints. Their private helper
retains the predecessor's delivery, fairness and lease algorithm, drains v1 jobs
without rewriting versions, and ignores unknown future versions. The old helper
filters both claim and exhaustion paths to projection-v1/completion-v1. A mutation
trigger fences v49 bodies already waiting at the stage advisory lock.

The first draft had an unparenthesized CASE in the trigger IF condition. The
PostgreSQL error position identified it; adding parentheses fixed parsing. The
live security check then returned true. Current schema50 semantic fingerprint:
`276fb9a09d25f38b2e46d43c82c0b854a80e90a02f9767f112fd8cf63fa5a1a7`.
The API checkpoint fingerprint above is historical, not the current draft pin.

- [x] Old/new readers: both stages, pending, retryable, expired lease, exhausted,
  and final attempt. Actual PostgreSQL races passed36.387s
  (`/tmp/zasp-sandbox-stage-routing-green.log`).
- [x] Already-entered v49 bodies: both stages, claim/exhaustion, fenced and
  deliberately unfenced controls. Together with v1 draining and unknown-version
  cases, actual PostgreSQL races passed43.223s
  (`/tmp/zasp-sandbox-stage-routing-races.log`).
- [x] Historical rollback and guarded rejection selection passed26.035s
  (`/tmp/zasp-sandbox-stage-routing-rollback.log`).
- [x] Final combined checks: same-transaction marker restoration, caught nested
  claim rollback, attempt100 retryable/failed terminal receipt/cascades/replay,
  readiness drift after advisory/exhaustion-row waits, role/trigger drift, runner
  roundtrip and session history reinstall. Actual PostgreSQL races passed51.598s
  (`/tmp/zasp-sandbox-stage-routing-review-final.log`).
- [x] Full sandbox PostgreSQL race rerun passed282.902s
  (`/tmp/zasp-sandbox-stage-routing-all-postgres.log`).
- [x] Fresh standalone UI build passed
  (`/tmp/zasp-sandbox-stage-routing-build.log`).
- [x] Independent review of final controls found no remaining issues and
  approved this bounded local checkpoint only, not merge or activation.

Review found the initial autocommit marker assertion could not prove explicit
restoration. The replacement asserts within one transaction, with both empty
and preexisting caller markers. Initial marker/final-completion controls passed
23.522s (`/tmp/zasp-sandbox-stage-routing-review-tests.log`); the strengthened
nested-claim control and remaining focused checks then passed51.598s. The full
sandbox suite subsequently passed282.902s. No production
microtask credit, commit, push or activation follows from this checkpoint.

Fresh Go race suites passed for runtimeevent3.971s, migrations2.076s,
agentsec-worker9.404s and agentsec-migrate68.439s
(`/tmp/zasp-sandbox-stage-routing-go.log`). The status validator still accounts
for all728 rows:536 production-available,131 component-only,61 external,0 missing.
`git diff --check` passed. The known full-verification chart49/embedded50 gate
has not been changed or bypassed; no push is authorized by these partial gates.

## Session worker activation checkpoint

The new `NewPostgresSandboxSessionPipelineRepository` declares immutable
projection/completion-v2 capability, checks compiled schema50 checksum and
fingerprint on readiness and every claim, and accepts only stage-matching v1/v2
leases. Missing functions, denied access, invalid readiness or failed claims
never fall back. Historical constructors are unchanged. Worker configuration
accepts the matching v2 versions, and the production factory selects the new
repository only for those versions. Existing AWS/database/graph constraints
remain in force. Cached health readiness cannot skip the claim-time check.

Actual PostgreSQL exposed an incorrect initial rollout assumption: schema49's
readiness grant excludes projection workers. The27 compatibility wrapper cannot
accept independently compiled49 pins, so it was not substituted. Independent
review confirmed the revised sequence: deploy new binaries with v1 configuration
on49, install healthy50, then enable v2 configuration. This changes an internal
rollout detail, not any product requirement. Released migrations are untouched.
Migration50 adds only projection-worker EXECUTE on its read-only readiness
function and pins the grant in security/fingerprint checks. No table or role
membership grants were added. Current fingerprint:
`fdba6fe094cf7b89051954ca17b12654b5f7f345003a57f24f3fb19b845179fc`.
Earlier checkpoint fingerprints in this document are historical.

- [x] Repository behavioral RED before claim routing implementation:
  `/tmp/zasp-session-worker-routing-red.log`.
- [x] Composition RED rejected both v2 worker configurations:
  `/tmp/zasp-session-worker-composition-red.log`.
- [x] Actual provider RED identified missing projection readiness access and
  the unsupported49 v2 fallback:
  `/tmp/zasp-session-worker-routing-rollout-red.log`.
- [x] Focused unit/composition, SQL grant drift and runner roundtrip tests passed
  1.613s/2.257s/9.497s (`/tmp/zasp-session-worker-routing-final.log`). This selection
  did not include the new PostgreSQL transition test, which ran separately.
- [x] Actual PostgreSQL transition passed9.460s
  (`/tmp/zasp-session-worker-routing-postgres-completion.log`): v1 claim and
  retry completion on49, v2 rejection on49, v2 claim on50, and failure without
  mutation when50 readiness disappears. An earlier fixture left the old lease
  active and correctly hit the tenant concurrency limit; the test now settles
  it through the actual finish authority before testing the second job.
- [x] Full Go race suites passed runtimeevent3.110s, worker9.663s,
  migrations1.773s, migrate63.940s
  (`/tmp/zasp-session-worker-routing-go-final.log`).
- [x] Independent spec/quality review found no concrete issue and approved the
  bounded local checkpoint only, not deployment or merge.
- [x] Fresh full sandbox PostgreSQL race run passed277.550s
  (`/tmp/zasp-session-worker-routing-corrected-all-postgres.log`). The preceding
  run failed275.678s only on the two known pre-correction lease fixture cases
  (`/tmp/zasp-session-worker-routing-all-postgres.log`). The fresh full run
  includes the corrected transition fixture and supersedes that failed run.

No additional microtask credit or push. End-to-end producer activation, real
search-index cutover, browser acceptance and deployment remain incomplete.
The final50-only lease allowlist simplification was rechecked with the full
runtimeevent race suite, passed3.558s
(`/tmp/zasp-session-worker-routing-final-version-check.log`). The status check
still validates728/536/131/61/0 and `git diff --check` passes.

The search selector now covers all three existing production consumers:
`agentsec-worker/projection_init.go` (index initialization),
`agentsec-worker/runtime_index_production.go` (session document writes), and
`agentsec-api/policy_production.go` (session queries). Each uses the shared strict
`ZASP_RUNTIME_SESSION_INDEX` selector. Empty defaults to v1, exact v1/v2 names
select their fixed driver, and unknown names, whitespace and wildcards fail.
Nonempty worker selection is confined to runtime-index/projection-search-init.
Deployment configuration remains unchanged. Historical backfill and coordinated
query/write readiness are still required before enabling v2.

Behavioral RED reproduced the API selecting v1 despite explicit v2 and accepting
invalid selection (`/tmp/zasp-session-search-factories-red.log` and
`/tmp/zasp-session-search-selection-red.log`). Factory/provider path tests and
strict environment-loader tests now pass. Full package races passed API2.563s,
worker9.195s and OpenSearch driver1.358s
(`/tmp/zasp-session-search-factories-go-final.log`). Independent Superpowers
review found no concrete findings and approved this bounded local checkpoint.
This is a bounded factory checkpoint, not completed search cutover. The existing
single search outbox and query status cannot prove v2 backfill; separate durable
target-index progress and matching API freshness remain required. No task credit.

After import grouping and test-layout cleanup, fresh full package races passed
API2.582s, worker8.977s and driver2.478s
(`/tmp/zasp-session-search-selection-final.log`). The fresh Node22 standalone UI
build passed (`/tmp/zasp-session-search-selection-ui-build.log`). No push.
Inspection of released SQL43 confirms both query status and hydration use the
single existing search outbox; the next change must bind both to the selected
target's durable progress without rewriting released migration43.

## Work still required

### Durable v2 search backfill checkpoint

The separate `zasp_runtime_sandbox_search_outbox` now backfills canonical
projection receipts through successful project/complete authority, independently
of old search progress. It keeps receipt digest, object reference/version and
ordered document IDs, but starts every v2 row pending with attempt0. The private
receipt trigger adds future receipts atomically; replay doesn't reset old or new
work. Forced RLS and no direct worker/API table grants remain in place.

Rollback locks the v2 queue NOWAIT and refuses any nonzero attempt or nonpending
state, preserving attempted indexing evidence. Unattempted derived work can be
removed by guarded rollback and rebuilt from canonical receipts on reinstall.

The first actual PostgreSQL RED failed8.432s because the separate queue was
absent (`/tmp/zasp-sandbox-search-backfill-red.log`). Initial green passed9.539s.
Expanded controls passed16.562s. Independent review then withheld approval for
missing outbox-trigger coverage in the fingerprint. The explicit mutation test
reproduced readiness=true after an unexpected queue trigger (RED4.771s,
`/tmp/zasp-sandbox-search-queue-trigger-red.log`). The fix fingerprints all
noninternal triggers on both receipt and queue tables, including relation
identity. Scoped re-review confirmed the correction with no new finding.

Current compiled50 semantic fingerprint:
`0f70f748cfefb582a0e4379ccda5634a206b25a56a2b1a34a25f66ac90422c43`.
Earlier fingerprints here are historical.

- [x] Fresh actual PostgreSQL backfill/ACL/drift/rollback acceptance passed25.084s
  (`/tmp/zasp-sandbox-search-backfill-acceptance.log`), including missing old
  progress, missing canonical authority, preserved v1 checkpoints, v2 receipt
  enqueue/replay, reinstall and queue-lock contention.
- [x] Full package races passed migrations1.854s, migrate67.364s,
  runtimeevent3.879s and worker9.242s
  (`/tmp/zasp-sandbox-search-backfill-go.log`).
- [x] Fresh Node22 standalone UI build passed
  (`/tmp/zasp-sandbox-search-backfill-ui-build.log`).
- [x] Full sandbox PostgreSQL races passed296.264s under that checkpoint's
  fingerprint (`/tmp/zasp-sandbox-search-backfill-all-postgres.log`).

Design and dependency plan: `2026-09-11-session-search-v2-design.md` and
`2026-09-11-session-search-v2-plan.md`. Their next work is fixed-v2 lease and
query-status authorities, then matching worker/API composition and coordinated
provider cutover. Current production factories still default to v1. No activation,
push, additional microtask credit or production-readiness claim.

### Target-specific query and API checkpoint

Migration50 now creates `zasp_runtime_sandbox_query_status` and `_hydrate` with
the released43 response shape, API-only EXECUTE and separate v2 backlog indexes.
Both read only the v2 queue and check50 readiness, with tenant and principal
authorization still applied on each call. Released43 definitions are unchanged.
The new API repository constructor validates the exact same target selection as
the provider driver. Empty/v1 uses old status/hydration, v2 uses the new pair.
V2 startup and every search require the compiled50 checksum/fingerprint with no
missing-function fallback. Production composition passes the same config to both.

Current compiled50 semantic fingerprint:
`8f1a019bfb7bd001a54de8887c3355272800e7cfefe1a9df7867432dced2b5e6`.

- [x] Actual PostgreSQL RED: missing v2 query function (42883),8.344s,
  `/tmp/zasp-sandbox-search-query-red.log`.
- [x] Repository routing RED proved old SQL selected and unknown name accepted,
  `/tmp/zasp-sandbox-search-query-routing-red.log`; green2.109s includes legacy
  repository compatibility and closed malformed/missing readiness cases.
- [x] Startup RED4.522s proved v2 API incorrectly reported ready on49,
  `/tmp/zasp-sandbox-search-query-startup-red.log`. Compiled50 startup gate fixed it.
- [x] Query/backfill PostgreSQL tests passed31.162s after correcting the revocation
  fixture. Removing a direct scope permission left security-admin role-derived
  access, so the fixture now deactivates membership as the existing revocation
  contract requires. `/tmp/zasp-sandbox-search-query-postgres-final.log`.
- [x] Composed repository/PostgreSQL tests passed10.121s,
  `/tmp/zasp-sandbox-search-query-composed.log`: v1 current/v2 catching_up,
  scoped hydration, empty/blocked/current v2 states, revoked membership,
  wrong principal/scope and readiness drift. Search provider is a stub and index
  checkpoint states are seeded; these are not actual provider cutover evidence.
- [x] Independent Superpowers review found no concrete issue and approved the
  bounded local checkpoint conditional on remaining package verification.
- [x] Expanded search acceptance passed31.242s, including revocation during
  provider search: `/tmp/zasp-sandbox-search-query-final.log`.
- [x] Fresh Node22 standalone UI build passed,
  `/tmp/zasp-sandbox-search-query-ui-build.log`; ledger check remains728/536/131/61/0
  and `git diff --check` passed.
- [x] Targeted apiserver run passed153.417s:
  `/tmp/zasp-sandbox-search-query-packages.log`. API selection matched no tests;
  the subsequent full API run below covers that package.

The query/API portion was implemented before v2 lease functions because it can
prove target-specific freshness against the already-existing queue independently.
The following checkpoint implements v2 claim/heartbeat/finish authorities and
recovery-hold controls. Default configuration remains v1; cutover stays disabled.

### Fixed-v2 lease and Go worker checkpoint

The new queue now has claim, heartbeat and finish authorities. They require a
registered index principal and healthy50; target-specific grants, fixed search
paths, recovery-hold guards and function definitions are pinned. Claim skips
locked recovery scopes, including exhausted work. Heartbeat and finish recheck
readiness and expiry after waits. Exact acknowledgement retry keeps the existing
receipt binding. V1 queue progress stays unchanged.

The worker chooses the matching fixed authority from its index configuration.
Empty/v1 keeps existing behavior. V2 probes the compiled50 pins before operations
and rejects a lease tagged for another target before database I/O.

Current compiled50 semantic fingerprint:
`31dfb1220db8926234073b673893ae451709d4d981b5ea2c971987b63e5d2c33`.
Earlier fingerprints above identify historical local checkpoints only.

- [x] Expanded actual PostgreSQL lease races passed40.506s:
  `/tmp/zasp-sandbox-search-lease-final.log`. Cases include competing claims,
  expiry/reclaim, wrong targets/tokens, exact retry, held/exhausted work,
  readiness drift during row waits and expiry during scope waits.
- [x] Fresh package races passed API2.491s, worker9.633s, migrations1.895s:
  `/tmp/zasp-sandbox-search-lease-packages.log`.
- [x] Actual Go/PostgreSQL round trip passed11.052s, including the child worker
  package2.655s: `/tmp/zasp-sandbox-search-worker-postgres-final.log`. It proves
  compiled readiness, claim, heartbeat, indexed checkpoint and exact retry.
  No OpenSearch write occurs in this test, so it isn't cutover evidence.
- [x] Fresh Node22 UI build passed:
  `/tmp/zasp-sandbox-search-lease-ui-build.log`.
- [x] Full sandbox PostgreSQL regression passed360.809s before the harness fix:
  `/tmp/zasp-sandbox-search-lease-all-postgres.log`.
- [x] Independent Superpowers review found no concrete lease/worker authority
  defect, but flagged child-process cleanup in the integration harness.
  CommandContext kills only the immediate Go process; descendants can retain
  pipes or outlive the fixture. The bounded owned-process cleanup regression and
  fix passed re-review. Details follow.

The earlier query package run passed apiserver153.417s; its API selection matched
no tests. The fresh full API package run above supplies that missing coverage.
No activation, push, task credit or production-readiness claim.

### Search executor receipt gate follow-up

Provider composition inspection found the executor still rejected all v2
projection receipts. The fixed-v2 authority could claim them, but execution
would return malformed before reaching the index. A four-case target/receipt
test reproduced this exact failure in1.167s:
`/tmp/zasp-search-executor-target-red.log`.

The executor now permits authenticated projection-v2 only on a v2-tagged lease.
Historical projection-v1 remains supported on both targets. The legacy target
still rejects v2 before archive/provider I/O. Focused tests passed2.215s:
`/tmp/zasp-search-executor-target-green.log`. Full package races passed worker
9.569s, sessionsearch1.541s, runtimeprojection2.782s and OpenSearch driver1.856s:
`/tmp/zasp-search-executor-packages.log`. Independent review found no issue and
approved this bounded local fix. These tests use real receipt/document code with
boundary doubles, not actual provider cutover. The separate harness cleanup
review finding is closed by the following checkpoint.

### Harness cleanup and legacy enqueue follow-up

The child worker test now owns a dedicated process group. Linux observes exit
with WNOWAIT; Darwin uses kqueue. The leader stays unreaped through the last
group signal, then the helper joins it and its output reader and checks group
disappearance. Cancellation or cleanup failure can't report success. Escaped
process groups aren't contained by this test-only boundary.

Lifecycle tests reproduced both inherited-pipe blocking and a surviving listener
before the fix. They passed3.748s, then ten race-enabled repetitions passed
20.047s. Actual PostgreSQL18.3 protocol proof passed10.291s. Independent review
approved the scoped fix. Logs are in
`/tmp/zasp-sandbox-worker-process-review.h99PqA/`. Linux was cross-compiled, not
executed; Windows excludes these POSIX-only tests. Parent verification of all
lifecycle cases plus the real worker/PostgreSQL round trip passed17.665s:
`/tmp/zasp-search-harness-parent-final.log`.

The legacy enqueue test then reproduced v2 receipts entering the v1 queue,
4.726s: `/tmp/zasp-search-legacy-enqueue-red.log`. Migration50 now skips the
legacy enqueue for projection-v2 and adds an insert-only version guard to the
legacy queue. A stale enqueue write is rejected at that boundary; old checkpoint
updates and historical rows are unchanged. The v2 clone is made before altering
legacy enqueue, so it still queues both receipt versions.

Current compiled50 semantic fingerprint:
`b8557cc69d90173a5333a08a4f6c322f7596371f76e7606c7a58fae1f2e23039`.
Backfill, new receipt, stale insert, drift and rollback/reinstall controls passed
24.683s: `/tmp/zasp-search-legacy-enqueue-green.log`.

A new migration-lock case reproduced missing preflight refusal for the touched
legacy queue,4.839s: `/tmp/zasp-search-legacy-lock-red.log`. Both runner lock sets
and raw rollback SQL now include it. Expanded acceptance passed30.312s in
`/tmp/zasp-search-legacy-acceptance.log`. Review requested fresh v1-after50
coverage because prior tests only replayed pre-migration receipts. That proof
passed6.032s in `/tmp/zasp-search-fresh-legacy-final.log`: both targets enqueue,
registered legacy claim/heartbeat/finish and exact retry succeed, and canonical
replay leaves the pending v2 row byte-identical. Independent re-review approved
this bounded checkpoint. Full sandbox regression passed363.577s under the new pin:
`/tmp/zasp-search-legacy-all-postgres.log`. Fresh package/CLI races passed API
2.507s, worker9.783s, migrate65.549s and migrations1.869s in
`/tmp/zasp-search-legacy-packages.log`; the fresh Node22 UI build passed in
`/tmp/zasp-search-legacy-ui-build.log`.
No full provider cutover, producer activation, publication or task credit yet.

The actual-provider backfill/API-switch fixture is being implemented in the
existing runtime-only harness. Its new opt-in refuses broad browser mode before
dependency startup. The real subprocess test reproduced the missing refusal,
then passed after the guard; logs `/tmp/zasp-search-cutover-mode-{red,green}.log`.
The harness also requires the opt-in proof marker. Independent review approved
this guard/assertion change. Its script suite passed35 tests with2 platform
skips and0 failures: `/tmp/zasp-search-cutover-harness-tests.log`.
The provider-backed cutover completed in the next checkpoint.

### Provider composition and pre-stage command work

The opt-in provider-backed fixture is now implemented and source-reviewed. It
uses the existing runtime pipeline's committed historical receipts across two
tenants, then the actual50 runner, selected production search processor, real S3
objects/OpenSearch index and API repository. Execution passed with exit0 in
`/tmp/zasp-sandbox-search-composed-first.log`. Its required marker proves7 real
PostgreSQL/S3 receipts and58 visible OpenSearch occurrences across2 scopes.
V1 stayed current during backfill; v2 became current after its own scoped
checkpoints completed. V1 queue history was unchanged, tenant denial held and
idle replay changed neither checkpoints nor provider versions. The existing
48-to49 ingestion/candidate-recovery proofs also passed. Cleanup reached its
final stage; read-only container checks found no remaining owned provider
containers. Independent review approved this historical cutover checkpoint.
It does not
exercise HTTP authentication, browser interaction or fresh sandbox producers.

The schema49 chart job previously used open-ended `up`, which would advance to
a later release once the CLI default changes. A real Helm-render regression
reproduced that risk. The job and release validator now require `up-to-49`, with
48 still pinned to `up-to-48` and the same48/49 allowlist. Three render/negative
cases passed and independent review approved the bounded fix. Logs:
`/tmp/zasp-schema49-prestage-{red,green}.log`.

The initial complete release-contract suite had40 passes and1 failure:
`/tmp/zasp-schema49-release-contract-all.log`. The failing obsolete constructor
string assertion is now replaced with actual production composition and real
idle-socket cleanup tests. Mutation RED proved that dropping the configured
repository selector or session-search Close breaks the new coverage. Independent
review accepted the behavioral replacement. Parent API/worker races passed
2.249s/8.927s in `/tmp/zasp-search-composition-ci-final.log`; the complete
release-contract suite passed40/40 in
`/tmp/zasp-schema49-release-contract-final.log`.

CI now runs these API/worker packages and the full Sandbox PostgreSQL selector.
Review caught stale exact-command fixtures in the workflow contract. Parent
reproduced1 failure, updated both fixtures without relaxing validation, then
passed23/23 checks in `/tmp/zasp-search-workflow-{red,green}.log`.
A fresh UI build passed in `/tmp/zasp-search-reviewed-ui-build.log`.
These bounded results do not clear the full schema50 rollout/release gate.

### Remaining product path

The deployment phase design is recorded in
`2026-09-11-sandbox-rollout-design.md` and independently reviewed. It requires
compatible49 pods before50, ordered initializers, a parallel v2 worker and
identity-bound, expiring backfill evidence before API switch. It is not yet
implemented or deployed.

Evaluating IAM with known offline provider values exposed an existing queue
configuration defect: both work queues and DLQs set an explicit KMS key and
`sqs_managed_sse_enabled=false`. AWS provider6.60.0 rejects the combination for
all14 queue instances. The pinned provider's
[queue schema](https://github.com/hashicorp/terraform-provider-aws/blob/v6.60.0/internal/service/sqs/queue.go)
declares these attributes mutually exclusive. The two managed-SSE flags are now
removed locally; explicit customer KMS expressions are unchanged. Full offline
policy evaluation now passes, including exact keys for all14 work/DLQ queues.
The three policies add only12 exact v2 resource paths, preserving v1 access.
Missing-v2 assertions and three permission-broadening mutations failed as
expected; all mutations were restored. Parent plan-only verification passed2/2
in `/tmp/zasp-session-iam-parent.log`, and release tests passed43/43 in
`/tmp/zasp-session-iam-release-tests.log`. Independent review approved the IAM
and queue correction. This does not claim live AWS apply success. Detailed
diagnostics, RED and GREEN evidence are retained under
`/tmp/zasp-session-iam.5eX7Hl/`.

CI now installs checksum-pinned Terraform1.15.8 into an isolated temporary
directory, initializes with backend disabled and a read-only dependency lockfile,
and runs the mocked policy test with a10-minute limit. Exact workflow contract
RED reproduced the missing step; GREEN passed23/23 in
`/tmp/zasp-session-iam-ci-{red,green}.log`. Independent review closed the CI
condition. The same Linux archive checksum was verified locally, but the hosted
Linux CI run has not happened. No local check is a managed-IAM attestation.

Explicit CLI registration is now implemented locally: `up-to-50` calls the
guarded50 runner, and `down-to-49` calls its guarded rollback without cascading
into prior releases. Plain `up` still targets49 for this phase. Dispatch tests
reproduced unsupported-command failures before implementation, then passed
1.832s including49 pre-stage compatibility. Logs:
`/tmp/zasp-sandbox-cli-{red,green}.log`. Actual PostgreSQL command-handler acceptance
passed5.608s and independent review approved this bounded checkpoint. It covers
post50 principal registration, compiled readiness, unchanged runtime bindings,
unchanged SQL producer versions, retained-evidence rollback refusal, clean49
rollback and50 reinstall. Mutation RED caught a skipped guarded runner; main.go
was restored byte-for-byte. Evidence:
`/tmp/zasp-cli50-postgres-{mutation-red,green}.log`.
This tests command-handler functions, not a spawned binary or deployment.
Parent full migration package races then passed69.103s for agentsec-migrate and
1.421s for migrations, with PostgreSQL18 on PATH:
`/tmp/zasp-cli50-packages-final.log`. Ledger validation and diff checks passed.
This does not register a deployed50
rollout or activate fresh sandbox producers.

Command review found no routing/registration defect; it requires actual
post-migration principal registration and rollback-guard acceptance before
rollout approval. Full Vitest passed1238/1238 tests across197 files in
`/tmp/zasp-sandbox-cli-vitest.log`; typecheck and lint exited0 in matching
`/tmp/zasp-sandbox-cli-{typecheck,lint}.log`. Release tests passed43/43 in
`/tmp/zasp-sandbox-cli-release-tests.log`. No task credit changes.

A fresh full `npm run verify` stopped at the known staging contract mismatch:
the chart targets49 while the embedded migration set contains50. All earlier
commands completed, but this is still a failed full gate, not a publishable
release. Evidence: `/tmp/zasp-sandbox-cli-full-verify.log`. Keep the mismatch
visible until phase-specific deployment configuration is implemented and tested;
changing the expected number alone would not prove a safe rollout.

Finish deployment rollout registration for the guarded50 runner and compatible
workers, including actual executable/environment acceptance. Finish recovery-hold coverage and deployed
configuration sequencing for the new session workers. Prove the compatible API
and v3 workers in the composed49 deployment before producer routing and50
activation. Finish downstream
projection, graph, search, API and browser binding retention, then rerun composed
ingest/recovery acceptance, full verification, independent review and publication.
The source process-time precision gap remains part of M3-46.

The versioned projection contract and both worker consumers are local drafts.
Production claim/configuration wiring is now local and reviewed. Route new
projection work only after compatible consumers are available; keep old work
versions and receipts immutable through recovery and rollback.

Separate schema50 event-page/get readers now return sandbox/source, while
schema41/44 representations remain unchanged. The new readers still need
composed browser acceptance and rollout. The new search consumer and separate v2 index still
have reviewed local historical backfill/cutover coverage; fresh sandbox receipts
and deployed cutover still need acceptance.
Phase-aware Helm resources now implement compatibility49 and backfill/query50.
Both50 phases retain the v1 worker and add a separately selected v2 worker,
Service, PDB/HPA, monitoring, network coverage and initializer. The API selects
v2 only in query. Migration and initialization are ordered by pre-upgrade hooks.
Actual render tests went RED to GREEN. Mutations reject missing workers,
incorrect targets/authorities, broken resource/probe bounds, missing network or
scrape reachability and reordered migration hooks. The obsolete source-text
initializer-weight check now uses actual renders of all three phases.
Full release tests passed46/46 in `/tmp/zasp-rollout-review-green.log`, full
Vitest passed1238/197 in `/tmp/zasp-rollout-vitest.log`, and the UI build passed
in `/tmp/zasp-rollout-ui-build.log`. Typecheck, lint and ledger checks exited0.
Independent re-review found one more hook-type gap for v1 search/graph init.
Both hostile mutations reproduced the failure, then the validator was corrected;
final full-suite evidence is `/tmp/zasp-rollout-init-hooks-green.log` (46/46,
exit0). Independent Superpowers review approved the bounded manifest task.
This is local manifest work. Transition authorization, executable/environment
acceptance, fresh sandbox ingestion/recovery and browser acceptance are open.
The default49/embedded50 full-gate mismatch remains visible. Nothing was pushed
and original task counts are unchanged.

Compatibility observation now has a read-only collector and revalidation helper
in `deploy/production/compatibility-observation.mjs`. It uses explicit kubectl
context/kubeconfig, bounded reads, namespaceUID, all10 required API/runtime
deployments, ready replica counts, current generations, ownership chains,
intended admitted-template digests and resolved main/init image identities.
It rejects changed pod metadata/config and expires evidence after30seconds.
Initial15-case RED/GREEN was followed by review regressions for added Pod
privileges and changed labels/annotations. Those controls failed8 of24 cases
before correction. Final release tests passed70/70 in
`/tmp/zasp-compatibility-final.log`; Vitest passed1238/197 in
`/tmp/zasp-compatibility-vitest.log`, and build passed in
`/tmp/zasp-compatibility-ui-build.log`. Lint, ledger and diff checks passed.
Independent Superpowers scoped review approved this bounded local observer.
This is controlled-provider evidence, including
actual chart templates, not proof of API-server defaulting/admission or live
cluster readiness. Intended admitted artifact generation, cluster server/CA
pinning, serialized migration invocation and database readiness remain required
integration work. The helper does not authorize mutation or grant reusable
cutover permission. Query receipt coverage and fresh ingestion remain open.

The guarded50 command now also has actual compiled-executable acceptance in
`runtime_sandbox_binary_postgres_test.go`, called by the existing real PostgreSQL
CLI acceptance test. The child gets explicit principal settings with ambient
ZASP/PG variables removed. Missing runtime-index principal rejects before49
changes; explicit install/retry reaches50 with compiled readiness and unchanged
bindings. Plain up and unknown51 reject; clean rollback/retry restores49.
Initial PostgreSQL race run passed13.665s in `/tmp/zasp-binary50-green.log`.
A mutation removing50 from the executable's forward-command classification
failed exactly because missing configuration was accepted, recorded in
`/tmp/zasp-binary50-mutation-red.log`. Production `main.go` was restored to
SHA256 `0a57ef6ffc985b7cd83c0219538edd516521efde7a08be98d13d3f5e813dd30d`.
Review found a descendant-cleanup gap in the initial build harness. The existing
owned process-group runner and interruption regressions now live in shared
`internal/testprocess`; both the migration executable/build and API test wrapper
use it. Focused cleanup and binary reruns passed4.034s/12.614s. CI now runs the
shared interruption tests; workflow contracts passed23/23 and production source
import checks passed. Linux/amd64 tests cross-compiled in
`/tmp/zasp-binary50-linux.ywQwcB`; they were not executed on Linux. Independent
Superpowers scoped review approved the local binary-acceptance checkpoint.
Full package races after extraction passed: testprocess3.151s,
agentsec-migrate69.082s, migrations1.647s, with PostgreSQL18 available;
evidence `/tmp/zasp-binary50-final-packages.log`. Fresh UI build, lint, ledger and
diff checks passed. This closes the
launched-binary boundary for the tested commands, not Kubernetes job environment
materialization, retained-evidence child-process rollback or live deployment.

The staging contract now accepts the deliberately staged49/50 release sequence.
The old default-equals-latest assertion failed6/7 in
`/tmp/zasp-phase-staging-red.log`; it incorrectly prohibited compatibility49
despite the reviewed requirement to run compatible pods before the50 hook.
Its replacement pins latest50, requires default49 compatibility, renders all
three phases and checks exact migration job/API target/parallel worker behavior.
Mixed phases and undefined51 are rejected. No default was renumbered and no
deployment was authorized. Staging tests passed7/7 in
`/tmp/zasp-phase-staging-green.log`; independent Superpowers review approved this
local contract correction. Fresh full `npm run verify` exited0 in
`/tmp/zasp-phase-full-verify.log`, including1238 UI tests,70 release tests,
typecheck, lint, build, source/compiled import checks and ledger validation.
This is the repository verification chain, not live provider/deployment proof.
The earlier mismatch is historical evidence,
not a currently claimed blocker. Live transition authorization and composed
product acceptance remain required before publication.

Process precision work now has an independently reviewed local V2 observation
contract. It preserves canonical `source_event_time` and process start to
nanoseconds, requires the source instant to truncate to the exact millisecond
wire time, and leaves V1 decoding unchanged. Five component race suites passed
in `/tmp/zasp-precision-contract-green.log`; the positive same-millisecond
case was RED first. UI build passed in `/tmp/zasp-precision-ui-build.log`.
See `2026-09-11-process-precision-design.md` for required generation/envelope,
persistence, frozen-matcher and composed acceptance integration. This type is
not yet emitted, stored or used by the product pipeline; M3-46 remains open.

The separate V3 source normalizer now preserves the original provider instant
and validates process identity before retaining it. Epoch/pre-epoch starts omit
the pair without dropping valid container lineage, confirmed by a RED regression
and the final three-package race suite in `/tmp/zasp-precision-source-final.log`.
UI build passed in `/tmp/zasp-precision-source-ui.log`; independent Superpowers
re-review found no remaining scoped findings. See
`2026-09-11-process-precision-source-plan.md`. No daemon activation, transport,
persistence or original task credit is claimed.

Precise record decoding also now rejects malformed/aliased/duplicate wire,
invalid event content and wrong source-time bins before receiver assignment.
It reconstructs the embedded legacy-rejection marker that ordinary JSON decode
had lost. RED evidence: `/tmp/zasp-precision-record-red.log`. Final component
races: `/tmp/zasp-precision-record-green.log` (sensoradapter11.465s,
runtimelineage1.710s, runtimeevent3.855s). UI build exited0 in
`/tmp/zasp-precision-record-ui.log`; independent Superpowers review found no
findings. This proves local codec behavior only, not transport, checkpoint
activation or original task completion.

The distinct V2 precise envelope now supports frozen serialization/retry with
schema, digest, destination and enrollment constraints. It preserves nanosecond
source/process identity through credential rotation, rejects legacy conversions
and does not fall back after server rejection. Three final platform package race
suites passed in `/tmp/zasp-precision-envelope-final-reviewed.log`; the existing
sensor-agent race suite passed107.051s in `/tmp/zasp-precision-envelope-daemon.log`.
UI build passed in `/tmp/zasp-precision-envelope-ui.log`. Independent review
closed all findings, including a valid oversized-body mutation test proving the
8MiB guard. See `2026-09-11-process-precision-envelope-plan.md`. Durable owned
chunk checkpoint integration, server V2 archive ingest and activation remain open.

Owned precise chunk checkpoint integration is now locally verified. The shared
private state machine keeps public V1 types/wire layouts and selects V3 source
normalization plus V2 envelope/checkpoint contracts through a separate constructor.
Real-root tests exercise interrupted upload, restart, exact bytes, rotated token,
restored process cache, generation/boot rejection, persistence/preparation failure,
expiry and all-dropped accounting. Platform race suites passed in
`/tmp/zasp-precision-chunk-full.log`; sensor-agent races passed104.542s in
`/tmp/zasp-precision-chunk-daemon.log`. UI build passed in
`/tmp/zasp-precision-chunk-ui.log`; independent Superpowers review found no findings.
See `2026-09-11-process-precision-chunk-plan.md`. This does not activate actual
daemon V3 generation ownership or server archive/persistence support.

The separate V3 daemon constructor now reuses actual identity-bracketed Unix
subscription startup and publishes a profile-bound format3 manifest. Reservation
prefix recovery includes V3; admitted reader profiles select the precise consumer.
Local Unix gRPC/pump/spool/reader/consumer retry tests preserve exact nanoseconds,
and identity drift rejects before publication. Full sensor-agent races passed
110.715s in `/tmp/zasp-precision-daemon-full.log`; three platform race suites
passed in `/tmp/zasp-precision-daemon-platform.log`; UI build passed in
`/tmp/zasp-precision-daemon-ui.log`. Independent Superpowers review found no
findings. Production startup still selects V2. Precise checkpoint retirement and
server V2 archive/persistence are required before activation; local controlled
fixtures are not deployed Kubernetes/provider acceptance.

Precise receipt verification and completed checkpoint retirement are now locally
verified through explicit V3 entry points. V1 still rejects V3; shared filesystem,
authorization, exact-progress and pending-state guards remain intact. Daemon
tests cover ACK, producer completion/reclamation, retained slot locks and reuse
across24 V3 generations. Platform races passed in
`/tmp/zasp-precision-retirement-full.log`; full daemon races passed119.190s in
`/tmp/zasp-precision-retirement-daemon.log`; added V3 completion/slot tests passed
12.921s in `/tmp/zasp-precision-retirement-slots.log`. UI build passed in
`/tmp/zasp-precision-retirement-ui.log`; independent Superpowers review found no
findings. Only disposable test files were retired. Server V2 archive/persistence,
precise frozen matching and deployed activation remain required.

The separate precise server archive now carries a mandatory `runtime-archive-v2`
root, trusted-argument scope, exact source/process times and filtered content.
Canonical decoding rejects aliases, duplicates, hostile lineage and unversioned
archives. The original HTTP handler remains unchanged and rejects V2 before
reservation or artifact writes. Tests include the actual precise normalizer and
client envelope, absent-lineage legacy rejection,1000-record bounds and a
64MiB pre-decode limit. Expected stub failures are in
`/tmp/zasp-precision-archive-red.log`; removing only the size guard failed in
`/tmp/zasp-precision-archive-size-mutation.log`, then the guard was restored.
Fresh races passed runtimeevent4.987s, sensoradapter10.909s and runtimelineage1.430s
in `/tmp/zasp-precision-archive-final.log`; UI build exited0 in
`/tmp/zasp-precision-archive-ui.log`. Independent Superpowers review closed all
conditions without findings. No push or original task credit. SQL persistence,
new frozen matching and deployed end-to-end acceptance remain open.

The precision SQL fragment now computes exact numeric epochs from whole seconds
plus canonical fractional digits. It does not cast nanosecond source/process
times to timestamptz. Its separate V2 lineage validator checks identity, exact
process ordering and display-bin binding, with invoker security and PUBLIC
execution revoked. PostgreSQL18 stub failures are recorded in
`/tmp/zasp-precision-sql-red.log`; final actual PostgreSQL races passed3.197s
in `/tmp/zasp-precision-sql-final.log`, including session setting independence
and a1ns occurrence-window boundary. Three related Go race suites and UI build
passed in `/tmp/zasp-precision-sql-packages.log` and
`/tmp/zasp-precision-sql-ui.log`. Independent Superpowers review closed with
no findings. The fragment is not yet included in a migration or used by candidate
queries. Schema lifecycle, worker routing and deployed acceptance remain open.
No push or original task credit.

The separate precise candidate-freeze SQL now consumes V2 archive/index evidence
under a V4 lease and retains snapshot-v3 bytes. Its exact numeric source window
runs before LIMIT1001, retaining an indexed coarse time prefilter. Existing
enrollment, tenant, predecessor, lease/delivery, replay and post-lock checks
remain. The private fragment has no worker grant. Actual PostgreSQL RED is in
`/tmp/zasp-precision-freeze-red.log`; final new+legacy freeze races passed13.953s
in `/tmp/zasp-precision-freeze-reviewed.log`. Related precision/historical tests
passed15.757s in `/tmp/zasp-precision-freeze-final.log`; UI build exited0 in
`/tmp/zasp-precision-freeze-ui.log`. Independent Superpowers review approved
the scoped SQL and fixture changes. Tests prove exact1ns selection, immutable
late-admission replay, version refusal,1001-row crowding and true overflow with
no partial snapshot. These use owner-seeded database authority fixtures, not
real V2 API acceptance. Complete migration readiness, registration and Go worker
integration remain open. No push or original task credit.

The Go precise-freeze repository now accepts only a current V4 correlation
lease with V2 index/archive bindings, calls the private freeze SQL and returns
a separately sealed snapshot-v3. It validates candidate scope/identity/order
and exact source-time selection, retains unknown historical sandbox values,
sanitizes provider errors, and rechecks lease/cancellation after the response.
The actual PostgreSQL precision fixture now consumes this Go method; new+legacy
races passed13.781s in `/tmp/zasp-precision-repository-postgres.log`. Three related
Go races passed in `/tmp/zasp-precision-repository-full.log`; UI build exited0
in `/tmp/zasp-precision-repository-ui.log`. Expected stub failures are retained
in `/tmp/zasp-precision-repository-red.log`. Independent Superpowers review
closed with no remaining findings. This does not activate V4 correlation,
worker claiming, schema registration or deployed ingestion. No push/task credit.

The separate V4 correlator now consumes sealed precise snapshots and V2 archives.
It checks exact source time, optional process/cgroup conflicts and complete
source/sandbox/agent/session bindings, preserving unknown historical sandboxes.
Ambiguity clears assigned identity; kernel records never receive Exact confidence.
Expected stub failures are in `/tmp/zasp-precision-correlation-red.log`.
Actual PostgreSQL-to-repository-to-correlator and legacy races passed in
`/tmp/zasp-precision-correlation-postgres.log` (13.812s). Four package races
passed in `/tmp/zasp-precision-correlation-full.log`; UI build exited0 in
`/tmp/zasp-precision-correlation-ui.log`. Independent Superpowers review closed
with no findings. Receipt V4, worker dispatch and migration activation are still
open. No push or original task credit.

V4 receipt encoding/decoding now has separate entry points, canonical version
checks and an enforced1MiB serialized limit. Review reproduced and closed a
valid escaped-text overflow and corrected integration fixture predecessor
references to their actual SQL values. Final actual PostgreSQL-through-receipt
and legacy races passed14.070s; four related package races and UI build passed.
Direct-wire tests reject rehashed Exact confidence and identity conflicts.
See `2026-09-11-process-precision-receipt-evidence.md`. Worker dispatch and
migration activation remain open; no push or original task credit.

The local V4 correlation executor now selects precise freeze authority and
index V2, while historical job versions retain their own receipts. Review
reproduced and closed a graph-before-receipt-validation issue with a valid
1000-event Strong correlation. Cancellation, failure classification and renewed
window replay tests pass. Final focused worker races passed4.773s; four related
package races and UI build passed. Evidence and provider limits are recorded in
`2026-09-11-process-precision-worker-evidence.md`. Production startup/factory,
claim routing, migration activation and downstream receipt consumers remain
open. No push or original microtask credit.

Database changes must use new migration code,
not edits to already-released migrations. Revalidate rollback and all pinned
readiness fingerprints after any such schema50 draft change.
