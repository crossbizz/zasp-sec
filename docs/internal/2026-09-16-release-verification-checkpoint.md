# Recovered worktree release verification

This is local verification of the recovered implementation, not a production
deployment or proof that all 728 tasks are complete. Counts remain 534
production-available, 133 component-only and 61 external gates.

## September 16 grouped checks

### Feature-batched verification cadence and release checks

Run focused red/green tests for changed behavior during implementation. Group
integration, browser checks and independent review by cohesive feature, mapping
the evidence back to every original microtask. Run the full release checks before
publication; reuse prior expensive evidence only while its relevant inputs remain
unchanged. Tenant isolation, authorization and migration checks remain required.
This changes execution cadence, not the 728-task scope or completion criteria.

Full ESLint294fb3 passes. Lint-scope/import contracts f966b1 pass8 tests; source
imports afdfb6 pass61 files and compiled imports692c92 pass7 client/8 server
chunks. Go race run25c03e passes externalclient, database, jobqueue, agentsec-api,
healthserver and securityagent with downloads disabled and controlled loopback
permission. Canonical production release-contract tests8dd09f pass204 tests,
zero failures or skips. These are local checks, not the production release gate,
a fresh advisory scan, deployment or live provider acceptance. PostgreSQL
shared-memory cleanup and dependency-advisory authorization remain unresolved.

### Full recovered-tree Vitest verification

Initial broad run6b3a88 failed91/1919 checks. Forty-five Stytch tests failed on
loopback listen EPERM, independently reproduced by f13202; all49 Stytch contract
tests passed0b7af3 with permission for controlled local mock servers. No live
provider acceptance or credentials were used.

The remaining failures exposed stale integration contracts: the recovered
TestAuditExportRunContextConsumersPostgres lacked a CI lane, the LocalStack
restart ownership check omitted its extracted helper, and API-map expectations
omitted three existing operations. audit_a3 now includes RunContext with its
existing race/count/timeout/provider requirements. Source analysis follows
parent -> exerciseAuditExportLocalStackRestart -> launch; hostile mutations test
both edges. All227 declarations retain coverage (226 direct assignments and one
parent-owned API child). Map expectations now include getSecurityAgentAuditEvent,
listSecurityAgentActivityRuns and listSecurityAgentRunActivity without changing
their availability or weakening missing/duplicate-operation checks.

Focused265 checks3db48a pass. Independent source review found no Important
blocker, while explicitly distinguishing schema52/53 LocalStack restart coverage
from54 consumer readiness. Final full runf2e8a0 passes **1921 tests in217 files**
in83.48s, with two workers and local-loopback permission. Typecheck51b7f7,
focused lint/API coverage64cace and whitespace589333 pass. App/build inputs are
unchanged from standalone UI build309578. This is local suite evidence, not a
production rollout, PostgreSQL acceptance or full release clearance. Shared-memory
cleanup and fresh dependency-advisory authorization remain unresolved.

### M7A-90 registered reverse-read scale characterization

New full-path acceptance uses the actual registered API database login and
PostgresRepository.ListSecurityAgentActivityRuns against10,000 stopped runs in
two scopes,100 definitions per scope and50 matching typed attack-path receipts.
It checks all50 literal expected IDs over20/20/10 pages, exact cursor boundaries
and complete coverage in custom/generic modes. Reads include pinned readiness,
browser authority, whole-scope coverage and decoded envelopes under the existing
five-second repository deadline. Initial full-path run58418/da29f0 passes6.920s;
page measurements95.7–160.3ms. Setup errors e90459/d5f15b were unused fixture
arguments and a nonconforming session ID, not product defects.

The final grouped run62167/30d4ae passes24.191s, including all three candidate
query kinds plus the complete registered path, with added off-page receipt deletion:
foreign-scope gap must leave primary coverage complete, then primary-scope gap
must report partial without changing the20 related IDs. Owned fixtures are
destroyed by the existing disposable-database cleanup. No production rows are
mutated. Final full-path measurements are102.9–171.0ms per page. This is
characterization, not a claimed TDD product repair. Independent review found
no blocking issue; its direct expected cursor timestamp assertion is added and
the affected registered test passes88736/b30277 in7.519s (102.7–148.1ms/page).
The scope-integrity mutations run under the final generic-plan setting.

These measurements cover serial local registered repository calls with
owner-seeded identity and no retained execution plans. They do not prove live
authentication, HTTP/network timing, concurrent/noisy-tenant isolation,
action-plan integrity at scale or production capacity. Full-scope coverage cost
remains volume-dependent; this result does not justify a materialized cache or
weakened integrity checks. No production promotion or publication.

### M7A-90 reverse action containment access

Installed-candidate baseline7077a9 scans5,000 tenant plans and removes4,950
for both finding and session action relations. Two-scope fixtures hold10,000
distinct plans; hashes use each canonical fixture document. Earlier99c62c was
only a duplicate-hash fixture setup error, not a product failure.

Unpublished54 now adds a fingerprinted GIN(plan jsonb_path_ops) index with
explicit rollback removal and drop-drift refusal. The first grouped run
25700/e92f4f proves the index alone is insufficient: custom plans improve but
generic plans still remove4,950 rows because of the parameterized OR. Separate
mutually exclusive finding/session UNION branches preserve typed predicates,
scope and deduplication while exposing containment to generic plans. Calibration
e1bdb2 pins0a88dadd8dde5c25adb0f48d6b36eff9cd58394cb3f4a773f890914078b2a73f.
Independent review found no blocking issue in the index or branch split. Its
index-recheck accounting recommendation is included in the regression.

Final grouped verification66036/41d642 passes45.757s, including registered API
authority, audit/trigger/action custom+generic first/next plans, compiled pin,
drift refusal and rollback. Both action kinds remove zero rows across all four
plan/page combinations; measured candidate execution0.843–1.061ms versus baseline
5.835–6.136ms. These timings are local measurements, not a production SLO.
This is candidate-only fixture
evidence, not validated envelope or live-load proof. BitmapAnd can still read
all tenant index entries and the global GIN may expand shared-target fan-out;
full-scope coverage and high-fan-out work are not closed by fewer filtered rows.
No availability promotion, publication or deployment.

### M7A-90 reverse trigger access across definitions

The installed candidate SELECT now has a full-scope/kind/trigger covering index
in unpublished54, included in the existing pinned index fingerprint and dropped
on rollback. Baseline7de689 used100 receipt searches across100 definitions per
scope, plus50 run lookups. The owned fixture has10,000 runs across two scopes,
5,000 selected-scope runs and50 matching receipts. The test checks actual work,
not a required index name. An earlier one-definition test failed only because
it demanded a new index name; that was not evidence of a performance defect.

Grouped run15952/41c292 passes34.771s: registered relation APIs, audit cursor
plans, reverse trigger custom/generic first/next plans, compiled fingerprint,
index-drop drift refusal and rollback to53. Receipt searches fall100 to1;
total candidate searches are51 custom/52 generic, with zero filter removals.
Calibration4ee9d5 pins bf18a3d588b148efe127368a77de8d8abceeae7135f776dabc5766857d17f91f.
Independent review found no blocking issue; its missing-metric guard is added
and the affected test alone passes3ba4af (6.446s). Ledger/diff/format checks4475dc
pass with728 rows and unchanged classifications. No unrelated full browser or
UI build repetition is warranted by this index-only production change before
the eventual publication batch.

This is owner-prepared candidate-query evidence, not nested security-definer,
envelope expansion or production-load proof. Full-scope integrity scans, action
target lookup and high relation fan-out remain scaling work. No task promotion,
commit, push or deployment; fresh release/publication gates remain open.

### M7A-90 independently authenticated foreign-tenant relations

The existing isolated foreign browser now upgrades only its owned fixture
membership to security_admin and reloads. It checks authorized non-audit reverse
reads return exact empty complete pages, while all four forward primary-run
reads and exact/reverse primary-audit reads return safe404. The foreign audit
list must return200 as an audit-permission positive control. Its mounted
foreign-scope exact audit page must settle on not-found with no primary IDs.
Reads must leave the primary approval/audit snapshot unchanged and use no
mutation requests; owned foreign identity/session cleanup remains in finally.

Initial run44805 failede2bb5d because the test incorrectly expected audit reverse
200/empty. The repository first authorizes the exact audit row and correctly
returns404 for its absence in the foreign scope. Source inspection and review
confirmed that contract; the test/log were corrected, not production behavior.
Corrected run88918 completed exit0/d28a3a, including all prior grouped cases.
Independent review confirms the audit-contract finding is closed. Screenshot
activity-foreign-audit-denied.png in zasp-run-context-browser-ETFpX4 was visually
inspected and shows only the settled safe refusal, with no primary record data.
These are independent local authenticated contexts with owner-seeded identity,
not live identity-provider/deployment proof. Query scaling and fresh release/
publication gates remain open; counts and production availability are unchanged.

### M7A-90 forward pagination and nine-read scope matrix

The mounted batch now seeds20 additional audit fixtures after the committed
audit roundtrip, preserves the original row, and requires exact20+1 forward
pages plus Previous replacement in the audit card. Approval snapshots now
include full persisted audit rows. Nine mounted reads (all four relation kinds
in both directions plus exact audit detail) must return200, reject each wrong
expected-scope dimension409 without IDs, reject inactive membership401 without
IDs, and return200 after restoration. All reads must leave the post-seed
approval/audit snapshot unchanged and issue no mutations.

First run78778 faileda9c078 on fixture uniqueness before forward pagination:
clones reused correlation/event/run/step. Review independently found the same
issue. Each extra fixture now has its own correlation ID as well as audit ID;
the original committed row remains unchanged. Corrected run32662 completed
exit0/e5c5af, including forward paging, all nine reads and the prior four-kind,
reverse-page, UI capability and approval cases. Independent review confirms the
fixture constraint finding is closed; no remaining blocker in this increment.
This was a fixture setup failure, not a schema/product defect. Expected-scope
refusal is not independently authenticated foreign-session isolation proof.

### M7A-90 mounted pagination and permission boundaries

The four-kind browser batch now includes21 related session runs with known
creation-time/ID ordering: exact20 records, next-page exact1 with Next disabled,
and Previous replacing the page with the original20. It also checks a mismatched
environment URL refuses entity reads and clears the run links, then restores via
history. Explicit run-detail and session-events GET assertions were added.

Owned membership downgrade gives an actual-cookie relation403 with no run ID,
followed by UI reload and finally-restored membership/positive200. The full
execution/runtime snapshot must remain unchanged. First batch33520 passedd0c778,
but review found UI absence could be observed during loading. The assertion now
requires mounted downgraded navigation (Overview selected at '/', Sessions absent)
before checking all21 run IDs absent. Strengthened run52467 completed exit0
70ae3f; independent review confirms the loading false-pass finding is closed.
This verifies the server403 and the refreshed mounted capability state, not
instantaneous revocation in an idle tab without a refresh. Syntax/diff and
728-row ledger checks passda9dd1.

No production changes or production availability promotion in this increment.
Forward cursor browsing, broader relation scope/revocation matrix, query scaling
and release gates remain open; fixtures are not live ingestion/provider proof.

### M7A-90 all four entity roundtrips in one mounted batch

Session77632 completed exit0/9cd49b. The same owned browser/API/PostgreSQL suite
now checks finding, attack-path, runtime-session and audit roundtrips, with exact
entity IDs and all three scope fields in destination URLs. Existing audit reload
and back/forward assertions and approval authorization checks remain in the batch.

The path comes from the existing scoped finding.path_id. The session is one
explicit owner-seeded canonical event, whose normal database projection produces
the summary. Two distinct stopped runs have explicit typed trigger receipts and
no plans/effects. These are display/navigation prerequisites, not producer or
worker ingestion evidence. Required detail/relation GETs, visible reverse links,
read-only request checks and unchanged execution/runtime snapshots pass.

Both activity-attack_path-roundtrip.png and activity-session-roundtrip.png in
zasp-run-context-browser-Lk8bkb were visually inspected. Each shows the exact
related run and honest partial-coverage notice. Independent review found no
Critical/Important blocker. Minor follow-up: explicitly assert session events
and exact linked-run detail GETs, which current successful UI flows exercise
indirectly. No production code changed in this increment.

This closes the four-kind mounted happy-path roundtrip coverage, not relation
paging/revocation, invalid-scope transitions, query scaling or release gates.
Counts remain534/133/61; no commit, push or production promotion.

### M7A-90 finding and audit browser roundtrips

Session3247 completed successfully377751, including finding/run/finding clicks,
the previous rationale/action/approval cases, mobile layout, real local approval
decisions, foreign-scope/membership/signout and foreign-tenant denial checks.
No live provider or deployment acceptance was run.

The same feature batch now follows the exact audit row written by its real local
cancellation API: run/audit/run/audit, exact scoped URLs, reload, history back and
forward, required detail/relation GETs and unchanged approval authority.
Initial run99687 exited0/92490b, but independent review found the reload oracle
could accept previously rendered content and cancel the reload with history.back.
That pass does not prove reload completion. The strengthened test settles the
initial detail, installs an exact-response listener, clicks Reload and requires
a new200 response with the expected audit/run IDs before history traversal.
Back and forward now assert every scope query field as well. Verification
session11265 completed exit0/186c6c. Independent review confirms the reload
response boundary and history-scope findings are closed. The resulting
activity-audit-roundtrip.png in zasp-run-context-browser-4SeLvF was visually
inspected: exact audit fields and the reverse run link render correctly.
This is mounted local UI/API/database evidence with fixture prerequisites,
not deployment or live provider acceptance. Ledger checker0d94d8 validates all
728 rows; syntax and diff checks also pass.

Attack-path/session browser roundtrips, relation paging/revocation, scaling and
release gates remain open. Counts remain534/133/61, with no commit or push.

### M7A-90 mounted activity acceptance exposes an integration gap

Follow-up: production.go composes NewSecurityAgentWorkflowSurface before the
public handler. Its operation switch omitted both relation reads and exact audit
detail, sending them to the generic workflow fallback. Wrapping the existing
real HTTP-handler pagination and audit tests in that surface reproduced all
three404 failures54868e. Adding only those three switch cases makes the group
passf07376; broader SecurityAgent HTTP/workflow-surface group passesd13ba4.
Independent review found no Critical/Important blocker in the repair or finding
roundtrip check. The snapshot claim is limited to execution authority.

Browser retry35188 reached a separate existing harness failure15dad3: waiting
for all descendant animation promises returned a rejected result during drawer
updates. The wait now checks current drawer opacity and its own animation state,
without depending on cancelled child animations. Browser session71323 is the
next acceptance run. It completed the finding/run/finding roundtrip4b427e;
the screenshot activity-finding-roundtrip.png in zasp-run-context-browser-cAgvIe
was visually inspected and shows the actual scoped run link with honest partial
coverage. The suite then failed75a287: returning with navigateBrowser replaced
the CDP target and lost the existing detail-response listeners. Return now uses
the actual Security agents sidebar link and asserts the list URL, retaining the
target. Session42887 passed the roundtrip and all three rationale states, then
failedb2856f at another descendant-animation Promise.all in the recorded-action
display check. The remaining three such waits now use allSettled so cancellation
does not replace the requested DOM projection with a rejected promise value;
all content assertions remain. Independent review approved the prior current-
drawer wait and sidebar-return changes. Session3247 is the fresh grouped run;
no full pass claimed yet. Both earlier test processes are terminal and cleaned up.

Existing simulation/run-context/approval browser suite completed with exit0
(session80118, terminal7f9e89). Its assertions did not exercise the new activity
links. Visual inspection of run-context-available.png in the owned temporary
artifact directory zasp-run-context-browser-nWbZG5 showed all four activity
panels displaying not-found errors despite the exact run detail loading.

The existing suite now requires run-to-finding-to-run-to-finding clicks, exact
IDs and all three scope fields in each destination URL, real detail/relation GETs,
and unchanged execution authority. Node syntax and whitespace checks pass497756.
Mounted RED173a73 (session21868, exit1) reproduces the absent finding link: all
four panels report related activity not found in this scope. This is an unresolved
integration failure, not proof that the record is absent. Source inspection
confirms both relation operation definitions and public handler cases exist;
the next investigation must capture HTTP status/body and trace routing/authority
before changing product behavior. The disposable test process cleaned up.

No production code was changed for this check. Other activity kinds, paging,
browser history and authorization transitions remain browser acceptance work.
Counts stay534/133/61; no availability promotion, commit or push. Owner-seeded
local records and an owned identity server do not establish live provider proof.

### M7A-90 generic-plan audit cursor repair

The access-path test now extracts the actual installed forward function's audit
SELECT and prepares it under force_custom_plan and force_generic_plan. RED0a65ac
showed the generic next-page plan seeking only the scope/run prefix and filtering
21 predecessor rows. Custom-plan success alone had missed this behavior.

The query now has mutually exclusive NULL-cursor and non-NULL-cursor branches,
each ordered and limited before their ordered outer merge/limit. The non-NULL
branch exposes audit_id>cursor directly. No sentinel cursor or malformed-ID
filter changes the previous fail-closed semantics. Calibrationfb4480 produced
compiled fingerprint c408aaeaf97dcc792f493a382ac39bc44d7727af3dce03eb322d20b7d7b320f0.

Initial repair verification rejected PostgreSQL's zero-row Sort on the impossible
branch. The assertion now rejects sorts of actual records while allowing empty
branch sorts; fixture counts, exact21 output, index usage and zero filter removals
remain required. Final serial group a88079 passes28.884s: all four custom/generic
first/next cases pass with zero filtered rows, and registered relation APIs,
compiled fingerprint, drift refusal and rollback pass. Review found no blocker.

This verifies owner-prepared installed-query plans, not nested SECURITY DEFINER
plan capture, production concurrency or latency. Reverse-query indexes and the
non-audit full-scope coverage scan remain scaling work. Full browser/release
acceptance and publication are unfinished. Counts and availability unchanged.

### M7A-90 audit pagination access path

REDb6b238 established a sequential scan over 10,000 seeded audit rows: 50 match
the selected scope/run, 9,950 are filtered and the 21-row page requires a sort.
Migration54 now adds zasp_security_agent_activity_audit_v54_idx over organization,
workspace, environment, run and audit IDs. Its definition/owner/valid-ready-live
flags participate in the v54 fingerprint; down removes it. Drop-index drift must
refuse readiness, and rollback must restore53 and remove the index.

Owned calibration820008 yields compiled fingerprint
925fc5f21971d8997aef02a1d73bed18d654d69374a09790a6fd48dfd48fc065.
Serial group26dc84 passes 28.468s across access path, registered relation API,
compiled fingerprint and release rollback tests. Independent review found no
blocking issue; its fixture/result-count suggestion is implemented. Final
access-path test db3d70 passes5.819s, asserting 10,000 total/5,000 scoped/50
matching fixture rows and 21 returned rows per first/next page. Both plans use
the new index, remove zero rows by filter and avoid a sort. Local measured query
times were0.031ms/0.013ms; these are not production latency targets or promises.

The EXPLAIN queries run as the fixture owner with custom plans after ANALYZE.
They do not prove SECURITY DEFINER generic-plan behavior or end-to-end request
latency. Non-audit coverage currently can inspect a whole scope's run/plan
integrity; that remains an explicit scaling gate, as do reverse-query indexes,
broader cardinality/concurrency testing and mounted browser acceptance. No
availability promotion or push. Ledger check0131ff confirms728 rows with counts
534 production/133 component/61 external/0 missing.

### M7A-90 forward run consumers and combined UI verification

Run detail now mounts all four typed forward relation panels. Production supplies
per-destination capabilities; defaults deny reads and trigger navigation. The
existing exact-run identity/current-request checks gate publication. Unresolved
run cancellation disables every relation control. Direct and list-open tests
cover all four endpoints, scope headers/URLs, default denial, all-capability
removal and single-capability revocation while other destinations remain usable.

RED265183 reproduced missing forward links/default-deny behavior. The list-test
selector was corrected to the actual aria label; existing scoped trigger/manual
tests gained the APIProvider required by their new real relation consumers.
Production-shell tests now exercise controlled-response roundtrips for findings,
paths, sessions and audit records, without general list scans for exact links.

Final group f0a786 passes 166 tests across ten run/shell/risk/session/audit/panel/
client files plus scoped test lint. Lint/typecheck/diff63d52e pass. UI build7eb0f6
passes all five vinext stages and produces standalone output. Independent review
found no Critical/Important issue; its selective permission suggestion is covered.

All forward/reverse UI consumers are locally implemented. These tests still use
controlled HTTP responses; they do not prove mounted browser authentication,
live provider collection or production readiness. Database indexes/performance,
complete browser acceptance, fresh release gate and publication remain open.
The previously denied external dependency-advisory gate is not bypassed. No push
or production-availability promotion; M7A-90 remains component-only.

### M7A-90 runtime session reverse consumer

The production session surface now passes explicit scope, current run capability
and route navigation through both direct and list-open timelines. A relation
panel mounts only after exact session identity and event page validation succeed.
The unattributed collection is excluded, since it is not one inferred session.
Permission removal hides links without another relation request.

RED7d1816 reproduced the missing consumers. Group afd59d passes 54 tests across
session integration/list/timeline, shared relation panel and production shell,
followed by typecheck; lint/diff f9cc88 pass. Tests cover both entry paths,
expected-scope header, permission removal, mismatched detail ID, unavailable
events and unattributed exclusion. The real-client shell flow now travels from
a run's persisted trigger to session detail and back through its related-run API.
Independent review found no Critical/Important issue. Its suggested valid-page
foreign-session event case is now covered; final group 5e2ef7 passes 55 tests,
scoped lint and diff checks. That case refuses relations before any request.

All four reverse UI consumers are locally connected. Forward run panels still
remain, as do complete mounted-browser acceptance, database index/performance,
fresh UI build, release gates and publication. Controlled HTTP responses are
not live production evidence; M7A-90 stays component-only with counts unchanged.

### M7A-90 finding/path relation consumers

Finding and attack-path drawers now mount reverse relation reads beneath loaded
detail. The production shell supplies current security-agents.read capability;
permission removal hides links and makes no extra relation request. Finding
mutation locks disable relation navigation and reload. Direct and list-open
consumers preserve explicit full scope and use the typed real relation client.

RED4ccbb3 reproduced missing consumers. The first integration run also caught
invalid empty-evidence test fixtures, corrected to the existing run contract,
and an old single-alert test assumption, narrowed to its intended alert.
Independent review found list-open attack-path detail lacked selected-ID binding.
RED495ee4 proved another path's response mounted its relation reader; the fix
checks identity before publishing detail. Negative coverage now proves no
relation request is made. Successful list-open coverage exists for both kinds.
Shell tests follow both relation links through real providers/clients to exact
run detail and assert the expected-scope header without scanning general lists.

Group afbfee passes 82 tests across six shell/risk/panel/audit/client files.
Follow-up independent review confirms the identity gap is closed with no
remaining Critical/Important finding. Lint, typecheck and diff checks dd129c pass. Controlled responses remain local
component evidence, not a mounted browser or production claim. Session reverse
and run forward consumers, database index/performance, full browser acceptance,
fresh build/release gate and publication are still required. No count changes.

### M7A-90 relation panel and audit consumer

The shared relation panel reads both real API directions, shows partial coverage,
replaces pages using opaque cursor history and refuses cursor cycles. It binds
full scope, resets on entity/principal/query generation changes, aborts stale
requests and hides links during reload, permission loss and scope suspension.
Mutation locks disable its controls. Panel/client group 5bf9cf passes 34 tests.

Audit detail now mounts the reverse panel only after exact detail succeeds and
gates its reader on run capability. RED9a06d2 reproduced the missing consumer;
group ef0d46 passes 48 panel/client/audit tests. The independent reviewer found
no Critical/Important issue and requested pending-relation cancellation coverage;
that additional passing test confirms a failed detail reload aborts the reader
and a late relation response cannot restore links. Typecheck48ae28 and scoped
lint c5fb26 pass. Existing exact-audit fixtures isolate relation responses; the
new integration suite checks actual client sequencing and scoped navigation.

These are component tests with controlled HTTP responses, not mounted-browser
or production proof. Finding, path and session reverse consumers and run forward
consumers remain unfinished, along with indexes/performance, complete browser
acceptance and release gates. No push or availability promotion.

### M7A-90 strict bidirectional relation client

RED177b3a leads to typed real-client functions for both relation routes, using
explicit request-scope headers instead of mutable global selected scope. They
forward cancellation, require no-store, preserve partial coverage and validate
closed page shapes before returning data. Forward targets require matching kind
and strictly ascending canonical IDs; reverse pages reuse the run decoder and
reject duplicates. Audit-specific coverage/cardinality and request-limit/cursor
bounds are retained. Repeated returned cursors fail rather than loop.

RED9ca0ba exposed a null limit being treated as the default; only undefined now
selects the default and malformed values fail before transport. Groupd0ce8c passes
64 activity/audit/client tests plus typecheck. Lint passes2f2285 after removing an
unused test argument. Tests cover all four kinds in both directions, scope pinning,
cancellation, malformed/over-limit/duplicate pages, invalid audit pages, repeated
cursors and cacheable response refusal. Independent review found no blocker.

Opaque cross-page position and tenant provenance remain signed server/SQL
responsibilities; controlled HTTP responses are not a mounted browser proof.
Relation UI integration, database indexes/performance and full release/browser
acceptance remain pending. No availability promotion or push.

### M7A-90 registered forward HTTP API

RED86450c to GREEN982e57 registers browser-only
`GET /api/v1/security-agent-runs/{id}/activity/{kind}` for all four kinds. The
handler enforces exact browser credentials, current view and kind-specific
permissions, zero request bytes, bounded exact query fields and signed forward
cursor binding. Returned targets must match the requested kind, be strictly
ascending beyond the cursor, and obey page/continuation/coverage bounds.

Groupd765f1 passes14.918s, including registered forward handler-to-repository/SQL
audit pagination using the first HTTP response's signed next cursor. Group3f5686
passes0.875s, adding handler-level malformed page and nonadvancing continuation
refusal. Independent review found no Critical/Important issue; several requested
response-validation negatives are covered in that followup. Identity remains
injected at the handler boundary, not proved by mounted authentication.

OpenAPI/generated types and UI/API lifecycle map now include both directions.
Group46281a passes40 contract tests, lint and coverage (planned4/api_available10/
available142/public152). Typecheck e39223 passes. Typed relation client/UI wiring,
reverse-lookup indexes/performance, full mounted browser acceptance and release
gates remain unfinished. No production promotion, commit or push is claimed.

### M7A-90 forward repository boundary

REDdec331 to GREEN4b83c6 adds the forward repository for all four relation kinds.
It requires browser identity/current permissions, nonzero digest, exact request
bounds and compiled54 availability before the scoped SQL call. The closed private
envelope is decoded before exposing targets. Non-audit pages reject audit fields;
audit pages bind the run context and require canonical strictly ascending IDs
beyond the requested cursor, with exact continuation bounds. Missing runs map to
not-found; incomplete legacy nonaudit authority remains partial.

Registered adapter group055e07 passes13.875s with forward repository reads added
to the existing owned PostgreSQL matrix. Group1bcefe passes0.893s across forward
projection/repository and relation cursor/association checks, including isolated
duplicate/out-of-order audit IDs, wrong run, wrong-kind payload, conditional
permissions, digest/request refusal and cancellation. The intermediate09dd65
failure was an incorrectly ordered negative fixture; its correction includes an
explicit positive ascending-ID case and did not change production behavior.

Independent review found no Critical/Important issue. Audit row association still
depends on the pinned full-scope SQL; the returned ID list does not independently
reconstruct audit records. Forward HTTP registration, client/UI, index/performance
and mounted browser verification remain open. No production promotion or push.

### M7A-90 forward target projection and scoped SQL

RED650cce leads to typed forward finding/path/session target projection through
the validated v54 envelope. Targets are deduplicated and sorted by canonical ID,
then paged exclusively after the cursor ID. Missing trigger or relevant legacy
action arguments preserve partial coverage. Manual/evidence/environment/integration
IDs never become guessed entity links. Group292992 passes0.880s, including a
100-action plan plus distinct trigger whose101st target appears on page2.

Missing-function REDf7c44f leads to a browser-authorized forward SQL reader.
It reuses current session/membership/effective-scope checks, requires a visible
nonsimulated run, and returns a private run envelope. Audit IDs come only from
exact scoped run/audit rows with exclusive ascending bounded pagination. Forward
repository/HTTP decoding remains required before public exposure.

Grouped ea7dc3 passes23.065s including compiled fingerprint and rollback. Review
found no Critical/Important issue; requested simulated-run refusal, direct
session/audit permission checks and decoded audit context binding were added.
Followup1f186c passes17.913s including those cases, restored permission, two-page
audit continuation and explicit forward-function removal on rollback. The new
compiled54 pin is `c9178b3f81d921b5bb11628a37581887231c4b87ff90dacdbd73e19a7e4cc54e`.

This is local typed projection and owned PostgreSQL evidence, not a forward
public API or live browser proof. Forward repository/HTTP, client/UI, relation
indexes/performance and complete mounted acceptance remain pending. Availability
counts are unchanged; no commit or push is claimed.

### M7A-90 registered reverse-relation HTTP API

RED637e3e (missing dispatch) and RED1130a4 (missing registration) now lead to
`GET /api/v1/security-agent-activity/{kind}/{id}/runs`, registered with browser
session and expected-scope security. The handler requires one unambiguous browser
cookie, base view plus kind-specific permissions, exact bounded query fields and
zero request bytes. It binds signed cursor positions before repository calls,
validates returned summaries/page bounds and emits explicit coverage with no-store.

Grouped184235 passes13.034s across relevant HTTP/composition checks and an owned
registered PostgreSQL fixture. That fixture now traverses handler to real adapter
and SQL for all four kinds, including signed two-page finding navigation. Identity
is injected at the handler boundary; this is not mounted authentication or live
browser proof. Focused followup88a6fc passes1.030s with unknown-length/chunked body
refusal added after independent review. Review found no Critical/Important issue;
additional malformed path/outgoing cursor test cases remain useful.

OpenAPI/generated types now describe the strict relation page and 2048-character
cursor. OpenAPI5b5cd3 passes40 tests; lint32b194 passes. Typecheck completed without
errors in73c9ec, whose subsequent coverage check failed because the new operation
was not yet mapped. Adding its honest api_available action resolves that failure:
fd6a66 reports planned4/api_available9/available142/public151. This lifecycle label
means the API is implemented locally, not that M7A-90 is production-available.

An earlier broad selector8fd821 accidentally included an unrelated process fixture
which failed on a restricted default Go cache; it is not counted as a passing
check. Forward relation reads, client/UI integration, index/performance checks,
mounted browser acceptance and release gates remain unfinished. No push or
availability promotion occurred.

### M7A-90 principal-bound relation cursors

Cursor REDb53827 led to domain-separated HMAC cursors for both relation
directions. The signed payload binds operation, direction, kind, entity ID,
principal, all three scope IDs, limit and position. Reverse positions require
canonical UTC microsecond timestamps plus IDs; forward positions contain only
IDs and an explicit empty timestamp string. Decoding rejects noncanonical base64,
tampering, unsupported fields/versions and crossed request bindings before any
position can reach SQL.

Independent review found that a correctly signed forward timestamp of null was
being treated as empty by Go. RED58ef21 reproduced that issue. The decoder now
requires a nonnull JSON string. Group6edaee passes1.021s across cursor, typed
repository and association tests, including signed malformed JSON, duplicate,
missing and extra fields, timestamp forms, signature domain and scope/principal
binding. This is an internal cursor boundary, not HTTP integration or live
production acceptance. Followup independent source review confirms the strict
timestamp repair and finds no remaining blocker in this cursor boundary. Public
routes and forward relation reads remain pending.

### M7A-90 typed reverse-relation repository

REDfe70c3 to GREEN2a0a47 establishes the new browser-only repository boundary.
It requires current identity permissions, a nonzero session digest and compiled54
availability. Each candidate is decoded through the existing typed v54 envelope
before accepting only the requested trigger kind or supported action target.
Manual/evidence/environment/connector IDs do not imply finding/path/session
associations. Audit relations also require the exact scoped nine-field audit
record and its persisted run ID. Only run summaries leave this boundary.

Grouped4a6d95 passes1.144s across repository, typed envelopes, action arguments
and projections. Tests include cross-kind refusal, action-only relationships,
duplicate/unknown page fields, duplicate run IDs, partial empty pages, valid and
nonadvancing continuation, unsupported release, missing permissions, invalid
digests/requests, cancellation and audit continuation after its sole row.
Owned registered PostgreSQL group794f44 passes11.852s with the actual repository
and adapter now used alongside SQL reads for all successful relation matrix
cases, including action-only and receipt/action deduplication.

Independent review found no Critical/Important issue. Candidate envelopes lack
per-item timestamps and scope, so tenant provenance, row ordering and cursor
timestamp-to-row binding depend on compiled scoped SQL, not independent Go
verification. Query-error classification still deserves a dedicated repository
test. HTTP/signed cursors, forward relation pages, indexes/performance, reverse UI
and mounted end-to-end acceptance remain pending. No live deployment proof or
availability promotion is claimed.

### M7A-90 reverse-relation database candidates

The private browser-authorized related-run query now reads typed trigger,
action-target and exact audit associations with bounded descending tuple
pagination. Full organization/workspace/environment and current browser session,
CSRF, membership and kind-specific permissions are checked in SQL. The private
authorization helper is not executable by the API login.

REDe769d0 exposed false complete coverage for a missing action target. Independent
review then found that valid-looking targets could conceal altered or unbound
plans; RED17b065 reproduced it. Coverage now reports partial for missing receipts,
malformed targets, unknown actions, mismatched session IDs, missing plans with
execution authority, and inconsistent plan/run hashes, definitions or persisted
step counts/indexes/IDs/actions/input digests. These checks do not make candidate
JSON containment sufficient proof for a public association.

Grouped cb87d6 passes18.925s across registered activity reads, compiled54
fingerprint and rollback. Followup6c2762 passes9.278s, adding action-only lookup
and receipt/action duplicate suppression through decoded private envelopes.
Direct reverse-query revocation, expiration, inactive membership, role downgrade,
scope refusal and restored positive reads are included. The compiled pin is
`48284e3ecd6e9dbdbdc1a79ec33b1a7bd18747b2b4717984d7729efba2fbb2a5`.
Independent source review found no remaining Critical/Important issue in the
integrity repair. Its test-quality caveat remains: some malformed-argument
matrix cases also have invalid plan bindings, so they are not isolated proof of
each argument guard after the integrity checks were added.

All evidence is from owned, seeded PostgreSQL fixtures. Typed public repository
validation, forward relation reads, HTTP/cursor contracts, relation indexes and
performance acceptance, UI reverse lists and mounted browser acceptance remain
unfinished. No availability promotion, commit, push or deployed proof is claimed.

### M7A-90 audit detail UI and persisted run link

REDf5dede catches all four missing audit component behaviors; RED6af0e0 catches
the shell's prior unavailable branch. Exact audit activity links now mount
`SecurityAgentAuditView` using the scoped real client. The view labels workers as
actor references, renders the nine-field record and links the persisted run ID
with all three scope IDs. General audit browsing stays unchanged. Run-link
visibility depends on the session's Security Agent read capability.

Group08b4cd passes79 tests across audit view, shell, client and URL contract.
Covered: direct record read without list enumeration; audit-to-run and synthetic
popstate; scope suspension immediately hides data and aborts pending requests;
changed IDs refuse late responses; denied audit permission makes no read;
403/404/503 reload responses hide prior data and links, with no raw server-error
text rendered. Lint/typecheck3c79a6 and UI/API coverage08b4cd pass (150 public
operations;142 UI-available actions). Build e11533 passes all five vinext stages
and emits standalone output. This is local React/client evidence with controlled
responses, not real browser history, mounted authentication or deployed proof.
Complete bidirectional relation APIs and browser acceptance remain pending.

Independent UI review found no Critical/Important defect. Its minor request for
an explicit loaded-record-to-permission-denied rerender test is implemented;
the view hides both record and run link synchronously. No production code change
was needed for that case. Source reconnaissance also confirmed temporary-policy
action targets are environment IDs, so the upcoming relation query must use the
typed finding trigger receipt, never mislabel the action target as a finding.

### M7A-90 audit HTTP and client contract

HTTP RED9373bd proves the missing route/handler. Browser-only
`GET /api/v1/security-agent-audit-events/{id}` is registered with `view_audit`
and expected-scope enforcement. Handler tests cover exactly one cookie,
cookie/bearer ambiguity, body/query/method refusal, permission checks,
missing/unavailable errors, foreign responses and no-store. OpenAPI and generated
types are updated; operation counts are148 base and150 with audit exports.

Client REDeac68b proves absent decoder/read behavior (earlier27165d also had
fixture configuration errors, not product failures). Scope-race REDb61bc0 proves
that adopting the client's changed global scope is wrong; the helper now sends
the explicitly requested scope and binds all response IDs. It validates a
closed nine-field record, bounded scalar worker/event references and real UTC
microsecond timestamps, while refusing missing/no-store authority. Groupc47404
passes43 client/transport tests and changed-source lint. Newline request/response
tests pass the existing non-multiline regex; review's initial newline finding was
withdrawn after executable counter-evidence7bc072.

Go HTTP/composition/repository group4bd9da passes. OpenAPI contract/generator
group66e8b1 passes39; lint007223 passes. Owned PostgreSQL groupb87201 passes7.309s,
including the HTTP handler through the actual repository and compiled-pin
adapter with distinct browser cookies for colliding IDs in both tenants. Identity
is injected at the handler boundary in this fixture, so this is not mounted
middleware/IdP/browser proof. Independent HTTP/client review has no remaining
blocking finding. Audit UI, reverse relations and complete feature acceptance
remain pending. No push or production availability promotion.

### M7A-90 exact Security Agent audit database read

Repository follow-up: REDf92108 catches absent Go read behavior. RED91251b
shows the map-based field checker accepts duplicate keys; the new decoder uses
the existing closed audit object parser and scalar validation. GREEN2d4f6c
passes focused repository/decoder tests. Group e75f0c passes in7.090s against
the real registered PostgreSQL adapter, repository constructor and compiled54
probe, verifying both colliding tenant records, missing404 classification,
revoked/expired authorization classification and application refusal after
ACL/metadata drift. The method rejects bearer access, missing audit permission,
invalid CSRF and pre-cancelled reads before SQL; it bounds the shared release/read
deadline to five seconds and validates returned scope, IDs, text and timestamp.
Independent repository review found no Critical/Important issue. Additional
mid-query cancellation/invalid-digest test cases remain useful coverage work.
This remains local repository evidence, not a registered public HTTP endpoint.

Missing-function RED ece1b9 establishes the absent lookup. The unpublished54
fragment now provides a distinct nine-field audit projection, including worker
`actor_reference`, with no private `body`. Every read checks registered API
authority, exact browser session, CSRF, active membership and current scoped
`view_audit`, then joins the exact full-scope audit/run association. General
audit browsing and its human actor contract are unchanged.

Owned calibration cc07cd yields compiled54 fingerprint
`d46a8894cfb502cb2515f1fad008ba39166d1838271ecf6828d28f83870c0d2e`.
Grouped test a43df2 passes in15.840s: same IDs in two tenants stay separate;
foreign session/workspace/environment, wrong CSRF, role downgrade, inactive
membership and expired/revoked sessions refuse reads. Restored permissions
permit reads again. Worker execution is denied, simulated runs return no rows,
and malformed retained actor data refuses disclosure. A PUBLIC ACL grant plus
adopted live fingerprint still fails pinned readiness. Registered54 fingerprint
and rollback pass; rollback explicitly removes the audit function.

Independent bounded SQL review found no Critical/Important defect and prompted
the expanded matrix. The application must still use its compiled-v54 verifier
before the eventual repository call. No HTTP/client/UI audit implementation,
reverse-relation acceptance, live tenant/provider proof or publication is claimed.
M7A-90 remains component-only. The prior UI build is unchanged by this SQL-only
batch; a fresh release/UI verification remains required before any push.

### M7A-90 production-shell detail wiring, local UI/client evidence

The shared scoped URL contract is mounted in the production shell. Query state
survives client navigation and synthetic popstate. Exact linked findings, paths,
runtime sessions and runs use their existing real API clients without enumerating
lists; wrong organization/workspace/environment links refuse record readers and
never switch scope. Finding-to-path and run-to-trigger buttons retain exact IDs.
Audit links explicitly report unavailable exact lookup until the API batch.

REDc4ed05 catches the missing risk detail behavior and lost path ID; RED961d74
catches shell query loss and scope refusals; RED29ecc5 catches missing direct
run/session selection. REDe385c9 exposes older run responses overwriting a newer
reload. One shared cancellable detail-read owner now covers run/approval/definition
selection, including the competing-drawer regression RED ee6cb2.

Review and typecheckf88f7d caught an incorrect trigger enum assumption. The public
contract is runtime_decision/manual, not session. Migration24's persisted writers
bind runtime_decision trigger IDs to scoped session IDs; that explicit mapping is
now used. Manual triggers remain unlinked (REDb33d25). The initial dfe783 failure
also included invalid test fixtures using rationale state missing; the actual
contract is null. Fixtures were corrected without relaxing production decoding.

Grouped verificationbc5ecb passes125 tests across the URL/shell/risk/run/session
files. Typecheckaffc95 and changed-source ESLint58cec8 pass. Build5525f6 passes
all five vinext stages and emits the standalone UI. Independent follow-up review
confirms the trigger mapping and shared request ownership fixes with no remaining
blocking finding in this slice.

This uses local component tests and controlled HTTP responses through real
clients. It is not registered-PostgreSQL/browser proof or live production proof.
Exact audit lookup, persisted reverse relationships for all four entity types,
full browser history/scope-transition acceptance and publication remain required.
No commit, push or task promotion is claimed. Existing release gates remain.

### M7A-90 scoped activity URL contract, not yet mounted

The original four-way bidirectional entity/run requirement remains intact in
the activity-link design and plan. Source inspection confirms the shell currently
stores pathname only and the audit browser has no exact-record lookup. Neither
generic list landing pages nor client-side scans establish the required links.

New `app/domain/activity-links.ts` defines canonical relative destinations for
finding/path/session/audit/run records with exact Product IDs and explicit
organization/workspace/environment assertions. It refuses duplicate, extra,
missing, malformed, external and wrong-scope input without changing session scope.
This helper does not authorize a record or establish a persisted relationship.

The missing-module result a7bd15 is setup evidence only. Interface-stub RED96b09d
executes all35 tests with27 behavioral failures. GREENb526bc passes all35 after
implementation. Independent contract review found no Critical/Important issue.
Consumer integration must retain raw query input, bind the selected entity kind
to the mounted route, and account for any existing non-activity queries. Minor
additional malformed-input cases were suggested; they are not production proof.

At this earlier contract-only checkpoint, no page called the helper. The newer
UI wiring section above supersedes that limitation. Authorized reverse
relationship reads, exact audit lookup and the full browser batch remain pending.
No M7A-90 production promotion, commit or push is claimed.
TypeScript check1b4db2 and changed-source ESLint2dece6 both pass with exit0.
Ledger validationb31443 confirms728 rows,534 production-available,133
component-only,61 external and0 missing. These checks do not establish UI wiring.

### Independently authenticated foreign-tenant approval reads

Assertionsb0770f and terminalaf4fee pass using an isolated Chrome context with
an owner-seeded valid second-tenant member/scope/session. Bootstrap reconciles to
that foreign scope; its own approval list returns200/empty, while all three
first-tenant approval detail reads return404/not_found with strict non-disclosing
errors. The mounted approvals page reaches its empty state and renders none of
those IDs. Original approval authority stays unchanged. Isolated browser context
and exact owned identity/session rows are cleaned up, followed by all parent
resources. Independent review found no blocking authority issue; requested-ID
checks and settled-empty-state wait close two minor proof notes. Helper-local
cleanup if browser setup fails before returning remains a minor follow-up.

09d356 rejected a fixture session ID without the required session- prefix;
ae3e01 rejected fixture organization/member references without required prefixes.
Both are setup errors, not product RED evidence. The final setup obeys existing
validators. This establishes mounted API/UI isolation with controlled identities,
not live IdP login, production tenant isolation under load or provider execution.

### Approval read authorization boundaries

Browser batchdddb9d passes mounted list/detail positive200 controls, foreign
expected-scope409/scope_stale, inactive membership401/authentication_required,
restored membership200 and signed-out401. Every refusal has only the fixed error
envelope, with no approval ID/context. Sign-out removes all three fixture approval
IDs from the rendered page. The original approval authority snapshot stays
unchanged. All owned resources cleaned up; independent review found no blocking
issue. Snapshot coverage of the two later runs is a minor strengthening.

Initial91e9bd failed an incorrect test assumption: removing legacy scope `view`
permissions does not remove role-derived access. Migration25's effective-scope
function explicitly grants view for every supported active role. The corrected
test disables/restores the exact owned organization/principal membership in a
finally block. No product defect or fix is claimed. The409 case is stale scope
enforcement, not an authenticated foreign-tenant session. This batch does not
prove live tenant isolation, provider execution or production availability.

### Fresh-auth approval flow through the mounted browser

Browser batch6c5c49 passes after aging only the owned principal's active fixture
sessions. The stale UI exposes reauthentication and none of Approve/Reject/Cancel.
A direct decision POST with valid scope, CSRF, version, idempotency and a claimed
fresh-auth header still returns403/fresh_auth_required; approval/run/step rows and
audit/receipt counts stay unchanged. UI reauthentication uses exactly one owned
identity-provider start/callback, returns to the same URL/scope, leaves decision
authority untouched and restores the Approve control. The subsequent approval
commits normally. Cancellation and rejection also pass in the same run.

All owned resources cleaned up. Independent review found no blocking issue;
exact-session narrowing of fixture aging is a minor follow-up. This proves
controlled-IdP freshness enforcement after fixture-induced aging, not natural
elapsed expiration, live IdP/MFA assurance or live provider execution. The updated
rejection screenshot was inspected after waiting for drawer animation completion:
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-8ZdsSo/approval-rejected-committed.png`.
No product code, schema pin or production availability classification changed.

### Browser cancellation commits through the product API

Expanded browser batch86c024 passes all three UI decision branches. Approve and
reject use distinct owner-seeded runs/plans/approvals, without resetting the
committed cancellation. Each emits exactly one POST and persists version2 with
one audit/receipt and zero effects. Approve queues/authorizes; reject moves the
run to needs_human and cancels its step. All owned resources cleaned up.
Independent review found no blocking issue. Cross-case unchanged snapshots are
a minor strengthening. Both new screenshots under
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-9eXhCW/`
were inspected: approval-approved-committed.png and approval-rejected-committed.png.
The rejection capture catches a drawer animation and is not final-layout proof.
Both show version2 and context unavailable until an explicit refresh, preserving
the decision receipt. Fresh-auth prompting, denied identities, four-action
browser coverage and live provider effects are not established by this batch.

Owned browser assertionsf045f2 and terminaldb5082 pass against compiled54. After
explicitly resetting only the owned display fixture to waiting approval and
removing seeded effects/controls, the real UI submits exactly one cancellation
POST. Independent owner reads confirm approval cancelled/version2, run and step
cancelled, exactly one decision audit and receipt, and zero effects. A subsequent
UI context refresh is read-only and leaves authority snapshots unchanged.

All owned resources cleaned up; affected harness suite536453 passes55 with2
explicit container opt-in skips. Independent source review found no blocking
issue. Minor: explicitly capture the refresh response instead of relying on
context disappearing with the decision receipt and returning after refresh.
The cancellation screenshot was inspected at
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-hlE6mj/approval-cancelled-committed.png`;
it shows refreshed context but is scrolled below the state badge, so durable
state proof comes from assertions, not that screenshot. This is one real browser
cancellation with seeded temporary-policy prerequisites, not all browser decision
branches, production identity, live provider execution or release publication.

### Committed approval decisions and replay

Expanded matrix4cf793 now passes8.077s across all four actions (finding response,
temporary policy, session isolation, connector revocation) and all three decisions.
Each of12 committed cases has a distinct plan/run/idempotency key and checks the
selected action, state transition, exact replay, unchanged context and one audit
and receipt. Owned PostgreSQL joined. Independent review found no Critical or
Important issue; action-specific failure diagnostics are a minor follow-up.
This closes the four-action registered-repository decision matrix, not HTTP role
or fresh-auth enforcement, browser submission, full multi-step lifecycle or
provider execution. No production code or availability class changed.

Grouped PostgreSQL testaa266d passes7.239s with committed approved, rejected and
cancelled finding-approval decisions through the actual registered54 repository.
Each branch reads context before/after, checks version2, checks the literal
run/step state transition, replays the same idempotency key, compares the entire
receipt except its replay flag, and verifies exactly one audit and receipt.
Owned PostgreSQL joined normally. No provider action worker was run.

Initial4bc131 failed fixture setup: cloned plans retained a hash constrained to
be unique within scope. Distinct fixture plan content, canonical hashes and
synchronized run/step/approval bindings fix setup. This is not a product RED or
a product code change. Independent review's Important fixture finding is closed;
no further Important source finding. These tests use seeded identities/runs and
do not prove HTTP fresh-auth enforcement, all-action decisions, browser decision
submission, provider execution or production availability. Those gates stay open.

### Scoped approval-page reuse verification

The page now reuses verified run context once per distinct run within a single
request and fixed organization/workspace/environment. Each approval still gets
its own scoped row, plan-hash, step and authorization checks. The private assembly
helper is owner-only; API-role direct invocation must fail with42501. Independent
source review found no Critical/Important issue. Its mixed-run follow-up is now
covered by comparing all six rows across two runs with direct-detail reads.

Fresh grouped test30d04a passes all three projection, compiled fingerprint and
rollback tests in15.692s. All owned PostgreSQL processes joined normally.
Samplesfc94e5 for100 approvals sharing100 steps are37.592916ms,37.519417ms and
38.823666ms, each113753 bytes through the real Go decoder. Literal selected
action/target and step identity checks pass. The earlier750ms guard failed in
a9bc2b before reuse; the current implementation passes it.

Current unpublished54 fingerprint:
`17f6f97d3c291ae1b8f53af9583a027a504c9a9ea90313e52ccd46eb09e19fbf`.
Fresh browser batch573a84 now passes against this pin. It runs simulation
no-execution checks and owner-seeded run/action/approval display through the
registered SQL, actual API and built UI. All three approval rationale states
pass; mobile viewport/dialog/body/header widths are375px without horizontal
overflow. All owned processes cleaned up and the command exited0. I inspected
available, withheld, missing and mobile approval screenshots in
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-DTny7F/`.
This supersedes predecessor-pin browser evidence for these same display checks.
These samples do not prove reference-load HTTP p95, a page of
100 distinct large runs, live provider operation or production availability.
No push or task classification change is claimed.

### Full approval-page latency characterization

Owned PostgreSQL/API-role testabdd98 passes structural checks for100 approvals
sharing one100-step run, with a113753-byte private page decoded by the real Go
page validator. Three sequential local query+decode samples took1.484460s,
1.475107s and1.518110s. This is not reference-load API p95 acceptance. It already
exceeds the plan's750ms standard-API target before HTTP/rendering, so performance
remains an implementation gate. The SQL page currently recomputes the full run
context once per approval; next work is page-local reuse of verified run context
without accepting caller-forged context or weakening full-scope approval binding.
Initial52ed83 was fixture parameter type setup failure, not behavioral RED.
No schema/pin or product implementation changed in this characterization.

### Approval rationale and mobile follow-up

Owned browser47aa21 passes available (redacted), withheld (oversized) and missing
approval rationale through the actual registered54 API and built UI. Receipt
snapshots are included in the read-only authority comparison; explicit response
states are checked. Mobile RED473689 measured375px viewport/body client width
but568px body scroll width. Screenshot inspection identified the unbroken plan
hash. Scoped overflow-wrap:anywhere fixes it; build9c487c and compiled imports
370ec1 pass. Browser47aa21 measures viewport375, drawer bounds0..375 and both
header/body client and scroll widths375. All owned resources joined, with no
browser console errors. Independent review's Important viewport-oracle gap was
fixed by asserting effective viewport and drawer bounds, not just inner overflow.
Four screenshots in
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-JtzZsB/`
were inspected: approval-context-available/withheld/missing/mobile.png.
This is seeded display proof. Mobile pending controls/available rationale, actual
SQL decisions, page performance and publication remain open.

### Approval context authority design and list-response prerequisite

The approval-context SQL detail/page projections and pure Go validator now exist,
and repository/HTTP integration is now implemented. Repository behavioral
REDe97aff and HTTP RED9e7da3 precede grouped race59ca19 and final review-follow-up
76ecf5 (2.053s). The real handlers validate context before opt-out and preserve
legacy shape unless the header is exactly one v1 value. Registered capability
selects full-scope detail/page SQL; errors do not fall back. These repository
tests use controlled database responses, not actual registered repository reads.
Independent review found no Critical/Important source issue. Its stale-map
assertion weakness was repaired, and corrupt-page/list-probe negatives added.
Actual registered repository acceptance is now verified in groupedf1274f
(7.392s), using real constructors/release probing and API-role reads for four
actions in two tenants, plus unfiltered two-page cursor traversal. Controlled
capability-absent/false routing checks preserve the legacy path. The real test
first failed7566a3 because the new query omitted NULLIF normalization for empty
optional state/run/cursor arguments. The repair passesc7a038 and expandedf1274f;
schema54/pin unchanged. Follow-up review found no blocking issue. Exact equality
of traversed IDs to the filtered-page ID set remains optional test strengthening.
OpenAPI/generated types and client integration now pass groupedab7045 (136
client/UI tests, typecheck), plus39/39 OpenAPI tests and scoped lint244487.
Behavioral RED239ca8 rejected valid context for all four actions; RED624d77
observed absent list/detail opt-in headers. The real client now sends v1 and
accepts both valid context and legacy omission. Strict decoding binds action to
effect/risk, requester state/ID, target/hash/catalog/reason and bounded rationale.
Independent source review found no Critical/Important issue; explicit undefined
context is still treated as omission, a minor case not expressible in JSON.
UI rendering now has mounted approval fields in pending/history rows and the
detail drawer, with separate persisted-step reason, catalog risk and inert-text
rationale. RED56d172 precedes grouped107 tests/scoped lintcd7f56; typecheck1bcb50
passes before the two test-only additions. Missing/withheld read-only cases and
HTML-like inert rationale are covered. Production build7436ef passes all five
stages, compiled imports06a0fc pass7 client/8 server chunks. Independent UI review
found no Critical/Important issue; a richer row accessible description remains
a minor follow-up, now resolved by row aria-describedby. Explicit terminal-only
read-only context refresh is implemented with ID/version and all non-context
receipt fields checked before display substitution. Read failures cannot undo
the decision or trigger mutation retry. RED4be829 precedes89 tests/typecheck
e12e5f and expanded91 tests/lint/production buildf9d99a; compiled imports a8d2fa
pass7 client/8 server chunks. Independent review found no Critical/Important issue.
Deferred close/switch response coverage remains a minor follow-up. The isolated
actual browser/API acceptance now passes59194c, terminalbc9a0c after all owned
resources joined. It uses an owner-seeded temporary-policy approval, first pending
with an available requester and then rejected with withheld unsafe requester text.
Actual list/detail reads and mounted drawer assertions verify target/action,
requester, missing rationale, persisted reason/catalog risk and accessible row
description. Scoped plans/controls/approvals/execution snapshots remain unchanged
and product network traffic is read-only. Browser console errors are empty.
Both desktop1440x1000 approval screenshots under
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-rSRzmL/`
were inspected: `approval-context-available.png` and `approval-context-withheld.png`.
Affected harness lifecycle testsb07a46 pass55/0fail/2 opt-in container skips.
Independent harness review found no blocking issue; explicit response-state and
list-section categorization assertions remain a minor strengthening. Mobile,
actual-browser available/withheld approval rationale, real decision execution
and page performance remain open. Mounted fixtures and supplied
cancellation receipts are not live-user or actual SQL decision proof. Fresh owned
PostgreSQL check56f724 passes5.856s with exact four-action/two-tenant values,
two-page cursor traversal, safe/withheld requester, foreign environment refusal,
altered approval hash refusal and authorization mismatch refusal. Check302001
previously failed because the test expected55000 while the existing v24 strict
plan lookup correctly refused withP0002. No production behavior changed to make
that assertion pass. Independent SQL review found no Critical/Important issue;
repeated full-run projection per approval still needs page-performance acceptance.
The compiled54 pin is
`17b48f5b7e28dd239f5a9de27874da046e7c4823bce875dabd1048d4f2d85766`.
Grouped projection/fingerprint/rollback checks6bf0f1 passed16.809s before these
test-only extensions. Earlier4e94ac fingerprint evidence is historical.

The pure approval-context validator is implemented in
`security_agent_approval_context.go`.
It binds approval/run/step and equal valid plan hashes, catalog/action/effect/TTL,
returns fixed typed fields, withholds non-product-ID requester text and sanitizes
only accepted plan-bound rationale. Null legacy arguments preserve null target.
Initialcc8870 was an undefined-function setup failure, not behavioral RED proof.
Local grouped racea3807b passes2.044s; valid-but-foreign IDs/hashes, contradictory
effect/TTL and receipt run/hash/outcome tests passd1357e, joined terminal51484c.
Independent review found no Critical/Important source issue. Its final malformed
and oversized rationale cases pass grouped racea6df72 (1.862s).
The SQL path binds agent ownership, tenant scope and actual plan-content hash;
end-to-end context display and live-user authentication acceptance remain open.
JSONB is the intended private boundary; duplicate raw JSON keys remain an existing
strict-decoder limitation. No source-ready claim here proves API reachability.

Source-backed M7A-88/89 context design/plan are in
`2026-09-16-security-agent-approval-context-design.md` and
`2026-09-16-security-agent-approval-context-plan.md`. Stored approval requester and
plan binding exist, but the public context is not yet implemented. The design
requires exact header compatibility, selected-step binding, product-ID-only
requester disclosure, persisted authorization reason and versioned catalog risk.
It does not infer targets from evidence IDs or identify worker labels as users.

Tracing this path found list-response validation missing at the public handler
interface while detail responses were validated. REDd4e64c returned200 for an
unsafe effect sentinel, duplicate IDs, wrong state/run filter and incomplete
cursor. The handler now validates each approval, bound, filters, unique IDs and
cursor shape before serializing. Initial grouped handler/fresh-auth racea275f2
passes1.863s. Added positive cursor and distinct-ID over-limit cases pass grouped
race9f8c30 (1.858s), including existing valid-empty-page coverage. Independent
bounded source review found no Critical/Important issue. Its remaining minor
negative cursor cases (timestamp-only, malformed timestamp/ID, empty-with-cursor)
stay on the context-batch test checklist; not every new branch has a direct case.
This is interface defense in depth with a controlled repository response, not
proof of a live PostgreSQL disclosure; that repository already validates items.
No migration/pin/UI input changed in this prerequisite; approval context remains
unfinished and task availability counts do not change.

### Approval cancellation gap and action-decoder acceptance

Original M7A-89 requires Approve/Deny/Cancel. Source inspection found Cancel
missing from ApprovalDetail despite the existing client/handler supporting the
cancelled decision. New mounted test RED4b34ea reproduces the missing control;
two stale/read-only negative cases already passed. The UI now routes cancellation
through existing fresh-auth, pending-state, write-authority and retained-intent
guards. The generic retry control is separate from permission to approve an
irreversible action, allowing a lost cancellation response to retry its exact
id/version/decision/idempotency key while competing decisions and dismissal stay
locked. No server permission or decision contract changed.

Grouped UI/client db08c9 passes156 tests across4 files; typecheck238cd7 and scoped
ESLintabbdf0 pass. That group includes19 added malformed enum/field/TTL and
old-server-omission decoder cases (earlier decoder-only1d3a1d72/72). They prove
rejection and compatibility, not19 successful-payload cases. Independent review
found no Critical/Important issue. Optional rejection-retry characterization for
an irreversible approval remains a follow-up; cancellation retry is covered.
The mocked transport UI tests do not prove actual server cancellation execution.
Production build session10250 is terminal PASS5d8202, all five stages complete.
Compiled-import119731 passes7 client/8 server chunks. An initial invocation
without --compiled was rejected before scanning; it is not verification evidence.

Next original-scope gaps identified from source: M7A-88 approval list lacks action,
agent, target and requester metadata; M7A-89 detail lacks explicit reason/risk
evidence. Existing expected-effect/TTL/evidence and fresh-auth controls do not
substitute for those missing requirements. Both tasks remain component-only.

### Persisted action-details feature batch, unpublished54

Follow-up database acceptance8140c3 passes (5.858s), including eight new actual
API-role refusal cases: tampered content with a stale hash; rehashed foreign step,
wrong action, wrong index and foreign environment scope; empty/malformed step
arrays; and two matching controls. Each case requires SQLSTATE55000 and the fixed
authority error, restores the owned fixture and verifies the read works again.
The existing four-action/two-tenant and assembled cleanup checks pass in the same
run, with joined PostgreSQL cleanup. These characterize existing guards; no
production code/pin changed and no behavioral RED/GREEN repair is claimed.
Independent review found no Critical/Important issue. Its minor fixture-scope
note is repaired: hash synchronization now constrains the complete scope/run.
The empty-array case is named accurately and does not prove absent legacy steps.
Post-review rerunaccbf6 passes in5.912s with joined owned PostgreSQL cleanup.
The subsequent same-organization collision batch5e2153 passes in5.909s with joined
owned PostgreSQL cleanup. Two environments share organization/workspace/run/step
IDs but persist expected versions2/7, temporary TTLs120/240 and session TTLs300/600.
The second alone has unknown_outcome/pending effects and a fixed control expiry.
Restricted API-role reads decoded through the real Go envelope retain these
differences without disclosing protected sentinel fields. This tests scoped
database projection, not user-session authorization or live execution. Initial
attempt2b8d21 failed to compile a test timestamp assertion; it was a test setup
error, not a product regression or behavioral RED. Independent review found no
Critical/Important issue and confirmed two-direction contamination assertions.
Recorded result/cleanup browser follow-up282837 now passes through registered54,
actual authenticated HTTP, strict client and mounted UI: known_failure with an
outcome/digest; unknown_outcome with neither; temporary-policy cleanup_pending
without an outcome/digest, with120-second TTL and independent control expiry.
Application evidence is failed/inconclusive/unavailable respectively; pending
cleanup never becomes verified. Protected argument sentinels remain absent.
Each state is deliberately owner-seeded, not actual failure or cleanup execution.
All owned processes joined. Production code/build inputs are unchanged.

Review found no Critical/Important source issue. Its minor no-mutation coverage
note prompted snapshots of complete scoped plan/control rows in addition to the
existing runs/steps/approvals/effects/finding snapshot. Post-repair browser282837
proves those rows remain unchanged and all display network requests are reads.
Known-failure and cleanup-pending screenshots were visually inspected at
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-mC4Kmf/`.
The unknown-outcome screenshot was captured, not separately visually inspected.
This is single-step finding/temporary-policy display acceptance, not all four
actions executed in the browser, complete mobile/accessibility acceptance or live
production proof. Follow-up review of the snapshot repair found no
Critical/Important issue and closed the minor coverage note.

Affected harness tests48d472 pass55/0fail/2 opt-in skips. Earlier5e521a failed
because this invocation omitted PostgreSQL tools from PATH; corrected concurrent
attempt2a0ca5 hit host shared-memory ID exhaustion during its actual SIGTERM
PostgreSQL test. Serial rerun after browser cleanup passes. Keep DB-owning harness
tests serial with browser/Go PostgreSQL work; they are not purely static checks.

M7A-87 now has fixed allowlisted arguments for all four actions, persisted result
and control expiry, action TTL, rollback support/state, and separate application
and cleanup verification. SQL binds scope/run/plan/step/action; Go validates before
exact-single-header negotiation; the strict generated client and real RunDetail
render typed fields. Missing evidence stays unavailable. These are local component
changes, not production availability or completion of all M7A-87 acceptance.

The unpublished54 fingerprint changed to
`4e94ac9824a1a523725f22779050a77a226c8d4f49bebe53ca7c6d1dd5939f27`.
Earlier pin evidence below is historical. Schema53 is unchanged.

Recorded feature-batch evidence:

- Envelope behavior RED51b2b7 and HTTP negotiation/unsafe-authority RED575ab3
  precede grouped race GREEN609b4a. Initial undefined-function failures are setup
  failures, not behavioral RED proof.
- Review found cleanup_pending without outcome/digest was refused and leased
  partial cleanup was labeled not started. Behavioral RED8f5e2c precedes repair;
  grouped action arguments/projection/HTTP race1c3946 passes.
- Registered PostgreSQL8df616 proves four actions, colliding run/step IDs across
  two tenants, mixed-scope refusal and protected argument omission. Current-pin
  consumer/release/retention grouped racecd7611 passes in112.191s.
- Expanded registered PostgreSQL0f4336 passes in6.989s. The real assembled claim
  function moves two owner-seeded stopped histories to leased/cleanup_pending,
  both with absent outcome/digest. Scoped reads preserve pending cleanup and
  pending application without inventing success. Seeded signed-target fields
  are fixtures, not actual delivery or provider execution.
- Client/UI group343b91 passes132 tests. Added mounted result, unknown-outcome,
  cleanup and TTL-versus-expiry cases pass50cebf39/39. Typecheck/scoped lintccdd94,
  OpenAPI reproducibilityeaf14839/39, production UI buildb81c50 and compiled-import
  check64b6b3 pass. Later changes were test-only.
- Owned rebuilt browser4a03b5 passes available/withheld/missing rationale states
  plus finding-action arguments, protected sentinel absence in HTTP/DOM, navigation
  geometry, no console errors, unchanged execution snapshots and joined cleanup.
  Available screenshot was inspected at
  `/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-Eiwz0N/run-context-available.png`.
  The stopped run is explicitly owner-seeded from a real simulation. This is not
  browser execution of all four actions or live-provider planning.
- Pending harness session9677 was joined in the continuation: terminal55dbe1,
  exit0,55 passed/0 failed/2 opt-in skips. Earlier sandbox failures2509d8 were
  permission/process restrictions; this permitted run supersedes that attempt.

Independent feature review closed its two blocking cleanup findings and found no
new Critical/Important source issue. Follow-up review of the added mounted cases
closed the coverage note with no blocking source issue. The follow-up above adds
SQL tampered-content/binding and ambiguous-control refusals. Remaining acceptance
includes full release and live execution evidence. The bounded result/cleanup
browser and same-organization collision follow-ups are recorded above. Keep unproved compound plan checkboxes
open. Fresh approved advisory evidence and release/publication gates remain open;
no commit, push, deployment or availability promotion follows this batch.

### Run-context review and action-detail binding prerequisite

The complete M7A-86 source review found no Critical/Important issue. Its optional
duplicate-JSON-key hardening note remains open; jsonb authority output currently
normalizes keys before Go decoding. Its suggested multi-step UI characterization
now passes33/33 (session44917 terminal b486a3), with scoped ESLint cbe924 and
typecheck b3c30c. The test uses the actual decoder and RunDetail, literal ordered
steps and contradictory rationale, not the separate simulation component.

M7A-87 source investigation found `validSecurityAgentRunDetail` silently replacing
duplicate plan IDs in its map and accepting duplicate execution references.
New repository-decoder tests reproduced both defects (RED c73724); the distinct
two-step positive case passed. Unique membership guards now pass the grouped
race suite5d5ac0 (1.916s), alongside context-envelope, context-header and budget
negotiation tests. Independent grouped review found no Critical/Important issue.
This is a binding prerequisite, not completion of the action-detail API/UI.
No migration/pin changed, no release gate was bypassed and nothing was pushed.

### Mounted54 run-context display

Explicit `ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION_ONLY=true` plus
`ZASP_COMBINED_E2E_SECURITY_AGENT_RUN_CONTEXT=true` selects registered54 in
`scripts/production-combined-e2e.mjs`; default simulation48 is preserved.
Mode validation behavior RED433d05 precedes implementation. Affected harness
batch d0db4a passes55 tests with2 unrelated opt-in skips; sandbox attempt dd74ee
failed at local permissions plus an extracted test's missing mode binding.
Scoped lint b32f90 and syntax04f708 pass.

First browser attempt f62e58 correctly found simulations absent from execution
reads. A separate owner-seeded stopped run now uses the real UI simulation's
steps with distinct fixture plan content and a content-derived hash. Duplicate
plan-hash failure92a8e2 reproduced that uniqueness boundary before correction.
Independent review closed the hash and missing rendered trigger/evidence findings.
No product read filter or uniqueness constraint was weakened.

Functional browser33ed95 passes all available/withheld/missing rationale states;
initial screenshots caught a drawer transition, so visual rerun84a553 explicitly
waits for real animation completion at1440x1000. All three retained screenshots
were viewed: `/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-gkmCTx/`.
Real scoped HTTP and DOM agree on redaction, trigger kind/id/version, evidence and
the single plan step's deterministic label. Console errors and unexpected read-flow
mutations are absent; execution snapshots are unchanged; owned processes cleanly
stop. Controlled identity and seeded stopped run/trigger/receipt do not prove live
provider planning, multi-tenant browser cutover or production deployment.

Visual inspection also found a launch defect outside the drawer: production
sidebar links run together. `ZaspProductionApp.tsx` renders a plain `nav` while
existing link layout/active styles target `.nav-group`. Next UI batch must add a
real-browser layout assertion, repair production navigation without demo imports,
and rebuild/verify. Full feature and release acceptance remain open.

### Production desktop navigation repair

Browser geometry REDac4601 reproduces the preceding launch defect against the
actual mounted production shell: anchors lacked full-height click targets.
Four existing CSS selector lists now also match `.production-app .sidebar > nav`
and its links, including selection from existing `aria-current="page"`. Routing,
capability filtering, session state and demo imports are untouched.

Grouped UI checks f977d8 pass41/41. Production buildd8047f completes all five
stages; compiled-import6eb571 passes7 client/8 server chunks. Rebuilt browser
GREEN9dd131 proves distinct nonoverlapping36px-or-taller link rows and exactly
one visually selected Security Agents route, alongside available/withheld/missing
run context, HTTP redaction and unchanged execution authority. All owned processes
stop. Screenshot visually inspected:
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-dOGfJD/run-context-available.png`.
Independent bounded review found no Critical/Important issue. This closes the
observed desktop layout bug, not mobile access, keyboard navigation, contrast
compliance or whole-product usability. Complete run-context source review is
in progress, and dependency-advisory/release/publication gates remain open.

### Completed race-child orderly restart

Session29163 is terminal PASS720a53 (556.011s). Output24dc60 records two complete
traversals (117.247s/114.548s),100002 events/101 chunks/98028101 bytes, API A/B
replacement and terminal-ready replay with102 PUTs/zero repeats. All owned API,
publisher, executor, replay and PostgreSQL processes joined. This closes the
pending race-child orderly-restart lane, not crash recovery, deployed memory,
live AWS or schema54 browser acceptance. Race-child RSS remains diagnostic only.

### Registered54 reservation retention

New `TestSecurityAgentRunContextBudgetRetentionPostgres` checks owner-seeded
unknown and complete known-zero provider accounting plus stable step reservations.
Every column in six populated tables is unchanged after actual53->54 upgrade
and54->53 rollback. Explicit version checks prevent a no-op migration from
satisfying the test, and exact compiled53 readiness must return afterward.
Initial characterization ae98d1 passes7.001s; after independent review's version
assertion, grouped retention/release race e0d9cb passes12.553s with both owned
PostgreSQL instances joined. No production code changed and no TDD repair claim
is made. Review found no Critical/Important issue. This is migration retention
proof, not provider execution, concurrency, multi-tenant cutover, all53 data
families or live deployment. Ledger check90d732 validates all728 rows unchanged.

### Feature-batched verification policy

The user explicitly requested grouped testing to reduce implementation delay.
Use focused RED/GREEN tests while changing behavior, then one affected integration
batch and independent review covering every included microtask. Run required
release checks and the UI build before publication. Do not repeat an expensive
unchanged check unless a relevant source, dependency, configuration or environment
change invalidates its evidence. Record the tested scope and invalidation reason
when a repeat is necessary; a shared run may support multiple task IDs but cannot
replace any task's acceptance requirement or live-production gate.

The prior response agreed to this policy but did not itself implement product
work. This continuation revalidated the existing memory process instead of
starting a duplicate: session87517 returned live output34c88c, joining executor
53197 after3m4.571s with five lease renewals and one queue ACK. The parent still
owns remaining sensitivity/traversal checks; this is not a terminal pair result.

Independent source review also reconfirmed M7A-86's remaining product gap.
RunDetail currently renders evidence, ordered steps and authorization, but the
public Go detail type and rendered UI have neither trigger context nor an AI
rationale projection. The accepted planner receipt stores planner_summary;
that field must not be exposed without bounded redaction, correct receipt/plan
binding and strict-client rollout compatibility. Source review is planning
evidence, not implementation or acceptance. No status count changes follow.

### Registered54 run-context database slice

CLI and audit-configuration follow-up: focused RED2c3634 reproduced missing
up-to-54/down-to-53 commands and rejection of54 configuration/registration.
Explicit commands now preserve default49 and historical refusal boundaries;
after principal registration the executable checks compiled54 readiness.
ConfigureAuditExports, RegisterAuditExportAPI and RegisterAuditExportWorkers
select exact52/53/54 registry identities with pre/post compiled readiness in the
same transaction. Focused race438562 passes. Real executable lane54 passes9eaf20
(race,48.946s): preflight, upgrade/retry, historical refusal, exact53 rollback,
audit API/worker principal registration and policy rotation on54. No migration
SQL or pin changed in this slice. Independent review found no blocking issue.

Actual audit API factory, stored-session authentication and HTTP create/replay/
queued-read on54 pass62f52e (race,10.405s), including scope/CSRF/permission refusal
and no duplicate durable effects. Unrelated routes and storage adapters are
controlled fixtures; this is not completed export bytes, live storage or browser
acceptance. Audit worker54 lifecycle and stronger application-supplied54 pin
enforcement across audit API/worker adapters remain explicit follow-ups.
Additional migration regression82898 is terminal FAILa99670. Its name filter
excluded Postgres/Binary-named tests but still selected PostgreSQL-using tests.
Failures include initdb and two stale unsupported54 assertions. The latter now
use unsupported55, retaining positive54 coverage and historical refusal checks;
focused raceaa6723 passes (1.796s), with independent review approval. Migrations
package passed3.193s in the failed aggregate. No aggregate success is claimed.

Normal numeric memory rerun48084 is terminal PASS13df28 (1237.129s), all three
small/full pairs and cleanup complete. N3 API RSS48611328->41861120 (growth0),
executor72056832->76611584 (growth4554752), publisher50855936->51003392
(diagnostic only). API/executor retain unchanged192MiB peak/48MiB growth gates.
Each full case traverses100002 events/101 chunks/98028101 bytes twice. This proves
the pinned binaries for that run, not deployment-wide RAM or later schema54 work.
Current UI production build passes2292d4, including all five vinext stages.

Orderly restart76263 failed659c7d before database startup. Direct initdb diagnostic
596e7e identifies shmget shared-memory ID exhaustion;26GiB disk remains free.
Read-only IPC/process inventorya30d90 and exact postmaster checkbed8b1 identify
PID56794/segment166002698 as the retained fixture from terminal failureceb32f.
No other shared-memory segments or unrelated processes are authorized for cleanup.
The failed restart root1349859791 remains retained for diagnosis. No restart
acceptance or whole-release success is claimed.
Exact owned-fixture cleanupd2bf97 confirms PID56794 stopped normally and
segment166002698 disappeared. Its files were preserved. Other processes and
shared-memory segments were untouched. Database-heavy checks must run serially
while host shared-memory capacity is constrained; the reviewed CLI corrections
and current UI build do not require additional database processes.
Restart rerun52669 is confirmed live byc6495e with owned PostgreSQL ready under
root3676700916/fixture3087765430. It is not yet a terminal acceptance result.
Later terminal9e1927 supersedes that pending state: PASS399.162s. API A/B separate
lifetimes, membership403/401 with zero storage reads,100002 events/101 chunks/
98028101 bytes, repeat traversal and exact ready replay pass. Replay adds no PUTs
or durable changes; all owned processes join, including PostgreSQL70273. This is
the non-race child numeric restart lane; the race-child lane remains separate.
Current compiled production-import check9eb1b0 passes (7 client/8 server chunks).

Audit54 compiled-trust follow-up: RED562a65 -> focused race71133e; expanded
panic/cancellation coverage1a75a5 passes. API/executor/outbox readiness now calls
the actual database's uncached54 application-pin capability before legacy52
readiness. Production API tracing forwards it; production worker composition
uses the concrete adapter. No claim is made about arbitrary hidden-capability
decorators. Affected worker regressionff8de6 passes8.463s with local loopback
permission; prior9b3e1e failed at sandbox-denied listen, not a product assertion.
Independent review found no new blocking source issue beyond the known missing
client-ready EXECUTE grants for audit worker/outbox. New real-DB consumer and
completed-worker54 coverage awaits the live restart lane52669 releasing the
single available shared-memory slot. No SQL grant/pin change is verified yet.

Subsequent registered54 audit verification supersedes that pending grant/pin
state. REDb111ad identifies missing worker/outbox EXECUTE on54 client-ready.
Grant only those two roles that boolean readiness function; no table privilege
changes. Owned calibration3012a2 yields the new compiled54 fingerprint
7df9718bea4f3866dcdb677b18ddfd30a1fe9e18c3ce23ac64a5af6010c058c7.
Grouped race dc2f20 passes46.399s: exact fingerprint, registered lifecycle,
API/ingest/planner/action consumers, public Get, and audit principals52->53->54->53.
The adversarial control deliberately grants PUBLIC access to54 client-ready and
rewrites SQL readiness's embedded fingerprint plus stored metadata; inherited
SQL readiness accepts this coherent rewrite while application-pinned checks
refuse it. Restoration and rollback restore readiness. All fixture DBs join.
This is local registered-database proof, not live deployment or worker execution.

Completed-worker observer was hiding54 capability: RED7f8db0 precedes forwarding
repair; focused race3f2009 passes2.190s. The observer refuses a missing capability
instead of silently bypassing it. Actual completed-worker and paged HTTP matrix
52/53/54 is running in session51214; controlled storage/seeded wakeup limitations
remain. Independent follow-up source review requested; no milestone promotion.
Matrix51214 terminal PASS555bc8 (race,102.109s) supersedes its pending state:
52/53/54 actual worker completion and authenticated paged HTTP,1006 events/two
chunks/manifest, lost-response recovery, fresh replay without new writes and24
provider-fault subcases pass. Each owned PostgreSQL process joins. The worker
observer forwards compiled54 trust; this is actual executor composition but not
durable outbox publication54 or live AWS. Independent review found no blocking
finding; full migrations package131e1c passes2.910s. Deployment54 configuration,
mounted-browser acceptance and final release publication remain open.
Race-child orderly restart lane started as session29163 (e09d42), with the current
source and ZASP_AUDIT_HTTP_SIZE_BUILD=race. It has no terminal result yet. Preserve
that handle and serial database ownership; do not start a duplicate on silence.

### Schema54 deployment artifact batch

Render RED6a8a8a reproduced four rejected54 phase/export combinations. Renderer
and Helm phase/schema lists now explicitly accept54; audit configuration and
validation accept52/53/54. Defaults remain49; the selected precision phase alone
controls intake. Explicit migration target and API/worker annotations must agree;
missing registration commands and predecessor-schema mutations refuse.
One historical future-version negative still used54 (FAIL6dbd4f); it now uses55,
with positive54 coverage and invalid implicit/compatibility/query/backfill cases.
Focused render group passes84/84 (8cf928). Source verifier omitted54 in its matrix
(RED071802); both phases are now checked, GREENbc78e3.

Grouped local production:release:test passes204/204 (f030c0,26.716s), including
the strengthened preceding-schema mutation cases and existing network/operations
contracts. Targeted lint55e753 passes. npm_config_offline=true and GOPROXY=off
were set; no dependency advisory request was sent. This is not a passing full
production:release:gate: the fresh advisory source requirement remains unresolved.
Runbooks document explicit54/rollback53 and that manifest support is not live
rollout authorization. Independent source review requested; no availability change.
Review identified an Important staging-gate mismatch not exercised by the204-test
production group: latest embedded migration expected53 and valid54 phases were
negative cases. REDf80cf2 reproduced it. gate.test.mjs now tests54 positive phases,
runtime selectors and exact job selection, while rejecting implicit/incompatible54
and future55. Full staging gate/preflight passes76425d7/7 (4.635s); lint0d032a
passes. Independent re-review closes the finding, with no remaining
Critical/Important issue in this bounded deployment contract. No deployed
acceptance or full release approval follows.
Race restart29163 is confirmed live453665: joined executor73960 in4m6.83s,
API A73883 joined, API B membership403/401 barriers passed with zero storage
calls. Final traversals/replay/cleanup remain pending; do not restart this handle.

Latest integration evidence supersedes the initial54 pin below. The distinct
Security Agent API role lacked EXECUTE on54 client-ready (RED9db119). Adding only
that role to the new function changes the compiled fingerprint to
1d65f1584a006c5c3706c1b9022dc583e25c2f2981eb6ebd038adf94c23ccf1c, measured in
owned fixture d5b4fe and verified stable by grouped race2b8370 (31.949s).
No53 source or compiled pin was changed.

Product Get now requests the private scoped54 envelope only after an uncached
application-pinned release check. Missing54 preserves legacy detail; corrupt54
returns unavailable with no fallback. RED4847a8 demonstrated missing context.
The grouped PostgreSQL result verifies actual repository and HTTP handler
negotiation, redaction, tenant separation, receipt binding, ambiguity refusal,
permission denial and tamper refusal, plus migration identity/rollback.
HTTP request identity and planner receipts are fixture-provided, not live login
or a live planner invocation.

Fresh/warmed API, precision-ingest, planner and action readiness across53->54->53
first failedca91cc, then passed12dfb2; the current-pin rerun is included in2b8370.
Tests reject ACL drift and recomputed stored fingerprint. These are actual
registered adapters' readiness checks, not worker action/ingestion end-to-end runs.
Audit registration/configuration and CLI54 integration were pending at that
checkpoint; newer executable evidence above covers that slice.

Independent review found a production integration blocker: tracedJSONDatabase
hid both optional capabilities. The decorator now forwards them while preserving
legacy absence and invalid/canceled refusal. Wrapper RED561563, race65d2e5;
actual production composition/middleware/decorator/repository/handler verification
passes57cebe (2.052s). That composition test uses controlled SQL/session boundaries
and proves scoped54 routing, negotiated sanitized output and no data read after
late gate refusal. It is separate from the real PostgreSQL tests and does not
prove a browser with a real database/login. Re-review found no remaining
Critical/Important issue in the repair. Mounted browser acceptance remains open.
The existing52/53 unrelated-consumer upgrade/tamper regression passes fresh race
f57590 (12.344s) after the shared-verifier change. Ledger905ebf is valid with
unchanged728-row availability counts.
The broader affected runtime composition/tracing group passes race d79bc6
(1.936s), including audit runtime and public-page composition safeguards.

New migration runner, metadata, compiled fingerprint, Version54 and transactional
up/down SQL now have real PostgreSQL evidence. Lifecycle RED882239 rejected the
unimplemented runner. Controlled fixture calibration844d53 measured fingerprint
a09dc3baf715a9399cfd5f2b8f6f7dfdfcdf8006624ed59d471cf0ccb8b3b2f7; replacing
the placeholder with this compiled pin preserves the digest (cf3453). Production
code never learns or accepts an expected pin from the live database.

Grouped race e22c7c passes18.287s: registered54 scoped reads preserve tenant/run/
plan binding and reject ambiguous receipts; upgrade checks exact53; rollback
restores exact53 readiness and removes54-owned functions. An organization-admission
row survives rollback. This is not yet a populated reservation-graph retention
test. Public EXECUTE drift, search-path drift,53 metadata tampering and a tampered
catalog with recomputed stored54 fingerprint all refuse readiness.

Independent registered-slice review found no Critical/Important issue. New54
readiness has its own normalized-pin hashing path, and inherited52 wrappers do
not embed54 pins. The unchanged53 client-ready gate refuses54; this proves that
gate's boundary only, not every cached old binary operation. All-consumer fresh/
warmed compatibility, CLI commands, API Get54 routing, mounted browser verification
and full release acceptance remain open. No availability count is promoted.

The migrations package initially failed8d3b2d because its unknown-release fixture
still treated54 as unsupported. The fixture now uses55 and adds exact54 version
recognition; the full migrations package passes fresh race cf0061 (2.213s).
Ledger validation c351fa confirms728 rows and unchanged availability counts.

### Audit lanes

Normal rerun48084 continues from its existing handle. N1 passed with API growth0
and executor growth1359872 bytes (382af2), joined cleanup,100002events/101chunks.
N2 now passes7cd377 with API/executor growth0 and joined cleanup; publisher
growth753664 is diagnostic only. N3-on small passed and full is active in
fixture zasp-http-fixture-970764188 under the owned741133093 root. Do not restart
or count partial results as aggregate normal-memory acceptance.

Parallel product progress: M7A-86 sanitizer, optional Go context validation/header
negotiation, OpenAPI/generated types, strict browser decoder and separate UI
sections are implemented locally. Go RED00534c/442253 then race GREENabdc88
(1.854s); browser RED302c2a then GREENea664b113/113. Typecheck found two new UI
fixtures missing templates (53e3ac); corrected fixtures pass32 tests5c9b78 and
typecheck4463ef. OpenAPI39 tests9da4fa, lint9de76c and generated checka0edb5 pass.
Independent grouped review found malformed credential-URL suffix disclosure.
Four regression cases reproduced it (RED8e10a4); whole-token matching and
ambiguous-delimiter refusal pass the focused race group6e9401 (1.896s).
Scoped re-review confirms the finding addressed, with no new blocking regression.
Conservative withholding of quoted URLs can reduce rationale availability.
Targeted TypeScript ESLint90e441 passes. Registered54/private receipt decoding,
release consumers and mounted-browser acceptance remain open; real repository
reads still omit context. Source additions do not change already-built audit
child binaries; their hashes identify the exact tested artifacts. No availability
count changes follow from these component results.

The previous turn made progress: schema52/53 local publisher/worker restart
acceptance passed with independent review. This matrix separates completed
checks from live handles and work still required. Do not restart live handles.

| Check | Current evidence | Limit |
| --- | --- | --- |
| Codec/configuration/artifact packages | PASS fe60e1, race | Package tests, not hosted storage |
| Artifact/contents/cursor/descriptor/policy/read/repository contracts | PASSb9814c, race,3.302s | Controlled provider/repository boundaries and golden wire fixtures, not live reads |
| Schema52 SQL authority A-Z | PASS5d3969, race,1019.930s | Original single process; not53 or HTTP |
| Public audit-source protocols | PASS375bc1, race,112.161s | Exact `^TestAuditExportPublicSourcePostgres` selection, schema52 |
| CI audit HTTP/process helpers | PASS ca666c, race,59.149s | `audit_helpers` selection from runnable-ui.yml, not full-size memory acceptance |
| Authenticated queued HTTP52/53 | PASS5031ea, race | Fixture sessions, in-process middleware |
| Completed worker/paged HTTP52/53 | PASS9655b7, race | Seeded wakeup and separate controlled storage adapters |
| Durable publisher/continuous S3 restart52/53 | PASS9561f1, race | LocalStack S3; controlled SQS/STS; manually aged lease/visibility |
| Broker lifecycle | PASS5acc96,36 tests | Owned-loopback harness; initial sandbox EPERM retained |
| API/publisher/worker process composition | PASSb4dd00, race,75.083s | Small and controlled-zero source; owned cleanup joined |
| Full-size functional race | PASSdba72f,503.166s | `ZASP_AUDIT_HTTP_SIZE_BUILD=race`; not numeric memory evidence |
| Numeric memory sensitivity controls | PASSd1c88a,821.717s | Both deliberate retention controls rejected by unchanged growth gate; unaffected roles passed |
| Normal numeric memory pairs | PASS13df28; prior FAIL ceb32f | Three pinned non-race pairs pass unchanged numeric gates; controlled fixtures, not deployment RAM |
| Orderly restart | Non-race child PASS9e1927 | Actual API replacement and ready replay; race-child CI lane still pending |
| Native browser saved-file/live provider acceptance | Open | Prior controlled browser preparation is not native-save or live proof |

No availability count changes or release publication follow from this matrix.

Sensitivity observation6368af completes the api-retain pair: full API retained
196399000 bytes from verified traffic; peak RSS grew from49627136 to173375488
(growth123748352), correctly rejected by the unchanged50331648 growth limit.
The unaffected executor grew3440640 bytes and passed. API53179 exited normally
with exact protocol EOF; its owned PostgreSQL and fixture cleanup joined.
Terminald1c88a now completes both controls (session87517 exit0,821.717s).
The worker retained98028582 bytes; peak RSS grew71434240 to148979712
(growth77545472), correctly rejected. Its unaffected API passed with zero growth.
Both full cases traversed100002 events/101 chunks/98028101 bytes and joined all
owned processes/fixtures. This is sensitivity acceptance, not normal-build bounds.

Normal-build session16365 started only after that terminal result. Pinned Go1.25.6
children are explicitly non-race, GOGC100/GOMEMLIMIToff/GOMAXPROCS2; parent is race.
API hash5a334774d1e5871b87491ded86ddefdcfbac9174d842c1008555c4c0236c71c2,
worker hashb3825d7b4a7331e728efb473cb55a1aeda512e490ec732fb71d1a9870402756b.
Terminal observation ceb32f supersedes earlier live observations: N1 passed,
but N2 full failed during provider HTTP shutdown after both traversals completed.
The manually closed admission listener produced net.ErrClosed from Shutdown;
the owner conservatively retained resources and refused the pair. N3 did not run.
Root retained for inspection is
/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-audit-http-composition-1675287187.
The failed session is stopped; no aggregate normal memory acceptance follows.
Focused reproduction9120c7 confirms the already-closed listener error. A scoped
cleanup repair preserves the existing handler joins, normalizes only net.ErrClosed
after HTTP Shutdown drains, and retains timeout/unrelated-error failures. Fresh
focused race verification and independent review precede the expensive rerun.
The repair now passes race count10 (08086d), and the bounded-wait follow-up passes
fresh race count10 (29ecef,44.935s), including owned PostgreSQL lifetime checks.
Independent review found no Critical/Important issue and approved the rerun;
its minor bounded-wait/deferred-release recommendation is implemented. Only this
cleanup failure invalidates/requires repeating normal acceptance; unrelated
feature tests are not being rerun. Ledger validation a413be confirms728 rows and
unchanged availability counts.
Normal rerun session48084 started after the focused tests and review. It uses the
same required three-pair command, non-race children, race parent and unchanged
memory limits. No result is claimed until its complete terminal output.

M7A-86 private envelope and SQL candidate evidence: race214d92 verifies scoped
receipt decoding and sanitization before public construction. Manual triggers
remain supported, matching the existing persisted trigger contract; browser40/40
987e69 and typecheck/generated OpenAPI6aa566 pass. PostgreSQL candidate RED60bedd
and GREEN4dc553 (race,6.953s) cover colliding tenant run IDs, mixed-scope refusal,
direct-table/worker-role denial, execution retries, rejected/wrong-plan receipts,
ambiguity refusal and missing receipts. This installs a candidate fragment over
registered53 in a test fixture. It is NOT registered54, production wiring or live
proof. Independent scoped review found no Critical/Important issue; literal JSON
duplicate-key tests remain a minor follow-up. Final feature acceptance is open.

Full-size functional race session61293 is now terminaldba72f exit0 (503.166s).
Small and full cases both passed; full processed100002 events/101 chunks/
98028101 bytes, two traversals in113.016s and114.657s, and joined all owned
resources. API/publisher/executor terminal protocol and cleanup were checked.
Reported race RSS values are diagnostics only (`numeric=false`), not normal-build
memory acceptance. All earlier live observations below are superseded by this
terminal result. The next serial lane tests the two non-race retention controls;
normal three-pair numeric verification and orderly restarts still remain.

Independent memory-oracle source review found no Critical/Important flaw. The
retention controls must retain actual verified traffic and make the unchanged
gate reject the affected role; unaffected roles must pass. Normal API/executor
kernel peak RSS must be at most192MiB and small-to-full growth at most48MiB in
all three serial pairs. Peaks require successfully joined child exits. Publisher
RSS is diagnostic only; parent/provider, PostgreSQL and browser memory are not
included. Diagnostics on/off differences are logged, not separately thresholded.
These are schema52/local process bounds, not53 or deployment-wide memory proof.

Latest continuation is a verified wait on session61293, not a restart. Read-only
owned-process observationaa565c confirmed full-size worker51160 actively consuming
CPU at2m59s, within its existing8-minute execution deadline; API51126 and parent
50969 remained alive. A quiet output interval is not a terminal result. Do not
start numeric memory pairs until this functional race run is joined.

Later observation7b0185 joined worker51160 successfully after3m52.763s, with five
successful lease renewals and one terminal queue ACK. Session61293 remains live
for HTTP traversal. Read-only4c9e62 confirms active verifier50969 and API51126;
the worker is absent after its joined exit. No full-pair outcome is claimed.

Subsequent observation7a1b67 confirms the first full-size HTTP traversal finished
in1m53.016s within its3-minute phase budget. Session61293 remains active for
remaining retrieval/cleanup checks. Lightweight complementary contract batch
b9814c passed without changing the running input sources; its precise selection
was `^TestAuditExport(Artifact|Contents|Cursor|Descriptor|Policy|Read|Repository)`.

Read-only remote query6eae34 confirms main still points to
fda8ae99921be468b3d95f2369f54112a725e046. No fetch, branch change, push or CI run
was performed. This refreshes the remote tip only, not the historical CI result.

SQL authority session95709 is now terminal5d3969 exit0. The uninterrupted combined
A-Z selection passed in1019.930s, including real PostgreSQL capture, outbox,
idempotency, lease/revocation, registration, immutable bytes, scoped reads and
rollback checks. Large-source subcases recorded100002 events/101 chunks/98028101
bytes, and1001 large events/112 chunks/110952999 bytes. These are local schema52
database/component results, not full HTTP memory or live provider proof. Earlier
running observations below are superseded by this terminal result. Session61293
remains active for the separate full-size functional race lane.

Composition terminalb4dd00 verifies two cases:1001 events/two chunks/977209 bytes,
and a controlled empty source (owned POST audit deliberately removed). Actual
API/publisher/executor processes joined, with exact terminal protocol EOF and
owned PostgreSQL/resource cleanup. It is not a naturally empty production POST,
live provider or full-size memory result. Child race RSS is not numeric acceptance.

Independent review confirms public-source fixtures use52. Actual repository and
protocol mutations generate policy, administration and test history, while
membership setup and receipt aging remain synthetic. The helper group validates
expected-byte/provider authority and joined process/resource lifetimes, not
full-size memory limits. Its terminal Go PASS is recorded without substituting
it for full-size composition, race, memory sensitivity/normal pairs or orderly
restart. Scope review did not approve any live or schema53 claim for these groups.

### Durable publisher and continuous local storage restart

The previous turn added verified completed-worker/paged-reader coverage on53.
Current local restart run55251 terminated successfullyee2623 (37.322s), with no
skip. Existing pinned LocalStack image was inspected, not pulled (f44b2b):
linux/arm64 image ad4f76a02108f52479a33bbe0de40690d63ef51713971731f21f1de1e4eedb85.
The actual registered publisher sent the sole canonical wakeup; worker A was
SIGKILLed after physical persistence and before its receipt/ACK. Worker B reused
the same version through conditional412/discovery and completed. Worker C replay
made no new S3 requests or SQL/object changes. Exact1006-event source produced
two chunks and one manifest in one continuous LocalStack instance. All worker
processes joined; PostgreSQL joined; broker/container absence was checked and
the owned temporary root removed. No user data was removed.

Independent scope review found no critical false-positive or cleanup issue.
This result covers schema52, controlled SQS/STS adapters and real local S3.
Lease expiry/message visibility were manually aged after confirmed death. It
does not establish elapsed-time expiry, live AWS or native-save acceptance.
The same test now runs separate52/53 subtests, each with its own owner and
cleanup. Setup regression62ac82 failed actual52/wanted53 and joined all owned
resources. The53 branch now applies the real migration before registration and
admission, then checks installed max(version). Independent review found no
Critical/Important issue or weakened crash/replay oracle. Both-schema verification
session85897 terminated successfully9561f1 (65.858s), schema52 31.02s and schema53
33.12s, with no skips. Each proved the saved-version recovery, one conditional412,
three exact physical objects and zero duplicate S3 requests. Both owned resource
sets joined and were removed with exact container absence verified. This adds
schema53 local durable publisher/worker restart compatibility, not live AWS or
elapsed-time expiry evidence. No task availability promotion or publication.

Broker lifecycle tests initially terminated772d0d with35 loopback EPERM failures
and1 pass. After owned-listener permission, unchanged tests5acc96 pass36/36 in
3.429s, including signal/EOF cleanup and exact-owned-candidate refusal cases.
This is harness component evidence, separate from the actual container run.

### Current-schema completed worker and paged retrieval

The previous turn made progress with authenticated queued-job acceptance on53.
The existing TestAuditExportHTTPPostWorkerSDKPagedGet scenario now runs on52
and53. Setup REDfcac49 confirmed the missing53 migration (actual52 expected53).
The current-schema branch applies real UpProductionSecurityAgentBudgets and
checks the installed version before registering principals or starting HTTP.
All original worker, exact1006-event/two-chunk byte, paged retrieval, reconstructed
API cursor, authority refusal and corrupt-provider assertions remain shared.

Independent read-only review found no Critical/Important issue. Verification
session46247 terminated successfully9655b7 (68.799s), both schema cases and all
eight provider-fault cases per schema passed without skips. Worker child output
d33328 confirms actual SDK completion, saved-Put/lost-response recovery and
fresh-composition replay. Owned PostgreSQL cleanup joined successfully for both.
The fixture seeds the wakeup and transfers actual captured worker objects to a
separate controlled reader. This is not continuous S3, live AWS, durable outbox
execution, native saved-file proof or the complete53 database-authority matrix.
Broader schema52 SQL session95709 is also live (observation0b0197), with completed
manifest/ready cases passing and post-wait ready-replay cases in progress.

### Authenticated audit export HTTP on schemas52 and53

The preceding turn made progress: package race verification passed and independent
scope review identified that mounted HTTP acceptance still exercised only52.
The original authenticated export factory scenario now runs on both52 and53.
RED21c69a failed the direct installed-version assertion (actual52, expected53),
demonstrating absent current-schema setup, not a product defect. Schema53 now
uses real UpProductionSecurityAgentBudgets and then checks max(version), without
metadata injection. The existing52 fixture and shared HTTP oracles remain intact.

Affected race group5031ea passes in16.044s: HTTPCreate/HTTPGet, Composition and
Production tests, including both actual PostgreSQL schema scenarios (14.01s).
The real middleware authenticates fixture-seeded sessions through PostgreSQL;
handler creation/read/replay, scope/CSRF/session refusal, durable single-effect
counts and zero storage calls pass. Independent review found no Critical or
Important issue. Optional stronger checks remain: stable error codes and a
second durable-count assertion after final role/freshness/revocation refusals.

This is in-process mounted middleware/handler coverage. It does not prove
network/browser authentication, executed export workers, ready-content retrieval,
native saved files, live cloud storage, or the full schema53 authority matrix.
No task availability promotion or publication. Broader schema52 SQL session95709
continues independently and must be joined before reporting its final outcome.

### Audit export authority verification in progress

The previous turn made implementation progress by containing false offline-audit
clearance. The next batch preserves existing source and groups local race checks.
Package batchfe60e1 passes audit (11.955s), auditexportconfig (1.718s),
artifactstore (1.800s), and artifactstore/s3driver (1.812s), using cached offline
Go dependencies. This is package evidence, not a deployed storage check.

Combined PostgreSQL authority command is running as exec session95709:
`go test -C services/platform -race -count=1 -v -timeout=30m ./apiserver -run '^TestAuditExportPostgres[A-Z]'`.
Latest observation592787 confirms the process remains running: all seven
OutboxPostWaitLossIsAtomic cases passed (64.19s), then OutboxNeverLifetimeExhausts
started. No terminal outcome is claimed. Resume this exact
handle; do not launch a duplicate because an observation times out.

Independent read-only scope review traced auditExportPGFixtureWithPolicy at
audit_export_postgres_test.go:3395: it installs50/51/52, not53. The selected
tests exercise real SQL with restricted registered API/worker principals,
fixture browser sessions, durable replay, capture, quotas, chunks/manifests,
leases, retry/outbox and post-wait atomicity. A passing result belongs to the
schema52 baseline only. It cannot complete M2-41/42 handler acceptance or
M7-36 browser acceptance. Next checks must include HTTPCreate/HTTPGet,
Composition/Production/Public families and current53 mounted API/worker
acceptance while retaining the52 baseline. The earlier53 browser preparation
and native saved-export gate remain separate evidence. No status promotion.

### Offline audit false-clearance containment

The last policy-only turn made no implementation progress. This batch repairs
the release gate's acceptance of missing advisory evidence: installed Arborist
source0472fc confirms offline skips lookup but initializes zero counters. The
gate now runs its existing local checks then rejects release explicitly, without
issuing an audit request or claiming dependency clearance. RED4466e8 demonstrates
the prior false acceptance; GREEN63a7af passes3 real-orchestration tests with
controlled external-command responses. Independent review found no Critical or
Important issue for this interim containment. An approved advisory source and
fresh exact-lock evidence validator remain required; M8-47 is still component-only.
No publication, network scan, live production proof or availability promotion.

Grouped release suitec10b13 passes200 tests with zero failures/skips in25.95s.
Full lintb6823f and ledger/diff checkbc5e57 pass. These verify the containment
and affected rollout contracts, not the intentionally blocked standalone release
gate or an actual advisory scan.

### Earlier grouped verification

- Full Vitest run220b6e: 1,620 passed and45 failed because sandbox policy denied
  IPv4/IPv6 loopback listeners. The terminal run was joined before retry.
  With local-server permission, run725687 passes all1,665 tests in208 files.
  That snapshot preceded the lint-scope test and JSX escaping below.
- Dependency validation and9 regressions pass in725687. Initial run3b6b8c
  passed8 but could not bind the owned esbuild loopback server. No npm audit,
  provider request or external dependency disclosure was performed.
- Lint4cb8cf found the budget guidance apostrophe and a Git-ignored local
  `.superpowers` scratch evidence script. Escaped the JSX without changing its
  rendered text and excluded only `.superpowers/**`, matching `.gitignore`.
  Actual ESLint scope regression RED5a255e preceded the config change. It checks
  scratch exclusion while preserving product and durable-script linting.
  Group e083c7 passes29 affected tests and the full lint command.
- The production source gate d89b58 rejected AuditExportPanel's sessionStorage.
  Its controller/resume code stores bounded principal/scope IDs, an idempotency
  key and optional server export ID, not credentials or export data. Reads
  require exact identity matching; real APIs remain authoritative. Added only
  that exact path to the existing retry-recovery boundary allowlist, with
  REDf84bb4 then passing positive and sibling-denial source-graph tests68fb0e.
  Independent review found no Critical/Important concern and confirmed the
  narrow exemption; it is not approval of the entire export implementation.
- OpenAPI lint,10 UI/API mapping tests, current map check,3 raw-fetch rule tests
  and23 export resume/controller tests pass7d7147. The map reports141 available,
  8 API-available and4 planned UI entries; these are map checks, not live proof.
- Fresh typecheck, all5 build stages and compiled import check pass24f628.
  Production import graph has53 source files,7 client chunks and8 server chunks.

## Release blockers and next work

### Actual sensor daemon on historical48 and current53

Sensor race package passes1587ac (126.742s); the CI runtime acceptance/ingestion
group passes8aa2e9 (56.309s). These package summaries do not establish that every
opt-in fixture executed. The explicit Linux daemon proof below has no skips.

Initial actual daemon proof319c15 passed twice on schema48 only. Independent
scope review identified the missing current-release53 coverage. Added both
profiles at48 and53, retaining all original replay/rotation/SQL/ACK assertions.
Actual-container REDbf0b39 passed48 and rejected53 because only48 was installed.
The fixture now registers the48 principals, runs the real49..53 migrations and
checks exact release version with both Runner and independent SQL reads.

Harness RED85aee0 also showed a missing profile could pass the parent-only
result check. It now requires exactly one PASS for each of the four cases and
rejects all nested skips;12 harness tests pass0bbe43. Independent review found
no Critical/Important issue or synthetic metadata bypass.
Full lint, ledger validator and diff check pass74f019 after the source changes.

Expanded actual daemon proof10375 exits0 atf11453. Both executions pass all
four cases (12.38s and12.67s), without skips. Actual non-root sensor daemon,
local HTTPS, public enrollment handler/repository and PostgreSQL verify lost
success, unchanged pending checkpoint, real token rotation, byte/key-exact
replay, single SQL/artifact authority and verified ACK on both schemas.
Successful owned container and binary directory were removed after joined
commands and exact stopped-container/absence checks. Linux arm64, pinned image
postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af.
Sensor binary SHA256:765cb0421087e55e2f19fcbe72f3ee025e7390007c115b74a0db811265e296ba.

Limits: enrollment identity/routing, producer input, Kubernetes identity/
readiness and artifact storage remain fixtures. This is not mounted production
authentication, real kernel/Tetragon capture, live cluster/cloud rollout,
downstream processing or database power-loss proof. Container builds are not
race-enabled. No availability promotion or publication follows.
The deliberate RED retains stopped container
zasp-daemon-replay-0ed39cf2-a273-461e-8ff5-c4b0e770370e and private host evidence
at /var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-daemon-proof-PXUDzl;
its tmpfs did not survive exit. This is diagnostic evidence, not an active job.

### Confirmed action heartbeat self-cancellation defect

Controlled actual-repository RED1f3d40 holds an in-flight heartbeat until Store
has committed a budget stop and returned. The worker canceled its shared
context before joining; the real heartbeat rejected that canceled context and
the processor returned worker execution unavailable. Diagnostics show Store
budget stopped, heartbeat repository operation rejected, zero IDs/reads/Finish.
This proves the scheduled defect, not the exact unobserved interleaving of the
earlier broad-suite failure.

Normal completion now closes a separate heartbeat scheduling channel and joins
the in-flight call before deferred cancellation. A second stop check handles
queued ticks; each heartbeat has its own five-second context bound and immediate
cancel after return. Parent cancellation still propagates, genuine heartbeat
conflict/unavailable/deadline errors still fail closed, and only the private
apply-Store stop marker can authorize this terminal path. No new effect or
provider dispatch is authorized by a late heartbeat.

Four actual PostgreSQL/worker scenarios passff7089 (37.363s). Action-processor
unit group2ce611 passes7.233s, including actual five-second heartbeat timeout,
parent cancellation and zero post-stop readback/Finish/artifact assertions.
Independent review found no Critical/Important issue. Test cleanup then moved
processor.Close after its join; the full affected worker package was launched
to verify that final delta as well (session50287). Full worker package now passes
46d095 (31.381s), exit0. Gofmt/diff checke4db1d passes. No publication,
availability promotion, live gateway/daemon proof or full release approval.

### Terminal CI groups and actual RunOnce coverage

Tenant acceptance follow-up: focused RED3a8fec reproduced all three planner
cases failing before tenant validation. Converted only that fixture to the
actual registered53 migration chain and configured its controlled200 nano-credit
allowance in the definition before admission. The child checks Ready and uses
explicit controlled transport pricing/usage. Actual RunOnce now reserves and
settles each request; parent SQL requires exactly one scoped reservation with
1000/200 maxima and120/40/160/100 usage. Foreign asset/environment rejection,
authorized waiting_approval, scoped prompt, zero foreign runs/effects, target
snapshots and no leaked rejected targets remain asserted. Independent review
found no weakened coverage or authority bypass. Combined planner/action group
3b72ea passes48.560s, and diff checkba2bb5 passes. This restores current-release
local tenant acceptance, not production pricing or live provider approval.

Expired-action failure was not reproduced in either focused group. Added only
joined Store/heartbeat diagnostics, independently reviewed as race-safe; no
production behavior or expectation changed. Focused expired-only count5
session73262 is terminal: five repetitions passf5253e (52.342s). No failure
diagnostic was emitted, so the original intermittent failure remains unexplained.
Do not count these reruns as a full Security Agent pass. Inspection ebe4f4
confirms the fixture uses a real pgx pool (maximum3 connections), not an unsafe
single shared pgx connection. Cancellation/heartbeat ordering needs controlled
investigation before a production change; no workaround has been applied.

Session25010 finished successfully: complete agentsec-migrate package passes
7f9aac (322.460s), sandboxcutover passesfbb948 (25.555s), final exit0. It began
before the overlap test edit; the ten-repeat focused race run remains the
explicit post-edit evidence. Runtime pipeline session5592 exits0: metadata,
lineage, sensoradapter, sessionsearch, projection, correlation, runtimeindex
and opensearchdriver all pass56ecfe/38a5c1, sequentially with `-p=1`.

Security Agent acceptance1710 is terminal, exit1 at043a38 (1044.317s). Failures:
`TestProductionSecurityAgentBudgetStopsThroughActionWorker/expired` returned
worker execution unavailable with zero IDs; all three cases of
`TestProductionSecurityAgentPlannerTenantIsolationThroughWorker` returned
worker execution unavailable. No full Security Agent pass is claimed. Initial
inspection e6bd48 shows the tenant test still uses the older attack-path fixture
and an unwrapped production planner with no verified cost authority. Diagnose
and preserve its authorized/foreign-target oracles before changing the fixture.
The expired-action failure remains unexplained, not dismissed as host timing.

Added `run_once_missing_cost_authority` to the composed provider batch. The
new branch uses registered53 Ready, the real repository and unwrapped planner,
then calls actual `RunOnce` twice before any fixture scheduling/claim/budget
mutation. Parent SQL requires exactly one run and budget, needs_human with
budget_usage_unknown, cleared lease and zero plans/steps/approvals/effects/
receipts/reservations; the public API reason/tenant-denial oracles still run.
Child checks zero transport calls and artifact IDs. RED560f5d identified missing
scenario wiring, not a production defect. Seven-mode race batch580083 passes
71.603s; independent review found no blocking issue. Gofmt/diff check4994bc
passes. This is controlled local repeated RunOnce acceptance, not a long-lived
daemon, concurrent polling, live pricing, gateway delivery or production proof.
No task promotion, commit or push. All handles mentioned in this subsection
are terminal; do not resume or duplicate them as though still running.

### Canonical release batch and recovered CLI regression

Follow-up overlap correction: inspection confirmed three HTTP preflight reads
occur before PATCH. The old100ms deadline could reject before the test's
delayed-persistence boundary existed. The test now waits for each indexed
PATCH arrival, cancels the client while persistence remains held, and joins
the call. It requires an ambiguous-write error and zero applied state, then
preserves both winner orders, winner-only reconciliation and two attempts.
Cleanup cancels, releases both server gates and joins owned dispatch calls.
No production code or timeout changed. Independent review found no blocking
issue. Ten race-enabled repetitions passfe4986 (2.980s); diff checkdeca21 passes.
Full sequential session25010 started before this source edit and cannot prove
this correction; its latest poll2f121c remains live. API1710 also remains live
at069cc2, with child5267 independently confirmed26cfd9. The observation-cache
test remains unchanged and its shared15s timing sensitivity is still open.

The standalone release gate now invokes `npm run production:release:test`,
including audit and schema53 rollout checks, instead of its stale four-file
list. Actual orchestration regression RED e24e1c failed both checks before the
change. The tests run the gate body with controlled command boundaries and
prove canonical dispatch and failure stopping later checks; they do not run
an advisory audit. Independent review found no Critical/Important issue.
Grouped release run42b805 passes199/199 and lint5d2f1f exits0. Initial restricted
runs failed on the local watcher/listener and Go cache permissions; the passing
run used owned local-server permission, an owned Go cache and GOPROXY=off.
No external audit request was sent.

Migration/process group94188 is terminal: exit1 at8783e0. Migrations,
runtimeevent and internal/testprocess passed, but the CLI parent and two
sandboxcutover tests failed. The CLI's historical50 fixture expected supported
`up-to-52` to fail. It succeeded and advanced the fixture, causing subsequent
rollback errors. Updated its unknown-target rejection to unsupported54 while
retaining the exact50 unchanged-state and49 rollback assertions. Dedicated
real-binary tests retain supported52/53 coverage. Independent review found no
coverage weakening; the entire failing CLI parent now passes76d762 (19.035s).

The two cutover failures were PATCH not reaching its overlap gate and an
observation rejection at the15-second context boundary. Both pass together
unchanged in22c9bc (6.954s). This does not resolve timing sensitivity or turn
the earlier full group green; no timeout or production behavior was changed.
Security Agent suite1710 remains live (exact PID4786 confirmed9ce295), not a
passing claim. No task promotion, commit, push or production-readiness claim.
Full CLI and sandboxcutover packages were then started sequentially (`-p=1`,
unchanged test timeouts) in session25010. That handle remains live at daabaf;
resume it along with1710, without launching duplicate suites. Ledger validator
and `git diff --check` pass15abc9. Source inspection c126d5 confirms the overlap
test starts a100ms deadline before request arrival and the observation test
shares15 seconds across ten bridge observations. Those are timing-sensitive
test boundaries, not yet a proven sole cause of both earlier failures.

### Broad verification and tooling-test isolation

Full `npm run verify` session77265 passed dependency9, health contracts/packages,
OpenAPI39/lint/generated output, UI/API10/map, raw-fetch3, tenancy, graph28 and
RLS checks before stopping in Vitest. Terminal477969 reports1665 passed and one
5000ms timeout in the real ESLint scope check. Host load23b34a was178.05 while
multiple suites ran; the tooling check loaded ESLint through the jsdom/React
test pool. No scope assertion reported a wrong value.

Moved that tooling-only check from the untracked browser-test wrapper to
`scripts/eslint-scope.test.mjs`, preserving all three assertions and adding a
self-inclusion assertion. `npm run lint` now runs it before the unchanged ESLint
command with `&&`. It remains bounded (10 seconds) and uses actual ESLint config.
Independent review found no coverage bypass or rule relaxation. Native Node
checkf71ea3 passes4.408s; full lint4e8b31 exits0. Browser reruna51b5b passes1665
tests in208 files,51.16s, and typecheckd860a4 exits0. This relocates one test;
it does not remove coverage or establish that all host saturation is resolved.

Remaining local verification was resumed without repeating passed early groups:
source/import7, staging7 and production-release197 pass in session20162, followed
by all5 build stages. These are grouped recovery results, not a claim that the
original one-shot command succeeded. No npm audit or disclosure runner executed.

Independent integration audit identified additional CI suites absent from npm
verification. Started the exact migration/CLI/runtime/process group in
session94188 and the Security Agent apiserver acceptance group in session1710.
Both were live at that observation, not passing. The newer subsection above
records94188's terminal failures and follow-up; resume only live1710. The
remaining runtime pipeline and audit CI proof matrix is also not established by
the npm checks. Source publication still requires explicit inclusion/review of
221 untracked and130 tracked changed entries. Cached main diverges3/1 in history,
but its tree equals a9341c08 (verified957b3b), already the parent of this branch's
three commits; no merge or fresh remote-state claim follows from that check.

### Schema53 mounted preparation acceptance

The subsequent small native-save attempt (session77421) reached picker handoff
dd39cd after real API/replay and both worker modes passed. Native control resolved
the user's separate Chrome instance; its window menu did not expose the owned
test window. No directory selection or saved-byte verification occurred. Sent
SIGTERM only to verified parent2039 and joined exit143 at66911b. Cleanup logged
all owned resources; read-only process check8b1a3c found none of the exact parent,
database, provider, API or browser PIDs remaining. This is an aborted attempt,
not a native-save pass. No large retry is justified until exact native-window
targeting is available.

That attempt also exposed a background fixture exception: the audit-only
policy-history server has no runtime search endpoint, but a session mapping
request constructed a URL against undefined. Real HTTP RED019dd2 reproduced the
exception. The fixture now returns503 for recognized session reads with no
configured engine, preserving authorization and configured-engine forwarding.
Grouped harness570173 passes86 with2 opt-in container-signal tests skipped;
expanded missing-engine mapping/marker/search and forwarding checksfb71d5 pass.
Independent review found no Critical/Important issue. This fixes fixture failure
handling, not production search availability or native saving; long-lived mounted
readiness still needs verification with the appropriate runtime dependencies.

Fresh build4eb74d passes all5 stages; compiled import graph368d35 passes.
The actual selected audit/export preparation runner (session1870) completed with
exit0 at53be2e. It ran the real53 migration/registration/configuration CLI,
mounted API and Chrome login, four mutation families with raw SQL audit checks,
lost-create response plus actual browser reload/replay with one durable job,
and separate outbox/export worker child processes. Both child modes passed.
Authenticated browser-context fetch returned1 page,7 events and4757
manifest-declared chunk bytes; nativePickerInvoked and nativeSavedBytesVerified
were both false. The owned provider joined with exit0 and cleanup completed.

Identity, storage credentials and provider transports were controlled local
fixtures. Preparation reads did not exercise the production native-save writer;
4757 is not independently verified saved bytes. Independent evidence-scope
review confirmed those limits. No live-provider, large-volume memory, full
fault-matrix or availability claim follows. The earlier native-control timeout
was rechecked: CUA discovery now responds, allowing a small native-save attempt
without repeating the large preparation run.

### Mounted audit harness selects the current release

The browser harness still selected52 and compiled a test-only registration
child. RED4ed416 exposed that mismatch against the current53 release. Its
selected audit path now invokes `up-to-53`, checks the exact49–53 release list,
then calls the real `register-audit-export-api` executable command before policy
configuration. The non-audit path stays48. Existing worker registration remains
in the export composition. No product SQL or application behavior changed.

Grouped browser-harness contracts8d40cd pass85 with2 skipped; lint16ec58 passes.
The actual setup block is executed with controlled command boundaries, checking
order, selected principal environment, default-path exclusion and fail-fast
behavior at every command. Missing53, wrong-name53 and extra54 schema output
must stop before API/policy mutation. Independent review found no Critical or
Important issue and requested those successful-command/invalid-output controls.
This is source/setup-sequencing evidence, not a mounted browser acceptance run.
The next check must execute the owned schema53 composition through authenticated
UI/API and worker export delivery; native saved-file and live-provider proof
remain separate gates. No push or availability promotion.

### Grouped health, tenancy, graph and RLS verification

Fresh checks on the recovered worktree pass with offline Go dependencies,
temporary Go cache and permission for owned local listeners:

- `npm run health:contract:test`: six health-contract checks and race-enabled
  health, healthserver, API, worker, event-ingest and runtime-gateway packages.
  Session88589 exited0; final output1cc973. Worker package took25.943s.
- `npm run saas:tenancy:test`: all seven configured packages pass, including
  repository, event/artifact stores, queue, graph and tenant quota.
  Session89006 exited0, output964b8e.
- `npm run graph:neo4j:test` and `npm run db:tenant-rls:test`: graph adapter/proof
  Go packages,28 Node checks and all selected tenant-context/RLS/repository and
  proof-rendering Go packages pass. Session35020 exited0, output210dd4.

These are the default local regression commands, not the live proof runners.
Parent-owned subprocess tests and opt-in combined/browser/provider fixtures are
not established by a package-level pass. No live Neo4j, Neon, tenant enrollment,
provider billing or mounted authenticated export lifecycle is claimed. This
closes the outstanding default Go/tenant verification group only. Schema53
deployment integration, mounted browser/auth/proxy evidence, whole-change review
and external release/disclosure authorization remain open. No push or task
availability promotion occurred.

### API capability registration command

The schema53 exact52 API-registration gap below is now closed locally through
the real executable and enabled-export hook. RED71f858 reproduces the missing
command, unit RED76b50b reproduces the library's exact52 refusal, and shell
REDdc3ee5 shows the hook omitting API registration. The command uses the existing
explicit discovery API principal setting; unchanged SQL requires the actual
migration authority and an already registered least-privilege discovery login.
It creates no login or role membership. RegisterAuditExportAPI now uses the same
exact compiled52/53 pre/post-readiness helper as configuration and worker setup.

Migration racefa6862 passes2.241s. The real CLI test adds exact capability binding,
complete role-grant invariance, replay and malformed/wrong-authority/unregistered
target refusals to both52 and53 flows. The rendered hook includes API registration
only with enabled exports, between migration and worker registration; removal
and failure sequencing are tested. Grouped executable preflight and full52/53
CLI acceptance b5d02a passes77.942s; release197 and staging7 tests58efc4 pass.
Lint/typecheck/ledger b7a61d pass. Independent review found no Critical/Important
issue, confirmed the existing chart principal environment and production handler
mount, and limited its approval to this change. These are local controlled tests,
not production enrollment or an authenticated export lifecycle.

Initial staging gate68fb0e failed: latest embedded schema is53, while the
deployment contract is explicitly limited to52. Six other staging tests pass.
Both `deploy/staging/product/templates/_session-search.tpl` and the release
renderer reject53. The chart's audit-export migration command also has its own
schema52 sequence, so updating only the test's latest-version number would not
make schema53 deployable.

Next batch must define and test an explicit53 rollout that preserves runtime
precision phases and audit-export policy registration, binds the exact53
migration and API schema, and retains old-runtime readiness/rollback restrictions.
Keep default49 unchanged until the compatibility sequence is proven. Add actual
rendered-manifest and hostile-drift tests, followed by grouped runtime/readiness
checks; do not silently permit arbitrary future versions.

### Schema53 rendered deployment support

The next batch above is now implemented at the manifest boundary. REDbb9bb4
proved all four schema53 phase/export combinations were refused. The renderer,
Helm phase guard and export validators now accept exact53 with either precision
phase; default49 remains unchanged and future54/implicit phases are rejected.
The migration hook uses up-to-53 and, when exports are enabled, retains worker
registration followed by predecessor-checked policy configuration. API and
export-worker annotations bind the selected schema. Hostile command/annotation
drift is rejected. No deployment command or external service was invoked.

Focused5 render tests6acb84 pass. Grouped staging7 tests89cd98 and production197
tests193bf3 pass, with schema53 included in the release-source gate. Lint,
typecheck and all728 ledger rows passae94e3. Independent review found no
Critical/Important issue and no further hardcoded52 assumption in the reviewed
manifest path; approval is limited to manifest support.
This closes the original schema53 render-contract mismatch, not runtime
compatibility, API capability registration or live production acceptance.

### Schema53 operational setup prerequisite

Tracing that rollout exposed an executable failure before chart changes:
audit-export worker registration and policy configuration required exactly52
release rows. Real built CLI RED3b6bee fails registration on53. Operational
setup now accepts only exact compiled52 or53 chains, then uses the selected
release's compiled checksum/fingerprint readiness before and after mutation.
The schema53 readiness includes audit policy, worker, source/workflow ACL and
whole-release fingerprint checks. Historical up/down metadata readers are
unchanged; arbitrary future releases still fail closed.

Migration race suite1d7dc0 passes2.007s including configure/register controls for
future metadata, wrong53 checksum, initial drift and final drift, transaction
refusal and compiled pre/post authority arguments. Combined real binary52/53
registration/configuration/rotation/replay/rollback group791779 passes64.934s.
Independent review found no Critical/Important issue and requested an explicit
lower-version refusal control, now added. RegisterAuditExportAPI remains exact52;
only ConfigureAuditExports and RegisterAuditExportWorkers were extended. The API
registration caller/rollout boundary still needs separate analysis. This does
not make the chart support53 or establish live migration/tenant/export proof.

Production release contracts initially report189/192 passing. The three failures
are a restricted filesystem watcher, a loopback listener, and the default Go
cache outside writable roots. The permission-aware rerun b144f4 with offline Go
and temporary cache passes all192 tests in20.796s. Those tests cover the existing
supported release phases, not schema53. The later rendered-deployment checkpoint
above supersedes that initial staging failure with explicit53 coverage.

The default broader Go/tenant suites now pass as recorded above. Remaining gates
include schema53 deployment
integration, mounted browser/auth/proxy checks, external release/disclosure
authorization and real operational evidence. No commit, push, live readiness or
task availability promotion is claimed here.
