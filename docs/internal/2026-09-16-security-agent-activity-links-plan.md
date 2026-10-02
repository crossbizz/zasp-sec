# Security Agent Activity Links Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Execute related changes in feature batches with independent review at the feature boundary.

**Goal:** Complete original M7A-90 with exact, bidirectional scoped links between runs and findings, paths, runtime sessions and audit records.

**Architecture:** Typed URLs carry an explicit scope assertion. Existing detail APIs resolve records; authorized persisted relationships supply links, including paginated reverse reads. The shell refuses invalid or wrong-scope links before mounting detail readers.

**Tech Stack:** TypeScript, React, Vitest, Go, PostgreSQL, existing isolated-browser harness.

**Spec:** `docs/internal/2026-09-16-security-agent-activity-links-design.md`.

## Global Constraints

- All four entity types remain required.
- Scope is an assertion against the authenticated session, never an instruction to switch it.
- Generic evidence IDs cannot establish types.
- Missing, forbidden, ambiguous or unsupported relation authority stays unavailable, never guessed or silently empty.
- No production completion claim from local fixtures. Existing release gates remain required.

## Batch 1: Exact scoped URL and detail navigation

Files: create `app/domain/activity-links.ts` and `app/domain/activity-links.test.ts`; modify `app/components/ZaspProductionApp.tsx` and its tests, `app/features/risk/ProductionRiskView.tsx`, `app/features/securityagents/SecurityAgentsView.tsx`, and `app/features/sessions/RuntimeSessionsView.tsx` with their behavior tests.

Interfaces:

```ts
type ActivityScope = Readonly<{ organizationID: string; workspaceID: string; environmentID: string }>;
type ActivityKind = "finding" | "attack_path" | "session" | "audit" | "run";
type ActivityTarget = Readonly<{ kind: ActivityKind; id: string }>;
type ActivityLinkResult = { state: "none" | "invalid" | "scope_mismatch" } | { state: "selected"; target: ActivityTarget };
function activityLink(target: ActivityTarget, scope: ActivityScope): string;
function parseActivityLink(location: string, scope: ActivityScope): ActivityLinkResult;
```

- [x] Write failing URL tests using literal paths and IDs. Cover all five kinds and each scope dimension; parameter ambiguity, malformed IDs and external URLs must fail closed. Executable RED96b09d: 27 assertion failures; initial missing-module a7bd15 is setup evidence only.
- [x] Implement builder/parser. Node 22 Vitest GREENb526bc: 35 tests. Independent contract review found no Critical/Important issue. Consumer work and feature review remain required.
- [ ] Write failing shell and page tests: an exact linked ID absent from the list must request its detail, a wrong-scope link must make no detail request, and popstate must replace the selected ID. Preserve locked mutation behavior and abort stale reads.
- [ ] Wire query-bearing route state and validated selection into the real detail components. Do not enable audit selection until batch 2 provides its authority. Show explicit unavailable detail for unsupported authority.
- [ ] Run affected shell/risk/security-agent/session Vitest files together, typecheck and lint changed sources.

Batch 1 checkpoint: shell query state, scope refusal, exact finding/path/session/run reads without lists, finding-to-path and three persisted trigger destinations are implemented. Groupbc5ecb passes125 tests; typecheckaffc95, lint58cec8 and five-stage UI build5525f6 pass. Real-client tests use controlled HTTP responses, including shell run-to-session and finding-to-path flows plus synthetic popstate. Wrong org/workspace/environment refuse record readers. Read-order tests reproduce/fix older reloads and competing drawer selections. Independent review confirms both fixes. Full browser history/scope-transition acceptance and audit detail remain pending, so this batch is not marked fully complete.

## Batch 2: Authorized bidirectional relations and audit lookup

- [ ] Inspect exact persisted run/step/approval audit writers and current pagination conventions before fixing the relation-query API shape. This is source reconnaissance, not permission to guess associations.
- [ ] Extend the design with the concrete persisted associations, endpoint signatures, SQL ownership/grants and cursor binding found in that inspection; write executable failing API/SQL tests before implementation.
- [ ] Implement typed, bounded relation reads and an exact authorized audit-record lookup. Update OpenAPI, regenerate the client, and add strict decoders. Keep unsupported-schema deployments honest.
- [ ] Render links in all five detail surfaces, including reverse run lists. Enforce capability checks and scope assertions on every destination. Add no fake links or demo records.
- [ ] Execute one serial owned-PostgreSQL matrix covering same-scope success, foreign tenant/workspace/environment, revoked access, audit permission, pagination and ambiguous associations. Verify migration fingerprint/rollback if the schema changes.

## Batch 3: Complete feature acceptance

Full-path checkpoint: group62167/30d4ae passes24.191s. Registered API-login
repository acceptance covers10,000 stopped-run fixtures, all50 exactIDs over
20/20/10 pages, complete coverage in both plan modes, foreign missing receipt
noninterference and local missing receipt partial coverage. Page timings
102.9–171.0ms are serial local characterization, not production capacity or
action-plan coverage at scale. No production availability promotion.

Action-target checkpoint: grouped66036/41d642 passes45.757s. Baseline7077a9
removed4,950 of5,000 tenant plans. GIN-only generic plans still failed4aab1d;
separate finding/session branches now pass custom+generic first/next checks
with zero removals, alongside registered APIs/pin/drift/rollback. Review found
no blocker. This does not close tenant bitmap/shared-target fan-out costs,
full-scope integrity coverage or nested/live-load acceptance.

Reverse trigger checkpoint: batch15952/41c292 passes34.771s across registered
APIs, audit/reverse custom+generic query plans, pinned schema drift and rollback.
Baseline7de689 observed100 receipt index searches across100 definitions; the
new full-scope/kind/trigger index needs1. Review found no blocker. Candidate
selection is measured independently of coverage/envelope costs; full-scope
integrity scans, action-target lookup and high fan-out remain scaling work.

Foreign-session checkpoint: batch88918 passesd28a3a with a separately authenticated
owned foreign-admin browser. Non-audit reverse reads return empty200, audit list
positive control200, primary forward/exact/reverse-audit reads404 and settled
mounted audit refusal without primary IDs. Primary audit/approval state remains
unchanged. Review corrected the test's initial audit-reverse200 expectation to
the existing exact-audit404 contract. Screenshot inspected. This closes that
local isolation matrix, not live identity/deployment or scaling/release gates.

Forward/boundary checkpoint: batch32662 passese5c5af, including exact20+1 audit
pages/Previous, all nine relation/audit reads positive200, each expected-scope
dimension409, inactive membership401 without entity IDs, and restored200.
Full persisted audit rows now participate in read-only snapshots. Review caught
fixture correlation-ID uniqueness, repaired before the passing run. These checks
do not replace independently authenticated foreign-session relation proof or
query-scaling/release gates. No production availability promotion.

Mounted boundary checkpoint: batch52467 passes70ae3f with exact20+1 session
reverse paging/Previous replacement, wrong-environment URL refusal without
entity reads, current-membership403, refreshed mounted capability enforcement
and restored200. Reviewer-required positive downgraded navigation assertion
closes a loading-state false-pass. Execution/runtime snapshots remain unchanged.
Forward cursor browsing and the broader boundary/scaling/release matrix remain
required; this is not idle-tab instantaneous revocation or production proof.

Mounted four-kind checkpoint: grouped browser77632 passes9cd49b across actual
UI/API/database finding/path/session/audit roundtrips. Exact destination IDs and
full scope, audit reload response boundary/history, read-only requests and
execution/runtime snapshots pass. Path/session screenshots inspected; independent
review found no blocker. Typed receipt/session prerequisites are owner-seeded;
the audit row is written by a real local approval cancellation. No provider or
ingestion completion claim. Relation paging/revocation, invalid-scope transitions,
scaling and release gates still prevent marking this batch complete.

Generic-plan checkpoint: installed-query extraction reproduced next-page prefix
rescanning under forced generic plans (RED0a65ac). Bounded mutually exclusive
cursor branches fix it; final serial a88079 passes28.884s across all four plan/
cursor cases, registered APIs, compiled fingerprint and rollback. Review found
no blocker. Nested-function/load proof, reverse indexes/non-audit coverage scaling
and complete mounted browser/release acceptance remain required.

Audit access-path checkpoint: REDb6b238 reproduced a full scan/sort for scoped
run audit pages. Migration54 now owns a full-scope/run/audit-ID index, includes
its definition in the fingerprint and removes it on rollback. Group26dc84 passes
registered APIs, compiled pin, access path and release rollback; final db3d70
adds explicit fixture/output counts and proves indexed first/next pages with
no sort/filter removals. Review found no blocker. Generic-plan behavior,
reverse-query indexes and non-audit full-scope coverage scaling remain open.

Forward consumer checkpoint: all four run relation panels and trigger links now
use default-deny destination capabilities with unresolved-run mutation locks.
Direct/list flows and all four real-client shell roundtrips are covered. Final
group f0a786 passes 166 tests plus scoped test lint; lint/typecheck63d52e and
five-stage standalone UI build7eb0f6 pass. Independent review found no blocker.
All relation UI consumers are locally wired. Database indexes/performance,
complete mounted-browser acceptance and release/publication remain required.

Session consumer checkpoint: exact and list-open timelines now read related
runs after summary/event validation; unattributed collections are excluded.
RED7d1816 to group afd59d passes 54 session/panel/shell tests and typecheck;
lint/diff f9cc88 pass. The shell proves controlled-response run/session/run
navigation. All four reverse consumers are connected locally. Forward run
panels and full database/browser/release acceptance remain required.
Independent review found no blocker. Its additional foreign-session event case
passes in final group 5e2ef7 (55 tests), with scoped lint/diff checks.

Finding/path consumer checkpoint: both direct and list-open drawers now read
related runs with current capability, exact scope and finding-mutation locks.
Review's list-open path identity mismatch was reproduced RED495ee4 and fixed.
Group afbfee passes 82 shell/risk/panel/audit/client tests; lint/typecheck/diff
dd129c pass. Session reverse and run forward consumers remain required, along
with database index/performance and full browser/release acceptance.

Panel/consumer checkpoint: the reusable permission/scoped paginated panel is
implemented, with cycle refusal, stale-response cancellation and mutation locks.
It is mounted beneath successful exact audit detail. RED9a06d2 to grouped
ef0d46 passes 48 audit/panel/client tests, including the review-requested pending
relation abort after failed detail reload. Typecheck48ae28 and lint c5fb26 pass;
independent review found no blocker. Finding/path/session reverse consumers and
run forward consumers remain required. This does not complete batch 2 or 3.

Client checkpoint: both typed relation client functions are implemented with
explicit scope binding, cancellation and strict response/coverage/pagination
checks. RED177b3a and null-limit RED9ca0ba lead to64-test groupd0ce8c plus typecheck;
lint2f2285 passes and independent review found no blocker. UI consumers and full
mounted acceptance are not yet complete.

Forward HTTP checkpoint supersedes pending registration below: both directions
are now registered and documented. RED86450c to forward HTTP groupd765f1 includes
real database-backed audit next-page navigation. Group3f5686 verifies malformed
response and nonadvancing cursor refusal. OpenAPI/lint/coverage46281a and typecheck
e39223 pass; independent review found no blocker. Client/UI, index/performance
and mounted browser acceptance still remain required.

Forward repository checkpoint supersedes the pending repository work below:
REDdec331 leads to strict all-kind repository reads, typed run-context validation,
exclusive ascending audit-ID pages and honest missing/partial authority. Owned
registered adapter group055e07 and focused group1bcefe pass. Independent review
found no blocking issue. Forward HTTP, client/UI and remaining batch2 gates stay
pending; no production acceptance is inferred.

Forward projection/SQL checkpoint: RED650cce and missing-function REDf7c44f
lead to typed deduplicated target pages and current-browser-authorized forward
SQL, including scoped audit-ID pagination. Group292992 preserves the101st target
after100 actions plus a distinct trigger. Groups ea7dc3/1f186c pass registered
database permission, simulation, context binding, fingerprint and rollback.
Independent review has no blocking issue. Forward repository/HTTP remains next;
this does not complete bidirectional API or browser acceptance.

Reverse HTTP checkpoint supersedes the cursor checkpoint's pending route:
browser-only reverse reads are registered and documented, with exact request,
permission and response-page checks. Group184235 passes13.034s including real
repository/SQL and signed next-page navigation. OpenAPI5b5cd3 passes40 tests;
followup88a6fc, lint/typecheck and coveragefd6a66 pass. Review has no blocking
issue. Forward reads, client/UI, index/performance and mounted authentication
acceptance remain pending; no production completion is claimed.

Cursor checkpoint: both directions have domain-separated HMAC cursors bound to
principal, full scope, operation/direction, entity kind/ID, limit and position.
REDb53827 and review regression RED58ef21 lead to group6edaee (1.021s). Explicit
nonnull timestamp decoding closes signed-null forward acceptance. These helpers
are not yet exposed through HTTP; route and forward-query work remain pending.

Typed reverse repository checkpoint: decoded v54 candidates must prove the
requested trigger/action association; exact scoped audit reads separately bind
audit run IDs. Only summaries are returned. REDfe70c3 to grouped4a6d95 passes;
real registered adapter/repository matrix794f44 passes11.852s. Independent review
found no blocking issue. Public HTTP/cursor contracts, forward pages and remaining
batch2 gates are still pending.

Reverse SQL checkpoint: browser-authorized candidate pages now exist for all
four relation kinds, with exact scoped audit and typed trigger/action filters.
Grouped cb87d6 passes authority/fingerprint/rollback in18.925s; followup6c2762
passes action-only lookup and receipt/action deduplication in9.278s. Review-found
false-complete legacy coverage is now partial when receipt or persisted
plan/run/step integrity is missing. Public typed validation, forward pages,
signed cursors, relation indexes/performance and reverse UI remain pending.
This does not close batch2 or constitute live production evidence.

Batch 2 checkpoint: exact audit database lookup implemented after missing-function
RED ece1b9. Group a43df2 passes registered scoped authorization, retained projection
refusal, compiled54 fingerprint and rollback in15.840s. Independent SQL review
found no blocking defect and prompted added expiry/worker/simulation/drift tests.
HTTP/client/UI audit wiring and typed bounded reverse relations remain pending;
these checks do not complete batch 2 or prove a live deployment.

Repository checkpoint: strict nine-field decoder and browser-only method now
use the real adapter's compiled54 verifier before lookup, with no old-release
fallback. REDf92108/91251b to GREEN2d4f6c; owned adapter group e75f0c passes7.090s,
including exact scope, missing/error classification and release drift. Independent
review found no blocking repository defect. Next: implement the documented
browser-only HTTP route and OpenAPI/client contract, then audit UI and relations.

HTTP/client checkpoint supersedes that next step: the route, OpenAPI/generated
types and scoped client are implemented. HTTP RED9373bd, client REDeac68b and
scope-race REDb61bc0 lead to Go4bd9da and client43-test groupc47404; OpenAPI39-test
group66e8b1 and lint pass. Owned handler-to-repository/database groupb87201 passes,
with injected identity explicitly not full authentication proof. Independent
review has no remaining blocker. Next: audit detail UI, audit-to-run links and
typed bounded reverse relations, followed by full mounted browser acceptance.

Audit UI checkpoint supersedes that next step: exact audit selection now uses
the production client and displays the distinct worker reference, event, time,
correlation and scope. Its persisted `run_id` opens the exact scoped run; the
general audit browsing route is unchanged. REDf5dede/6af0e0 to group08b4cd79 tests
cover scope suspension/abort, changed IDs, late responses, permission denial,
403/404/503 reload refusal and audit-to-run plus synthetic popstate. Lint/typecheck
3c79a6, UI/API coverage08b4cd and five-stage production build e11533 pass. Full
browser/authentication proof and complete bidirectional relation APIs remain pending.

- [ ] Extend `scripts/production-combined-e2e.mjs` to traverse all four entity types in both directions through real registered APIs and built UI. Verify exact IDs after reload/back/forward and safe refusal after scope changes.
- [ ] Request independent feature review; fix consequential findings, then rerun affected checks as a batch.
- [ ] Run the UI build and release checks before publishing. Update the authoritative ledger with exact local evidence and unresolved external gates. Do not promote M7A-90 to production-available without the required deployment evidence.

Batch 2's source-derived API design is a required checkpoint before its code, not an omitted implementation contract. The URL batch can proceed independently while retaining the complete deliverable.
