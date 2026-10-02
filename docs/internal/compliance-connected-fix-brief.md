# Connected compliance fix wave

Read `compliance-connected-review.md` first. Fix its three Important findings as
one batch under the existing compliance design/plan. Use Superpowers receiving-
review, systematic debugging, TDD and verification. No scope reduction.

1. Align execute candidate scope ordering with claim admission. Preserve tenant
   fairness, per-scope oldest-job ordering, reconcile/cleanup behavior and lease
   safety. Registered SQL/processor regression must show reverse creation order
   with batch1 makes progress and more waiting scopes than batch are serviced.
   Update unshipped release56 generated SQL/checksum/fingerprint using the existing
   mechanism; preserve predecessor55 SQL and pins exactly.
2. Populate HIPAA as well as SOC2 evidence in the actual UI, including all-
   framework and framework/control filtering. Preserve independent cursor chains,
   effect-to-page cancellation, late401/409 protection and exact source/version
   links. Add populated HIPAA mounted-client and actual browser detail tests.
3. Align compliance cursor bounds end-to-end, preferably a dedicated compliance
   contract without widening unrelated shared cursors. Derive the cap from valid
   source/filter inputs and existing encoded/decoded API bounds. Keep scope,
   operation and filter binding, malformed/foreign rejection. Run actual emitted
   maximum-ID cursors through HTTP, strict TS decoder and multi-page adapter.
   Regenerate generated contracts if OpenAPI changes.

Run focused RED/GREEN, then one affected Go/SQL/contract/UI group, types/lint/build
and one actual browser run on that build. Extend browser HIPAA and long-cursor
paging coverage without dropping downloads/restart/tenant/grant/session checks.
Respect100records/control export limit; paging fixtures do not justify relaxed
export caps. Explain any changed assertion. Reuse unchanged evidence by identity.

Capture fresh BEFORE blobs and incremental patch/AFTER manifest as connected-fix-*
in the existing plan workspace; preserve previous artifacts. Report commands,
outputs, pins, source changes, all joined handles/cleanup and limitations. One
root-owned scoped re-review follows, not one reviewer per finding.

One implementer, no subagents. No staging/commit/push, ledger edits, downloads,
new image pulls/builds, host PostgreSQL, live providers or advisory disclosure.
Use cached owned Docker, offline Go and Node22. Preserve unrelated edits and the
approved CI preflight/wiring. Local tests do not establish production deployment.
