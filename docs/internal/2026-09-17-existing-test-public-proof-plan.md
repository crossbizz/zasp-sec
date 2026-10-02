# Linked-test public proof implementation plan

> Use Superpowers TDD with independent feature-batch review. Execute within the
> existing isolated worktree; user authorization replaces routine approval pauses.

**Goal:** Expose actual stored linked-test proof through the scoped API and UI.
**Architecture:** Private schema55 projection -> strict Go action details ->
generated OpenAPI/strict browser decoder -> ActionDetails and scoped history.
**Tech stack:** PostgreSQL, Go, TypeScript/React.
**Spec:** 2026-09-17-existing-test-public-proof-design.md; original
2026-09-16-security-agent-existing-test-design.md remains authoritative.

## Global constraints

- Preserve full728 scope, private SQL ACLs, existing tenant/header authority.
- No production action enablement before full A-D acceptance/release gates.
- Never publish raw settlement, token, storage key, endpoint or credential data.
- Changed55 requires owned calibration and fresh registered compatibility tests.
- Preserve inherited dirty work; no blanket staging or host PostgreSQL.

## Task 1: One projection/consumer integration batch

- [x] Add failing Go action projection/public-struct tests using the spec's exact
  existing_test shape; cover pending, remediated, all safe outcome/reason pairs,
  invalid association/version/digests, null/missing/extra/duplicate fields,
  test-only applicability and unchanged older-server omission.
  Files: new apiserver/security_agent_existing_test_public_projection.go/_test.go;
  extend security_agent_action_projection.go and security_agent_action_validation.go.
  Run focused exact unit selections with `-skip Postgres` on the host; database
  tests run only in owned offline Docker.
- [x] Add private SQL public projection in a new
  migrations/sql/fragments/security_agent_existing_test_public.sql, embedded last
  in migrations/security_agent_existing_tests_release.go. Extend only the55
  registered run_context wrapper to apply it to the already-authorized envelope.
  All field names and invariants are specified in the design; predecessor54 is
  unchanged. Exact guarded function grants remain as before.
- [x] Add real registered-read assertions after pending dispatch and actual
  settlement, using existing owned completion/settlement fixtures. Prove scoped
  positive reads and owner/worker/foreign-scope refusals, no sensitive sentinel
  exposure, no DB mutation, and tampered receipt/proof rejection. Capture RED
  before SQL implementation, then calibrate55 and run grouped GREEN/release tests.
- [x] Implement Go validation and map the optional field; run affected API tests
  without launching database-owning tests on the host. No wire-shape fallback.
- [x] Extend OpenAPI schemas and regenerate apps/web/api/generated.ts. Add strict
  web decoder acceptance/refusal tests first, then its implementation. Files:
  apps/web/api/decoders.ts and new decoders.security-agent-test-proof.test.ts.
- [x] Render proof in app/features/securityagents/ActionDetails.tsx (or a focused
  child) with real React component tests for pending, improvement, no baseline,
  uncertainty and partial cancellation. Extend app/domain/activity-links.ts and
  the actual Red Team route consumer for scope-preserving before/after navigation.
- [x] One grouped affected Go race, web tests, typecheck, OpenAPI checks, UI
  build/runnability and independent integration review. Record exact evidence
  and remaining composed-browser/live gates in docs/internal before any push.

## Task 2: Original Batch D acceptance

- [x] Complete the public lifecycle integration gaps confirmed by
  2026-09-17-existing-test-mounted-readiness-audit.md: usable single-test
  templates/catalog rollout, activation/readback, scoped execution controls,
  manual and automatic trigger admission. Keep default production disablement
  and private authority intact until the complete release is verified. Test and
  review this as one feature batch; do not insert fixture rows to bypass it.
  Bounded acceptance: final v5 review closes all three Important findings;
  same-product runs18/19/20/21 supply passing coverage. See the lifecycle
  review checkpoint. This does not complete mounted browser or release gates.
- [x] Replace combined browser harness host PostgreSQL startup with an owned
  cached Docker lifecycle, with bounded cleanup and a real SQL smoke test.
  See 2026-09-17-owned-browser-postgres-report.md. Grouped66 pass/2 opt-in
  skips, actual SQL and exact-ID cleanup pass; independent review has no
  blocking findings. This is not schema55 or mounted browser acceptance.
- [x] Run the real mounted API/worker/controlled-target browser flow from the
  original design: select test/version, simulate, activate, trigger, approve if
  supervised, pending, actual execution, stored comparison, reload and scoped
  history. Include foreign-user denial with positive control, no-baseline pass,
  fail and engine error. Do not replace this with component rendering tests.
  Run15 exited0 with four cases and valid foreign/missing refusal plus owner
  cancellation; frozen V2 source independently approved for local spec/quality
  acceptance. See 2026-09-17-existing-test-mounted-batch-report.md. This does not
  satisfy the separate release gate below or establish live production proof.
- [ ] Run exact full release gates and whole-feature review before activation
  or main publication. External provider/load/advisory gates stay explicit.
