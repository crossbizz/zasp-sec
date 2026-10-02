# Existing-test public consumer contract

## Reproduced gap and implemented connection

The database/Go action projections already describe run_test/rerun_test, but
the browser rejected their action details and supervised approvals. RED6a7dab
fails four new positive cases with schema mismatch. The browser now accepts
exact persisted test arguments `{target_id, expected_version}`, version1..1000000,
and exact low-risk, nonreversible, zero-TTL approval semantics. Run-detail
approval association binds Run existing test to run_test and Rerun existing
test to rerun_test. Extra prompt/URL/credential/category/status fields remain
rejected. OpenAPI and generated types match; the component renders expected
version without assuming the finding-only target_status member exists.

This is an acceptance contract extension, not action capability enablement.
Public production capabilities remain disabled and M7A-21 is component-only.

## Evidence

- Focused GREENce8ae2:57/57 tests. Grouped decoder and SecurityAgentsView
  regression7358e4:165/165. Typecheck and OpenAPI9a466a:40/40.
- Independent review found no Critical/Important findings. Its Minor suggestions
  for swapped run/rerun effects and wrong catalog risk were added. Final focused
  d4b2cd:59/59, plus both OpenAPI documents pass lint.
- UI build and compiled import guardcc580d pass, seven client/eight server
  chunks. Owned standalone HTTP smoke30c234 returns200 for root and all seven
  referenced JS/CSS assets. Server4511 was stopped after the smoke check.
  This is not browser hydration, authenticated E2E or production availability.
- Scoped diff whitespace checkf7f816 exits0. No SQL/Go production source or
  release55 pin changed in this consumer delta. No commit or push.
- Focused ESLint375368 passes the decoder, its two test files and ActionDetails.

## Remaining public proof work

The existing ActionDetails component still shows only generic effect state and
verification, not linked test history or before/after proof. The browser cannot
meet the original Batch D acceptance until that gap is implemented.

Extend the existing action-details projection, retaining its exact scoped API
authority and opt-in behavior. A closed optional existing_test member should
carry the persisted definition/version and linked test run, pending/settled
state, safe outcome/reason, and redacted before/after attempts and per-check
comparison. Use stored reconcile_settlement proof/receipt under exact link,
step and effect association; never infer remediation from aggregate pass.
Do not serialize the private settlement object, snapshots, tokens, proof_hex,
storage keys, credential references, endpoint URLs or raw responses. Retain
artifact identity/checksum/version/size without making new storage requests.

Relevant boundaries: migrations/sql/fragments/security_agent_existing_test_reads.sql
and settlement.sql; apiserver/security_agent_action_projection.go and
security_agent_action_validation.go; OpenAPI, browser strict decoder and
app/features/securityagents/ActionDetails.tsx. Pending, no-baseline pass,
condition-persists, inconclusive, confirmed cancellation and verified change
must remain distinct. Scoped exact-ID history navigation needs the existing
activity-link parser extended for actual Red Team run routing, not ad hoc URLs.

This remaining work preserves the original design in
2026-09-16-security-agent-existing-test-design.md. Full proof projection,
composed browser workflow, whole-feature review and release/live gates remain
required; this checkpoint does not replace or shrink them.
