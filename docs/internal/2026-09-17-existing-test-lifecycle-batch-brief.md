# Existing-test public lifecycle integration batch

This is Task2's public lifecycle prerequisite in
2026-09-17-existing-test-public-proof-plan.md. Read this brief first, then the
contract and admission sections of 2026-09-16-security-agent-existing-test-design.md
and the interfaces in 2026-09-17-existing-test-mounted-readiness-audit.md.
The original 728-task scope is unchanged. User authorized autonomous decisions,
GPT-6 Astra, Superpowers TDD and feature-batched verification.

## Goal and boundaries

Make real public creation/catalog, simulation, activation/readback, scoped
controls, manual run admission and automatic scheduling usable for both
run_test and rerun_test on the unpublished compiled55 candidate. Reuse the
existing planner/preparation/dispatch and linked test execution path. Do not
fabricate enabled definitions, test-action controls, trigger receipts or prepared
runs in the acceptance fixture to bypass the public admission path.

No host PostgreSQL server. No external service invocation, network downloads,
dependency audit disclosure, commit, push or deployment. No static readiness or
ledger promotion. Do not enable the deployed reconciler. Preserve the dirty
worktree; only scoped edits and generated OpenAPI output. No subagents.

## Selected architecture

Compiled55 capability means runtime protocol support, not production proof.
Catalog helpers use a small capability value with existing-test support probed
per request through SecurityAgentExistingTestDefinitionsAvailable(ctx). Add only
run_test/rerun_test metadata plus usable single-action finding-trigger templates
with verification_condition=test_run. Append templates to preserve existing
index-derived public IDs. Keep static ProductionActionReadiness unchanged.
Runtime catalog text must not promise production certification. A failed
capability probe fails closed; an unavailable capability omits test actions.

Existing durable global/environment/per-action controls remain the execution
authority and absent rows are disabled. Expose supported metadata even when
controls are off so the user can configure and enable through the real API.
No separate local-only flag. Candidate55 must not be deployed before A-D and
release gates; remote deployment absence has not been proved. No production
rollout is authorized by this local implementation batch.

## Files and responsibilities

- services/platform/securityagent/templates.go and focused catalog/template tests:
  append usable run/rerun templates. Do not modify the old multi-action templates.
- services/platform/apiserver/workflow_handler.go and focused tests: catalog
  capability probe, exact two supported test actions, preserved older behavior.
- services/platform/migrations/sql/fragments/security_agent_existing_test_lifecycle.sql:
  complete registered55 activation and replay; retain old-caller fences.
- New fragment security_agent_existing_test_controls.sql: registered55 control
  detail/mutation and private helpers; new fragment
  security_agent_existing_test_admission.sql: manual/automatic admission shared
  private core and guarded public wrappers. Embed both at the appropriate point
  in migrations/security_agent_existing_tests_release.go. Keep responsibilities
  separate, no unrelated migration refactor.
- Extend 0055 release fingerprint/ACL registration and unused rollback coverage
  for these functions only. Never edit published predecessor migration bodies.
  Update compiled55 fingerprint only after an owned calibration test observes it.
- services/platform/apiserver/security_agent_repository.go,
  security_agent_worker_repository.go and focused existing-test repository files:
  route controls/run/scheduling to registered55 with compiled pins; validate
  enabled existing-test readback against capability, exact reference and body.
- security_agent_handler.go, openapi/openapi.yaml, apps/web/api/decoders.ts and
  generated.ts: expose the six-action control shape at55 and preserve valid old
  two/three/four-action shapes. Exact sorted new action order:
  create_temporary_policy,isolate_session,rerun_test,revoke_integration_connection,
  run_test,update_finding_response. Reject duplicate/missing/malformed controls.
  Manual run contract includes finding, attack_path and session (session maps
  to persisted runtime_decision evidence); older schemas retain older support.
- app/features/securityagents/SecurityAgentsView.tsx and focused tests: render
  supported catalog and actual controls without a fake executor. Existing picker
  and public proof rendering remain. Change catalog heading if it claims
  production certification. Do not redesign the screen.
- New focused Go/SQL/HTTP/web tests named for this lifecycle batch. Existing
  lifecycle tests that assert an unconditional intermediate activation fence
  must be replaced with actual safety refusal cases, not silently deleted.

## Required admission behavior

1. Draft creation remains disabled and exact-version. Validation and simulation
   enqueue nothing. Public activation requires fresh browser authority, correct
   optimistic version, current exact test binding, supported non-production
   environment/target/credential, and enabled global/environment/action controls.
   Resolve and recheck after blocking locks and before writes using wall-clock
   expiry. Keep normal budget/cost configuration requirements.
2. Preserve replay's durable response and IDs. Replayed activation must not
   renew fresh auth or authorize stale/currently unsafe binding. Wrong scope,
   version, stale credential, disabled test/control or expired auth leaves
   durable state unchanged. Enablement must not evade guards through a legacy
   function or a forged checksum/fingerprint.
3. Enabled-definition readback requires exact55 capability and valid stored
   identity/reference/autonomy. Kill-switch-off must not make valid stored
   definitions/history unreadable. Reading history is not new-work authority.
4. Control mutation has browser fresh-auth, current scoped version, idempotency
   conflict detection, audit/receipt and final expiry checks. Include both test
   actions. Missing controls are disabled; no automatic enabled rows. Preserve
   stop/cancel/reconciliation/history when new work is disabled.
5. Shared manual/automatic admission preserves one trigger receipt/run per exact
   scoped definition/trigger version. Manual attack_path must work at55; automatic
   finding, attack_path and runtime_decision must all work. Use existing canonical
   trigger digest formats consumed by planner/dispatch, exact fresh evidence,
   bounded candidate selection, per-definition concurrency and organization-first
   budget lock order. Do not allow a stale candidate or lock wait to consume
   expired authority. Changed intent conflicts rather than replaying unrelated work.
6. Scheduler total return is bounded by caller limit1..25, including delegated
   legacy work. Legacy actions still schedule. One invalid/stale candidate must
   not create partial receipts or mutate foreign scope. Do not broaden direct
   worker EXECUTE privileges or let workers impersonate API principals.

## TDD and grouped verification

Write tests first and capture expected failing outputs before implementation.
Reuse runVersionedExistingTestFixture and mounted handler/repository helpers,
but new acceptance must create and activate through registered public functions
or HTTP, enable tenant controls through their public API, and admit triggers
through the new public route. It is okay to seed underlying scoped test/target,
risk evidence, deployment-global control and owned identity prerequisites.
Clearly distinguish API/SQL fixtures from actual authenticated browser proof.

Use hand-derived expectations, for example the public control result must
contain this literal sequence (not an expectation built from the implementation):

```go
wantActions := []string{"create_temporary_policy", "isolate_session", "rerun_test",
    "revoke_integration_connection", "run_test", "update_finding_response"}
```

Acceptance matrix: both actions x supervised/autonomous activation/readback;
manual finding/attack_path/session; automatic finding/attack_path/runtime_decision;
manual/automatic dedup; stale trigger/control/version/credential and foreign
scope refusal with a valid positive control; fresh-auth expiry during a held
lock; control-off history readability; schema54 refusal/fallback; owner/API/
worker/private-helper ACL boundaries;55 fingerprint, old-binary refusal and
unused rollback. Include real registered planner context/preparation for at
least one newly admitted run to prove the trigger digest/definition contract
connects downstream, without bypassing actual planner authority.

Run focused RED/GREEN during coding. Then one grouped affected Go race selection
(host tests MUST use an explicit positive non-database test allowlist, verified
against function bodies/call paths, plus -skip Postgres as a secondary filter;
that negative filter alone is insufficient because database-backed tests exist
without Postgres in their names), owned SQL acceptance group, web decoder/UI
tests, typecheck, OpenAPI generation/checks, runnable UI build/import guard.
Main can run heavy SQL/build verification on request; coordinate to avoid
duplicate runs and concurrent database fixtures. Never run the broad apiserver
package on the host based only on a name-exclusion filter. Report exact cases skipped or
still incomplete instead of calling the batch complete.

Go: /opt/homebrew/bin/go, GOTOOLCHAIN=local GOPROXY=off
GOCACHE=/private/tmp/zasp-budget-go-cache.
Compile owned tests with GOOS=linux GOARCH=arm64 CGO_ENABLED=0 into a new uniquely
named /private/tmp executable. Never overwrite an executable currently mounted.
Docker: /usr/local/bin/docker; cached pinned image only:
postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba.
Run tests --rm --pull=never --network none --read-only --user postgres with
/tmp tmpfs and readonly executable/repo mounts. No image pull or host database.
Use exact test selections and bounded timeout; join all owned resources.
Calibration test: TestSecurityAgentExistingTestCompiledFingerprintPostgres.
Node22: /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node.

## Handoff

Self-review against the original design, not just green fixtures. Write a concise
report to docs/internal/2026-09-17-existing-test-lifecycle-batch-report.md with
RED/GREEN commands/output, changed files, final55 pin, compatibility/ACL evidence,
remaining browser/live gates and terminal resource cleanup. Produce a scoped
baseline-to-final patch including new files for independent review; baseline is
the inherited dirty state, not just HEAD. Main owns status ledger and review.
Return DONE, DONE_WITH_CONCERNS, BLOCKED or NEEDS_CONTEXT. Raise concrete security
or interface ambiguity promptly; do not invent a weaker acceptance path.
