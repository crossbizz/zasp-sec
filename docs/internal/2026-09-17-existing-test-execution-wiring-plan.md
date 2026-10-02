# Existing-test execution wiring implementation plan

> Execute inline with Superpowers TDD and independent batch review. Standing
> user authorization replaces routine approval pauses. Preserve the full728.

**Goal:** Connect prepared existing-test work to guarded registered execution,
without publishing private dispatch or weakening uncertain-invocation stops.

**Architecture:** A schema55 execution wrapper selects the private existing-test
dispatch core or the retained v24 execution path from locked persisted intent.
The Go repository selects this wrapper only after current release readiness and
passes compiled checksum/fingerprint. SQL verifies registered worker identity,
release integrity and exact scope/lease; no caller-provided action selector.

**Tech stack:** Go/pgx and existing PostgreSQL55 candidate fragments.
**Spec:** 2026-09-16-security-agent-existing-test-design.md, Batch B execution
interface and Batch D publication gates in its implementation plan.

## Global constraints

- M7A-21 stays component-only and public action availability stays disabled.
- Private dispatch retains no application EXECUTE grant. Only a fully guarded
  wrapper may gain the registered worker role grant in the complete candidate.
- Existing schema24 actions must still work at55; no legacy fallback on drift.
- Do not publish this protocol separately from A-C safeguards and D acceptance.
- Preserve dirty work; owned offline PostgreSQL only, no host database startup.
- Release55 fingerprint changes require owned calibration, drift and rollback
  checks. Local fixtures are not live queue/provider/storage or production proof.

## Task 1: Repository and registered execution as one integration batch

Files: apiserver/security_agent_existing_test_execute_routing_test.go,
security_agent_existing_test_worker_repository.go, security_agent_worker_repository.go;
migrations/sql/fragments/security_agent_existing_test_dispatch.sql,
security_agent_existing_test_candidate_down.sql and
migrations/security_agent_existing_tests_release.go. All paths below
services/platform unless prefixed docs/internal.

- [x] Run the new routing regression:
  `go test -C services/platform -run '^TestSecurityAgentExistingTestExecutionRouting$' ./apiserver`.
  It must expose warm55 execution still selecting v24. The test also requires
  exact compiled pins and zero execution queries after readiness drift.
  RED56465d fails at warm55 selection: ExecuteSecurityAgentRun still emits the
  v24 query. No production change is made yet. Later assertions for supplied
  pins and drift are not reached in this failing run; do not claim them passed.
- [ ] Implement the guarded SQL signature before changing production routing:
  `zasp_production_security_agent_existing_tests_execute_run(o text,w text,e text,r text,worker_value text,lease_value text,audit_value text,correlation_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb`.
  Authenticate worker principal; verify supplied release pins; take existing
  budget admission/run locks; derive action from the exact persisted authorized
  step and matching plan. Use private dispatch for run_test/rerun_test and
  retained zasp_security_agent_execute_run_v24 for existing supported actions.
  Recheck release after returned writes so drift rolls back atomically.
  Capture the original lease and relevant plan/credential deadlines before
  dispatch. Recheck those captured wall-clock deadlines after every final
  write and post-call readiness check: the private core clears the lease, so
  inspecting the cleared row cannot establish original ownership validity.
  Reject ambiguous/mismatched test intent. Do not impose test single-step
  restrictions on legacy multi-step actions or alter legacy budget-stop output.
- [ ] Add real registered API/owner/worker refusal and positive execution tests,
  using existing preparation/dispatch fixtures without temporary private grants.
  Assert one scoped link/run/outbox on accepted dispatch; zero writes on wrong
  pins, scope, lease, missing controls and changed prepared intent. Retain the
  existing uncertain-invocation claim/retry/start protections and replay tests.
  Include registered legacy execution at55 and observed blocked final-write/
  readiness expiry cases. Independent design review specifically identified
  post-dispatch waits after lease clearing as a rollback obligation.
- [x] Route ExecuteSecurityAgentRun with the same warm capability check as
  PrepareSecurityAgentRun. Versioned statement is exactly
  `SELECT public.zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`.
  Append compiled checksum/fingerprint to the existing eight arguments. Keep
  current response validation and legacy statement only when55 is absent.
  Routing GREEN95cfcf and actual registered Go repository58636b pass all four
  positive modes. SQL wrapper is implemented; bounded supervised legacy and
  final-write and final-readiness expiry acceptance now pass for the supervised
  legacy path. Broader action coverage remains open. See
  execution-wiring-checkpoint for exact evidence and instrumentation limits.
- [ ] Calibrate changed55 in the owned fixture; verify direct bootstrap,
  readiness body/ACL drift, rollback refusal after links, and clean rollback.
  Run grouped repository/worker/migration race and registered dispatch,
  invocation, cancellation, reconciliation and recovery acceptance once.
- [ ] Independent review of the complete privilege and routing delta. Record
  exact results and limits in the authoritative ledger. Do not mark this task
  complete from a routing mock or a private-owner dispatch fixture alone.

## Completion boundary

This batch closes the worker execution connection only. Safe public before/after
evidence projection, composed browser create/activate/trigger/execute/result
acceptance, release/advisory clearance and live canary/load remain required by
the original plan. No original requirement or external gate is removed.
