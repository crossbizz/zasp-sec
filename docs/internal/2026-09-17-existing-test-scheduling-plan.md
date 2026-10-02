# Existing-test production scheduling integration plan

Goal: automatically schedule all eligible tenant-scoped existing-test links,
without granting the reconciler target execution or relying on operator tenant
lists. This continues the approved full728 scope; M7A-21 remains component-only
until the complete runtime and production evidence exist.

Architecture decision: add guarded keyset scope discovery and a round-robin
processor calling the current ReconcileOne. A dedicated production worker mode
will use the existing registered security-agent worker SQL authority, compiled
release pins and read-only artifact access. Reusing the planner loop would couple
reconciliation availability to planner credentials; a static scope list misses
new tenants. Discovery does not claim work; existing scoped leases remain the
only mutation authority. The cursor is a fairness hint, never an authorization.

Global constraints: no new target execution authority; no global direct-table
grant; SQL principal and compiled checksum/fingerprint checks before and after
discovery; all scope IDs canonical and pairwise distinct; no production claims
from controlled tests; preserve all unrelated dirty work; no partial protocol push.
Standing user authorization replaces additional design/implementation approval.

## Task 1: Guarded database scope discovery

Modify migrations/sql/fragments/security_agent_existing_test_reconcile.sql and
owned apiserver reconciliation tests, plus the compiled fingerprint only after
owned calibration. Paths are relative to services/platform.

Interface: zasp_production_security_agent_existing_tests_reconcile_scopes(
after_o text,after_w text,after_e text,worker_value text,
expected_checksum text,expected_fingerprint text) RETURNS jsonb.
Empty cursor is exactly three empty strings; otherwise three valid distinct IDs.
Return zero or one row with exactly organization_id, workspace_id, environment_id,
ordered by that tuple strictly greater than cursor. Only links with admitted orgs
and pending next_at<=DB clock or leased expires_at<=DB clock qualify. Settled,
future pending and live leases do not. SQL never wraps; caller owns wrap.
Worker name uses existing regex, principal must be registered security-agent
worker; private owner cannot call as registered worker. Grant only worker role,
revoke PUBLIC. Validation22023, principal42501, release55000.

- [x] Add owned behavior tests and observe missing function42883 before SQL.
- [x] Implement bounded keyset discovery, strict guards and grants.
- [x] Verify eligible/empty/after-cursor behavior, invalid/null/partial cursors,
  owner/API refusal and wrong pins, no durable mutations. Include expired/live
  lease and delayed pending cases using actual rows; restore fixture state.
- [x] Calibrate fingerprint in owned offline Docker only; group migration and
  registered reconciliation regression. Record actual logs and limitations.

## Task 2: Worker selection and production lifecycle

New security_agent_test_scheduler.go/_test.go in agentsec-worker. Interface:
client.NextScope(ctx, after domain.Scope) (domain.Scope,bool,error), accepting
zero scope as start; strict receipt decoding and returned tuple > cursor.
Processor.RunOnce(ctx) handles at most one scope via ReconcileOne. On end of
list, retry discovery once from zero; no unbounded loop. Advance cursor before
reconciliation so an unhealthy tenant cannot starve later tenants. Keep cursor
on discovery error. Serialize calls; cancellation while waiting must return.

- [x] TDD NextScope closed decoding, exact pins/arguments, monotonic cursor,
  empty list, missing/alias/duplicate keys, invalid IDs, errors and cancellation.
- [x] TDD round-robin wrap, failure isolation, empty population, canceled waits
  and process restart rediscovery using real client SQL-boundary fixtures.
- [x] Add dedicated mode, read-only production artifact dependencies, readiness,
  bounded cancel/join shutdown, config validation and exact workload deployment.
- [ ] Owned registered database/client composition for multiple scopes and
  restart/reclaim. Run grouped race/integration review; UI/build/release before
  push. Keep deployment/live provider and load characterization gates separate.

The last item is partially verified by
[multi-tenant queued restart acceptance](2026-09-17-reconciler-restart-checkpoint.md).
Completed-test lost-ack settlement recovery now also passes all four modes in
that checkpoint. Exact push-candidate gates remain open; do not mark the entire
item complete from owned process recovery alone. Persisted-request replay,
concurrent replica/load characterization and live rollout are separate gates.

Execution: inline Go work with one SQL implementation subagent, then independent
batch review. Both consume the exact scope interface above. SQL and Go writes
are disjoint; no other implementation agents or competing commits.

Runtime implementation decisions (2026-09-17): mode
`security-agent-test-reconciler`, registered `zasp_security_agent_worker`
database authority, dedicated `ZASP_TEST_RECONCILER_ROLE_ARN` and
`ZASP_TEST_RECONCILER_WEB_IDENTITY_TOKEN_FILE`. The configured lease is exactly
60 seconds and batch size1, matching the existing reconciler. Shared config
fields outside core worker/database and evidence-reader settings must be zero.
No planner, target execution or queue credentials are accepted.

Cloud composition uses explicit web identity, role/account matching, versioned
S3 evidence with exact bucket owner/KMS, maximum1MiB and 5-second I/O bounds.
Only Get and ObjectReference methods reach the reconciler. Existing read-only
bucket/KMS readiness checks are reused. Readiness is bounded5s and cached30s;
each scheduling/reconciliation SQL call still validates release and authority.
The runtime tracks readiness and execution borrowers, cancels both on close,
and retains cloud/database dependencies if joining exceeds shutdown timeout.
Deployment IAM must enforce read-only permissions independently of Go methods.
