# Compliance deployment batch: registration bridge

Original scope: deployed M7-12/13/14/15 export lifecycle, within the unchanged
728-task plan. Design authority: `2026-09-18-compliance-production-design.md`.
Current gap: `2026-09-18-compliance-deployment-gap.md`. This is one bounded
implementation unit of the connected deployment batch, not full acceptance.

## Existing authority and selected interface

SQL56 already implements `public.zasp_compliance_register_workers(executor,
cleanup,checksum,fingerprint)` and separate `zasp_compliance_worker` and
`zasp_compliance_cleanup` capability roles. It registers two pre-created LOGIN
INHERIT roles through the registered migration authority and checks exact
readiness. Do not edit any migration SQL, metadata checksum or semantic pin.

Add `(*migrations.Runner).RegisterComplianceWorkers(ctx, executor, cleanup)` and
the actual migration command `register-compliance-workers` with exactly one
argument. Environment names are `ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL` and
`ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL`. Validate both canonical bounded login
names, distinct, neither starting `zasp_`; no credentials are created or read
from these values. Missing, extra, duplicate, reserved or malformed inputs must
fail with existing fixed public error messages before database connection.
Do not print raw DSNs, principal values or SQL errors.

Use the existing runner transaction/error protocol: exact56 state and compiled
readiness before registration, parameterized call using compiled checksum and
fingerprint, require true, final readiness before commit, rollback on error or
cancellation. Existing `up-to-56` and historical commands keep their semantics.
Registration is explicit, not a hidden side effect of all migrations.

Primary files: `services/platform/migrations/production_compliance.go` plus
focused migration tests; `services/platform/agentsec-migrate/main.go`, a focused
`compliance_registration.go` and corresponding tests. Reuse the audit-export
registration pattern without changing its authority or historical behavior.

## Verification and report

1. Capture exact before bytes and establish focused behavioral RED for the
   missing registration path before implementing it.
2. Cover true/false result, SQL errors, exact pins, wrong release, invalid names,
   rollback/cancellation, extra CLI args, fixed-error/no-secret output.
3. Exercise the actual migration CLI binary against one owned isolated cached
   PostgreSQL fixture using registered non-superuser migration identity. Register
   two pre-created login roles; prove exact capability binding, idempotent replay,
   cross-authority denial and refusal without changing binding rows on invalid
   or unavailable release. Do not substitute a mocked dispatcher for this proof.
4. Use focused tests while coding; run one affected Go/race batch at the boundary.
   No full frontend suite, no whole cmd test suite that could reach host Postgres.
   Existing deployment-suite failure is retained until later batch integration.
5. Retain commands, RED/GREEN, before/after hashes and task-only patch under
   `docs/internal/compliance-registration-20260918/`; full report `report.md`.
   Root handles independent review and authoritative ledger. No task promotion.

## Local execution constraints

Work only in the existing shipping worktree. Preserve inherited edits. Use
apply_patch. No stage/commit/push, cloud/provider calls, dependency downloads,
image pulls/builds, host databases or subagents. User authorizes autonomous
routine decisions; no approval pause for this bounded bridge.

Go: `/opt/homebrew/bin/go`, `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
GOCACHE=/private/tmp/zasp-budget-go-cache`. Docker: `/usr/local/bin/docker`.
Only owned cached PostgreSQL with `--pull=never --network none`, pinned image
`postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`.
Inspect existing owned fixture conventions before selecting exact test command.
Own and join all processes and remove only fixture resources proven owned.

Ruling: use the existing56 SQL registration function through a new explicit
CLI/runner bridge; do not add57 or weaken existing role checks. Cost if wrong:
local wrapper rework, with no change to deployed migration history.

Interface coherence: CLI produces two validated names; runner consumes those
names and compiles pins; SQL grants/registers the existing two roles. No other
implementation agent edits these files during this task. Later Helm wiring
consumes the command and environment names above, not a duplicated SQL script.
