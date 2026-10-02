# Owned Docker database for combined browser acceptance

Bounded prerequisite to Task2 of the public-proof plan. Original scope and
acceptance remain unchanged. User authorized autonomous implementation and
feature-batched verification. No host PostgreSQL server may be started.

## Implementation contract

Replace the host initdb/postgres/pg_ctl lifecycle in
scripts/production-combined-e2e.mjs with a focused helper
scripts/owned-browser-postgres.mjs and behavioral tests beside it. Keep host
PostgreSQL clients for SQL/setup/readiness if useful. Default combined runner
must use the owned container, not an opt-in fallback to host PostgreSQL.

Use only cached image
postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba
with --pull=never. Bind only 127.0.0.1 on the harness's allocated port. Run as
postgres with read-only root, writable ephemeral /tmp and PGDATA beneath /tmp.
Use zasp_e2e database user and postgres database. Preserve optional
track_functions=pl instrumentation. No host data directory, daemon startup,
external database reuse, mounts of user data, image pull or online audit.

Resource ownership must survive failed readiness/startup and cancellation:
track the exact container created by this invocation; bounded stop/remove and
join only that resource, never broad Docker cleanup or guessed historical IDs.
Use existing owned-command/bounded-signal-cleanup patterns. Failure to join must
surface and preserve harness artifacts. Concurrent/repeated stop is safe.
Update the diagnostic liveness assertion to inspect this actual owned resource.
Do not treat the Docker CLI child alone as database liveness or cleanup proof.

Write focused failing behavioral tests first for success, invalid port,
startup/readiness failure, early container exit, concurrent stop, bounded
command failure and cleanup failure as relevant to the chosen minimal API.
Inject only the external command boundary; assert real lifecycle decisions and
exact safe command arguments. No source-string presence tests.

Run one grouped Node test selection for changed helper, owned-command, bounded
signals and combined-runner tests. Then use the cached image to smoke-test the
actual helper, real SQL query and successful cleanup. A full mounted browser
flow is not required for this prerequisite and must not be claimed.

## Boundaries and report

Work only in the existing budget-recovery-20260916 worktree. Preserve inherited
dirty changes. Do not commit, push, enable test actions, alter migrations or
production readiness. Do not spawn subagents. Use apply_patch for file edits.
Node: /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node.
Docker: /usr/local/bin/docker (PATH may be set accordingly).
If cached Docker is unavailable, report the exact failure; do not install/pull.

Read Superpowers TDD and writing-good-tests instructions. Self-review, then
write docs/internal/2026-09-17-owned-browser-postgres-report.md with exact
RED/GREEN commands/output, files, live smoke evidence and terminal cleanup.
Return a short DONE/DONE_WITH_CONCERNS/BLOCKED report. Main owns independent
review and authoritative ledger. No production or full-browser proof claim.
