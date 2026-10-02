# Registration bridge: ready for review

September 18, 2026. Bounded implementation complete in the existing shipping
worktree at HEAD `8733b16f8d939d38a8157dd2519e57fc6f630542`.

The explicit `register-compliance-workers` command now calls
`(*migrations.Runner).RegisterComplianceWorkers(ctx, executor, cleanup)`.
It accepts exactly one argument and reads the selected names from
`ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL` and
`ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL`. Both must match the existing canonical
3..63-character login pattern, differ, and avoid the reserved `zasp_` prefix.
Invalid inputs fail before connection with the existing fixed configuration
error. Names are not credentials.

The runner checks every release row through exact56, checks compiled56
readiness, calls the existing SQL function with four parameters (both names,
compiled checksum, compiled fingerprint), requires true, and checks readiness
again before commit. Its existing transaction helper handles rollback,
cancellation and fixed database errors.

Only six source/test files changed in this task; `scoped.patch` contains those
changes against the actual starting bytes, including inherited local changes.
The two pre-existing edited files were copied byte-for-byte into `before/`
before implementation. The four added files did not exist at task start.
No migration SQL, checksum, semantic pin, audit-export implementation,
deployment file or task ledger changed. Nothing was staged or committed.

## What the evidence says

`red.log` records behavioral failures before implementation. The runner had no
explicit registration method; twelve invalid CLI cases reached the database
connection path instead of rejecting configuration. The valid boundary case
already reached the connection path as expected.

`green.log` then passed the focused feature checks. Thirteen transaction modes
cover true/false results, wrong/lower/future releases, initial/final readiness
drift, parameterized compiled pins, SQL/commit/rollback errors, and cancellation
during registration or final readiness. Invalid runner and nil/canceled context
checks also passed. Thirteen executable preflight cases cover missing names,
duplicates, either reserved prefix, malformed names, bounds, extra arguments,
and fixed public output without input markers.

The grouped boundary run is `affected-race.log`: both affected Go packages
passed with `-race`, using the exact selector in `commands.md`. It also covered
existing audit-export registration/configuration paths and historical
compliance migration dispatch. Eight top-level tests passed. The one PostgreSQL
test intentionally skipped on macOS; its actual Linux execution is below.
No full command suite or frontend suite ran.

## The real CLI and PostgreSQL

`owned-postgres-green.log` passed in 8.24 seconds. This was the actual offline
cross-compiled migration binary, not a mocked dispatcher. The cached pinned
PostgreSQL container used `--pull=never --network none --read-only`, an owned
tmpfs cluster, and the postgres OS user. No host database was used.

The test installed exact56 through the published CLI command and checked that
forward migration left compliance bindings empty. Setup used a separate
migration owner with temporary superuser privileges; before any registration
attempt the test removed SUPERUSER, CREATEDB, CREATEROLE, REPLICATION and
BYPASSRLS, then verified that the login was registered migration authority.
Every compliance registration attempt used a fresh CLI connection.

The single connected fixture proved:

- Exact bindings and grants: executor to `zasp_compliance_worker`, cleanup to
  `zasp_compliance_cleanup`, INHERIT TRUE / SET FALSE / ADMIN FALSE.
- Replay passed with byte-identical binding, membership, release and metadata
  snapshots. A missing second SQL login rolled back the first grant.
- Other authority? A pre-existing API principal was refused as a worker.
  Executor, cleanup, API, unregistered login and unregistered superuser callers
  were denied through the CLI and through the SQL function directly.
- Missing, duplicate, reserved and malformed inputs, extra arguments, attempted
  binding replacement, wrong release checksum, unavailable readiness and a
  future release all failed without changing the captured state.
- Compiled56 readiness passed after registration and restored-state replay.
  CLI success was silent; failures used fixed public messages without DSNs,
  principal markers or SQLSTATE details.

The Linux PostgreSQL binaries were CGO-disabled builds, not race builds.
The separate affected native Go batch supplied the race coverage.

## One fixture correction

The first container run reached56, then PostgreSQL refused demotion of its
bootstrap superuser. `owned-postgres.log` retains that failure;
`fixture-diagnostic.log` records the exact cause: "The bootstrap superuser must
have the SUPERUSER attribute." I changed only test setup to use a separately
created migration owner. No production workaround was needed.

The TDD skill drove the behavioral RED before production edits. The debugging
skill required inspecting the fixture error before changing setup; verification
used the one connected PostgreSQL run after correction and one affected race
batch. No independent microtask reviews or unchanged broad suites were repeated.

## Handoff boundary

All launched commands were joined. Each owned PostgreSQL cluster stopped through
the existing test cleanup, and the named Docker container used `--rm`.
The final container query found no resources with this task's ownership label;
the process check found no task executable or Docker-run process. Compiled
proof binaries remain under `/private/tmp/zasp-compliance-registration*`.
They are task-owned outputs, not running processes.

See `hashes.sha256`, `commands.md`, the logs, and `scoped.patch`.
Root still owns independent review, connected deployment integration and the
authoritative ledger. This bridge does not close deployed compliance lifecycle,
Helm/IAM, live provider, canary or advisory acceptance. The previously recorded
deployment-suite failure has not been rerun or claimed fixed here.
