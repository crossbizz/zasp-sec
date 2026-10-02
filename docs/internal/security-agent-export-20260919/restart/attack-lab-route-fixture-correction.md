# Attack Lab predecessor route fixture correction

Read-only diagnosis followed by authorized test-only corrections on 2026-09-19
(local date). No production code, migration, checksum, or fingerprint changed.

## Root cause

The inherited Attack Lab automatic fixture was valid for release57 but omitted
two contracts enforced by release58:

1. Its predecessor fixture inserts the live definition after migration18's
   historical backfill, then updates that live row directly. No immutable
   `zasp_security_agent_definition_versions` row exists. Release58's repository
   first calls `zasp_sa_export_run_kind`; its `SELECT INTO STRICT` at
   `security_agent_export_links.sql:380` raises P0002 for the absent version.
   The database adapter maps that to `repository record not found`, before the
   Attack Lab planner context query. The same release57 automatic fixture passes.
2. Once registered definition history is present, the fixture's direct
   Load-to-Accept path omits provider reservation and settlement. Release58 wraps
   predecessor acceptance with `zasp_sa_export_planner_accounting_gate`, which
   refuses unaccounted output. This appeared as `repository operation conflict`.

This was a stale fixture contract, not a stale compiled binary. The current
Attack Lab helper, worker repository, export planner repository, and export
links SQL hashes matched the source manifest in
`run-2026-09-20T01-04-59.602Z.json` before correction. That grouped run's log hash
is `7df59339aae7e0f3babe731aa4bd00d11294bf75f9301e9c6bf6599b456ae332`.

## Correction

`security_agent_export_approval_route_postgres_test.go` now registers the scoped
definition using the API-role definition mutation, enables the action through
the registered execution-control operation, and activates it through
validated, supervised, and autonomous states. The inherited live-only fixture
starts at version1; registered creation supplies version2, followed by
activation versions3 through5. Assertions compare final activation, exact
body, actor, and SHA256-backed immutable history before and after the dispatch
helper. No owner history insert is used.

`security_agent_attack_lab_postgres_test.go` now uses the actual repository
Reserve and Settle operations when release58 is installed. They bind the same
input digest, model, policy, output digest, worker, and lease later supplied to
acceptance. The provider output and usage remain deterministic test data, not
an external model/billing claim. Release57 keeps its previous path. All
source-drift, permission, expiry, and replay assertions remain intact.

## Verification

The native focused attempt could not start PostgreSQL: macOS SysV shared-memory
slots were exhausted (`shmget: No space left on device`). No shared segments or
unrelated processes were removed. Tests were instead compiled offline for the
existing Linux/arm64 PostgreSQL image and run in isolated containers with no
network, read-only root, read-only source/binary mounts, and owned tmpfs data.

Observed sequence:

- Before correction: `^TestSecurityAgentExportNonExportRoutePostgres$/^attack_lab$`
  failed at the planner bridge in6.28s with `repository record not found`.
- Before correction: release57
  `^TestSecurityAgentAttackLabAuthorityPostgres$/^automatic_autonomous_test_write$`
  passed in8.31s, including its eight refusal cases.
- Registered-history correction alone: current58 passed the planner bridge but
  failed at acceptance with `repository operation conflict`.
- Final combined selector
  `^TestSecurityAgent(ExportNonExportRoute|AttackLabAuthority)Postgres$` exited0,
  zero skips. Full release57 authority passed34.66s (all three modes and twenty
  refusal children). Current58 route group passed19.17s: existing_test6.11s,
  attack_lab13.06s, including eight refusal children.
- All five PostgreSQL lifetimes in the final run joined normally with pg_ctl
  exit0 and server Wait exit0. The `--rm` container was absent after completion.
- `git diff --check` and explicit whitespace checks of both inherited untracked
  test files reported no whitespace errors.

Compile command, from `services/platform`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test -c -o /private/tmp/zasp-attack-lab-diagnose-Wb1run/api.test ./apiserver
```

Container image:
`postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`.
Container name: `zasp-attack-lab-diagnose-wb1run`. Arguments included
`--rm --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512`,
tmpfs `/tmp:rw,exec,size=1400m` and `/var/run/postgresql:rw`, source mount at
`/workspace`, binary mount at `/export.test`, workdir
`/workspace/services/platform/apiserver`, entrypoint `/export.test`, and
`-test.run '^TestSecurityAgent(ExportNonExportRoute|AttackLabAuthority)Postgres$' -test.v -test.timeout 180s`.

The compiled test binary is retained in the exact temporary path above for
reproduction. It contains no PostgreSQL data.

## Frozen hashes

| File | SHA256 |
| --- | --- |
| `services/platform/apiserver/security_agent_export_approval_route_postgres_test.go` | `ade0f1c119bb7124c9d6998ce3b7bbdcc8d88a1869d7902680c820ff6892e99e` |
| `services/platform/apiserver/security_agent_attack_lab_postgres_test.go` | `85aa5e2c0d68a6482887408c3336cbe2a2f854de485fcfda8283cbf405dce913` |
| Retained `api.test` | `2697d52adfc27b1ee76f9099938053892fcbc0bf7d6ac96ffdc1fbd970b17de2` |
| Unchanged `services/platform/migrations/sql/fragments/security_agent_export_links.sql` | `ffbf42f3367fbac85021a5e01868729f72fc424cee94805840288a11143105a0` |

Current release58 remains checksum
`5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985`,
fingerprint `8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f`.

Assessment: the regression was a P2 verification/fixture blocker, not evidence
of a Critical product-authority defect. These focused tests are now green;
independent review and the full shipping selector remain the parent's gates.
