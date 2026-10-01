# Priority merge batch: 2026-10-01

This is the evidence record for a small merge onto `origin/main` at
`e9fc3dd4`. It supplements `implementation_status_v1.5.md`; it does not
reclassify any of the 728 original requirements or certify a release.

## Included changes

| Change | Classification | Boundary |
| --- | --- | --- |
| Built-in existing-test, rerun, and attack-lab templates | Component-only | Original reviewed commit `b8837297`; production action availability and autonomy gates are unchanged. These actions remain unavailable through the production catalog until their existing readiness gates are satisfied. |
| Grouped launch verification runner and its 12 regressions | Local tooling available | Exact reviewed copy from the active implementation worktree. Successful unchanged local deterministic checks may be reused; typecheck/build always execute. No result proves deployment acceptance. |
| Ordered artifact generation/check mode | Prerequisite-blocked on main | The three referenced migration generator scripts have not landed on main. Do not invoke artifact or refresh mode on main until their reviewed dependency batch lands. Missing scripts fail the batch, rather than reporting success. |

## Verification

On the isolated integration checkout, with Node 22.23.1 and Go 1.25.13:

- `node --test scripts/launch-batch.test.mjs`: 12 passed, zero failures.
- `npm test`: 197 test files, 1,244 tests passed, zero failures.
- `go test -C services/platform -mod=readonly -race -count=1 ./securityagent`: passed.
- `go test -C services/platform -mod=readonly -race -count=1 -run '^TestWorkflowHandler' ./apiserver`: affected API regressions passed, including production catalog/template filtering. The additional entire API package run was stopped after more than four minutes; it is not claimed as passing and is not this batch's merge gate.
- `node scripts/launch-batch.mjs release --run`: fresh typecheck and production build passed; logs retained under the integration worktree's Git directory.
- Built standalone UI started on a dedicated local port; `/` and `/login` returned HTTP 200. This is local HTTP smoke coverage, not authenticated browser or provider acceptance.

Review checked the new template consumers and production capability filtering,
source/input invalidation, task-boundary drift refusal, failed-rerun receipt
invalidation, immutable unique logs, atomic receipt replacement, shell argument
arrays, and absence of credentials in this batch. Templates were appended, so
existing catalog indexing is unchanged. No UI or API transport source changed.

The routine checks above use local Node/Go executables, with zero model API
calls. Model routing and any claimed 10x gain remain unverified. Source hashing
may itself be costly; the rejected two-endpoint-only optimization is not included.

## How to use the runner

Run from a stable checkout:

```sh
node scripts/launch-batch.mjs release
node scripts/launch-batch.mjs release --run
node --test scripts/launch-batch.test.mjs
```

Default mode prints a plan. `--root PATH` targets a different checkout. Once
the reviewed generators are present, `artifacts --run --reuse` permits local
receipt reuse. `refresh --run` writes generated artifacts and must only be used
by their current owner; refresh cannot reuse evidence. Never run it against a
worktree someone else is editing. Reusable verification rejects `NODE_OPTIONS`
and symlinked input directories rather than accepting unfingerprinted inputs.

## Still excluded

The full ordered migration bundle, unresolved source/definition acceptance,
Temporal/OpenFGA production composition, licensing closure, deployed Stytch and
provider connections, discovery/sync acceptance, and end-to-end launch gates
remain with the main coordinator. This batch removes none of that scope.

The root checkout's dirty user documentation and the active implementation
worktree were not modified. No version bump or deployment is part of this
internal tooling/component merge. Main was notified through its chat queue;
the isolated integration checkout owns this push only.
