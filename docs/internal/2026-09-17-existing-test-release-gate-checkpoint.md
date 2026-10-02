# Existing-test release gates after mounted acceptance

The mounted batch is locally accepted. Publication and live production
acceptance remain open. The next implementation is the global operator
transaction, command and stop/race matrix; its new55 fingerprint will require
fresh compiled-consumer and browser evidence before publication.

## Grouped source verification

Controller ran from the recovery worktree:

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache npm run production:release:test
```

Session85565 exited0,222 tests passed,0 failed,0 skipped,26.67 seconds.
Coverage includes rendered schema55 in both precision phases, exports on/off,
reconciler disabled defaults and explicit opt-in, scoped workload/network/RBAC
refusals, and release orchestration refusing unavailable advisory evidence.
These are local source/rendering checks, not a deployment, real-cloud policy
observation, completed production gate or vulnerability clearance.

Source identities observed for this run:

| Source | SHA-256 |
| --- | --- |
| scripts/production-release-gate.mjs | 5c36995b49dcb4461983ea6622d75d271c55bfea680c4cd9cfaaadce052836ba |
| deploy/production/release-gates.mjs | 6f542afecf287f90b2693b4e67bcf0d39d0c7d2824d9372f0df9b0d9626a5fa1 |
| deploy/production/release-contract.mjs | 9d15bd75cb3331505244eabbb17ab07dc8ca84e8d3cadeca01e0658cbcb79958 |
| deploy/production/test-reconciler-rollout.mjs | 0dcd8aa6d2d308fe14e7ba401f969fc686a2eeef642cc4cd5759eba0db9d31d4 |

## Remaining evidence boundaries

Local advisory prerequisite diagnostic: installed OSV Scanner2.5.1 documents
`--offline` as disabling network-dependent features. Controller executed only
the exact lockfile diagnostic with all networking disabled:

```sh
/opt/homebrew/bin/osv-scanner scan source --offline --offline-vulnerabilities --no-resolve --lockfile package-lock.json --format json
```

Session16982 exited127. It extracted725 packages from the one selected lockfile
(0 directories,1 inode,1 extract call), then reported no offline npm OSV database
available. Its empty results array is an error result, not zero vulnerabilities.
No database download flag, online request, dependency mutation or release-gate
change was used. The installed scanner alone does not satisfy fresh approved
advisory evidence or the separate image-scan requirement.

The source verifier's generic rollout loop ends at54. The canonical test command
also executes dedicated55 rollout tests; do not describe the helper alone as
covering55. This grouped run does not execute PostgreSQL migrations or prove the
forthcoming operator transaction.

`production:release:gate` includes broad Go package tests, including agentsec-api,
that may start reference databases. Do not run it unmodified on the host under
the current no-host-PostgreSQL constraint. Database-owning tests need an owned
cached container and exact process cleanup; a source-only selection is not a
substitute for those full tests.

The candidate gate ends with an explicit unavailable-advisory-evidence error.
No approved fresh scanner input or passing audit path exists yet. See
[the advisory diagnosis](2026-09-15-offline-audit-gate-gap.md). Do not perform an
online scan, change endpoints, infer clearance from offline zero counters or
remove the rejection to make a build green. This external gate is recorded
without blocking unrelated local implementation.

After the operator feature, recheck exact candidate migrations, affected
registered consumers, mounted browser flow, UI build/import/page/assets and
independent whole-feature review. Immutable deployed image, actual queue/storage/
credential policy, live provider canary and production load remain separate.
No728-task classification changes follow from this checkpoint.
