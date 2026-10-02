# Deployment review fixes: local checks pass, re-review pending

Root implemented this bounded fix round after both implementer followup and a
replacement dispatch returned agent-thread-limit. The authoritative agent list
showed no active source writer. No original frozen evidence was overwritten.

P1: go-test-runtime.mjs selects ZASP_GO_BIN or Go from the caller's PATH, keeps
configured compiler/cache paths, excludes ambient product credentials and forces
GOTOOLCHAIN=local, GOPROXY=off, GOSUMDB=off and GOENV=off. The actual harness
checks `go env GOVERSION` for1.25.6 before rendering/running. No workstation
executable or cache path remains in the harness. Three focused cases failed for
missing portable selection/version enforcement, then passed. They check a
setup-go-style PATH, explicit non-Homebrew executable, portable default cache,
credential exclusion, offline overrides and wrong-version refusal. This is
local configuration/integration evidence, not an executed Ubuntu CI run.

P2: api-startup.mjs shares the canonical secret-load and executable contract
between audit and compliance validators, with the audit cursor load conditional.
Five compliance-only mutations reproduced missing rejection; the same five
audit-enabled controls passed. All ten now pass, including shell worker-role
export, altered shell command, extra argument, changed executable and removed
DSN load. The real Go API loader now also consumes a compliance-only rendered
fixture, checks audit opt-in separately, and repeats the reader-role negatives.

## Exact commands and results

All commands ran from
`/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
Node below is `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node`.

1. `node --test --test-name-pattern='compliance API startup' deploy/production/compliance-export-rollout.test.mjs`
   RED: five mutation failures plus failed parent; five audit controls pass.
   GREEN:11/11 including parent. Full outputs retained in api-shell-red.log
   and api-shell-green.log.
2. `node --test deploy/production/compliance-export-toolchain.test.mjs`
   RED:3/3 fail. GREEN:3/3 pass. Full outputs retained in toolchain-red.log
   and toolchain-green.log.
3. `ZASP_GO_BIN=/opt/homebrew/bin/go GOCACHE=/private/tmp/zasp-budget-go-cache node --test deploy/production/compliance-export-toolchain.test.mjs deploy/production/compliance-export-rollout.test.mjs deploy/production/compliance-export-runtime.test.mjs deploy/production/audit-export-rollout.test.mjs`
   PASS106/106, no failures/skips,9.34seconds. Exec session88543 joined with
   exit0. Initial output chunk contained the audit cases; the retained
   boundary-green-tail.log is explicitly the final output chunk, not a full
   transcript. It includes the final106-test summary and the actual Go/race
   loader output for enabled, disabled, complianceOnly and both workers.
4. `git diff --check -- deploy/production/compliance-export-rollout.mjs deploy/production/audit-export-rollout.mjs deploy/production/compliance-export-rollout.test.mjs deploy/production/compliance-export-runtime.test.mjs services/platform/agentsec-api/compliance_deployment_config_test.go package.json`
   Exit0, no output.
5. `/opt/homebrew/bin/gofmt -l services/platform/agentsec-api/compliance_deployment_config_test.go`
   Exit0, no output. No formatting rewrite needed.

Only affected release/harness checks reran. Unchanged PostgreSQL CLI evidence
was reused; no database/container was started for this fix. The harness joins
Go and cleans its temporary manifest directory in finally. No live process
handles remain. No SQL/pins, UI product code, dependency files or Terraform
changed. No provider/network operation, full release script, scan, stage,
commit or push ran. Full pre-push UI verification and external acceptance gates
remain open. Independent re-review is required before local acceptance.
