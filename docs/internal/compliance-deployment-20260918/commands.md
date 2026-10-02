# Reproduce this local batch

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
Node is `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node`.
The commands below ran from the worktree root unless a section says otherwise.
Raw output redirection names are recorded beside each command.

## Focused RED/GREEN

`render-red.log`, then `render-green.log`:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/production/compliance-export-rollout.test.mjs
```

`principal-red.log`:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-name-pattern='migration uses' deploy/production/compliance-export-rollout.test.mjs
```

`image-red.log`:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-name-pattern='rendered compliance rejects' deploy/production/compliance-export-rollout.test.mjs
```

`focused-green.log`:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/production/compliance-export-rollout.test.mjs deploy/production/compliance-export-helm.test.mjs
```

`staging-red.log`, before updating the staged rollout contract:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-name-pattern='embedded migration' deploy/staging/gate.test.mjs
```

From `services/platform`, `audit-red.log` without `-v`, then `audit-green.log`
with `-v`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./migrations -run '^TestAuditExportConfigurationOnBudgetReleasePinsAuthority$' -count=1 -v
```

## Real loaders and the connected Node boundary

`runtime-config.log`:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/production/compliance-export-runtime.test.mjs
```

That orchestration invokes `/opt/homebrew/bin/go test -race ./agentsec-api
./agentsec-worker -run '^TestComplianceDeploymentRendered' -count=1 -v` from
`services/platform`. It sets `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
GOCACHE=/private/tmp/zasp-budget-go-cache` and
`ZASP_COMPLIANCE_RENDERED_FIXTURE=<owned temporary JSON path>`. It supplies only
the existing HOME, a bounded PATH, and those explicit settings to the child.

`connected-node.log`:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-concurrency=4 deploy/production/release-contract.test.mjs deploy/production/session-search-rollout.test.mjs deploy/production/security-agent-budget-rollout.test.mjs deploy/production/audit-export-workloads.test.mjs deploy/production/audit-export-rollout.test.mjs deploy/production/audit-export-network.test.mjs deploy/production/audit-export-operations.test.mjs deploy/production/audit-export-alerts.test.mjs deploy/production/test-reconciler-workloads.test.mjs deploy/production/test-reconciler-rollout.test.mjs deploy/production/test-reconciler-alerts.test.mjs deploy/production/compliance-export-rollout.test.mjs deploy/production/compliance-export-helm.test.mjs deploy/production/compliance-export-runtime.test.mjs deploy/staging/gate.test.mjs
```

Only the two missing-tool failures reran, `predecessor-alerts-green.log`:

```sh
ZASP_PROMTOOL_BIN=/private/tmp/zasp-reconciler-promtool.dYZ3bA/prometheus-3.14.0.darwin-arm64/promtool /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/production/audit-export-alerts.test.mjs deploy/production/test-reconciler-alerts.test.mjs
```

## Affected Go/race tests

From `services/platform`, `affected-go-race.log`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./migrations ./agentsec-migrate ./agentsec-api ./agentsec-worker -run '^Test(AuditExportConfigurationOnBudgetReleasePinsAuthority|AuditExportWorkerRegistrationConfiguration|AuditExportRegisterWorkersRequiresBothReadinessChecks|ComplianceRegistration.*|ComplianceExplicitReleaseCommands|ComplianceAPIConfiguration|ComplianceExportRuntimeConfiguration|AuditExportRuntimeEnvironment.*|AuditExportRuntimeTypedConfigurationRevalidated)$' -count=1 -v
```

The worker pattern above selected zero tests. Corrected worker-only run,
`worker-config-race.log`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-worker -run '^TestComplianceRuntimeConfiguration$' -count=1 -v
```

## Owned PostgreSQL

From `services/platform`, offline executable and test compilation:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go build -o /private/tmp/zasp-compliance-deployment-migrate ./agentsec-migrate
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test -c -o /private/tmp/zasp-compliance-deployment.test ./agentsec-migrate
```

The test binary alone was rebuilt after correcting its failure-message
expectation. From the worktree root, first `owned-postgres.log`, then
`owned-postgres-green.log`:

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-deployment-20260918 --label zasp.task=compliance-deployment-20260918 --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-deployment.test,dst=/compliance-deployment.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-deployment-migrate,dst=/compliance-migrate,readonly -e ZASP_COMPLIANCE_DEPLOYMENT_BINARY=/compliance-migrate --entrypoint /compliance-deployment.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestComplianceDeploymentBinaryOwnedPostgres$' -test.v -test.timeout 210s
```

## Original rendered evidence

Output is `rendered-fixture.json`:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --input-type=module -e 'import {renderRelease} from "./deploy/production/release-contract.mjs"; import {productionReleaseFixture} from "./deploy/production/release-fixture.mjs"; import {complianceExportReleaseFixture} from "./deploy/production/compliance-export-release-fixture.mjs"; import {auditExportReleaseFixture} from "./deploy/production/audit-export-release-fixture.mjs"; import {testReconcilerReleaseFixture} from "./deploy/production/test-reconciler-release-fixture.mjs"; const enabled=await renderRelease(productionReleaseFixture,{schemaVersion:56,sessionSearchPhase:"precision-intake",complianceExports:complianceExportReleaseFixture(),auditExports:auditExportReleaseFixture(),testReconciler:testReconcilerReleaseFixture()}); const disabled=await renderRelease(productionReleaseFixture); console.log(JSON.stringify({enabled,disabled},null,2));'
```

## Freeze and cleanup

```sh
shasum -a 256 /private/tmp/zasp-compliance-deployment-migrate /private/tmp/zasp-compliance-deployment.test
/usr/local/bin/docker container ls -a --filter label=zasp.task=compliance-deployment-20260918 --format '{{.ID}} {{.Names}}'
ps -axo pid,ppid,command | rg 'zasp-compliance-deployment|compliance-deployment.test|/compliance-migrate'
rm /private/tmp/zasp-compliance-deployment-migrate /private/tmp/zasp-compliance-deployment.test
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node docs/internal/compliance-deployment-20260918/capture-evidence.mjs
git apply --reverse --check docs/internal/compliance-deployment-20260918/scoped.patch
git diff --check -- deploy/production/release-contract.mjs deploy/production/session-search-rollout.mjs deploy/staging/gate.test.mjs deploy/staging/product/templates/_session-search.tpl deploy/staging/product/templates/migration.yaml deploy/staging/product/templates/workloads.yaml deploy/staging/product/templates/resilience.yaml deploy/staging/product/values.yaml package.json
```

The process search matched only its own shell/search commands. Generated binary
hashes are retained in `binary-hashes.sha256`; rebuilding is the recovery path.
