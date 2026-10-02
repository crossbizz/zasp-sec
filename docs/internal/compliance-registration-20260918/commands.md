# Reproduce the bounded checks

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
Go commands below run from its `services/platform` directory.

## RED, then focused GREEN

The same selector ran before implementation (`red.log`, exit1) and after
implementation (`green.log`, exit0):

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache PATH=/opt/homebrew/bin:$PATH /opt/homebrew/bin/go test ./migrations ./agentsec-migrate -run '^TestComplianceRegistration' -count=1 -v
```

## Offline proof binaries

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go build -o /private/tmp/zasp-compliance-registration-migrate ./agentsec-migrate
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test -c -o /private/tmp/zasp-compliance-registration.test ./agentsec-migrate
```

The test binary was rebuilt after the fixture-only diagnostic and correction.
The migration executable remained unchanged.

## One owned PostgreSQL fixture

This exact Docker command produced the setup failure, detailed diagnostic,
then final connected pass using the corresponding test binary revision.
Outputs are retained separately in `owned-postgres.log`,
`fixture-diagnostic.log`, and `owned-postgres-green.log`.

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-registration-20260918 --label zasp.task=compliance-registration-20260918 --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-registration.test,dst=/compliance-registration.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-registration-migrate,dst=/compliance-migrate,readonly -e ZASP_COMPLIANCE_REGISTRATION_BINARY=/compliance-migrate --entrypoint /compliance-registration.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestComplianceRegistrationBinaryOwnedPostgres$' -test.v -test.timeout 210s
```

## The affected race batch

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache PATH=/opt/homebrew/bin:$PATH /opt/homebrew/bin/go test -race ./migrations ./agentsec-migrate -run '^Test(ComplianceRegistration.*|ComplianceExplicitReleaseCommands|AuditExportWorkerRegistrationConfiguration|AuditExportRegisterWorkersRequiresBothReadinessChecks|AuditExportConfigurationOnBudgetReleasePinsAuthority|AuditExportConfigurationBinaryPreflight)$' -count=1 -v
```

## Ownership and formatting

From the worktree root:

```sh
/usr/local/bin/docker container ls -a --filter label=zasp.task=compliance-registration-20260918 --format '{{.ID}} {{.Names}}'
ps -axo pid,ppid,command | rg 'zasp-compliance-registration|compliance-registration.test|/compliance-migrate'
git diff --check -- services/platform/agentsec-migrate/main.go
git apply --reverse --check docs/internal/compliance-registration-20260918/scoped.patch
```

No owned container remained. The process search matched only its own shell and
search command, not a task process. Exact starting bytes are in `before/`.
