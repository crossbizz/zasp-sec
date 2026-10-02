# Login and migration-identity correction commands

Offline builds, from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-public-export-activation.test
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./agentsec-worker -c -o /private/tmp/zasp-export-login-worker.test
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./agentsec-migrate -c -o /private/tmp/zasp-export-login-cli.test
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go build -o /private/tmp/zasp-export-login-migrate ./agentsec-migrate
```

All container commands ran from the shipping worktree root. No ambient DSN was consumed.

## Prefixed login RED

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-login-red --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportPrefixedLoginsPostgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-login-red.log
```

## Self-role calibration

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-login-calibration --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportPrefixedLoginsPostgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-login-calibration.log
```

## Initial affected GREEN

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-login-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-login-worker.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgent(Export(PrefixedLogins|Definition(Receipt|HTTP|PublicLifecycle|AuthorityWait|Predecessors)|Release|Lifecycle|StoppedSettlement|SettlementInterleave|Authority|WorkerProcess)|Manual(Admission|HTTP))Postgres$' -test.v -test.timeout 900s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-login-green.log
```

## Reached CLI RED

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-login-cli --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw -e ZASP_COMPLIANCE_DEPLOYMENT_BINARY=/compliance-migrate --mount type=bind,src=/private/tmp/zasp-export-login-cli.test,dst=/cli.test,readonly --mount type=bind,src=/private/tmp/zasp-export-login-migrate,dst=/compliance-migrate,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/agentsec-migrate --entrypoint /cli.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportsDeploymentBinaryOwnedPostgres$' -test.v -test.timeout 360s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-login-cli.log
```

## Rollback SQL diagnostic

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-login-cli-diagnostic --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw -e ZASP_COMPLIANCE_DEPLOYMENT_BINARY=/compliance-migrate --mount type=bind,src=/private/tmp/zasp-export-login-cli.test,dst=/cli.test,readonly --mount type=bind,src=/private/tmp/zasp-export-login-migrate,dst=/compliance-migrate,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/agentsec-migrate --entrypoint /cli.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportsDeploymentBinaryOwnedPostgres$' -test.v -test.timeout 360s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-login-cli-diagnostic.log
```

## Owner canonicalization calibration

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-owner-calibration --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportPrefixedLoginsPostgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-owner-calibration.log
```

## Final affected batch

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-login-final --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-login-worker.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgent(Export(PrefixedLogins|MigrationIdentity|Definition(Receipt|HTTP|PublicLifecycle|AuthorityWait|Predecessors)|Release|Lifecycle|StoppedSettlement|SettlementInterleave|Authority|WorkerProcess)|Manual(Admission|HTTP))Postgres$' -test.v -test.timeout 900s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-login-final.log
```

## Final actual CLI

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-login-cli-final --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw -e ZASP_COMPLIANCE_DEPLOYMENT_BINARY=/compliance-migrate --mount type=bind,src=/private/tmp/zasp-export-login-cli.test,dst=/cli.test,readonly --mount type=bind,src=/private/tmp/zasp-export-login-migrate,dst=/compliance-migrate,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/agentsec-migrate --entrypoint /cli.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportsDeploymentBinaryOwnedPostgres$' -test.v -test.timeout 360s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-login-cli-final.log
```

Owner comparison used the same CLI diagnostic command with name zasp-public-export-login-cli-owner and log public-activation-login-cli-owner.log. Registered-fixture owner comparison used the prefixed-login RED command with name zasp-public-export-login-owner and log public-activation-login-owner.log. Temporary owner diagnostics are preserved in public-activation-login-before/cli_diagnostic_test.go; the actual CLI test source was restored byte-for-byte before final execution.

