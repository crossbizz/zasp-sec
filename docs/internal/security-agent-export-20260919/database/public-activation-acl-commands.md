# ACL canonicalization correction commands

All builds ran from `services/platform`; container commands ran from the shipping worktree root. No network or image pulls. The RED and calibration builds used the same API build command at their respective source/pin checkpoints. Final four builds exited 0.

## Offline builds

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-public-export-activation.test
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./agentsec-worker -c -o /private/tmp/zasp-export-login-worker.test
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./agentsec-migrate -c -o /private/tmp/zasp-export-login-cli.test
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go build -o /private/tmp/zasp-export-login-migrate ./agentsec-migrate
```

## Behavioral RED, old 5b8a094b pin

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-acl-red --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportMigrationIdentityPostgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-acl-red.log
```

## Calibration, typed correction with old compiled pin

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-acl-calibration --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportMigrationIdentityPostgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-acl-calibration.log
```

## Final affected API and worker batch, 8ddd2617

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-acl-final --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-login-worker.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgent(Export(PrefixedLogins|MigrationIdentity|Definition(Receipt|HTTP|PublicLifecycle|AuthorityWait|Predecessors)|Release|Lifecycle|StoppedSettlement|SettlementInterleave|Authority|WorkerProcess)|Manual(Admission|HTTP))Postgres$' -test.v -test.timeout 900s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-acl-final.log
```

## Final actual CLI58 batch, 8ddd2617

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-acl-cli-final --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw -e ZASP_COMPLIANCE_DEPLOYMENT_BINARY=/compliance-migrate --mount type=bind,src=/private/tmp/zasp-export-login-cli.test,dst=/cli.test,readonly --mount type=bind,src=/private/tmp/zasp-export-login-migrate,dst=/compliance-migrate,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/agentsec-migrate --entrypoint /cli.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportsDeploymentBinaryOwnedPostgres$' -test.v -test.timeout 360s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-acl-cli-final.log
```
