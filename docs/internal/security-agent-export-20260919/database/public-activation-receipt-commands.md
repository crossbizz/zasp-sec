# Exact receipt-correction commands

Run from the shipping worktree root, except the offline build from services/platform.

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-public-export-activation.test
```

## RED

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-receipt-red --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportDefinition(Receipt|HTTP)Postgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-receipt-red.log
```

## Fingerprint calibration

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-receipt-calibration --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportDefinitionReceiptPostgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-receipt-calibration.log
```

## Affected GREEN batch

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-receipt-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgent(ExportDefinition(Receipt|HTTP|PublicLifecycle|AuthorityWait|Predecessors)|ExportRelease|Manual(Admission|HTTP))Postgres$' -test.v -test.timeout 600s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-receipt-green.log
```

