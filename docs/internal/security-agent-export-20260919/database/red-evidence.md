# Registered fixture RED

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

Each run compiled with this offline command (exit 0):

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

The binary ran only inside the cached network-none linux/arm64 image:

```sh
/usr/local/bin/docker run --rm --name zasp-export-db-red-20260919 --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-db-test-initial.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExport.*Postgres$' -test.v -test.timeout 300s
```

First fixture run failed on its own incorrect claim decoder: registered claim returned `{items:[...]}`, while the test expected an array. This was fixed before counting product RED.

Setup RED (test exit 1, actual Runner56/57, separate registered worker login):

```text
registered export admission unavailable: ERROR: function zasp_sa_export_execute_run(unknown, unknown, unknown, unknown, unknown, unknown, unknown, unknown, unknown, unknown) does not exist (SQLSTATE 42883)
joined owned PostgreSQL pid=24: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestSecurityAgentExportAuthorityPostgres (4.32s)
FAIL
```

Initial fingerprint calibration observed d57d3274400c41b8e41618fd4a620d69bb369e45490c91d0c398f406886ab1ee. Subsequent58 application used its actual Runner.

Behavioral RED with the release58 registered entrypoint present, test exit 1:

```text
first dispatch did not admit one export: {}
joined owned PostgreSQL pid=23: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestSecurityAgentExportAuthorityPostgres (5.27s)
FAIL
```

I removed an untested source/lifecycle draft before writing the grouped refusal fixtures. It was not accepted implementation or GREEN evidence.
