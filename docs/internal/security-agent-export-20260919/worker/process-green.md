# Registered agent-export process checkpoint

2026-09-19: TestSecurityAgentExportWorkerProcessPostgres passed, exit0,
6.81s. This supersedes the earlier registration RED for this test only.

Compiled API and worker test binaries with Go1.25.6, GOTOOLCHAIN=local,
GOPROXY=off, GOSUMDB=off, GOCACHE=/private/tmp/zasp-budget-go-cache,
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 into a new owned
`/private/tmp/zasp-export-worker.XXXXXX` directory. Ran the API binary with
`-test.run '^TestSecurityAgentExportWorkerProcessPostgres$' -test.v -test.timeout 300s`.

Container: cached postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba,
--rm --pull=never --network none --read-only --user postgres --cpus 2
--memory 2g --pids-limit 512, tmpfs /tmp:rw,exec,size=1400m and
/var/run/postgresql:rw. Read-only mounts: owned API binary at /export.test,
worker binary at /compliance-worker.test, shipping worktree at /workspace.
Workdir /workspace/services/platform/apiserver; entrypoint /export.test.

Observed output:

```text
joined agent export interrupt process: TestComplianceRuntimeProcess PASS (0.78s)
joined interrupt polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
joined agent export resume process: TestComplianceRuntimeProcess PASS (0.69s)
joined resume polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
LOCAL component: registered agent dispatch, actual worker process SIGTERM, immutable prepared replay in second process; controlled AWS SDK transport, not live provider or public planner proof
joined owned PostgreSQL pid=24: pg_ctl exit=0 server Wait exit=0 normal-exit
PASS TestSecurityAgentExportWorkerProcessPostgres (6.81s)
PASS
```

The test checks registration, dispatch, pending storage uncertainty after
interrupt, prepared package metadata, immutable replay and completion. Separate
OS processes are real; object transport and seeded planner inputs are controlled.
This is not native race evidence or a live AWS/public planner/production proof.
Independent review of the process fixture and remaining feature integration
are still required. No original microtask is newly marked production-available.
