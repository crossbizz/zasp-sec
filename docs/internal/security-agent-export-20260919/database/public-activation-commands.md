# Retained exact registered commands

## Final HTTP-only rerun

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-definition-http-final --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportDefinitionHTTPPostgres$' -test.v -test.timeout 300s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-http-final.log
```

These commands ran from the shipping worktree root. Earlier behavioral RED and intermediate calibration outcomes are described in public-activation-sql-report.md.

## Historical affected feature batch

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-definition-feature --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgent(ExportDefinition(PublicLifecycle|AuthorityWait|Predecessors|HTTP)|Export(Release|Sources|Authority|PlannerAdmission|PlannerRefusals|PlannerAccounting)|Manual(Admission|HTTP|ClaimIsolation))Postgres$' -test.v -test.timeout 900s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-feature-1.log
```

## Final SQL affected batch

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-public-export-definition-final --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgent(ExportDefinition(PublicLifecycle|AuthorityWait|Predecessors|HTTP)|ExportRelease|ManualHTTP)Postgres$' -test.v -test.timeout 600s 2>&1 | tee docs/internal/security-agent-export-20260919/database/public-activation-final.log
```
