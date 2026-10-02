Pending execution, not a test failure or GREEN.

Resolved: original session47277 later completed exit0 without intervention or a duplicate run. Eight owned PostgreSQL lifetimes joined normally, five groups passed at the recorded pin. Exact complete output is projection-initial-green.log. The pending status below is historical context, not current status.

Original exec session: 47277
Owned CLI PID: 8143
Container name: zasp-export-db-projection-green
Compiled catalog pin: 7d10566a9e3982873098edd9b07fa4ed34f4e393b0d355308f16f6bf9c32b1dc

Exact command:
/usr/local/bin/docker run --rm --name zasp-export-db-projection-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-db-test-initial.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExport(Projection|ProjectionSettled|ProjectionRefusals|Release|ProofSources)Postgres$' -test.v -test.timeout 300s

The docker run has not emitted startup output. Read-only docker ps also waits on the daemon. No duplicate fixture or shared OrbStack restart is authorized. Root knows the pending handle. Test binary must not be replaced until the owned run joins.

Safe daemon diagnostic: `/usr/bin/curl --silent --show-error --max-time 3 --unix-socket /Users/manishmaheshwari/.orbstack/run/docker.sock http://localhost/_ping` exited 28 after 3009ms with zero bytes. The extra read-only docker ps/logs shell and its docker client were terminated by exact owned PIDs8264/8267 and joined exit143; the original fixture PID8143/session47277 was not signaled.

Pending source snapshot SHA256:
```
c43d21e8ec6750420f7d49b10bc1035167799c65da1e98ae6cb11341bcad1607 services/platform/migrations/security_agent_exports_release.go
17d90f26e95e02ccaca001a8ab83158b0ccd11e4f2ce07a4d76b56c8979bbfe5 services/platform/migrations/sql/fragments/security_agent_export_links.sql
f5a12029231382693997298576910c7b6c6ecc2213e1d9e7087ebcca4fef1c06 services/platform/apiserver/security_agent_export_projection_postgres_test.go
8587a6fd88a7eb308206c23dd89e4722a062acd0f12705004a62de1c2c01149a database/projection-draft.patch
9f3a5bfc52dfb2e520fa197212bcfde0577cc14be06681cf17f40ea2d95279d2 /private/tmp/zasp-export-db-test-initial.test
```

Original frozen task-only.patch, P2 patch, P3 patch and their evidence remain separate. This projection snapshot has no GREEN claim. Manual-parent public run/approval/claim provenance is an explicitly open connected design issue; typed selection coverage must not be confused with manual-parent public support. Approval value/decision/detail/page SQL is the next separate batch, not part of this pending projection.
