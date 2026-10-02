# P3 coverage correction

DONE. The P2 production fix and fingerprint stay unchanged at eb5d958fba7a720ad6f8d47c9f4cfb6a4193b10f4b48a4fb6bdcdc3b67ff0bf0.

The earlier review-p2-report.md overstated independent settled_at coverage. Its terminal-winner case still had a live lease, so either guard could block the stale candidate. This correction expires the winning lease through the fixture owner after the real registered worker settles and before the advisory barrier releases. Only the settled_at guard now protects that case.

To prove detection, ZASP_TEST_EXPORT_OMIT_SETTLED_GUARD=1 removes only that guard from the test-only copied function. Production source, installed public claim/settle, readiness and fingerprint are unchanged. The corrected terminal case failed behaviorally with the mutation: it returned the settled link and changed its winning lease/receipt. Container exit 1, one owned PostgreSQL lifetime joined normally.

Without that mutation both interleaving cases passed in 11.46s (5.92s live winner; 5.54s settled winner with expired lease). Container exit 0, two owned PostgreSQL lifetimes joined normally. No skips. No unrelated suite rerun.

Offline compilation exit 0:
```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

Mutation RED:
```sh
/usr/local/bin/docker run --rm --name zasp-export-db-review-p3-red --pull=never --network none -e ZASP_TEST_EXPORT_OMIT_SETTLED_GUARD=1 --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-db-test-initial.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportSettlementInterleavePostgres$/winner_settled_true$' -test.v -test.timeout 300s
```

Corrected GREEN:
```sh
/usr/local/bin/docker run --rm --name zasp-export-db-review-p3-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-db-test-initial.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExport(SettlementInterleave)Postgres$' -test.v -test.timeout 300s
```

Exact raw outputs: review-p3-mutation-red.log and review-p3-green.log. PostgreSQL ran only in the cached network-none container. No production mutation flag exists.

review-p3.patch is a test-only delta on the P2 snapshot; reverse apply check exits 0. Original P2 patch and original task-only patch are preserved.

SHA256:
```text
34e44130e9505216aa43a18fe6ffbcc05dc5396138f472b88e5620fd75f90e7d review-p3.patch
9d063164a1fcf0197bf0dd275bfddda81fb064740f8989be718a6a2aa87082ae review-before/p3-security_agent_export_postgres_test.go.txt
feec0ae7806f79d26718ca5bd207e7425cb802a7979e440e4cd243d9e79d69ed services/platform/apiserver/security_agent_export_postgres_test.go
f2dee50c6aa804536eac0b93f25098f9199d203a9adc17fc8aca0b6773d52922 review-p3-mutation-red.log
383363a48313f9017459f92d07afda9b937ed741c1f4c8298ec46e035e52efae review-p3-green.log
```

Same-reviewer follow-up requested. Action-details projection and approval projection are separate pending work.
