# Global operator transaction, local evidence

Task1 is complete locally. Final grouped run5147 passed all8 top-level tests, including the fresh non-superuser login check, with no skips. The controller reports final independent spec PASS and quality APPROVE, with no Critical/Important findings. No publication or live authority claim.

Current55 fingerprint: `2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04` (calibration85405, expected mismatch exit1 before updating the compiled pin). Compiled55 checksum: `01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00`. Final production sources are frozen. Historical pins stay unchanged.

## Final run, exact scope

Compile session40513 exited0 from `services/platform`:

```sh
env GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test -c -o /private/tmp/zasp-global-task1.LAeSCL/task1-final-matrix.test ./apiserver
```

Run session5147 exited0:

```sh
/usr/local/bin/docker run --rm --pull=never --network none --user postgres --name zasp-global-task1-final-matrix -e LANG=C.UTF-8 -v /private/tmp/zasp-global-task1.LAeSCL:/task:ro --entrypoint /task/task1-final-matrix.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^(TestSecurityAgentGlobalControl.*Postgres|TestSecurityAgentExistingTestCompiledFingerprintPostgres|TestSecurityAgentExistingTestReleasePostgres)$' -test.v -test.timeout 240s
```

Exact output is retained at `.superpowers/sdd/2026-09-17-global-execution-control-plan/task-1-final-matrix.log`, SHA256 `90221548734a98b1f706ef70a7ee940f6756070e694b6b047874c5ba0ac68922`. Its final line is `PASS`. All8 owned PostgreSQL instances joined with pg_ctl exit0 and server Wait exit0. The disposable container was removed; the subsequent owned-container listing was empty. There is no active test handle.

The final run covers compiled fingerprint (5.78s), existing release (11.32s), transaction/authority/input/replay checks (8.33s),16 catalog mutations (6.87s), late audit failure rollback (5.88s), exact unused rollback (5.94s), down-lock ordering (5.64s), and a fresh registered NOSUPERUSER/NOBYPASSRLS migration login (6.18s). That ordinary login committed stop/read/replay, exercised deferred receipt checks, and refused reads/sets after binding revocation without changing control, receipt or audit snapshots.

The frozen complete8-source-file patch against exact pre-edit snapshots is `.superpowers/sdd/2026-09-17-global-execution-control-plan/task-1-final.patch`, SHA256 `243ca9af97567a7f1c80692767bffac3aad12348eddc85402b842d66164151e7`. The final review delta is `task-1-review-fix.patch`, SHA256 `f7d3a4647f5a5f66d8ce7aca4710af38e21a0034f7cc821028e8ab384c70c288`. The earlier `task-1.patch` (SHA256 `331665555fdcfe6a8a46ac4bac9adf7e168486b6c3422ee57abe699f859f3380`) is historical, not the final patch.

This evidence is local SQL/authority acceptance. It does not establish live mounted acceptance, full release/advisory clearance, Task2 command/transport behavior, or Task3 competing-operation races. I did not rerun unchanged broad suites after the final small grant/fixture correction. No host PostgreSQL, image pulls, provider calls, commits, staging, pushes, or shared-file cleanup occurred.

The portability RED28380/60177 isolated exactly one new catalog row: `function-grant|zasp_valid_product_id(text)|EXECUTE|f|zasp_e2e` versus the same row with grantor `zasp_test`. Private predecessor fingerprint was identical (`d352bf845957bca84662e55fe1f5b3f97b6f3d9a952c6f0f389c8e4228cdb9d2`); all other global identity rows matched. The helper already permits execution through PUBLIC. Controller approved removing the redundant explicit helper grant/revoke, with no fingerprint field removed or normalized away. The final tests assert inherited validator execution in both owner-name fixtures and retain malformed-ID refusal.

Those diagnostic fixtures also exposed a test DSN mistake: pgx ConnConfig.ConnString preserves the original DSN after User is edited. The alternate diagnostic actually migrated as `zasp_test`, so it proved owner-name fingerprint variance, not an ordinary-login commit. The final starter builds the local DSN explicitly, connects and verifies session_user/current_user before migration, and uses the distinct non-bootstrap `global_operator_migration` login. Only the existing bootstrap `zasp_test` connection performs fixture maintenance. The registered operator then connects afresh with NOSUPERUSER/NOBYPASSRLS; no SET ROLE substitute or catalog bypass is used.

Historical GREEN53942 (superseded pin dd7157): exit0, all9 selected top-level tests passed with no skips. Binary `/private/tmp/zasp-global-task1.LAeSCL/task1-grouped2.test`, compiled with GOTOOLCHAIN=local, GOPROXY=off, GOCACHE=/private/tmp/zasp-budget-go-cache, GOOS=linux, GOARCH=arm64, CGO_ENABLED=0 and `/opt/homebrew/bin/go test -c ... ./apiserver`. Cached PostgreSQL digest, `--pull=never --network none --user postgres --rm`, LANG=C.UTF-8, unchanged from RED. Exact test selection:

```
^(TestSecurityAgentGlobalControl.*Postgres|TestSecurityAgentExistingTestCompiledFingerprintPostgres|TestSecurityAgentExistingTestReleasePostgres|TestSecurityAgentExistingTestLifecyclePostgres|TestSecurityAgentExistingTestVersionedDefinitionPostgres)$
```

The run passed the global transaction (9.02s),16 catalog drift cases (7.60s), actual audit-INSERT failure after receipt/control writes (7.00s), exact unused ACL/trigger restoration (7.41s), lock-before-readiness witness (6.62s), compiled55 fingerprint (6.45s), inherited release checks (11.99s), lifecycle controls (18.34s), and versioned-definition checks (9.30s). Eight actual API/worker login identities refused operator execution, receipt reads, and capability-role assumption. Catalog checks cover every other NOLOGIN zasp API/worker role as well. Every owned PostgreSQL process joined normally and the container was removed.

The fault seam preserved/restored the exact pgcrypto digest function body, owner and ACL. Its exception observed `control=2,receipt=1` at the audit INSERT; after rollback all three snapshotted authorities were byte-equivalent JSON. The receipt's direct INSERT/UPDATE/DELETE refusal is separate evidence, not a claim of a late receipt-insertion fault.

Earlier setup failures55884/86821/29781 are historical. The original fixture's migration login is a bootstrap superuser; PostgreSQL refused to remove SUPERUSER from bootstrap OID10 (`0A000`, `The bootstrap superuser must have the SUPERUSER attribute.`). No system-catalog bypass was attempted. Controller approved optional test-only starter propagation through three fixture helpers, preserving their default path. Run29781 passed that default operator test (8.12s) but alternate-bootstrap Up55 refused before the operator callback. The exact grantor diagnosis and corrected non-bootstrap setup are documented above; those diagnostics have ended.

## Earlier attempts, superseded

Expanded matrix53045 did not pass. Compiled pin and exact unused rollback passed;15/16 catalog mutations refused as intended. One test guessed a truncated constraint name and was corrected to select the actual correlation constraint strictly. Both operator tests still failed42501, with PostgreSQL's Where field naming the explicit RowShare control lock. AccessShare is the correct explicit fence for the existing SELECT grant; it conflicts with rollback's AccessExclusive, while SELECT FOR UPDATE and UPDATE keep their normal write locks. GREEN53942 later verified that correction.

Rollback-order RED90128 exited1 as intended: a refusing readiness witness checked actual pg_locks and found the three global relations had not yet been fenced. The runner returned ErrDatabase, not the expected ErrInvalidState after fenced readiness refusal. Owned PostgreSQL joined normally. Controller approved the narrow runner lock-order edit. Its exact predecessor is also saved in the snapshot directory, SHA256b94437754036ef73b93d7d90b0a17dc3d3d29f53920f8aff2c9dfc80e12bee.

Calibration49020 observed343c4aa370adc141f121cf260c5eb4081fe86095e0dfabf135fc671ecc8ca092 (expected mismatch, exit1). After that pin update, batch78407 passed compiled-fingerprint and existing-release/unused-rollback checks. The stop failed42501: its explicit RowExclusive lock on the control table required table-level write privilege, but the role has only column UPDATE privileges. I changed that one fence to RowShare, which still conflicts with rollback. No UPDATE grant expansion.

Calibration59435 observedc09a19c1ee87ee81f0c51cfea415dee840ab511a78bf8dad8ee60250c8dad6fa. Before treating it as final, I added catalog coverage for every capability-owned function/relation/schema/database and default ACLs, including objects outside the operator prefix. Calibration26187 then observedaa481d480c93f97277018a8726e10cc81c326e4a1a220823fb9dbbb1e64c9998. Each calibration exited1 for its reported mismatch, each owned PostgreSQL process joined normally, and each container was removed. These intermediate pins were superseded by dd7157 above.

Remote main checked before edits: `8733b16f8d939d38a8157dd2519e57fc6f630542`; its tree has no0055 migration. The mounted browser batch has ended. Historical27/53/54 bytes and pins are outside this patch.

Pre-edit copies live at `/private/tmp/zasp-global-task1.LAeSCL`. SHA256:

```
fa48786fc7bb6ce168112ee7548fb7740efe01e0c8c409d9fe981f787b518cd5  0055_production_security_agent_existing_tests.down.sql
c48cba7686171d02cd04eddadfbf6506dbf25983ba06c6c4a2da17c778b8710e  0055_production_security_agent_existing_tests.up.sql
f2750fd1492c19f3b1554bcb4f6f333f1639667e8e57c6ebe832aa24555448e5  security_agent_existing_tests_release.go
```

RED: `env GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test -c -o /private/tmp/zasp-global-task1.LAeSCL/task1-red.test ./apiserver` compiled exit0 (session59602).

Ran that binary inside cached `postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba` with `--rm --pull=never --network none --user postgres`, LANG=C.UTF-8, `-test.run '^TestSecurityAgentGlobalControlPostgres$' -test.v -test.timeout 120s`. Session56841 exited1 after7.80s: registered fixture passed release readiness, then `global_set` was missing, SQLSTATE42883. Owned PostgreSQL pid28 joined normally (`pg_ctl exit0`, server Wait exit0), then the container was removed. This is the expected feature RED, not a passing integration test.
