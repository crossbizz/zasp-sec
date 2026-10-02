# Task 4 fix1 accepted evidence

Full captured output follows each exact command. The SQL suites run only inside owned network-none cached Docker. Both local race selectors were enumerated and read before their corresponding race command. Unchanged storage/formatter controlled-transport evidence remains in the original Task4 log; the changed SQL pin is covered again by byte replay and worker runtime acceptance here.

## fix1sqlbatch

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task4-fix1 --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task4-fix1.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task4-fix1-worker.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestCompliance' -test.v -test.timeout 240s
```

Exit: 0

```text
=== RUN   TestComplianceConflictClassification
--- PASS: TestComplianceConflictClassification (0.00s)
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/old
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/context
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/foreign-context
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/future-envelope
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/duplicate
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/foreign-id
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/context-null
--- PASS: TestCompliancePersistedAttributionAndHistoricalBytes (0.05s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/old (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/context (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/foreign-context (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/future-envelope (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/duplicate (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/foreign-id (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/context-null (0.00s)
=== RUN   TestCompliancePersistedEmptyFindingReferences
--- PASS: TestCompliancePersistedEmptyFindingReferences (0.00s)
=== RUN   TestComplianceExportBindsRequestedJobAndCanonicalFilters
--- PASS: TestComplianceExportBindsRequestedJobAndCanonicalFilters (0.04s)
=== RUN   TestComplianceCreateFreshAfterWaitPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=24 data=/tmp/TestComplianceCreateFreshAfterWaitPostgres3904400361/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceCreateFreshAfterWaitPostgres (7.12s)
=== RUN   TestComplianceGrantFreshAfterWaitPostgres
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true
=== NAME  TestComplianceGrantFreshAfterWaitPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=54 data=/tmp/TestComplianceGrantFreshAfterWaitPostgres1973145802/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceGrantFreshAfterWaitPostgres (4.82s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false (0.10s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false (0.13s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true (0.11s)
=== RUN   TestComplianceWorkerReplayPostgres
    compliance_exports_fix_postgres_test.go:235: joined worker prepare: === RUN   TestComplianceReplayRestartProcess
            compliance_export_replay_test.go:184: registered worker committed exact v1 intent then exited before I/O
        --- PASS: TestComplianceReplayRestartProcess (1.15s)
        PASS
    compliance_exports_fix_postgres_test.go:253: joined worker replay: === RUN   TestComplianceReplayRestartProcess
            compliance_export_replay_test.go:232: fresh registered worker replayed SQL v1 bytes through NewExport.Put; renderer-v2 calls=0; Finish used renewed lease after original deadline
        --- PASS: TestComplianceReplayRestartProcess (2.13s)
        PASS
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=86 data=/tmp/TestComplianceWorkerReplayPostgres2277960616/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceWorkerReplayPostgres (7.94s)
=== RUN   TestComplianceExportsDurablePostgres
    compliance_exports_postgres_test.go:93: joined fresh owner state-inspection process, state=pending storage=reserved snapshot=false
    compliance_exports_postgres_test.go:144: joined fresh owner state-inspection process, state=pending storage=reserved snapshot=false
    compliance_exports_postgres_test.go:154: joined fresh owner state-inspection process, state=pending storage=reserved snapshot=true
    compliance_exports_postgres_test.go:174: joined fresh owner state-inspection process, state=pending storage=intent snapshot=true
    compliance_exports_postgres_test.go:201: joined fresh owner state-inspection process, state=pending storage=unknown snapshot=true
    compliance_exports_postgres_test.go:219: joined fresh owner state-inspection process, state=failed storage=reconcile_required snapshot=true
    compliance_exports_postgres_test.go:235: joined fresh owner state-inspection process, state=failed storage=verified snapshot=true
    compliance_exports_postgres_test.go:244: joined fresh owner state-inspection process, state=failed storage=delete_pending snapshot=true
    compliance_exports_postgres_test.go:258: joined fresh owner state-inspection process, state=failed storage=deleted snapshot=false
    compliance_exports_postgres_test.go:274: capture denied and snapshot rolled back after observed lock wait, postCapture=false
    compliance_exports_postgres_test.go:274: capture denied and snapshot rolled back after observed lock wait, postCapture=true
    compliance_exports_postgres_test.go:284: concurrent policy/finding transaction captured one source snapshot: map[finding:5 policy:5]
    compliance_exports_postgres_test.go:297: joined fresh owner state-inspection process, state=completed storage=verified snapshot=true
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=127 data=/tmp/TestComplianceExportsDurablePostgres3066397205/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceExportsDurablePostgres (13.39s)
=== RUN   TestComplianceExportRestartProcess
    compliance_exports_postgres_test.go:576: owned parent launches this subprocess
--- SKIP: TestComplianceExportRestartProcess (0.00s)
=== RUN   TestComplianceConcurrentQuotasPostgres
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_active_100
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=100 retained_bytes=12583011
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=219 data=/tmp/TestComplianceConcurrentQuotasPostgresdeployment_active_100147982083/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_retained_bytes_16GiB
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=2049 retained_bytes=17179869184
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=249 data=/tmp/TestComplianceConcurrentQuotasPostgresdeployment_retained_bytes2420675957/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_retained_jobs_10000
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=10000 retained_bytes=12592911
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=281 data=/tmp/TestComplianceConcurrentQuotasPostgresdeployment_retained_jobs_199482459/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/scope_retained_jobs_100
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=100 retained_bytes=12583011
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=313 data=/tmp/TestComplianceConcurrentQuotasPostgresscope_retained_jobs_1001425228824/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/principal_scope_grants_20
    compliance_exports_quotas_postgres_test.go:69: registered concurrent clients: principal/S grants=20, target job grants=4; one admitted, one 54000
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=345 data=/tmp/TestComplianceConcurrentQuotasPostgresprincipal_scope_grants_20149341450/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceConcurrentQuotasPostgres (21.03s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_active_100 (4.19s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_retained_bytes_16GiB (4.12s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_retained_jobs_10000 (4.35s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/scope_retained_jobs_100 (4.27s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/principal_scope_grants_20 (4.10s)
=== RUN   TestComplianceExportsRepository
--- PASS: TestComplianceExportsRepository (0.04s)
=== RUN   TestComplianceHTTPPostgresControlFreshness
=== RUN   TestComplianceHTTPPostgresControlFreshness/fresh_101st_source
=== RUN   TestComplianceHTTPPostgresControlFreshness/all_stale
=== RUN   TestComplianceHTTPPostgresControlFreshness/missing
=== RUN   TestComplianceHTTPPostgresControlFreshness/migration_seeded_only
=== NAME  TestComplianceHTTPPostgresControlFreshness
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=375 data=/tmp/TestComplianceHTTPPostgresControlFreshness3844337423/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresControlFreshness (5.00s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/fresh_101st_source (0.13s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/all_stale (0.12s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/missing (0.11s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/migration_seeded_only (0.13s)
=== RUN   TestComplianceHTTPPostgresGrantLifecycle
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=404 data=/tmp/TestComplianceHTTPPostgresGrantLifecycle1732682207/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresGrantLifecycle (5.53s)
=== RUN   TestComplianceHTTPMountedPublicLifecycle
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download
--- PASS: TestComplianceHTTPMountedPublicLifecycle (0.16s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls (0.03s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7 (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID` (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download (0.02s)
=== RUN   TestComplianceHTTPMountedDenials
=== RUN   TestComplianceHTTPMountedDenials/origin
=== RUN   TestComplianceHTTPMountedDenials/csrf
=== RUN   TestComplianceHTTPMountedDenials/scope
=== RUN   TestComplianceHTTPMountedDenials/duplicate-cookie
=== RUN   TestComplianceHTTPMountedDenials/fresh
=== RUN   TestComplianceHTTPMountedDenials/audit-permission
=== RUN   TestComplianceHTTPMountedDenials/view-permission
--- PASS: TestComplianceHTTPMountedDenials (0.15s)
    --- PASS: TestComplianceHTTPMountedDenials/origin (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/csrf (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/scope (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/duplicate-cookie (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/fresh (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/audit-permission (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/view-permission (0.02s)
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/bytes
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/version
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/scope
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/digest
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/size
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/error
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/revoked
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/expired
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/replay
--- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume (0.21s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/bytes (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/version (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/scope (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/digest (0.03s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/size (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/error (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/revoked (0.03s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/expired (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/replay (0.03s)
=== RUN   TestComplianceHTTPStrictInputs
--- PASS: TestComplianceHTTPStrictInputs (0.15s)
=== RUN   TestComplianceRegisteredSourceAuthorityPostgres
=== RUN   TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_session
    compliance_postgres_test.go:406: observed reader PID 450 blocked by session updater PID 451; committed revocation denied without evidence
=== RUN   TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_membership
    compliance_postgres_test.go:406: observed reader PID 450 blocked by membership updater PID 452; committed revocation denied without evidence
=== NAME  TestComplianceRegisteredSourceAuthorityPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=434 data=/tmp/TestComplianceRegisteredSourceAuthorityPostgres2227594842/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceRegisteredSourceAuthorityPostgres (7.20s)
    --- PASS: TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_session (0.07s)
    --- PASS: TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_membership (0.06s)
=== RUN   TestComplianceCompiledFingerprintPostgres
    compliance_postgres_test.go:468: release56 checksum=1aed1a8b4e637d6fa77a2e993eaee3b58c4025e071b483b76487bb9e7a6fa606 fingerprint=30358a1ceacbb18f0283e42353a06c88834d78927814dd8c6a9552a3a1d77a6f
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=467 data=/tmp/TestComplianceCompiledFingerprintPostgres533825707/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceCompiledFingerprintPostgres (3.74s)
=== RUN   TestComplianceEvidenceStrictDecoding
--- PASS: TestComplianceEvidenceStrictDecoding (0.00s)
=== RUN   TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput
--- PASS: TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput (0.02s)
=== RUN   TestComplianceRuntimePollingPostgres
    compliance_runtime_postgres_test.go:66: joined interrupt: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined interrupt polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.67s)
        PASS
    compliance_runtime_postgres_test.go:74: joined resume: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined resume polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.56s)
        PASS
    compliance_runtime_postgres_test.go:79: joined cleanup_denied: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined cleanup_denied polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.59s)
        PASS
    compliance_runtime_postgres_test.go:84: joined cleanup: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined cleanup polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.58s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.63s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.50s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.45s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.46s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.46s)
        PASS
    compliance_runtime_postgres_test.go:96: joined reconcile: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined reconcile polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.57s)
        PASS
    compliance_runtime_postgres_test.go:103: joined revoked: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined revoked polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.66s)
        PASS
    compliance_runtime_postgres_test.go:114: joined lease_lost: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined lease_lost polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.56s)
        PASS
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=497 data=/tmp/TestComplianceRuntimePollingPostgres2067429234/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceRuntimePollingPostgres (11.20s)
PASS
```

## fix1sqlgreen

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task4-fix1-green --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task4-fix1.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task4-worker-final.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestCompliance(HTTPPostgres(ControlFreshness|GrantLifecycle)|CompiledFingerprintPostgres)$' -test.v -test.timeout 240s
```

Exit: 0

```text
=== RUN   TestComplianceHTTPPostgresControlFreshness
=== RUN   TestComplianceHTTPPostgresControlFreshness/fresh_101st_source
=== RUN   TestComplianceHTTPPostgresControlFreshness/all_stale
=== RUN   TestComplianceHTTPPostgresControlFreshness/missing
=== RUN   TestComplianceHTTPPostgresControlFreshness/migration_seeded_only
=== NAME  TestComplianceHTTPPostgresControlFreshness
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=23 data=/tmp/TestComplianceHTTPPostgresControlFreshness2497962398/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresControlFreshness (5.88s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/fresh_101st_source (0.15s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/all_stale (0.15s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/missing (0.17s)
    --- PASS: TestComplianceHTTPPostgresControlFreshness/migration_seeded_only (0.14s)
=== RUN   TestComplianceHTTPPostgresGrantLifecycle
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=53 data=/tmp/TestComplianceHTTPPostgresGrantLifecycle861103616/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresGrantLifecycle (5.58s)
=== RUN   TestComplianceCompiledFingerprintPostgres
    compliance_postgres_test.go:468: release56 checksum=1aed1a8b4e637d6fa77a2e993eaee3b58c4025e071b483b76487bb9e7a6fa606 fingerprint=30358a1ceacbb18f0283e42353a06c88834d78927814dd8c6a9552a3a1d77a6f
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=83 data=/tmp/TestComplianceCompiledFingerprintPostgres2967951495/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceCompiledFingerprintPostgres (3.76s)
PASS
```

## fix1buildgreen

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 /opt/homebrew/bin/go test -c ./apiserver -o /private/tmp/zasp-compliance-task4-fix1.test
```

Exit: 0

```text
(no output)
```

## fix1workerbuild

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 /opt/homebrew/bin/go test -c ./agentsec-worker -o /private/tmp/zasp-compliance-task4-fix1-worker.test
```

Exit: 0

```text
(no output)
```

## fix1racelist

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -list '^TestCompliance(ConflictClassification|PersistedAttributionAndHistoricalBytes|PersistedEmptyFindingReferences|ExportBindsRequestedJobAndCanonicalFilters|ExportsRepository|HTTPMountedPublicLifecycle|HTTPMountedDenials|HTTPDownloadNoDisclosureBeforeConsume|HTTPStrictInputs|EvidenceStrictDecoding|RepositoryBindsScopeAndRejectsUnsafeInput)$'
```

Exit: 0

```text
TestComplianceConflictClassification
TestCompliancePersistedAttributionAndHistoricalBytes
TestCompliancePersistedEmptyFindingReferences
TestComplianceExportBindsRequestedJobAndCanonicalFilters
TestComplianceExportsRepository
TestComplianceHTTPMountedPublicLifecycle
TestComplianceHTTPMountedDenials
TestComplianceHTTPDownloadNoDisclosureBeforeConsume
TestComplianceHTTPStrictInputs
TestComplianceEvidenceStrictDecoding
TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput
ok  	github.com/zasp-ai/zasp-sec/services/platform/apiserver	1.155s
```

## fix1race

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^TestCompliance(ConflictClassification|PersistedAttributionAndHistoricalBytes|PersistedEmptyFindingReferences|ExportBindsRequestedJobAndCanonicalFilters|ExportsRepository|HTTPMountedPublicLifecycle|HTTPMountedDenials|HTTPDownloadNoDisclosureBeforeConsume|HTTPStrictInputs|EvidenceStrictDecoding|RepositoryBindsScopeAndRejectsUnsafeInput)$' -count=1 -v
```

Exit: 0

```text
=== RUN   TestComplianceConflictClassification
--- PASS: TestComplianceConflictClassification (0.00s)
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/old
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/context
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/foreign-context
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/future-envelope
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/duplicate
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/foreign-id
=== RUN   TestCompliancePersistedAttributionAndHistoricalBytes/context-null
--- PASS: TestCompliancePersistedAttributionAndHistoricalBytes (0.05s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/old (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/context (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/foreign-context (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/future-envelope (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/duplicate (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/foreign-id (0.00s)
    --- PASS: TestCompliancePersistedAttributionAndHistoricalBytes/context-null (0.00s)
=== RUN   TestCompliancePersistedEmptyFindingReferences
--- PASS: TestCompliancePersistedEmptyFindingReferences (0.00s)
=== RUN   TestComplianceExportBindsRequestedJobAndCanonicalFilters
--- PASS: TestComplianceExportBindsRequestedJobAndCanonicalFilters (0.08s)
=== RUN   TestComplianceExportsRepository
--- PASS: TestComplianceExportsRepository (0.04s)
=== RUN   TestComplianceHTTPMountedPublicLifecycle
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download
--- PASS: TestComplianceHTTPMountedPublicLifecycle (0.28s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls (0.04s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security (0.04s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7 (0.04s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports (0.04s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID` (0.04s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants (0.04s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download (0.04s)
=== RUN   TestComplianceHTTPMountedDenials
=== RUN   TestComplianceHTTPMountedDenials/origin
=== RUN   TestComplianceHTTPMountedDenials/csrf
=== RUN   TestComplianceHTTPMountedDenials/scope
=== RUN   TestComplianceHTTPMountedDenials/duplicate-cookie
=== RUN   TestComplianceHTTPMountedDenials/fresh
=== RUN   TestComplianceHTTPMountedDenials/audit-permission
=== RUN   TestComplianceHTTPMountedDenials/view-permission
--- PASS: TestComplianceHTTPMountedDenials (0.25s)
    --- PASS: TestComplianceHTTPMountedDenials/origin (0.04s)
    --- PASS: TestComplianceHTTPMountedDenials/csrf (0.04s)
    --- PASS: TestComplianceHTTPMountedDenials/scope (0.04s)
    --- PASS: TestComplianceHTTPMountedDenials/duplicate-cookie (0.04s)
    --- PASS: TestComplianceHTTPMountedDenials/fresh (0.04s)
    --- PASS: TestComplianceHTTPMountedDenials/audit-permission (0.04s)
    --- PASS: TestComplianceHTTPMountedDenials/view-permission (0.04s)
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/bytes
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/version
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/scope
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/digest
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/size
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/error
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/revoked
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/expired
=== RUN   TestComplianceHTTPDownloadNoDisclosureBeforeConsume/replay
--- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume (0.34s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/bytes (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/version (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/scope (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/digest (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/size (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/error (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/revoked (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/expired (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/replay (0.04s)
=== RUN   TestComplianceHTTPStrictInputs
--- PASS: TestComplianceHTTPStrictInputs (0.29s)
=== RUN   TestComplianceEvidenceStrictDecoding
--- PASS: TestComplianceEvidenceStrictDecoding (0.00s)
=== RUN   TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput
--- PASS: TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput (0.05s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/apiserver	3.425s
```

## fix1compatlist

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-api -list '^TestComplianceAPIProductionComposition$'
```

Exit: 0

```text
TestComplianceAPIProductionComposition
ok  	github.com/zasp-ai/zasp-sec/services/platform/agentsec-api	0.988s
```

## fix1compatrace

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-api -run '^TestComplianceAPIProductionComposition$' -count=1 -v
```

Exit: 0

```text
=== RUN   TestComplianceAPIProductionComposition
=== RUN   TestComplianceAPIProductionComposition/installed
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"64caa1c3aba96a54a0c87bc6f6e72d7c","span_id":"da745854e8f61eaa","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"8f0c9c32b04fd31501bf15ede61c2525","span_id":"6d7ad91b1e9efd15","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"7b26f1b060bf06c32530481d958d31b7","span_id":"d4470b10fd071d92","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"5829a308bf89e159664600e5fad2f576","span_id":"04076a90302b85ae","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"febc4549c108181bc160bd757769af46","span_id":"cb7369164de05bc9","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e6a7618a6940a2a16432812201c4cb53","span_id":"5a1caa09cb5b968b","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"9d8061e5e96e393a44591b811200092d","span_id":"d27d023501e68d02","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"154afe02bd7dd573060a97683bdb96a5","span_id":"7a59b54bc86a3471","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"36a8cc56cecd6f4af6e466e5e841f5c0","span_id":"32422630750960ff","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"431ba9e27b520e3021e5e08e477e4942","span_id":"a1e3c35a1fdca09b","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e9e0066ddd14fbf29fa136f274ce264a","span_id":"182aa4b49ea1264e","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"03b202f78c22bd6a5d471cdd2c17657a","span_id":"295a944fba07f24c","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e15497849d03d59523bce935b6445ea5","span_id":"80a1e371ba5170d3","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"83fc571ecfff0394fdba0652adb8ac0c","span_id":"9ea1ebf7741ef1b8","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"bd1005a80d9376bcc167dce230c13572","span_id":"c3dde413e358c7e2","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"eae7bf3e2bb17e57f811ff19539ad399","span_id":"1d0c721f19fff0e3","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"9f4c6f14194dd984b8c194cfda5e5656","span_id":"9a1cdfa9f4989213","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"f325c5ec032decae789a564f6cc31600","span_id":"ef6113d06d46508d","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"0fad35a891dd833b9be34b1482187f19","span_id":"e0115e8e0ea3b058","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"12f255d2f560284cadfd08e98808a7a1","span_id":"daf296c49a70ca6c","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"92b8147f91abb5b29f561df88d519239","span_id":"6372b612ee12f4de","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"445d301a0358e23ee501221f5c05e203","span_id":"850d23bb9dbc4e59","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"ecad5d90afae4a45782be141799d3642","span_id":"6ef3945f98b26988","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"1e37055fb79114ee5eed6458fb39e3c4","span_id":"6605f93e01bfeb8b","parent_span_id":"2126582c0ab99482","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"1e37055fb79114ee5eed6458fb39e3c4","span_id":"4088315bd7012eea","parent_span_id":"2126582c0ab99482","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"correlation_id":"pid_eb210f65-3443-423d-86e9-cd1352426e01","duration_ms":0,"event":"http_request","method":"GET","route":"/api/v1/compliance/:resource","severity":"INFO","span_id":"2126582c0ab99482","status":200,"timestamp":"2026-09-19T01:07:46.436751Z","trace_id":"1e37055fb79114ee5eed6458fb39e3c4"}
{"event":"correlation_span","name":"http.request","kind":"server","trace_id":"1e37055fb79114ee5eed6458fb39e3c4","span_id":"2126582c0ab99482","parent_span_id":"2054d39f81a78d29","status":"ok","duration_ms":0,"attributes":{"http.request.method":"GET","http.response.status_code":"200","http.route":"/api/v1/compliance/:resource"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"6216ec0c0f12ca784dd3d648ccde809b","span_id":"b8d976dfd4c30f32","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
=== RUN   TestComplianceAPIProductionComposition/disabled
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"55e4d80a18eb25160556d8c3cd7ba4ed","span_id":"013f3bc8f2482172","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"2a17ef88c9f12a4141910a96eb55529a","span_id":"d1f3579f23d783b5","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"a97fe81c4256ee0e323584a67f24b061","span_id":"49da903ad5ab5f1e","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"86bf96098817462b19525f0016836342","span_id":"b7b1083f33ad6f6e","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"43d51ea49cd2465e3f18cd8d9f139763","span_id":"ff578fda0bcda2be","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"1883ac5b3c97b3e3aaba4aac7861ddd8","span_id":"22d166f3bebc68fb","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"cd982cd21b464ce4c77a5a4e38acf551","span_id":"70566278ef4c047c","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"d87d4c1017f342a81cc65c8b5f3834c0","span_id":"53730a865c37111e","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"636af1db1745abbfb5b52f1169f2c958","span_id":"0615510832379f7e","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"d14f0f9943c667eb2db36f9c552aa599","span_id":"6adac6428c9a5ca4","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"90108b9a4751c400b28b6a6f42b063d2","span_id":"3561c1e0d2004d92","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"da7377735d530df6a70218e44152d451","span_id":"6a44e150cf7df675","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"c5be13deac48a4c653fac7b8052ab353","span_id":"c5a8ef695f666558","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"eda9598f3fbd4a19724f401fe4d5c3d3","span_id":"5c74d70d72eb53d7","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"c445a2663f650418c08368f42135639b","span_id":"c4203fb36a01bf79","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"5b6be05ba772bdfe917f64b46430018e","span_id":"18444a6d3f4e43eb","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"4fad273bddf24b722ece378509fab8a1","span_id":"1ddde601439d82ac","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"a90b3e37ac12816f7adfc6775bdc2361","span_id":"992a3c2b8f4ef4a8","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"db448df56ef895dfa0dc2bb94a0b7f04","span_id":"33b9999868bca43c","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"11c73b1757086a2f8d1a66460b2bfe30","span_id":"8c37abdf1a9774f3","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"7c098cd8959215e4618717b0096f12ac","span_id":"18112d53d8df0731","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"6f84c74a51dca89da722b3fdaff7a265","span_id":"add368540d968630","parent_span_id":"f4ec91c239a77515","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"correlation_id":"pid_d39f67a9-0f6e-47df-8ed9-4ccb692e4366","duration_ms":0,"event":"http_request","method":"GET","route":"/api/v1/compliance/:resource","severity":"INFO","span_id":"f4ec91c239a77515","status":404,"timestamp":"2026-09-19T01:07:46.452074Z","trace_id":"6f84c74a51dca89da722b3fdaff7a265"}
{"event":"correlation_span","name":"http.request","kind":"server","trace_id":"6f84c74a51dca89da722b3fdaff7a265","span_id":"f4ec91c239a77515","parent_span_id":"44d96fd8540246d9","status":"ok","duration_ms":0,"attributes":{"http.request.method":"GET","http.response.status_code":"404","http.route":"/api/v1/compliance/:resource"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e126ba9dacb5056907669601553a5435","span_id":"e4f067218301ccc0","parent_span_id":"6fe17e1f2afbd13a","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e126ba9dacb5056907669601553a5435","span_id":"22b095df7f8e4f80","parent_span_id":"6fe17e1f2afbd13a","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"correlation_id":"pid_667540c1-6aa8-421c-b713-6d8d09408583","duration_ms":0,"event":"http_request","method":"GET","route":"/api/v1/compliance/:resource","severity":"INFO","span_id":"6fe17e1f2afbd13a","status":200,"timestamp":"2026-09-19T01:07:46.452533Z","trace_id":"e126ba9dacb5056907669601553a5435"}
{"event":"correlation_span","name":"http.request","kind":"server","trace_id":"e126ba9dacb5056907669601553a5435","span_id":"6fe17e1f2afbd13a","parent_span_id":"96272cf1bc8f5898","status":"ok","duration_ms":0,"attributes":{"http.request.method":"GET","http.response.status_code":"200","http.route":"/api/v1/compliance/:resource"}}
=== RUN   TestComplianceAPIProductionComposition/unregistered
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"c6659233a2a43d4ac2bd3fee5279396c","span_id":"3154eb99c4e505aa","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"90547a195597ade30f20b8b91903cfa4","span_id":"43bdefae63ca2a64","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"b00d8f52a55d1b78879fa3c4a648b69a","span_id":"3d0ae4d97d7094b1","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"7e8e26976b56c5f163e39eb0adbc1776","span_id":"ba8db0b72be4e28e","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"36010b67d66199c6c845e08cacd458d8","span_id":"49c6a1b84a7cbf07","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"239d549d54dd73960ca60b662f1ef232","span_id":"3a724bcb522c511c","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"502f8693bb767b54daaf743738288bbe","span_id":"274d498df12a2ad5","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"ef89b5e0fc4bfd9e7e6b642194ed6ed2","span_id":"60e118de9dcdb93b","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"459945ee2ed2fa3ea921985b457c436b","span_id":"26a9c167ed7fdd8e","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"73175a8df7b0920000d200c262104dbd","span_id":"988e547c6b968d79","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"d949995241536313a879043f4da26511","span_id":"1b88c9bbe5d9d26c","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
--- PASS: TestComplianceAPIProductionComposition (0.13s)
    --- PASS: TestComplianceAPIProductionComposition/installed (0.06s)
    --- PASS: TestComplianceAPIProductionComposition/disabled (0.02s)
    --- PASS: TestComplianceAPIProductionComposition/unregistered (0.05s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/agentsec-api	2.234s
```

## fix1webfinal

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/vitest/vitest.mjs run apps/web/api/compliance-decoders.test.ts apps/web/api/compliance-download.test.ts apps/web/api/client.test.ts apps/web/api/administration-decoders.test.ts apps/web/api/audit-exports.test.ts app/features/sessions/SessionsComplianceView.test.tsx
```

Exit: 0

```text

 RUN  v4.1.11 /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917


 Test Files  6 passed (6)
      Tests  57 passed (57)
   Start at  18:07:41
   Duration  1.94s (transform 544ms, setup 1.62s, import 645ms, tests 254ms, environment 7.06s)

```

## fix1contractfinal

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs openapi/identity-admin.test.mjs scripts/check-ui-api-coverage.test.mjs
```

Exit: 0

```text
TAP version 13
# Subtest: pins the official generator/runtime and wires exact local-only scripts into verify
ok 1 - pins the official generator/runtime and wires exact local-only scripts into verify
  ---
  duration_ms: 12.099833
  type: 'test'
  ...
# Subtest: reproduces the committed bytes and rejects changed or missing output without rewriting it
ok 2 - reproduces the committed bytes and rejects changed or missing output without rewriting it
  ---
  duration_ms: 2526.624375
  type: 'test'
  ...
# Subtest: exports the mounted Security Agent, red team, Attack Lab, and policy evidence APIs
ok 3 - exports the mounted Security Agent, red team, Attack Lab, and policy evidence APIs
  ---
  duration_ms: 26.918167
  type: 'test'
  ...
# Subtest: audit page filters validate exact values without changing browser authority
ok 4 - audit page filters validate exact values without changing browser authority
  ---
  duration_ms: 45.501375
  type: 'test'
  ...
# Subtest: retained identity actions preserve their exact public and export schema values
ok 5 - retained identity actions preserve their exact public and export schema values
  ---
  duration_ms: 75.459625
  type: 'test'
  ...
# Subtest: audit export descriptors model durable async state without partial ready metadata
ok 6 - audit export descriptors model durable async state without partial ready metadata
  ---
  duration_ms: 21.12275
  type: 'test'
  ...
# Subtest: audit export reads separate pending, failed, ready-empty and immutable chunk contents
ok 7 - audit export reads separate pending, failed, ready-empty and immutable chunk contents
  ---
  duration_ms: 30.194708
  type: 'test'
  ...
# Subtest: runtime session search publishes closed selectors and checkpoint freshness
ok 8 - runtime session search publishes closed selectors and checkpoint freshness
  ---
  duration_ms: 6.374125
  type: 'test'
  ...
# Subtest: runtime session reads preserve operation IDs and console-only revocation
ok 9 - runtime session reads preserve operation IDs and console-only revocation
  ---
  duration_ms: 5.51225
  type: 'test'
  ...
# Subtest: publishes the identity administration operations at their honest UI lifecycle
ok 10 - publishes the identity administration operations at their honest UI lifecycle
  ---
  duration_ms: 7.268125
  type: 'test'
  ...
# Subtest: uses strict product schemas and the shared stable error response
ok 11 - uses strict product schemas and the shared stable error response
  ---
  duration_ms: 5.904417
  type: 'test'
  ...
# Subtest: M1-23 strict OpenAPI root
    # Subtest: defines the exact self-contained OpenAPI, auth, pagination, and error boundary
    ok 1 - defines the exact self-contained OpenAPI, auth, pagination, and error boundary
      ---
      duration_ms: 6.633209
      type: 'test'
      ...
    # Subtest: uses only the exact pinned local linter command and justified rule exception
    ok 2 - uses only the exact pinned local linter command and justified rule exception
      ---
      duration_ms: 0.13525
      type: 'test'
      ...
    # Subtest: rejects duplicate YAML keys before semantic validation
    ok 3 - rejects duplicate YAML keys before semantic validation
      ---
      duration_ms: 16.023375
      type: 'test'
      ...
    # Subtest: accepts only canonical unpadded base64url cursor encodings
    ok 4 - accepts only canonical unpadded base64url cursor encodings
      ---
      duration_ms: 0.175291
      type: 'test'
      ...
    # Subtest: rejects every product-error control-character class
    ok 5 - rejects every product-error control-character class
      ---
      duration_ms: 0.143125
      type: 'test'
      ...
    # Subtest: rejects hostile root, authentication, pagination, and error mutations
    ok 6 - rejects hostile root, authentication, pagination, and error mutations
      ---
      duration_ms: 69.319958
      type: 'test'
      ...
    1..6
ok 12 - M1-23 strict OpenAPI root
  ---
  duration_ms: 114.575667
  type: 'suite'
  ...
# Subtest: production workflow concurrency contract
    # Subtest: publishes the exact replay-safe sensor management surface
    ok 1 - publishes the exact replay-safe sensor management surface
      ---
      duration_ms: 0.372334
      type: 'test'
      ...
    # Subtest: publishes the three retained DELETE operations with no request body
    ok 2 - publishes the three retained DELETE operations with no request body
      ---
      duration_ms: 0.179
      type: 'test'
      ...
    # Subtest: reports asynchronous integration revocation without claiming early deletion
    ok 3 - reports asynchronous integration revocation without claiming early deletion
      ---
      duration_ms: 0.224
      type: 'test'
      ...
    # Subtest: separates server-assigned security-agent identity from create input
    ok 4 - separates server-assigned security-agent identity from create input
      ---
      duration_ms: 0.066875
      type: 'test'
      ...
    # Subtest: types idempotency, versions, fresh auth, and durable mutation receipts
    ok 5 - types idempotency, versions, fresh auth, and durable mutation receipts
      ---
      duration_ms: 0.2465
      type: 'test'
      ...
    # Subtest: publishes bounded browser-only receipt reconciliation and acknowledgement
    ok 6 - publishes bounded browser-only receipt reconciliation and acknowledgement
      ---
      duration_ms: 0.1015
      type: 'test'
      ...
    # Subtest: requires the browser scope precondition on every scoped session operation
    ok 7 - requires the browser scope precondition on every scoped session operation
      ---
      duration_ms: 0.05875
      type: 'test'
      ...
    # Subtest: publishes exact receipt intent and authoritative result object shapes
    ok 8 - publishes exact receipt intent and authoritative result object shapes
      ---
      duration_ms: 0.103958
      type: 'test'
      ...
    # Subtest: publishes the strict Task 4 sync, schedule, and freshness contract without internal execution authority
    ok 9 - publishes the strict Task 4 sync, schedule, and freshness contract without internal execution authority
      ---
      duration_ms: 0.225375
      type: 'test'
      ...
    # Subtest: publishes bounded browser-only typed activity relations with explicit coverage
    ok 10 - publishes bounded browser-only typed activity relations with explicit coverage
      ---
      duration_ms: 0.08575
      type: 'test'
      ...
    # Subtest: publishes the mounted Security Agent activation, simulation, manual run, and approval surface without read overclaims
    ok 11 - publishes the mounted Security Agent activation, simulation, manual run, and approval surface without read overclaims
      ---
      duration_ms: 1.148542
      type: 'test'
      ...
    # Subtest: publishes strict browser-only integration authorization and OAuth callback contracts
    ok 12 - publishes strict browser-only integration authorization and OAuth callback contracts
      ---
      duration_ms: 0.187292
      type: 'test'
      ...
    # Subtest: publishes strict fresh browser-only reference authorization
    ok 13 - publishes strict fresh browser-only reference authorization
      ---
      duration_ms: 0.061292
      type: 'test'
      ...
    # Subtest: binds risk reads and mutations to strict pagination, security, and recovery contracts
    ok 14 - binds risk reads and mutations to strict pagination, security, and recovery contracts
      ---
      duration_ms: 0.143917
      type: 'test'
      ...
    # Subtest: bounds Security Agent definition pagination with the shared opaque cursor contract
    ok 15 - bounds Security Agent definition pagination with the shared opaque cursor contract
      ---
      duration_ms: 0.038834
      type: 'test'
      ...
    # Subtest: bounds policy and integration pagination with the same exact cursor contract
    ok 16 - bounds policy and integration pagination with the same exact cursor contract
      ---
      duration_ms: 0.046291
      type: 'test'
      ...
    # Subtest: publishes typed discovery inventory pages, details, evidence, and freshness
    ok 17 - publishes typed discovery inventory pages, details, evidence, and freshness
      ---
      duration_ms: 0.088792
      type: 'test'
      ...
    1..17
ok 13 - production workflow concurrency contract
  ---
  duration_ms: 3.721208
  type: 'suite'
  ...
# Subtest: current API and planned map passes honestly
ok 14 - current API and planned map passes honestly
  ---
  duration_ms: 27.005458
  type: 'test'
  ...
# Subtest: all current public operations resolve and deliberate removal fails
ok 15 - all current public operations resolve and deliberate removal fails
  ---
  duration_ms: 4.5065
  type: 'test'
  ...
# Subtest: unmapped public operations fail while unmapped internal operations pass
ok 16 - unmapped public operations fail while unmapped internal operations pass
  ---
  duration_ms: 10.759125
  type: 'test'
  ...
# Subtest: planned, available, and internal lifecycle mismatches fail
ok 17 - planned, available, and internal lifecycle mismatches fail
  ---
  duration_ms: 5.333958
  type: 'test'
  ...
# Subtest: API-available operations require OpenAPI but do not claim a wired UI
ok 18 - API-available operations require OpenAPI but do not claim a wired UI
  ---
  duration_ms: 2.045917
  type: 'test'
  ...
# Subtest: OpenAPI operation extraction rejects missing, duplicate, and unclassified operations
ok 19 - OpenAPI operation extraction rejects missing, duplicate, and unclassified operations
  ---
  duration_ms: 0.20475
  type: 'test'
  ...
# Subtest: strict YAML parsing rejects representation and map-schema ambiguity
ok 20 - strict YAML parsing rejects representation and map-schema ambiguity
  ---
  duration_ms: 12.535
  type: 'test'
  ...
# Subtest: fixed file boundary accepts regular UTF-8 and rejects symlink, oversize, and invalid UTF-8
ok 21 - fixed file boundary accepts regular UTF-8 and rejects symlink, oversize, and invalid UTF-8
  ---
  duration_ms: 6.5665
  type: 'test'
  ...
# Subtest: CLI emits only fixed success or rejection lines
ok 22 - CLI emits only fixed success or rejection lines
  ---
  duration_ms: 9.02825
  type: 'test'
  ...
# Subtest: package command is wired into root verification
ok 23 - package command is wired into root verification
  ---
  duration_ms: 1.337625
  type: 'test'
  ...
1..23
# tests 44
# suites 2
# pass 44
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 2614.519417
```

## fix1tscfinal

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/typescript/bin/tsc --noEmit
```

Exit: 0

```text
(no output)
```

## fix1lintfinal

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/eslint/bin/eslint.js apps/web/api/client.ts apps/web/api/administration-decoders.ts apps/web/api/compliance-decoders.ts apps/web/api/compliance-decoders.test.ts apps/web/api/compliance-download.test.ts
```

Exit: 0

```text
(no output)
```

## fix1openapilintfinal

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
env REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/@redocly/cli/bin/cli.js lint openapi/openapi.yaml openapi/internal-health.yaml --config redocly.yaml
```

Exit: 0

```text
validating openapi/openapi.yaml...
openapi/openapi.yaml: validated in 102ms

validating openapi/internal-health.yaml...
openapi/internal-health.yaml: validated in 5ms

Woohoo! Your API descriptions are valid. 🎉

```

## fix1generatedcheckfinal

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/openapi-typescript/bin/cli.js openapi/openapi.yaml --output apps/web/api/generated.ts --alphabetize --export-type --immutable --root-types --root-types-no-schema-prefix --check
```

Exit: 0

```text
✨ openapi-typescript 7.13.0
```

## fix1patchcheck

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
git apply --check --reverse .superpowers/sdd/2026-09-18-compliance-production-plan/task-4-fix-1-scoped.patch
```

Exit: 0

```text
(no output)
```
