# Task 4 accepted verification commands and complete captured outputs

All results below are local, not live provider acceptance. SQL executes only in the owned cached Docker container; the race selection uses non-PostgreSQL tests. The race name enumeration was completed after the selected race started, not before it.

## task4sqllog

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task4-final --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task4-final.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task4-worker-final.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestCompliance' -test.v -test.timeout 240s
```

Exit: 0

Complete captured output:

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
--- PASS: TestCompliancePersistedAttributionAndHistoricalBytes (0.04s)
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
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=24 data=/tmp/TestComplianceCreateFreshAfterWaitPostgres2120867906/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceCreateFreshAfterWaitPostgres (7.00s)
=== RUN   TestComplianceGrantFreshAfterWaitPostgres
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true
=== NAME  TestComplianceGrantFreshAfterWaitPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=54 data=/tmp/TestComplianceGrantFreshAfterWaitPostgres703664812/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceGrantFreshAfterWaitPostgres (4.91s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false (0.11s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false (0.09s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true (0.10s)
=== RUN   TestComplianceWorkerReplayPostgres
    compliance_exports_fix_postgres_test.go:235: joined worker prepare: === RUN   TestComplianceReplayRestartProcess
            compliance_export_replay_test.go:184: registered worker committed exact v1 intent then exited before I/O
        --- PASS: TestComplianceReplayRestartProcess (1.13s)
        PASS
    compliance_exports_fix_postgres_test.go:253: joined worker replay: === RUN   TestComplianceReplayRestartProcess
            compliance_export_replay_test.go:232: fresh registered worker replayed SQL v1 bytes through NewExport.Put; renderer-v2 calls=0; Finish used renewed lease after original deadline
        --- PASS: TestComplianceReplayRestartProcess (2.13s)
        PASS
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=86 data=/tmp/TestComplianceWorkerReplayPostgres3298865478/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceWorkerReplayPostgres (7.77s)
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
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=128 data=/tmp/TestComplianceExportsDurablePostgres1863923940/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceExportsDurablePostgres (13.47s)
=== RUN   TestComplianceExportRestartProcess
    compliance_exports_postgres_test.go:576: owned parent launches this subprocess
--- SKIP: TestComplianceExportRestartProcess (0.00s)
=== RUN   TestComplianceConcurrentQuotasPostgres
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_active_100
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=100 retained_bytes=12583011
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=218 data=/tmp/TestComplianceConcurrentQuotasPostgresdeployment_active_1001814202020/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_retained_bytes_16GiB
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=2049 retained_bytes=17179869184
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=248 data=/tmp/TestComplianceConcurrentQuotasPostgresdeployment_retained_bytes2312871506/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_retained_jobs_10000
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=10000 retained_bytes=12592911
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=278 data=/tmp/TestComplianceConcurrentQuotasPostgresdeployment_retained_jobs_2038054211/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/scope_retained_jobs_100
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=100 retained_bytes=12583011
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=308 data=/tmp/TestComplianceConcurrentQuotasPostgresscope_retained_jobs_100165661539/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/principal_scope_grants_20
    compliance_exports_quotas_postgres_test.go:69: registered concurrent clients: principal/S grants=20, target job grants=4; one admitted, one 54000
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=340 data=/tmp/TestComplianceConcurrentQuotasPostgresprincipal_scope_grants_202808359472/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceConcurrentQuotasPostgres (23.96s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_active_100 (4.31s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_retained_bytes_16GiB (4.48s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_retained_jobs_10000 (5.53s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/scope_retained_jobs_100 (4.89s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/principal_scope_grants_20 (4.75s)
=== RUN   TestComplianceExportsRepository
--- PASS: TestComplianceExportsRepository (0.04s)
=== RUN   TestComplianceHTTPPostgresGrantLifecycle
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=370 data=/tmp/TestComplianceHTTPPostgresGrantLifecycle791402863/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresGrantLifecycle (6.71s)
=== RUN   TestComplianceHTTPMountedPublicLifecycle
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download
--- PASS: TestComplianceHTTPMountedPublicLifecycle (0.19s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls (0.03s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7 (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports (0.03s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID` (0.03s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants (0.02s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download (0.03s)
=== RUN   TestComplianceHTTPMountedDenials
=== RUN   TestComplianceHTTPMountedDenials/origin
=== RUN   TestComplianceHTTPMountedDenials/csrf
=== RUN   TestComplianceHTTPMountedDenials/scope
=== RUN   TestComplianceHTTPMountedDenials/duplicate-cookie
=== RUN   TestComplianceHTTPMountedDenials/fresh
=== RUN   TestComplianceHTTPMountedDenials/audit-permission
=== RUN   TestComplianceHTTPMountedDenials/view-permission
--- PASS: TestComplianceHTTPMountedDenials (0.17s)
    --- PASS: TestComplianceHTTPMountedDenials/origin (0.03s)
    --- PASS: TestComplianceHTTPMountedDenials/csrf (0.03s)
    --- PASS: TestComplianceHTTPMountedDenials/scope (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/duplicate-cookie (0.02s)
    --- PASS: TestComplianceHTTPMountedDenials/fresh (0.03s)
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
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/digest (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/size (0.03s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/error (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/revoked (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/expired (0.02s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/replay (0.02s)
=== RUN   TestComplianceHTTPStrictInputs
--- PASS: TestComplianceHTTPStrictInputs (0.17s)
=== RUN   TestComplianceRegisteredSourceAuthorityPostgres
=== RUN   TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_session
    compliance_postgres_test.go:406: observed reader PID 413 blocked by session updater PID 414; committed revocation denied without evidence
=== RUN   TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_membership
    compliance_postgres_test.go:406: observed reader PID 413 blocked by membership updater PID 415; committed revocation denied without evidence
=== NAME  TestComplianceRegisteredSourceAuthorityPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=399 data=/tmp/TestComplianceRegisteredSourceAuthorityPostgres243322202/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceRegisteredSourceAuthorityPostgres (8.05s)
    --- PASS: TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_session (0.08s)
    --- PASS: TestComplianceRegisteredSourceAuthorityPostgres/revoked_while_blocked_membership (0.07s)
=== RUN   TestComplianceCompiledFingerprintPostgres
    compliance_postgres_test.go:468: release56 checksum=af7be48e8b1444219414b4880cc7cfa4b40c6798222423a59e771e6af5955e41 fingerprint=794bd599bc37408e07b0c6238ad10052dbd40458ab24380481cc05caa0698cf9
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=430 data=/tmp/TestComplianceCompiledFingerprintPostgres2934781168/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceCompiledFingerprintPostgres (3.81s)
=== RUN   TestComplianceEvidenceStrictDecoding
--- PASS: TestComplianceEvidenceStrictDecoding (0.00s)
=== RUN   TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput
--- PASS: TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput (0.02s)
=== RUN   TestComplianceRuntimePollingPostgres
    compliance_runtime_postgres_test.go:66: joined interrupt: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined interrupt polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.69s)
        PASS
    compliance_runtime_postgres_test.go:74: joined resume: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined resume polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.51s)
        PASS
    compliance_runtime_postgres_test.go:79: joined cleanup_denied: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined cleanup_denied polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.54s)
        PASS
    compliance_runtime_postgres_test.go:84: joined cleanup: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined cleanup polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.56s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.57s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.53s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.52s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.51s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.51s)
        PASS
    compliance_runtime_postgres_test.go:96: joined reconcile: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined reconcile polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.57s)
        PASS
    compliance_runtime_postgres_test.go:103: joined revoked: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined revoked polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.67s)
        PASS
    compliance_runtime_postgres_test.go:114: joined lease_lost: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined lease_lost polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.57s)
        PASS
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=458 data=/tmp/TestComplianceRuntimePollingPostgres3880199583/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceRuntimePollingPostgres (11.59s)
PASS
```

## task4racelist

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

Command:

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver ./agentsec-api ./sessioncontrol ./artifactstore ./artifactstore/s3driver -list '^TestCompliance(ConflictClassification|PersistedAttributionAndHistoricalBytes|PersistedEmptyFindingReferences|ExportBindsRequestedJobAndCanonicalFilters|ExportsRepository|HTTPMountedPublicLifecycle|HTTPMountedDenials|HTTPDownloadNoDisclosureBeforeConsume|HTTPStrictInputs|EvidenceStrictDecoding|RepositoryBindsScopeAndRejectsUnsafeInput|APIConfiguration|APIProductionComposition|FormatterCapturedAttribution|FormatterFrozenContext|ExportFormatsRetainEvidenceAttribution|ExportCSVNeutralizesFormulaFields|ExportDetailedReportPersistsBeyondDisclaimerSize|ExportRefusesOversizedCombinedPackage|ExportWriterPreservesQuotedLabelsAndRejectsForgedReport|ExportRejectsUnboundedNestedInput|ExportAcceptsVersionedArtifactStoreReceipt|ExportRejectsInvalidVersionAndChangedOwnership|ExportPersistsExactArtifact)$|^TestExport|^TestCoreComposition|^TestNewComposition|^TestProductMiddleware|^TestAuditExportRuntimeEnvironment|^TestAuditExportRuntimeTypedConfiguration|^TestAuditExportWebIdentitySessionIsClosed'
```

Exit: 0

Complete captured output:

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
TestCoreCompositionMatchesPublicOpenAPI
TestCoreCompositionHasExactProductionSecuritySurfaceWithoutUnimplementedOverclaims
TestNewCompositionMountsOnlyCoreProductOperations
TestNewCompositionFailsClosedOnInvalidDependencies
TestProductMiddlewareAuthenticatesCookieAndOwnsRequestIdentity
TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection
TestProductMiddlewareAcceptsBearerAutomationWithoutBrowserCSRF
TestProductMiddlewareEnforcesBodyAndPanicBoundaries
TestProductMiddlewareSuppliesCorrelationToRouterErrors
ok  	github.com/zasp-ai/zasp-sec/services/platform/apiserver	1.823s
TestAuditExportWebIdentitySessionIsClosed
TestAuditExportRuntimeEnvironment
TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid
TestAuditExportRuntimeTypedConfigurationRevalidated
TestComplianceAPIProductionComposition
TestComplianceAPIConfiguration
ok  	github.com/zasp-ai/zasp-sec/services/platform/agentsec-api	0.876s
TestComplianceFormatterCapturedAttribution
TestComplianceFormatterFrozenContext
TestComplianceExportFormatsRetainEvidenceAttribution
TestComplianceExportCSVNeutralizesFormulaFields
TestComplianceExportDetailedReportPersistsBeyondDisclaimerSize
TestComplianceExportRefusesOversizedCombinedPackage
TestComplianceExportWriterPreservesQuotedLabelsAndRejectsForgedReport
TestComplianceExportRejectsUnboundedNestedInput
TestComplianceExportAcceptsVersionedArtifactStoreReceipt
TestComplianceExportRejectsInvalidVersionAndChangedOwnership
TestComplianceExportPersistsExactArtifact
ok  	github.com/zasp-ai/zasp-sec/services/platform/sessioncontrol	0.993s
TestExportStoreRejectsDriverProfileAndScopeSubstitution
TestExportStoreEnforcesRequestBoundsBeforeDriverIO
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore	1.184s
TestExportStoreSDKUsesScopedExportPrefix
TestExportStoreSDKCancellationAfterSavedPutRemainsRecoverable
TestExportProfilesRejectMixedConstructionBeforeProviderIO
TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO
TestExportReadRefusesCorruptedProviderAuthority
TestExportDriverKeepsImmutableReplayLimitsAndCancellation
TestExportCleanupSDKExactVersionAbsence
TestExportReadOnlyReconciliation
TestExportReadOnlyReconciliationSDKFaults
TestExportCleanupRequiresVerifiedExactVersionAbsence
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver	0.297s
```

## task4race

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

Command:

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver ./agentsec-api ./sessioncontrol ./artifactstore ./artifactstore/s3driver -run '^TestCompliance(ConflictClassification|PersistedAttributionAndHistoricalBytes|PersistedEmptyFindingReferences|ExportBindsRequestedJobAndCanonicalFilters|ExportsRepository|HTTPMountedPublicLifecycle|HTTPMountedDenials|HTTPDownloadNoDisclosureBeforeConsume|HTTPStrictInputs|EvidenceStrictDecoding|RepositoryBindsScopeAndRejectsUnsafeInput|APIConfiguration|APIProductionComposition|FormatterCapturedAttribution|FormatterFrozenContext|ExportFormatsRetainEvidenceAttribution|ExportCSVNeutralizesFormulaFields|ExportDetailedReportPersistsBeyondDisclaimerSize|ExportRefusesOversizedCombinedPackage|ExportWriterPreservesQuotedLabelsAndRejectsForgedReport|ExportRejectsUnboundedNestedInput|ExportAcceptsVersionedArtifactStoreReceipt|ExportRejectsInvalidVersionAndChangedOwnership|ExportPersistsExactArtifact)$|^TestExport|^TestCoreComposition|^TestNewComposition|^TestProductMiddleware|^TestAuditExportRuntimeEnvironment|^TestAuditExportRuntimeTypedConfiguration|^TestAuditExportWebIdentitySessionIsClosed' -count=1 -v
```

Exit: 0

Complete captured output:

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
--- PASS: TestCompliancePersistedAttributionAndHistoricalBytes (0.04s)
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
--- PASS: TestComplianceHTTPMountedPublicLifecycle (0.29s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls (0.05s)
    --- PASS: TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security (0.05s)
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
--- PASS: TestComplianceHTTPMountedDenials (0.27s)
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
--- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume (0.36s)
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
--- PASS: TestComplianceHTTPStrictInputs (0.28s)
=== RUN   TestComplianceEvidenceStrictDecoding
--- PASS: TestComplianceEvidenceStrictDecoding (0.00s)
=== RUN   TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput
--- PASS: TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput (0.09s)
=== RUN   TestCoreCompositionMatchesPublicOpenAPI
--- PASS: TestCoreCompositionMatchesPublicOpenAPI (0.16s)
=== RUN   TestCoreCompositionHasExactProductionSecuritySurfaceWithoutUnimplementedOverclaims
--- PASS: TestCoreCompositionHasExactProductionSecuritySurfaceWithoutUnimplementedOverclaims (0.00s)
=== RUN   TestNewCompositionMountsOnlyCoreProductOperations
--- PASS: TestNewCompositionMountsOnlyCoreProductOperations (0.00s)
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies/missing_session
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies/missing_identity
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies/missing_inventory
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies/missing_risk
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies/missing_workflow
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies/missing_connector
=== RUN   TestNewCompositionFailsClosedOnInvalidDependencies/same_handler_crosses_trust_boundary
--- PASS: TestNewCompositionFailsClosedOnInvalidDependencies (0.00s)
    --- PASS: TestNewCompositionFailsClosedOnInvalidDependencies/missing_session (0.00s)
    --- PASS: TestNewCompositionFailsClosedOnInvalidDependencies/missing_identity (0.00s)
    --- PASS: TestNewCompositionFailsClosedOnInvalidDependencies/missing_inventory (0.00s)
    --- PASS: TestNewCompositionFailsClosedOnInvalidDependencies/missing_risk (0.00s)
    --- PASS: TestNewCompositionFailsClosedOnInvalidDependencies/missing_workflow (0.00s)
    --- PASS: TestNewCompositionFailsClosedOnInvalidDependencies/missing_connector (0.00s)
    --- PASS: TestNewCompositionFailsClosedOnInvalidDependencies/same_handler_crosses_trust_boundary (0.00s)
=== RUN   TestProductMiddlewareAuthenticatesCookieAndOwnsRequestIdentity
--- PASS: TestProductMiddlewareAuthenticatesCookieAndOwnsRequestIdentity (0.00s)
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/missing_session
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/expired_session
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/missing_origin
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/foreign_origin
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/missing_csrf
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/wrong_csrf
=== RUN   TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/valid_mutation
--- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection (0.01s)
    --- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/missing_session (0.00s)
    --- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/expired_session (0.00s)
    --- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/missing_origin (0.00s)
    --- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/foreign_origin (0.00s)
    --- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/missing_csrf (0.00s)
    --- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/wrong_csrf (0.00s)
    --- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection/valid_mutation (0.00s)
=== RUN   TestProductMiddlewareAcceptsBearerAutomationWithoutBrowserCSRF
--- PASS: TestProductMiddlewareAcceptsBearerAutomationWithoutBrowserCSRF (0.00s)
=== RUN   TestProductMiddlewareEnforcesBodyAndPanicBoundaries
=== RUN   TestProductMiddlewareEnforcesBodyAndPanicBoundaries/wrong_content_type
=== RUN   TestProductMiddlewareEnforcesBodyAndPanicBoundaries/oversized
=== RUN   TestProductMiddlewareEnforcesBodyAndPanicBoundaries/panic_contained
--- PASS: TestProductMiddlewareEnforcesBodyAndPanicBoundaries (0.00s)
    --- PASS: TestProductMiddlewareEnforcesBodyAndPanicBoundaries/wrong_content_type (0.00s)
    --- PASS: TestProductMiddlewareEnforcesBodyAndPanicBoundaries/oversized (0.00s)
    --- PASS: TestProductMiddlewareEnforcesBodyAndPanicBoundaries/panic_contained (0.00s)
=== RUN   TestProductMiddlewareSuppliesCorrelationToRouterErrors
--- PASS: TestProductMiddlewareSuppliesCorrelationToRouterErrors (0.00s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/apiserver	4.433s
=== RUN   TestAuditExportWebIdentitySessionIsClosed
--- PASS: TestAuditExportWebIdentitySessionIsClosed (0.00s)
=== RUN   TestAuditExportRuntimeEnvironment
--- PASS: TestAuditExportRuntimeEnvironment (0.00s)
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_POLICIES_JSONmissing
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_POLICIES_JSONempty
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_POLICIES_JSONonly-empty
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_READER_ROLE_ARNmissing
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_READER_ROLE_ARNempty
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_READER_ROLE_ARNonly-empty
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILEmissing
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILEempty
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILEonly-empty
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEYmissing
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEYempty
=== RUN   TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEYonly-empty
--- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid (0.02s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_POLICIES_JSONmissing (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_POLICIES_JSONempty (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_POLICIES_JSONonly-empty (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_READER_ROLE_ARNmissing (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_READER_ROLE_ARNempty (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_READER_ROLE_ARNonly-empty (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILEmissing (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILEempty (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILEonly-empty (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEYmissing (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEYempty (0.00s)
    --- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid/ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEYonly-empty (0.00s)
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/role
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/connector_role
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/too_many_policies
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/selector
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/short_key
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/long_key
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/token_path
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/empty_policies
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/duplicate_policies
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/bad_bucket
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/zero_key
--- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated (0.02s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/role (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/connector_role (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/too_many_policies (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/selector (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/short_key (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/long_key (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/token_path (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/empty_policies (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/duplicate_policies (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/bad_bucket (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/zero_key (0.00s)
=== RUN   TestComplianceAPIProductionComposition
=== RUN   TestComplianceAPIProductionComposition/installed
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"2cc578770fbde3773f69ba1c597e0f4d","span_id":"6a7a9304314b4d18","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"7a6cf0d44c9308b96736934db7a5b790","span_id":"a5f07f74cbd9f279","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"7da859ae997047f99981bd27a2273a92","span_id":"da4192266ff6cb90","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"147e8a9c3a3bd7ec18f2f8c6d0285fa6","span_id":"602180240b86d733","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"a373815fedc2d5e12939cc3e70e78376","span_id":"35ac5af650188df3","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"613d9689e61356c186d52115b2f67d66","span_id":"40f3dfe2ac20a0fa","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"8a784ec97b8d928667ee187890c20b3f","span_id":"c18e6b1248120f3f","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"fb1324acc3b12ed9e3ba3f968a79576b","span_id":"36ef93feebf04c95","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e2906d24f834312eafbc91909a373730","span_id":"d962688f5e34f27b","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"aacc3e9a21dd47ab0c76abf5b003f7cb","span_id":"b20c6bf65703a083","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e7e89664fc86df265b744c8dd034f4d2","span_id":"8324e7102010266d","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"a70876053af83a73acad79ef32926ff5","span_id":"5d740a2b45e4d4a6","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"dcb9489610598ad8e1499bf0de81b079","span_id":"4d81e43d621ddea5","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"52356fe02c4be44fb096fe9162796e2d","span_id":"288c6623e624bebb","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"a641511c05a2dc7514b27b943327aa98","span_id":"19b7e050bfa97885","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"b0e51445548ae56469af70205e0cc38c","span_id":"dc7116f0cd4640d0","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"23a9719d51ece91d8e848c76c757f643","span_id":"04cddd0c44a9cafd","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"942d1dfe813cc4a057160698b91fcbba","span_id":"5367f39756bc8c52","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"436bcb57f600104b3a2f598a6b002065","span_id":"c8bd1c684210b8f0","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"b4a8507d102cc8c1e7b336fc1415983e","span_id":"0e83a3f28c9fd806","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"f9c23a6a28777094dd47ac29fc3d32b5","span_id":"d8fd9367d220c289","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"926ad3b20af540d47827381995314b6d","span_id":"d903adec853eb5f0","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"afa6dafc1ba790df1bd78038aa4d6734","span_id":"0087db8a39c0968a","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"7a5a56c314f57ee33bb4e7a1ef9947ba","span_id":"37129560b9f6caac","parent_span_id":"233db97e779dd53d","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"7a5a56c314f57ee33bb4e7a1ef9947ba","span_id":"f1df975fe9424ace","parent_span_id":"233db97e779dd53d","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"correlation_id":"pid_eac3ebb9-2562-4854-aa0e-9ea5ca93be7f","duration_ms":0,"event":"http_request","method":"GET","route":"/api/v1/compliance/:resource","severity":"INFO","span_id":"233db97e779dd53d","status":200,"timestamp":"2026-09-19T00:40:01.724004Z","trace_id":"7a5a56c314f57ee33bb4e7a1ef9947ba"}
{"event":"correlation_span","name":"http.request","kind":"server","trace_id":"7a5a56c314f57ee33bb4e7a1ef9947ba","span_id":"233db97e779dd53d","parent_span_id":"fa78cb38c7fa0009","status":"ok","duration_ms":0,"attributes":{"http.request.method":"GET","http.response.status_code":"200","http.route":"/api/v1/compliance/:resource"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"f475db9f68925c569ab8d44dc99c7531","span_id":"9f6284906728867a","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
=== RUN   TestComplianceAPIProductionComposition/disabled
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"f0248e45b0977f25d8bf1ce13562aa3a","span_id":"a72a4b8f2d9cbf07","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e059a3a606e0940925f2def87a6049e5","span_id":"febf91b6c7630133","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"133e5a52376626679df6d9f61e38c37d","span_id":"5a28002b0f980f7d","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"84eadfae90c5efc68157cb787cc30fef","span_id":"95316d395ddb22d6","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"443e939eeb0dcb278ec60edd34e7a66d","span_id":"a88a2b0608982538","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"cbc8181ecd817b3f617c43c7ad9f0ea2","span_id":"28caddf51286fe11","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"e321dba8550479fa2208cbc08b606de1","span_id":"79dbb15d8feabcd6","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"97f07b6beed07f6d7922f6e8c8c72cb7","span_id":"f3de8d103245f0a1","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"3f4619e806f4c9c0fe78fde215f38b7d","span_id":"b7809ce785bc58a8","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"5c84e58bfe7ce3303208b9fa72be261b","span_id":"a9d4317747befbdc","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"9db74583d8ee5a4e8d614a8bec90e206","span_id":"f96728f6d3c898c2","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"742f3b910c74876b9a448aec1fdab253","span_id":"75783889a6f6af8f","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"0f6f34062bf9377de64dbb964f217bd6","span_id":"ee4c2a9f5c4d41c3","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"2668710ca906839f9cb741242c34be97","span_id":"8ea5a5883333a083","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"ad1f375ed3dc6cee27b37b0860b06a1e","span_id":"2540afd9309b4105","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"4b989f6810cdb07f0aed2d46436a08fd","span_id":"3d2f5c344d275b28","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"b635fbb070f04fdd070c2d5895cfdb2a","span_id":"2b8ea824e349e052","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"d2dc760c2f9f663f6cb5e31e4bd3acb8","span_id":"d0f1989021e830a6","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"a6ea85185c5090cd36efea89616d807b","span_id":"ecc5fb21e392b27b","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"1b55a55243c2ec7e1d12245537ea6e63","span_id":"ab9ad751a31cbacf","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"bd23095a23f9c7463bbd7fe3f0cca750","span_id":"5b53e16177fa0de3","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e44350206f64e167ace04e3ad69f6fe2","span_id":"63094970ec4b5015","parent_span_id":"0577015e43cb43c9","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"correlation_id":"pid_f2903040-49aa-43f4-b5ec-a8c813aa6d6c","duration_ms":0,"event":"http_request","method":"GET","route":"/api/v1/compliance/:resource","severity":"INFO","span_id":"0577015e43cb43c9","status":404,"timestamp":"2026-09-19T00:40:01.740361Z","trace_id":"e44350206f64e167ace04e3ad69f6fe2"}
{"event":"correlation_span","name":"http.request","kind":"server","trace_id":"e44350206f64e167ace04e3ad69f6fe2","span_id":"0577015e43cb43c9","parent_span_id":"976c6508df67afcc","status":"ok","duration_ms":0,"attributes":{"http.request.method":"GET","http.response.status_code":"404","http.route":"/api/v1/compliance/:resource"}}
=== RUN   TestComplianceAPIProductionComposition/unregistered
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"bb4a998164172f46fdae3765d8eddbba","span_id":"1fd535f821bf8f68","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"5db1d4092b4eedcd3483c0e051f0c081","span_id":"61259d2821dee827","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"4475ec8b7f774b0b2bb5a848f7f7bf2f","span_id":"d0a5c26934ed7fc0","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"76c69c3cbae80a146a2366f3f5bf99d5","span_id":"45407d4082e24c72","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"56559e7a99cb0f15f14b72428f3f1d6b","span_id":"5a695c90792c334d","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"dab212ba2e1ba0bc588648c6e2f1d8ed","span_id":"b06b101ed2438261","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"03b7c1af732b82346f23f7c300e5b119","span_id":"1a0e3ab6250ac225","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"d354d87cc41b1ebae7adf47437a1841c","span_id":"6d6699a185259127","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"b3e31a0a3d0f63c1727305a0a57fab9d","span_id":"df5e2f00ef0f60e5","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.schema","kind":"client","trace_id":"a1c69c5b9f7464cfbd7bbd7f6bf35374","span_id":"e15f938b71819563","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"schema","db.system":"postgresql"}}
{"event":"correlation_span","name":"repository.query","kind":"client","trace_id":"e569c0fdfb861b3571c9b2a6934bc3ce","span_id":"24fc4c7569d42dac","status":"ok","duration_ms":0,"attributes":{"db.operation.name":"query","db.system":"postgresql"}}
--- PASS: TestComplianceAPIProductionComposition (0.12s)
    --- PASS: TestComplianceAPIProductionComposition/installed (0.06s)
    --- PASS: TestComplianceAPIProductionComposition/disabled (0.02s)
    --- PASS: TestComplianceAPIProductionComposition/unregistered (0.04s)
=== RUN   TestComplianceAPIConfiguration
--- PASS: TestComplianceAPIConfiguration (0.00s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/agentsec-api	3.116s
=== RUN   TestComplianceFormatterCapturedAttribution
--- PASS: TestComplianceFormatterCapturedAttribution (0.00s)
=== RUN   TestComplianceFormatterFrozenContext
--- PASS: TestComplianceFormatterFrozenContext (0.00s)
=== RUN   TestComplianceExportFormatsRetainEvidenceAttribution
--- PASS: TestComplianceExportFormatsRetainEvidenceAttribution (0.00s)
=== RUN   TestComplianceExportCSVNeutralizesFormulaFields
--- PASS: TestComplianceExportCSVNeutralizesFormulaFields (0.00s)
=== RUN   TestComplianceExportDetailedReportPersistsBeyondDisclaimerSize
--- PASS: TestComplianceExportDetailedReportPersistsBeyondDisclaimerSize (0.01s)
=== RUN   TestComplianceExportRefusesOversizedCombinedPackage
--- PASS: TestComplianceExportRefusesOversizedCombinedPackage (0.38s)
=== RUN   TestComplianceExportWriterPreservesQuotedLabelsAndRejectsForgedReport
--- PASS: TestComplianceExportWriterPreservesQuotedLabelsAndRejectsForgedReport (0.00s)
=== RUN   TestComplianceExportRejectsUnboundedNestedInput
=== RUN   TestComplianceExportRejectsUnboundedNestedInput/framework
=== RUN   TestComplianceExportRejectsUnboundedNestedInput/records
=== RUN   TestComplianceExportRejectsUnboundedNestedInput/expected_ids
--- PASS: TestComplianceExportRejectsUnboundedNestedInput (0.00s)
    --- PASS: TestComplianceExportRejectsUnboundedNestedInput/framework (0.00s)
    --- PASS: TestComplianceExportRejectsUnboundedNestedInput/records (0.00s)
    --- PASS: TestComplianceExportRejectsUnboundedNestedInput/expected_ids (0.00s)
=== RUN   TestComplianceExportAcceptsVersionedArtifactStoreReceipt
--- PASS: TestComplianceExportAcceptsVersionedArtifactStoreReceipt (0.00s)
=== RUN   TestComplianceExportRejectsInvalidVersionAndChangedOwnership
=== RUN   TestComplianceExportRejectsInvalidVersionAndChangedOwnership/scope
=== RUN   TestComplianceExportRejectsInvalidVersionAndChangedOwnership/reference
=== RUN   TestComplianceExportRejectsInvalidVersionAndChangedOwnership/space
=== RUN   TestComplianceExportRejectsInvalidVersionAndChangedOwnership/newline
=== RUN   TestComplianceExportRejectsInvalidVersionAndChangedOwnership/nul
=== RUN   TestComplianceExportRejectsInvalidVersionAndChangedOwnership/oversize
--- PASS: TestComplianceExportRejectsInvalidVersionAndChangedOwnership (0.00s)
    --- PASS: TestComplianceExportRejectsInvalidVersionAndChangedOwnership/scope (0.00s)
    --- PASS: TestComplianceExportRejectsInvalidVersionAndChangedOwnership/reference (0.00s)
    --- PASS: TestComplianceExportRejectsInvalidVersionAndChangedOwnership/space (0.00s)
    --- PASS: TestComplianceExportRejectsInvalidVersionAndChangedOwnership/newline (0.00s)
    --- PASS: TestComplianceExportRejectsInvalidVersionAndChangedOwnership/nul (0.00s)
    --- PASS: TestComplianceExportRejectsInvalidVersionAndChangedOwnership/oversize (0.00s)
=== RUN   TestComplianceExportPersistsExactArtifact
--- PASS: TestComplianceExportPersistsExactArtifact (0.00s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/sessioncontrol	3.658s
=== RUN   TestExportStoreRejectsDriverProfileAndScopeSubstitution
=== RUN   TestExportStoreRejectsDriverProfileAndScopeSubstitution/legacy_profile
=== RUN   TestExportStoreRejectsDriverProfileAndScopeSubstitution/foreign_scope
=== RUN   TestExportStoreRejectsDriverProfileAndScopeSubstitution/foreign_reference
=== RUN   TestExportStoreRejectsDriverProfileAndScopeSubstitution/changed_bytes
--- PASS: TestExportStoreRejectsDriverProfileAndScopeSubstitution (0.00s)
    --- PASS: TestExportStoreRejectsDriverProfileAndScopeSubstitution/legacy_profile (0.00s)
    --- PASS: TestExportStoreRejectsDriverProfileAndScopeSubstitution/foreign_scope (0.00s)
    --- PASS: TestExportStoreRejectsDriverProfileAndScopeSubstitution/foreign_reference (0.00s)
    --- PASS: TestExportStoreRejectsDriverProfileAndScopeSubstitution/changed_bytes (0.00s)
=== RUN   TestExportStoreEnforcesRequestBoundsBeforeDriverIO
--- PASS: TestExportStoreEnforcesRequestBoundsBeforeDriverIO (0.00s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore	2.989s
=== RUN   TestExportStoreSDKUsesScopedExportPrefix
--- PASS: TestExportStoreSDKUsesScopedExportPrefix (0.00s)
=== RUN   TestExportStoreSDKCancellationAfterSavedPutRemainsRecoverable
--- PASS: TestExportStoreSDKCancellationAfterSavedPutRemainsRecoverable (0.00s)
=== RUN   TestExportProfilesRejectMixedConstructionBeforeProviderIO
=== RUN   TestExportProfilesRejectMixedConstructionBeforeProviderIO/export_store_legacy_driver
=== RUN   TestExportProfilesRejectMixedConstructionBeforeProviderIO/legacy_store_export_driver
--- PASS: TestExportProfilesRejectMixedConstructionBeforeProviderIO (0.00s)
    --- PASS: TestExportProfilesRejectMixedConstructionBeforeProviderIO/export_store_legacy_driver (0.00s)
    --- PASS: TestExportProfilesRejectMixedConstructionBeforeProviderIO/legacy_store_export_driver (0.00s)
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/legacy_prefix
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/traversal
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/encoded_traversal
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_organization
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_workspace
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_environment
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_reference
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/missing_scope
=== RUN   TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/scope_ID_reused_as_reference
--- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO (0.01s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/legacy_prefix (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/traversal (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/encoded_traversal (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_organization (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_workspace (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_environment (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/foreign_reference (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/missing_scope (0.00s)
    --- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO/scope_ID_reused_as_reference (0.00s)
=== RUN   TestExportReadRefusesCorruptedProviderAuthority
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/organization
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/workspace
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/environment
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/reference
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/digest_metadata
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/missing_checksum
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/wrong_checksum
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/wrong_KMS
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/wrong_version
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/changed_body
=== RUN   TestExportReadRefusesCorruptedProviderAuthority/oversized_read
--- PASS: TestExportReadRefusesCorruptedProviderAuthority (0.01s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/organization (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/workspace (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/environment (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/reference (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/digest_metadata (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/missing_checksum (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/wrong_checksum (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/wrong_KMS (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/wrong_version (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/changed_body (0.00s)
    --- PASS: TestExportReadRefusesCorruptedProviderAuthority/oversized_read (0.00s)
=== RUN   TestExportDriverKeepsImmutableReplayLimitsAndCancellation
--- PASS: TestExportDriverKeepsImmutableReplayLimitsAndCancellation (0.00s)
=== RUN   TestExportCleanupSDKExactVersionAbsence
=== RUN   TestExportCleanupSDKExactVersionAbsence/deleted
=== RUN   TestExportCleanupSDKExactVersionAbsence/lost_delete
=== RUN   TestExportCleanupSDKExactVersionAbsence/ambiguous404
=== RUN   TestExportCleanupSDKExactVersionAbsence/denied
--- PASS: TestExportCleanupSDKExactVersionAbsence (0.00s)
    --- PASS: TestExportCleanupSDKExactVersionAbsence/deleted (0.00s)
    --- PASS: TestExportCleanupSDKExactVersionAbsence/lost_delete (0.00s)
    --- PASS: TestExportCleanupSDKExactVersionAbsence/ambiguous404 (0.00s)
    --- PASS: TestExportCleanupSDKExactVersionAbsence/denied (0.00s)
=== RUN   TestExportReadOnlyReconciliation
--- PASS: TestExportReadOnlyReconciliation (0.00s)
=== RUN   TestExportReadOnlyReconciliationSDKFaults
=== RUN   TestExportReadOnlyReconciliationSDKFaults/wrong_version
=== RUN   TestExportReadOnlyReconciliationSDKFaults/wrong_kms
=== RUN   TestExportReadOnlyReconciliationSDKFaults/wrong_checksum
=== RUN   TestExportReadOnlyReconciliationSDKFaults/wrong_scope
=== RUN   TestExportReadOnlyReconciliationSDKFaults/owner_denied
=== RUN   TestExportReadOnlyReconciliationSDKFaults/missing
=== RUN   TestExportReadOnlyReconciliationSDKFaults/timeout
=== RUN   TestExportReadOnlyReconciliationSDKFaults/different_bytes
--- PASS: TestExportReadOnlyReconciliationSDKFaults (0.04s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/wrong_version (0.00s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/wrong_kms (0.00s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/wrong_checksum (0.00s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/wrong_scope (0.00s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/owner_denied (0.00s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/missing (0.00s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/timeout (0.02s)
    --- PASS: TestExportReadOnlyReconciliationSDKFaults/different_bytes (0.00s)
=== RUN   TestExportCleanupRequiresVerifiedExactVersionAbsence
=== RUN   TestExportCleanupRequiresVerifiedExactVersionAbsence/deleted
=== RUN   TestExportCleanupRequiresVerifiedExactVersionAbsence/denied
=== RUN   TestExportCleanupRequiresVerifiedExactVersionAbsence/locked
=== RUN   TestExportCleanupRequiresVerifiedExactVersionAbsence/missing_version
--- PASS: TestExportCleanupRequiresVerifiedExactVersionAbsence (0.00s)
    --- PASS: TestExportCleanupRequiresVerifiedExactVersionAbsence/deleted (0.00s)
    --- PASS: TestExportCleanupRequiresVerifiedExactVersionAbsence/denied (0.00s)
    --- PASS: TestExportCleanupRequiresVerifiedExactVersionAbsence/locked (0.00s)
    --- PASS: TestExportCleanupRequiresVerifiedExactVersionAbsence/missing_version (0.00s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver	2.300s
```

## task4web

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/vitest/vitest.mjs run apps/web/api/compliance-decoders.test.ts apps/web/api/compliance-download.test.ts apps/web/api/client.test.ts apps/web/api/administration-decoders.test.ts apps/web/api/audit-exports.test.ts
```

Exit: 0

Complete captured output:

```text

 RUN  v4.1.11 /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917


 Test Files  5 passed (5)
      Tests  48 passed (48)
   Start at  17:45:18
   Duration  1.50s (transform 333ms, setup 1.14s, import 293ms, tests 59ms, environment 4.73s)

```

## task4contract

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs openapi/identity-admin.test.mjs scripts/check-ui-api-coverage.test.mjs
```

Exit: 0

Complete captured output:

```text
TAP version 13
# Subtest: pins the official generator/runtime and wires exact local-only scripts into verify
ok 1 - pins the official generator/runtime and wires exact local-only scripts into verify
  ---
  duration_ms: 13.199541
  type: 'test'
  ...
# Subtest: reproduces the committed bytes and rejects changed or missing output without rewriting it
ok 2 - reproduces the committed bytes and rejects changed or missing output without rewriting it
  ---
  duration_ms: 2347.383542
  type: 'test'
  ...
# Subtest: exports the mounted Security Agent, red team, Attack Lab, and policy evidence APIs
ok 3 - exports the mounted Security Agent, red team, Attack Lab, and policy evidence APIs
  ---
  duration_ms: 28.248292
  type: 'test'
  ...
# Subtest: audit page filters validate exact values without changing browser authority
ok 4 - audit page filters validate exact values without changing browser authority
  ---
  duration_ms: 41.402916
  type: 'test'
  ...
# Subtest: retained identity actions preserve their exact public and export schema values
ok 5 - retained identity actions preserve their exact public and export schema values
  ---
  duration_ms: 68.026667
  type: 'test'
  ...
# Subtest: audit export descriptors model durable async state without partial ready metadata
ok 6 - audit export descriptors model durable async state without partial ready metadata
  ---
  duration_ms: 20.255542
  type: 'test'
  ...
# Subtest: audit export reads separate pending, failed, ready-empty and immutable chunk contents
ok 7 - audit export reads separate pending, failed, ready-empty and immutable chunk contents
  ---
  duration_ms: 34.437125
  type: 'test'
  ...
# Subtest: runtime session search publishes closed selectors and checkpoint freshness
ok 8 - runtime session search publishes closed selectors and checkpoint freshness
  ---
  duration_ms: 6.185167
  type: 'test'
  ...
# Subtest: runtime session reads preserve operation IDs and console-only revocation
ok 9 - runtime session reads preserve operation IDs and console-only revocation
  ---
  duration_ms: 7.004958
  type: 'test'
  ...
# Subtest: publishes the identity administration operations at their honest UI lifecycle
ok 10 - publishes the identity administration operations at their honest UI lifecycle
  ---
  duration_ms: 8.812291
  type: 'test'
  ...
# Subtest: uses strict product schemas and the shared stable error response
ok 11 - uses strict product schemas and the shared stable error response
  ---
  duration_ms: 5.876792
  type: 'test'
  ...
# Subtest: M1-23 strict OpenAPI root
    # Subtest: defines the exact self-contained OpenAPI, auth, pagination, and error boundary
    ok 1 - defines the exact self-contained OpenAPI, auth, pagination, and error boundary
      ---
      duration_ms: 8.819125
      type: 'test'
      ...
    # Subtest: uses only the exact pinned local linter command and justified rule exception
    ok 2 - uses only the exact pinned local linter command and justified rule exception
      ---
      duration_ms: 0.108166
      type: 'test'
      ...
    # Subtest: rejects duplicate YAML keys before semantic validation
    ok 3 - rejects duplicate YAML keys before semantic validation
      ---
      duration_ms: 13.322375
      type: 'test'
      ...
    # Subtest: accepts only canonical unpadded base64url cursor encodings
    ok 4 - accepts only canonical unpadded base64url cursor encodings
      ---
      duration_ms: 0.162417
      type: 'test'
      ...
    # Subtest: rejects every product-error control-character class
    ok 5 - rejects every product-error control-character class
      ---
      duration_ms: 0.123792
      type: 'test'
      ...
    # Subtest: rejects hostile root, authentication, pagination, and error mutations
    ok 6 - rejects hostile root, authentication, pagination, and error mutations
      ---
      duration_ms: 76.412334
      type: 'test'
      ...
    1..6
ok 12 - M1-23 strict OpenAPI root
  ---
  duration_ms: 132.947666
  type: 'suite'
  ...
# Subtest: production workflow concurrency contract
    # Subtest: publishes the exact replay-safe sensor management surface
    ok 1 - publishes the exact replay-safe sensor management surface
      ---
      duration_ms: 0.34025
      type: 'test'
      ...
    # Subtest: publishes the three retained DELETE operations with no request body
    ok 2 - publishes the three retained DELETE operations with no request body
      ---
      duration_ms: 0.174375
      type: 'test'
      ...
    # Subtest: reports asynchronous integration revocation without claiming early deletion
    ok 3 - reports asynchronous integration revocation without claiming early deletion
      ---
      duration_ms: 0.192708
      type: 'test'
      ...
    # Subtest: separates server-assigned security-agent identity from create input
    ok 4 - separates server-assigned security-agent identity from create input
      ---
      duration_ms: 0.058667
      type: 'test'
      ...
    # Subtest: types idempotency, versions, fresh auth, and durable mutation receipts
    ok 5 - types idempotency, versions, fresh auth, and durable mutation receipts
      ---
      duration_ms: 0.248041
      type: 'test'
      ...
    # Subtest: publishes bounded browser-only receipt reconciliation and acknowledgement
    ok 6 - publishes bounded browser-only receipt reconciliation and acknowledgement
      ---
      duration_ms: 0.100125
      type: 'test'
      ...
    # Subtest: requires the browser scope precondition on every scoped session operation
    ok 7 - requires the browser scope precondition on every scoped session operation
      ---
      duration_ms: 0.044708
      type: 'test'
      ...
    # Subtest: publishes exact receipt intent and authoritative result object shapes
    ok 8 - publishes exact receipt intent and authoritative result object shapes
      ---
      duration_ms: 0.093458
      type: 'test'
      ...
    # Subtest: publishes the strict Task 4 sync, schedule, and freshness contract without internal execution authority
    ok 9 - publishes the strict Task 4 sync, schedule, and freshness contract without internal execution authority
      ---
      duration_ms: 0.233958
      type: 'test'
      ...
    # Subtest: publishes bounded browser-only typed activity relations with explicit coverage
    ok 10 - publishes bounded browser-only typed activity relations with explicit coverage
      ---
      duration_ms: 0.071583
      type: 'test'
      ...
    # Subtest: publishes the mounted Security Agent activation, simulation, manual run, and approval surface without read overclaims
    ok 11 - publishes the mounted Security Agent activation, simulation, manual run, and approval surface without read overclaims
      ---
      duration_ms: 0.992541
      type: 'test'
      ...
    # Subtest: publishes strict browser-only integration authorization and OAuth callback contracts
    ok 12 - publishes strict browser-only integration authorization and OAuth callback contracts
      ---
      duration_ms: 0.164583
      type: 'test'
      ...
    # Subtest: publishes strict fresh browser-only reference authorization
    ok 13 - publishes strict fresh browser-only reference authorization
      ---
      duration_ms: 0.05325
      type: 'test'
      ...
    # Subtest: binds risk reads and mutations to strict pagination, security, and recovery contracts
    ok 14 - binds risk reads and mutations to strict pagination, security, and recovery contracts
      ---
      duration_ms: 0.128875
      type: 'test'
      ...
    # Subtest: bounds Security Agent definition pagination with the shared opaque cursor contract
    ok 15 - bounds Security Agent definition pagination with the shared opaque cursor contract
      ---
      duration_ms: 0.031458
      type: 'test'
      ...
    # Subtest: bounds policy and integration pagination with the same exact cursor contract
    ok 16 - bounds policy and integration pagination with the same exact cursor contract
      ---
      duration_ms: 0.042
      type: 'test'
      ...
    # Subtest: publishes typed discovery inventory pages, details, evidence, and freshness
    ok 17 - publishes typed discovery inventory pages, details, evidence, and freshness
      ---
      duration_ms: 0.076459
      type: 'test'
      ...
    1..17
ok 13 - production workflow concurrency contract
  ---
  duration_ms: 3.367459
  type: 'suite'
  ...
# Subtest: current API and planned map passes honestly
ok 14 - current API and planned map passes honestly
  ---
  duration_ms: 30.980209
  type: 'test'
  ...
# Subtest: all current public operations resolve and deliberate removal fails
ok 15 - all current public operations resolve and deliberate removal fails
  ---
  duration_ms: 6.842792
  type: 'test'
  ...
# Subtest: unmapped public operations fail while unmapped internal operations pass
ok 16 - unmapped public operations fail while unmapped internal operations pass
  ---
  duration_ms: 2.695709
  type: 'test'
  ...
# Subtest: planned, available, and internal lifecycle mismatches fail
ok 17 - planned, available, and internal lifecycle mismatches fail
  ---
  duration_ms: 5.266458
  type: 'test'
  ...
# Subtest: API-available operations require OpenAPI but do not claim a wired UI
ok 18 - API-available operations require OpenAPI but do not claim a wired UI
  ---
  duration_ms: 3.276042
  type: 'test'
  ...
# Subtest: OpenAPI operation extraction rejects missing, duplicate, and unclassified operations
ok 19 - OpenAPI operation extraction rejects missing, duplicate, and unclassified operations
  ---
  duration_ms: 0.226375
  type: 'test'
  ...
# Subtest: strict YAML parsing rejects representation and map-schema ambiguity
ok 20 - strict YAML parsing rejects representation and map-schema ambiguity
  ---
  duration_ms: 18.630542
  type: 'test'
  ...
# Subtest: fixed file boundary accepts regular UTF-8 and rejects symlink, oversize, and invalid UTF-8
ok 21 - fixed file boundary accepts regular UTF-8 and rejects symlink, oversize, and invalid UTF-8
  ---
  duration_ms: 18.225542
  type: 'test'
  ...
# Subtest: CLI emits only fixed success or rejection lines
ok 22 - CLI emits only fixed success or rejection lines
  ---
  duration_ms: 8.385042
  type: 'test'
  ...
# Subtest: package command is wired into root verification
ok 23 - package command is wired into root verification
  ---
  duration_ms: 1.358625
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
# duration_ms 2436.235625
```

## task4typecheck

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/typescript/bin/tsc --noEmit
```

Exit: 0

Complete captured output:

```text
(no output)
```

## task4lint

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/eslint/bin/eslint.js apps/web/api/client.ts apps/web/api/administration-decoders.ts apps/web/api/compliance-decoders.ts apps/web/api/compliance-decoders.test.ts apps/web/api/compliance-download.test.ts
```

Exit: 0

Complete captured output:

```text
(no output)
```

## task4openapilint

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
env REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/@redocly/cli/bin/cli.js lint openapi/openapi.yaml openapi/internal-health.yaml --config redocly.yaml
```

Exit: 0

Complete captured output:

```text
validating openapi/openapi.yaml...
openapi/openapi.yaml: validated in 105ms

validating openapi/internal-health.yaml...
openapi/internal-health.yaml: validated in 7ms

Woohoo! Your API descriptions are valid. 🎉

```

## task4generatedcheck

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/openapi-typescript/bin/cli.js openapi/openapi.yaml --output apps/web/api/generated.ts --alphabetize --export-type --immutable --root-types --root-types-no-schema-prefix --check
```

Exit: 0

Complete captured output:

```text
✨ openapi-typescript 7.13.0
```

## task4patchcheck

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

Command:

```sh
git apply --check --reverse .superpowers/sdd/2026-09-18-compliance-production-plan/task-4-scoped.patch
```

Exit: 0

Complete captured output:

```text
(no output)
```
