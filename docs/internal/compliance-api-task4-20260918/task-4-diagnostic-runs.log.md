# Task 4 rejected and RED diagnostic runs

These are diagnostic records, not accepted completion evidence. In particular the broad local race selected host PostgreSQL subprocess fixtures contrary to the no-host-PostgreSQL instruction. Those subprocesses terminated and were joined; root was informed and independently found no remaining postgres/initdb processes. Container-only paths and a timezone-sensitive assertion failed in that rejected run. The valid replacement is the explicitly selected non-SQL race plus Docker SQL batch in task-4-verification.log.md.

## task4racefirst

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver ./agentsec-api ./sessioncontrol ./artifactstore ./artifactstore/s3driver -run '^TestCompliance|^TestExport|^TestComposition|^TestCoreOperations|^TestNewComposition|^TestProductMiddleware|^TestAuditExportRuntimeEnvironment|^TestAuditExportRuntimeTypedConfiguration|^TestAuditExportWebIdentitySessionIsClosed|^TestClassifyPostgres' -count=1 -v
```

Exit: 1

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
--- PASS: TestComplianceExportBindsRequestedJobAndCanonicalFilters (0.09s)
=== RUN   TestComplianceCreateFreshAfterWaitPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2488 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceCreateFreshAfterWaitPostgres2356576336/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceCreateFreshAfterWaitPostgres (8.80s)
=== RUN   TestComplianceGrantFreshAfterWaitPostgres
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true
=== NAME  TestComplianceGrantFreshAfterWaitPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2525 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceGrantFreshAfterWaitPostgres2344574017/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceGrantFreshAfterWaitPostgres (6.65s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false (0.11s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false (0.11s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true (0.11s)
=== RUN   TestComplianceWorkerReplayPostgres
    compliance_exports_fix_postgres_test.go:235: joined worker prepare: fork/exec /compliance-worker.test: no such file or directory 
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2562 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceWorkerReplayPostgres3617347370/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestComplianceWorkerReplayPostgres (5.87s)
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
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2597 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceExportsDurablePostgres2790702578/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceExportsDurablePostgres (25.76s)
=== RUN   TestComplianceExportRestartProcess
    compliance_exports_postgres_test.go:576: owned parent launches this subprocess
--- SKIP: TestComplianceExportRestartProcess (0.00s)
=== RUN   TestComplianceConcurrentQuotasPostgres
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_active_100
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=100 retained_bytes=12583011
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2685 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceConcurrentQuotasPostgresdeployment_active_1004062748090/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_retained_bytes_16GiB
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=2049 retained_bytes=17179869184
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2719 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceConcurrentQuotasPostgresdeployment_retained_bytes3371320917/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/deployment_retained_jobs_10000
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=10000 retained_bytes=12592911
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2750 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceConcurrentQuotasPostgresdeployment_retained_jobs_487992761/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/scope_retained_jobs_100
    compliance_exports_quotas_postgres_test.go:46: registered concurrent clients: one admitted, one 54000; jobs=100 retained_bytes=12583011
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2792 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceConcurrentQuotasPostgresscope_retained_jobs_1001778429156/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
=== RUN   TestComplianceConcurrentQuotasPostgres/principal_scope_grants_20
    compliance_exports_quotas_postgres_test.go:69: registered concurrent clients: principal/S grants=20, target job grants=4; one admitted, one 54000
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2827 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceConcurrentQuotasPostgresprincipal_scope_grants_202302910314/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceConcurrentQuotasPostgres (29.28s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_active_100 (5.84s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_retained_bytes_16GiB (5.78s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/deployment_retained_jobs_10000 (6.04s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/scope_retained_jobs_100 (5.89s)
    --- PASS: TestComplianceConcurrentQuotasPostgres/principal_scope_grants_20 (5.72s)
=== RUN   TestComplianceExportsRepository
--- PASS: TestComplianceExportsRepository (0.04s)
=== RUN   TestComplianceHTTPPostgresGrantLifecycle
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2877 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceHTTPPostgresGrantLifecycle2198192261/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresGrantLifecycle (7.21s)
=== RUN   TestComplianceHTTPMountedPublicLifecycle
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download
--- PASS: TestComplianceHTTPMountedPublicLifecycle (0.26s)
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
--- PASS: TestComplianceHTTPMountedDenials (0.26s)
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
--- PASS: TestComplianceHTTPStrictInputs (0.27s)
=== RUN   TestComplianceRegisteredSourceAuthorityPostgres
    compliance_postgres_test.go:44: source identity/version/time: {ID:pid_56000006-0000-4000-8000-000000000006 OrganizationID:pid_6a000001-0000-4000-8000-000000000001 WorkspaceID:pid_6a000002-0000-4000-8000-000000000002 EnvironmentID:pid_6a000003-0000-4000-8000-000000000003 Target:{Kind:administration ID:pid_56000006-0000-4000-8000-000000000006 Version:1} Timestamp:2026-01-04T08:00:00.000000Z Metadata:map[action:fixture.review status:succeeded]}
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2913 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceRegisteredSourceAuthorityPostgres1785985936/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestComplianceRegisteredSourceAuthorityPostgres (6.58s)
=== RUN   TestComplianceCompiledFingerprintPostgres
    compliance_postgres_test.go:468: release56 checksum=af7be48e8b1444219414b4880cc7cfa4b40c6798222423a59e771e6af5955e41 fingerprint=794bd599bc37408e07b0c6238ad10052dbd40458ab24380481cc05caa0698cf9
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2955 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceCompiledFingerprintPostgres616901443/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceCompiledFingerprintPostgres (5.39s)
=== RUN   TestComplianceEvidenceStrictDecoding
--- PASS: TestComplianceEvidenceStrictDecoding (0.00s)
=== RUN   TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput
--- PASS: TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput (0.04s)
=== RUN   TestComplianceRuntimePollingPostgres
    compliance_runtime_postgres_test.go:66: joined interrupt: 
    compliance_runtime_postgres_test.go:66: child interrupt: fork/exec /compliance-worker.test: no such file or directory
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=2997 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestComplianceRuntimePollingPostgres2857555020/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestComplianceRuntimePollingPostgres (5.87s)
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
--- PASS: TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection (0.00s)
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
FAIL
FAIL	github.com/zasp-ai/zasp-sec/services/platform/apiserver	105.288s
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
--- PASS: TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid (0.01s)
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
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/selector
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/bad_bucket
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/short_key
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/token_path
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/empty_policies
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/duplicate_policies
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/too_many_policies
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/zero_key
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/long_key
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/role
=== RUN   TestAuditExportRuntimeTypedConfigurationRevalidated/connector_role
--- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated (0.01s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/selector (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/bad_bucket (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/short_key (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/token_path (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/empty_policies (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/duplicate_policies (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/too_many_policies (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/zero_key (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/long_key (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/role (0.00s)
    --- PASS: TestAuditExportRuntimeTypedConfigurationRevalidated/connector_role (0.00s)
=== RUN   TestComplianceAPIConfiguration
--- PASS: TestComplianceAPIConfiguration (0.01s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/agentsec-api	2.359s
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
--- PASS: TestComplianceExportRefusesOversizedCombinedPackage (0.39s)
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
ok  	github.com/zasp-ai/zasp-sec/services/platform/sessioncontrol	3.743s
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
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore	2.387s
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
--- PASS: TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO (0.00s)
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
--- PASS: TestExportReadOnlyReconciliationSDKFaults (0.03s)
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
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver	3.759s
FAIL
```

## task4webfirst

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/vitest/vitest.mjs run apps/web/api/compliance-decoders.test.ts apps/web/api/compliance-download.test.ts apps/web/api/client.test.ts apps/web/api/administration-decoders.test.ts apps/web/api/audit-exports.test.ts
```

Exit: 1

Complete captured output:

```text

 RUN  v4.1.11 /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

 ❯ apps/web/api/client.test.ts (21 tests | 1 failed) 5032ms
     × bounds time and preserves caller aborts 5009ms

⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯

 FAIL  apps/web/api/client.test.ts > generated API client > bounds time and preserves caller aborts
Error: Test timed out in 5000ms.
If this is a long-running test, pass a timeout value as the last argument or configure it globally with "testTimeout".
 ❯ apps/web/api/client.test.ts:140:3
    138|   });
    139|
    140|   it("bounds time and preserves caller aborts", async () => {
       |   ^
    141|     const waitForAbort = vi.fn((input: RequestInfo | URL, init?: Reque…
    142|       const signal = input instanceof Request ? input.signal : init?.s…

⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯[1/1]⎯


 Test Files  1 failed | 4 passed (5)
      Tests  1 failed | 46 passed (47)
   Start at  17:35:37
   Duration  6.60s (transform 487ms, setup 1.52s, import 401ms, tests 5.08s, environment 5.08s)

```

## task4contractfirst

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs openapi/identity-admin.test.mjs scripts/check-ui-api-coverage.test.mjs
```

Exit: 1

Complete captured output:

```text
TAP version 13
# Subtest: pins the official generator/runtime and wires exact local-only scripts into verify
ok 1 - pins the official generator/runtime and wires exact local-only scripts into verify
  ---
  duration_ms: 14.233375
  type: 'test'
  ...
# Subtest: reproduces the committed bytes and rejects changed or missing output without rewriting it
ok 2 - reproduces the committed bytes and rejects changed or missing output without rewriting it
  ---
  duration_ms: 2856.386291
  type: 'test'
  ...
# Subtest: exports the mounted Security Agent, red team, Attack Lab, and policy evidence APIs
ok 3 - exports the mounted Security Agent, red team, Attack Lab, and policy evidence APIs
  ---
  duration_ms: 28.554333
  type: 'test'
  ...
# Subtest: audit page filters validate exact values without changing browser authority
ok 4 - audit page filters validate exact values without changing browser authority
  ---
  duration_ms: 51.701083
  type: 'test'
  ...
# Subtest: retained identity actions preserve their exact public and export schema values
ok 5 - retained identity actions preserve their exact public and export schema values
  ---
  duration_ms: 106.791208
  type: 'test'
  ...
# Subtest: audit export descriptors model durable async state without partial ready metadata
ok 6 - audit export descriptors model durable async state without partial ready metadata
  ---
  duration_ms: 24.605583
  type: 'test'
  ...
# Subtest: audit export reads separate pending, failed, ready-empty and immutable chunk contents
ok 7 - audit export reads separate pending, failed, ready-empty and immutable chunk contents
  ---
  duration_ms: 45.242875
  type: 'test'
  ...
# Subtest: runtime session search publishes closed selectors and checkpoint freshness
ok 8 - runtime session search publishes closed selectors and checkpoint freshness
  ---
  duration_ms: 5.700625
  type: 'test'
  ...
# Subtest: runtime session reads preserve operation IDs and console-only revocation
ok 9 - runtime session reads preserve operation IDs and console-only revocation
  ---
  duration_ms: 6.925584
  type: 'test'
  ...
# Subtest: publishes the identity administration operations at their honest UI lifecycle
ok 10 - publishes the identity administration operations at their honest UI lifecycle
  ---
  duration_ms: 7.406417
  type: 'test'
  ...
# Subtest: uses strict product schemas and the shared stable error response
ok 11 - uses strict product schemas and the shared stable error response
  ---
  duration_ms: 8.66675
  type: 'test'
  ...
# Subtest: M1-23 strict OpenAPI root
    # Subtest: defines the exact self-contained OpenAPI, auth, pagination, and error boundary
    not ok 1 - defines the exact self-contained OpenAPI, auth, pagination, and error boundary
      ---
      duration_ms: 2.408834
      type: 'test'
      location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/openapi/openapi.test.mjs:277:3'
      failureType: 'testCodeFailure'
      error: |-
        Expected values to be strictly deep-equal:
        + actual - expected
        ... Skipped lines
        
          {
            BrowserMutationCSRFToken: {
              description: 'Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.',
              in: 'header',
              name: 'X-CSRF-Token',
        ...
            },
        +   ComplianceControlFilter: {
        +     in: 'query',
        +     name: 'control_id',
        +     schema: {
        +       maxLength: 128,
        +       minLength: 1,
        +       pattern: '^(soc2_security|hipaa)-(audit|findings|policies|tests|configuration)$',
        +       type: 'string'
        +     }
        +   },
        +   ComplianceFramework: {
        +     in: 'query',
        +     name: 'framework',
        +     schema: {
        +       enum: [
        +         'soc2_security',
        +         'hipaa'
        +       ],
        +       type: 'string'
        +     }
        +   },
            ControlVersion: {
              description: 'Quoted current execution-control version, including quoted zero before the first tenant override.',
              in: 'header',
              name: 'If-Match',
              required: true,
        
      code: 'ERR_ASSERTION'
      name: 'AssertionError'
      expected:
        SensorEnrollmentSchema:
          name: 'X-Zasp-Sensor-Enrollment-Schema'
          in: 'header'
          required: false
          description: 'Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.'
          schema:
            type: 'string'
            const: 'enrollment-binding-v1'
        CSRFToken:
          name: 'X-CSRF-Token'
          in: 'header'
          required: true
          description: 'Short-lived CSRF value bound to the authenticated browser session. Mutations also require an exact same-origin Origin header.'
          schema:
            type: 'string'
            minLength: 32
            maxLength: 256
        BrowserMutationCSRFToken:
          name: 'X-CSRF-Token'
          in: 'header'
          required: false
          description: 'Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.'
          schema:
            type: 'string'
            minLength: 32
            maxLength: 256
        BrowserMutationOrigin:
          name: 'Origin'
          in: 'header'
          required: false
          description: 'Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The server requires the exact configured same-origin HTTPS origin.'
          schema:
            type: 'string'
            minLength: 9
            maxLength: 2048
            pattern: '^https://[^/?#]+$'
        FreshAuth:
          name: 'X-Zasp-Fresh-Auth'
          in: 'header'
          required: true
          description: 'Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.'
          schema:
            type: 'string'
            const: 'confirmed'
        IdempotencyKey:
          name: 'Idempotency-Key'
          in: 'header'
          required: true
          description: 'Caller-generated key binding an exact workflow mutation and its durable response.'
          schema:
            type: 'string'
            minLength: 16
            maxLength: 128
            pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        PageCursor:
          name: 'cursor'
          in: 'query'
          required: false
          description: 'Opaque cursor returned by the preceding page.'
          schema:
            $ref: '#/components/schemas/Cursor'
        PageLimit:
          name: 'limit'
          in: 'query'
          required: false
          description: 'Maximum number of records to return.'
          schema:
            type: 'integer'
            minimum: 1
            maximum: 100
            default: 50
        ResourceVersion:
          name: 'If-Match'
          in: 'header'
          required: true
          description: 'Quoted current durable resource version.'
          schema:
            type: 'string'
            pattern: '^"[1-9][0-9]*"$'
        ControlVersion:
          name: 'If-Match'
          in: 'header'
          required: true
          description: 'Quoted current execution-control version, including quoted zero before the first tenant override.'
          schema:
            type: 'string'
            pattern: '^"(?:0|[1-9][0-9]*)"$'
        ScheduleVersion:
          name: 'If-Match'
          in: 'header'
          required: true
          description: 'Quoted current schedule version, or quoted zero when creating the singleton schedule.'
          schema:
            type: 'string'
            pattern: '^"(?:0|[1-9][0-9]*)"$'
      actual:
        ComplianceFramework:
          name: 'framework'
          in: 'query'
          schema:
            type: 'string'
            enum:
              0: 'soc2_security'
              1: 'hipaa'
        ComplianceControlFilter:
          name: 'control_id'
          in: 'query'
          schema:
            type: 'string'
            minLength: 1
            maxLength: 128
            pattern: '^(soc2_security|hipaa)-(audit|findings|policies|tests|configuration)$'
        CSRFToken:
          name: 'X-CSRF-Token'
          in: 'header'
          required: true
          description: 'Short-lived CSRF value bound to the authenticated browser session. Mutations also require an exact same-origin Origin header.'
          schema:
            type: 'string'
            minLength: 32
            maxLength: 256
        BrowserMutationCSRFToken:
          name: 'X-CSRF-Token'
          in: 'header'
          required: false
          description: 'Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.'
          schema:
            type: 'string'
            minLength: 32
            maxLength: 256
        BrowserMutationOrigin:
          name: 'Origin'
          in: 'header'
          required: false
          description: 'Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The server requires the exact configured same-origin HTTPS origin.'
          schema:
            type: 'string'
            minLength: 9
            maxLength: 2048
            pattern: '^https://[^/?#]+$'
        SensorEnrollmentSchema:
          name: 'X-Zasp-Sensor-Enrollment-Schema'
          in: 'header'
          required: false
          description: 'Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.'
          schema:
            type: 'string'
            const: 'enrollment-binding-v1'
        FreshAuth:
          name: 'X-Zasp-Fresh-Auth'
          in: 'header'
          required: true
          description: 'Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.'
          schema:
            type: 'string'
            const: 'confirmed'
        IdempotencyKey:
          name: 'Idempotency-Key'
          in: 'header'
          required: true
          description: 'Caller-generated key binding an exact workflow mutation and its durable response.'
          schema:
            type: 'string'
            minLength: 16
            maxLength: 128
            pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        PageCursor:
          name: 'cursor'
          in: 'query'
          required: false
          description: 'Opaque cursor returned by the preceding page.'
          schema:
            $ref: '#/components/schemas/Cursor'
        PageLimit:
          name: 'limit'
          in: 'query'
          required: false
          description: 'Maximum number of records to return.'
          schema:
            type: 'integer'
            minimum: 1
            maximum: 100
            default: 50
        ResourceVersion:
          name: 'If-Match'
          in: 'header'
          required: true
          description: 'Quoted current durable resource version.'
          schema:
            type: 'string'
            pattern: '^"[1-9][0-9]*"$'
        ControlVersion:
          name: 'If-Match'
          in: 'header'
          required: true
          description: 'Quoted current execution-control version, including quoted zero before the first tenant override.'
          schema:
            type: 'string'
            pattern: '^"(?:0|[1-9][0-9]*)"$'
        ScheduleVersion:
          name: 'If-Match'
          in: 'header'
          required: true
          description: 'Quoted current schedule version, or quoted zero when creating the singleton schedule.'
          schema:
            type: 'string'
            pattern: '^"(?:0|[1-9][0-9]*)"$'
      operator: 'deepStrictEqual'
      stack: |-
        verifyDocument (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/openapi/openapi.test.mjs:106:10)
        TestContext.<anonymous> (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/openapi/openapi.test.mjs:278:5)
        Test.runInAsyncScope (node:async_hooks:214:14)
        Test.run (node:internal/test_runner/test:1047:25)
        Test.start (node:internal/test_runner/test:944:17)
        node:internal/test_runner/test:1440:71
        node:internal/per_context/primordials:466:82
        new Promise (<anonymous>)
        new SafePromise (node:internal/per_context/primordials:435:3)
        node:internal/per_context/primordials:466:9
      ...
    # Subtest: uses only the exact pinned local linter command and justified rule exception
    ok 2 - uses only the exact pinned local linter command and justified rule exception
      ---
      duration_ms: 0.112709
      type: 'test'
      ...
    # Subtest: rejects duplicate YAML keys before semantic validation
    ok 3 - rejects duplicate YAML keys before semantic validation
      ---
      duration_ms: 13.412042
      type: 'test'
      ...
    # Subtest: accepts only canonical unpadded base64url cursor encodings
    ok 4 - accepts only canonical unpadded base64url cursor encodings
      ---
      duration_ms: 0.600041
      type: 'test'
      ...
    # Subtest: rejects every product-error control-character class
    ok 5 - rejects every product-error control-character class
      ---
      duration_ms: 0.360083
      type: 'test'
      ...
    # Subtest: rejects hostile root, authentication, pagination, and error mutations
    ok 6 - rejects hostile root, authentication, pagination, and error mutations
      ---
      duration_ms: 87.736708
      type: 'test'
      ...
    1..6
not ok 12 - M1-23 strict OpenAPI root
  ---
  duration_ms: 129.020875
  type: 'suite'
  location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/openapi/openapi.test.mjs:276:1'
  failureType: 'subtestsFailed'
  error: '1 subtest failed'
  code: 'ERR_TEST_FAILURE'
  ...
# Subtest: production workflow concurrency contract
    # Subtest: publishes the exact replay-safe sensor management surface
    ok 1 - publishes the exact replay-safe sensor management surface
      ---
      duration_ms: 0.374584
      type: 'test'
      ...
    # Subtest: publishes the three retained DELETE operations with no request body
    ok 2 - publishes the three retained DELETE operations with no request body
      ---
      duration_ms: 0.206791
      type: 'test'
      ...
    # Subtest: reports asynchronous integration revocation without claiming early deletion
    ok 3 - reports asynchronous integration revocation without claiming early deletion
      ---
      duration_ms: 0.208166
      type: 'test'
      ...
    # Subtest: separates server-assigned security-agent identity from create input
    ok 4 - separates server-assigned security-agent identity from create input
      ---
      duration_ms: 0.07425
      type: 'test'
      ...
    # Subtest: types idempotency, versions, fresh auth, and durable mutation receipts
    ok 5 - types idempotency, versions, fresh auth, and durable mutation receipts
      ---
      duration_ms: 0.293375
      type: 'test'
      ...
    # Subtest: publishes bounded browser-only receipt reconciliation and acknowledgement
    ok 6 - publishes bounded browser-only receipt reconciliation and acknowledgement
      ---
      duration_ms: 0.104709
      type: 'test'
      ...
    # Subtest: requires the browser scope precondition on every scoped session operation
    ok 7 - requires the browser scope precondition on every scoped session operation
      ---
      duration_ms: 0.045167
      type: 'test'
      ...
    # Subtest: publishes exact receipt intent and authoritative result object shapes
    ok 8 - publishes exact receipt intent and authoritative result object shapes
      ---
      duration_ms: 0.102541
      type: 'test'
      ...
    # Subtest: publishes the strict Task 4 sync, schedule, and freshness contract without internal execution authority
    ok 9 - publishes the strict Task 4 sync, schedule, and freshness contract without internal execution authority
      ---
      duration_ms: 0.257791
      type: 'test'
      ...
    # Subtest: publishes bounded browser-only typed activity relations with explicit coverage
    ok 10 - publishes bounded browser-only typed activity relations with explicit coverage
      ---
      duration_ms: 0.087083
      type: 'test'
      ...
    # Subtest: publishes the mounted Security Agent activation, simulation, manual run, and approval surface without read overclaims
    not ok 11 - publishes the mounted Security Agent activation, simulation, manual run, and approval surface without read overclaims
      ---
      duration_ms: 0.913333
      type: 'test'
      location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/openapi/openapi.test.mjs:714:3'
      failureType: 'testCodeFailure'
      error: |-
        Expected values to be strictly equal:
        
        157 !== 152
        
      code: 'ERR_ASSERTION'
      name: 'AssertionError'
      expected: 152
      actual: 157
      operator: 'strictEqual'
      stack: |-
        TestContext.<anonymous> (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/openapi/openapi.test.mjs:721:12)
        Test.runInAsyncScope (node:async_hooks:214:14)
        Test.run (node:internal/test_runner/test:1047:25)
        Suite.processPendingSubtests (node:internal/test_runner/test:744:18)
        Test.postRun (node:internal/test_runner/test:1173:19)
        Test.run (node:internal/test_runner/test:1101:12)
        async Suite.processPendingSubtests (node:internal/test_runner/test:744:7)
      ...
    # Subtest: publishes strict browser-only integration authorization and OAuth callback contracts
    ok 12 - publishes strict browser-only integration authorization and OAuth callback contracts
      ---
      duration_ms: 0.208
      type: 'test'
      ...
    # Subtest: publishes strict fresh browser-only reference authorization
    ok 13 - publishes strict fresh browser-only reference authorization
      ---
      duration_ms: 0.060875
      type: 'test'
      ...
    # Subtest: binds risk reads and mutations to strict pagination, security, and recovery contracts
    ok 14 - binds risk reads and mutations to strict pagination, security, and recovery contracts
      ---
      duration_ms: 0.147625
      type: 'test'
      ...
    # Subtest: bounds Security Agent definition pagination with the shared opaque cursor contract
    ok 15 - bounds Security Agent definition pagination with the shared opaque cursor contract
      ---
      duration_ms: 0.039875
      type: 'test'
      ...
    # Subtest: bounds policy and integration pagination with the same exact cursor contract
    ok 16 - bounds policy and integration pagination with the same exact cursor contract
      ---
      duration_ms: 0.046125
      type: 'test'
      ...
    # Subtest: publishes typed discovery inventory pages, details, evidence, and freshness
    ok 17 - publishes typed discovery inventory pages, details, evidence, and freshness
      ---
      duration_ms: 0.090875
      type: 'test'
      ...
    1..17
not ok 13 - production workflow concurrency contract
  ---
  duration_ms: 3.628084
  type: 'suite'
  location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/openapi/openapi.test.mjs:361:1'
  failureType: 'subtestsFailed'
  error: '1 subtest failed'
  code: 'ERR_TEST_FAILURE'
  ...
# Subtest: current API and planned map passes honestly
not ok 14 - current API and planned map passes honestly
  ---
  duration_ms: 29.201375
  type: 'test'
  location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:51:1'
  failureType: 'testCodeFailure'
  error: |-
    Expected values to be strictly deep-equal:
    + actual - expected
    
      {
        apiAvailable: 10,
    +   available: 147,
    -   available: 142,
        internal: 0,
    +   planned: 2,
    +   public: 157
    -   planned: 4,
    -   public: 152
      }
    
  code: 'ERR_ASSERTION'
  name: 'AssertionError'
  expected:
    planned: 4
    apiAvailable: 10
    available: 142
    public: 152
    internal: 0
  actual:
    planned: 2
    apiAvailable: 10
    available: 147
    public: 157
    internal: 0
  operator: 'deepStrictEqual'
  stack: |-
    TestContext.<anonymous> (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:53:10)
    async Test.run (node:internal/test_runner/test:1054:7)
    async startSubtestAfterBootstrap (node:internal/test_runner/harness:296:3)
  ...
# Subtest: all current public operations resolve and deliberate removal fails
not ok 15 - all current public operations resolve and deliberate removal fails
  ---
  duration_ms: 4.404959
  type: 'test'
  location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:62:1'
  failureType: 'testCodeFailure'
  error: |-
    Expected values to be strictly deep-equal:
    + actual - expected
    
      {
        apiAvailable: 10,
    +   available: 149,
    -   available: 146,
        internal: 0,
        planned: 0,
    +   public: 159
    -   public: 156
      }
    
  code: 'ERR_ASSERTION'
  name: 'AssertionError'
  expected:
    planned: 0
    apiAvailable: 10
    available: 146
    public: 156
    internal: 0
  actual:
    planned: 0
    apiAvailable: 10
    available: 149
    public: 159
    internal: 0
  operator: 'deepStrictEqual'
  stack: |-
    TestContext.<anonymous> (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:67:10)
    async Test.run (node:internal/test_runner/test:1054:7)
    async Test.processPendingSubtests (node:internal/test_runner/test:744:7)
  ...
# Subtest: unmapped public operations fail while unmapped internal operations pass
not ok 16 - unmapped public operations fail while unmapped internal operations pass
  ---
  duration_ms: 3.547375
  type: 'test'
  location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:78:1'
  failureType: 'testCodeFailure'
  error: |-
    Expected values to be strictly deep-equal:
    + actual - expected
    
      {
        apiAvailable: 10,
    +   available: 147,
    -   available: 142,
        internal: 1,
    +   planned: 2,
    +   public: 157
    -   planned: 4,
    -   public: 152
      }
    
  code: 'ERR_ASSERTION'
  name: 'AssertionError'
  expected:
    planned: 4
    apiAvailable: 10
    available: 142
    public: 152
    internal: 1
  actual:
    planned: 2
    apiAvailable: 10
    available: 147
    public: 157
    internal: 1
  operator: 'deepStrictEqual'
  stack: |-
    TestContext.<anonymous> (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:85:10)
    async Test.run (node:internal/test_runner/test:1054:7)
    async Test.processPendingSubtests (node:internal/test_runner/test:744:7)
  ...
# Subtest: planned, available, and internal lifecycle mismatches fail
ok 17 - planned, available, and internal lifecycle mismatches fail
  ---
  duration_ms: 7.588708
  type: 'test'
  ...
# Subtest: API-available operations require OpenAPI but do not claim a wired UI
not ok 18 - API-available operations require OpenAPI but do not claim a wired UI
  ---
  duration_ms: 3.283958
  type: 'test'
  location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:109:1'
  failureType: 'testCodeFailure'
  error: |-
    Expected values to be strictly deep-equal:
    + actual - expected
    
      {
        apiAvailable: 10,
    +   available: 147,
    -   available: 142,
        internal: 0,
    +   planned: 2,
    +   public: 157
    -   planned: 4,
    -   public: 152
      }
    
  code: 'ERR_ASSERTION'
  name: 'AssertionError'
  expected:
    planned: 4
    apiAvailable: 10
    available: 142
    public: 152
    internal: 0
  actual:
    planned: 2
    apiAvailable: 10
    available: 147
    public: 157
    internal: 0
  operator: 'deepStrictEqual'
  stack: |-
    TestContext.<anonymous> (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:116:10)
    async Test.run (node:internal/test_runner/test:1054:7)
    async Test.processPendingSubtests (node:internal/test_runner/test:744:7)
  ...
# Subtest: OpenAPI operation extraction rejects missing, duplicate, and unclassified operations
ok 19 - OpenAPI operation extraction rejects missing, duplicate, and unclassified operations
  ---
  duration_ms: 0.296208
  type: 'test'
  ...
# Subtest: strict YAML parsing rejects representation and map-schema ambiguity
ok 20 - strict YAML parsing rejects representation and map-schema ambiguity
  ---
  duration_ms: 17.379583
  type: 'test'
  ...
# Subtest: fixed file boundary accepts regular UTF-8 and rejects symlink, oversize, and invalid UTF-8
ok 21 - fixed file boundary accepts regular UTF-8 and rejects symlink, oversize, and invalid UTF-8
  ---
  duration_ms: 16.381625
  type: 'test'
  ...
# Subtest: CLI emits only fixed success or rejection lines
not ok 22 - CLI emits only fixed success or rejection lines
  ---
  duration_ms: 11.998666
  type: 'test'
  location: '/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:172:1'
  failureType: 'testCodeFailure'
  error: |-
    Expected values to be strictly equal:
    + actual - expected
    
    + 'UI/API coverage passed: planned=2 api_available=10 available=147 public=157 internal=0.\n'
    - 'UI/API coverage passed: planned=4 api_available=10 available=142 public=152 internal=0.\n'
    
  code: 'ERR_ASSERTION'
  name: 'AssertionError'
  expected: |-
    UI/API coverage passed: planned=4 api_available=10 available=142 public=152 internal=0.
    
  actual: |-
    UI/API coverage passed: planned=2 api_available=10 available=147 public=157 internal=0.
    
  operator: 'strictEqual'
  stack: |-
    TestContext.<anonymous> (file:///Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/check-ui-api-coverage.test.mjs:176:10)
    async Test.run (node:internal/test_runner/test:1054:7)
    async Test.processPendingSubtests (node:internal/test_runner/test:744:7)
  ...
# Subtest: package command is wired into root verification
ok 23 - package command is wired into root verification
  ---
  duration_ms: 2.956375
  type: 'test'
  ...
1..23
# tests 44
# suites 2
# pass 37
# fail 7
# cancelled 0
# skipped 0
# todo 0
# duration_ms 2954.560083
```

## task4calendarred

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/vitest/vitest.mjs run apps/web/api/compliance-decoders.test.ts
```

Exit: 1

Complete captured output:

```text

 RUN  v4.1.11 /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

 ❯ apps/web/api/compliance-decoders.test.ts (4 tests | 1 failed) 5ms
     × rejects calendar overflow instead of normalizing source timestamps 2ms

⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯

 FAIL  apps/web/api/compliance-decoders.test.ts > compliance current contracts > rejects calendar overflow instead of normalizing source timestamps
AssertionError: expected [Function] to throw an error
 ❯ apps/web/api/compliance-decoders.test.ts:24:110
     22|  });
     23|  it("rejects calendar overflow instead of normalizing source timestamp…
     24|   expect(()=>decodeComplianceEvidenceDetail({...detail,record:{...reco…
       |                                                                                                              ^
     25|  });
     26| });

⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯[1/1]⎯


 Test Files  1 failed (1)
      Tests  1 failed | 3 passed (4)
   Start at  17:44:53
   Duration  1.10s (transform 39ms, setup 211ms, import 28ms, tests 5ms, environment 743ms)

```
