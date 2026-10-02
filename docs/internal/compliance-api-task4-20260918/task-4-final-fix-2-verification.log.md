# task-4-final-fix-2-verification.log.md

## fix2build

Working directory: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform`

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 /opt/homebrew/bin/go test -c ./apiserver -o /private/tmp/zasp-compliance-task4-final-fix-2.test
```

Exit: 0

```text

```

## fix2workerbuild

Working directory: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform`

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 /opt/homebrew/bin/go test -c ./agentsec-worker -o /private/tmp/zasp-compliance-task4-final-fix-2-worker.test
```

Exit: 0

```text

```

## fix2race

Working directory: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform`

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./artifactstore ./artifactstore/s3driver ./apiserver -run '^(TestGetClassifiesReturnedObjectIntegrity|TestPlannedObjectReferenceRequiresSeparatePureDriverCapability|TestPlannedObjectReferenceRejectsUninitializedStores|TestExportStoreRejectsDriverProfileAndScopeSubstitution|TestExportStoreEnforcesRequestBoundsBeforeDriverIO|TestStorePutGetDeleteHappyPath|TestStorePreservesAnOpaqueDriverVersionWithoutLettingItChangeContentIdentity|TestStoreObjectReferenceUsesTheExactVersionedDriverAuthority|TestNewRejectsInvalidConfigurationAndDriver|TestStoreAcceptsOnlyTheOwnedRecoveryMediaTypes|TestOperationsRejectInvalidProductRequestsBeforeDriver|TestPutRejectsEveryMismatchedDriverResult|TestGetValidatesExactDriverStateAndChecksum|TestOperationsContainDriverErrorsAndPanics|TestOperationsUseOneBoundedContextAndHonorCancellation|TestCanonicalKeyIsStableAndContainsOnlyProductIdentity|TestBuildDriverLocatorRejectsInvalidIdentity|TestStoreDeniesSameSessionCrossOrganizationRead|TestStoreDerivesConcurrentOrganizationPrefixesPerCall|TestStoreSupportsConcurrentIndependentOperations|TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls|TestPlannedObjectReferenceRejectsUninitializedDrivers|TestExportStoreSDKUsesScopedExportPrefix|TestExportStoreSDKCancellationAfterSavedPutRemainsRecoverable|TestExportProfilesRejectMixedConstructionBeforeProviderIO|TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO|TestExportReadRefusesCorruptedProviderAuthority|TestExportDriverKeepsImmutableReplayLimitsAndCancellation|TestDriverAcceptsOnlyTheOwnedRecoveryMediaTypes|TestDriverPutIsCreateOnlyAndReconcilesLostAcknowledgement|TestDriverGetPinsVersionAndValidatesEveryBoundary|TestDriverBuildsTheObjectReferenceFromItsExactBucketAuthority|TestDriverReadUsesThePersistedVersionAcrossNewerVersionsAndDeleteMarkers|TestDriverRejectsInvalidInputBeforeCloudAndNeverDeletesImmutableEvidence|TestDriverUsesOneAttemptAndContainsCancellationProviderErrorsAndPanics|TestNewRejectsHostileConfigurationAndTypedNilClient|TestExportCleanupSDKExactVersionAbsence|TestExportReadOnlyReconciliation|TestExportReadOnlyReconciliationSDKFaults|TestExportCleanupRequiresVerifiedExactVersionAbsence|TestComplianceConflictClassification|TestCompliancePersistedAttributionAndHistoricalBytes|TestCompliancePersistedEmptyFindingReferences|TestComplianceExportBindsRequestedJobAndCanonicalFilters|TestComplianceExportsRepository|TestComplianceHTTPMountedPublicLifecycle|TestComplianceHTTPMountedDenials|TestComplianceHTTPDownloadNoDisclosureBeforeConsume|TestComplianceHTTPStrictInputs|TestComplianceReadFailureClassification|TestComplianceEvidenceStrictDecoding|TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput)$' -count=1 -v
```

Exit: 0

```text
=== RUN   TestGetClassifiesReturnedObjectIntegrity
--- PASS: TestGetClassifiesReturnedObjectIntegrity (0.00s)
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/valid
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/missing_capability
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/versioned
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/scope
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/reference
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/empty_result
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/error
=== RUN   TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/panic
--- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/valid (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/missing_capability (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/versioned (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/scope (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/reference (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/empty_result (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/error (0.00s)
    --- PASS: TestPlannedObjectReferenceRequiresSeparatePureDriverCapability/panic (0.00s)
=== RUN   TestPlannedObjectReferenceRejectsUninitializedStores
--- PASS: TestPlannedObjectReferenceRejectsUninitializedStores (0.00s)
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
=== RUN   TestStorePutGetDeleteHappyPath
=== PAUSE TestStorePutGetDeleteHappyPath
=== RUN   TestStorePreservesAnOpaqueDriverVersionWithoutLettingItChangeContentIdentity
=== PAUSE TestStorePreservesAnOpaqueDriverVersionWithoutLettingItChangeContentIdentity
=== RUN   TestStoreObjectReferenceUsesTheExactVersionedDriverAuthority
=== PAUSE TestStoreObjectReferenceUsesTheExactVersionedDriverAuthority
=== RUN   TestNewRejectsInvalidConfigurationAndDriver
=== PAUSE TestNewRejectsInvalidConfigurationAndDriver
=== RUN   TestStoreAcceptsOnlyTheOwnedRecoveryMediaTypes
=== PAUSE TestStoreAcceptsOnlyTheOwnedRecoveryMediaTypes
=== RUN   TestOperationsRejectInvalidProductRequestsBeforeDriver
=== PAUSE TestOperationsRejectInvalidProductRequestsBeforeDriver
=== RUN   TestPutRejectsEveryMismatchedDriverResult
=== PAUSE TestPutRejectsEveryMismatchedDriverResult
=== RUN   TestGetValidatesExactDriverStateAndChecksum
=== PAUSE TestGetValidatesExactDriverStateAndChecksum
=== RUN   TestOperationsContainDriverErrorsAndPanics
=== PAUSE TestOperationsContainDriverErrorsAndPanics
=== RUN   TestOperationsUseOneBoundedContextAndHonorCancellation
=== PAUSE TestOperationsUseOneBoundedContextAndHonorCancellation
=== RUN   TestCanonicalKeyIsStableAndContainsOnlyProductIdentity
=== PAUSE TestCanonicalKeyIsStableAndContainsOnlyProductIdentity
=== RUN   TestBuildDriverLocatorRejectsInvalidIdentity
=== PAUSE TestBuildDriverLocatorRejectsInvalidIdentity
=== RUN   TestStoreDeniesSameSessionCrossOrganizationRead
=== PAUSE TestStoreDeniesSameSessionCrossOrganizationRead
=== RUN   TestStoreDerivesConcurrentOrganizationPrefixesPerCall
=== PAUSE TestStoreDerivesConcurrentOrganizationPrefixesPerCall
=== RUN   TestStoreSupportsConcurrentIndependentOperations
=== PAUSE TestStoreSupportsConcurrentIndependentOperations
=== CONT  TestStorePreservesAnOpaqueDriverVersionWithoutLettingItChangeContentIdentity
=== CONT  TestGetValidatesExactDriverStateAndChecksum
=== CONT  TestStorePutGetDeleteHappyPath
=== CONT  TestOperationsRejectInvalidProductRequestsBeforeDriver
=== CONT  TestStoreObjectReferenceUsesTheExactVersionedDriverAuthority
--- PASS: TestStorePreservesAnOpaqueDriverVersionWithoutLettingItChangeContentIdentity (0.00s)
--- PASS: TestStorePutGetDeleteHappyPath (0.00s)
--- PASS: TestStoreObjectReferenceUsesTheExactVersionedDriverAuthority (0.00s)
--- PASS: TestOperationsRejectInvalidProductRequestsBeforeDriver (0.00s)
=== CONT  TestCanonicalKeyIsStableAndContainsOnlyProductIdentity
=== CONT  TestStoreSupportsConcurrentIndependentOperations
=== CONT  TestPutRejectsEveryMismatchedDriverResult
=== CONT  TestStoreDeniesSameSessionCrossOrganizationRead
=== CONT  TestOperationsContainDriverErrorsAndPanics
=== CONT  TestBuildDriverLocatorRejectsInvalidIdentity
=== CONT  TestNewRejectsInvalidConfigurationAndDriver
=== CONT  TestStoreAcceptsOnlyTheOwnedRecoveryMediaTypes
=== CONT  TestOperationsUseOneBoundedContextAndHonorCancellation
--- PASS: TestCanonicalKeyIsStableAndContainsOnlyProductIdentity (0.00s)
=== RUN   TestGetValidatesExactDriverStateAndChecksum/empty
=== CONT  TestStoreDerivesConcurrentOrganizationPrefixesPerCall
--- PASS: TestStoreAcceptsOnlyTheOwnedRecoveryMediaTypes (0.00s)
--- PASS: TestStoreDeniesSameSessionCrossOrganizationRead (0.00s)
--- PASS: TestNewRejectsInvalidConfigurationAndDriver (0.00s)
=== RUN   TestPutRejectsEveryMismatchedDriverResult/key
--- PASS: TestStoreSupportsConcurrentIndependentOperations (0.00s)
=== RUN   TestOperationsUseOneBoundedContextAndHonorCancellation/put
=== RUN   TestOperationsContainDriverErrorsAndPanics/put_error
=== RUN   TestPutRejectsEveryMismatchedDriverResult/scope
--- PASS: TestStoreDerivesConcurrentOrganizationPrefixesPerCall (0.00s)
=== RUN   TestOperationsContainDriverErrorsAndPanics/put_panic
=== RUN   TestGetValidatesExactDriverStateAndChecksum/key
=== RUN   TestBuildDriverLocatorRejectsInvalidIdentity/zero
=== RUN   TestPutRejectsEveryMismatchedDriverResult/reference
=== RUN   TestOperationsContainDriverErrorsAndPanics/get_error
=== RUN   TestGetValidatesExactDriverStateAndChecksum/media
=== RUN   TestOperationsContainDriverErrorsAndPanics/get_panic
=== RUN   TestGetValidatesExactDriverStateAndChecksum/size
=== RUN   TestOperationsContainDriverErrorsAndPanics/delete_error
=== RUN   TestGetValidatesExactDriverStateAndChecksum/checksum
=== RUN   TestBuildDriverLocatorRejectsInvalidIdentity/scope
=== RUN   TestPutRejectsEveryMismatchedDriverResult/media
=== RUN   TestOperationsContainDriverErrorsAndPanics/delete_panic
=== RUN   TestGetValidatesExactDriverStateAndChecksum/body_checksum
--- PASS: TestOperationsContainDriverErrorsAndPanics (0.00s)
    --- PASS: TestOperationsContainDriverErrorsAndPanics/put_error (0.00s)
    --- PASS: TestOperationsContainDriverErrorsAndPanics/put_panic (0.00s)
    --- PASS: TestOperationsContainDriverErrorsAndPanics/get_error (0.00s)
    --- PASS: TestOperationsContainDriverErrorsAndPanics/get_panic (0.00s)
    --- PASS: TestOperationsContainDriverErrorsAndPanics/delete_error (0.00s)
    --- PASS: TestOperationsContainDriverErrorsAndPanics/delete_panic (0.00s)
--- PASS: TestGetValidatesExactDriverStateAndChecksum (0.00s)
    --- PASS: TestGetValidatesExactDriverStateAndChecksum/empty (0.00s)
    --- PASS: TestGetValidatesExactDriverStateAndChecksum/key (0.00s)
    --- PASS: TestGetValidatesExactDriverStateAndChecksum/media (0.00s)
    --- PASS: TestGetValidatesExactDriverStateAndChecksum/size (0.00s)
    --- PASS: TestGetValidatesExactDriverStateAndChecksum/checksum (0.00s)
    --- PASS: TestGetValidatesExactDriverStateAndChecksum/body_checksum (0.00s)
=== RUN   TestBuildDriverLocatorRejectsInvalidIdentity/reference
--- PASS: TestBuildDriverLocatorRejectsInvalidIdentity (0.00s)
    --- PASS: TestBuildDriverLocatorRejectsInvalidIdentity/zero (0.00s)
    --- PASS: TestBuildDriverLocatorRejectsInvalidIdentity/scope (0.00s)
    --- PASS: TestBuildDriverLocatorRejectsInvalidIdentity/reference (0.00s)
=== RUN   TestPutRejectsEveryMismatchedDriverResult/body
=== RUN   TestPutRejectsEveryMismatchedDriverResult/size
=== RUN   TestPutRejectsEveryMismatchedDriverResult/checksum
=== RUN   TestPutRejectsEveryMismatchedDriverResult/oversized
--- PASS: TestPutRejectsEveryMismatchedDriverResult (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/key (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/scope (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/reference (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/media (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/body (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/size (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/checksum (0.00s)
    --- PASS: TestPutRejectsEveryMismatchedDriverResult/oversized (0.00s)
=== RUN   TestOperationsUseOneBoundedContextAndHonorCancellation/get
=== RUN   TestOperationsUseOneBoundedContextAndHonorCancellation/delete
--- PASS: TestOperationsUseOneBoundedContextAndHonorCancellation (0.06s)
    --- PASS: TestOperationsUseOneBoundedContextAndHonorCancellation/put (0.02s)
    --- PASS: TestOperationsUseOneBoundedContextAndHonorCancellation/get (0.02s)
    --- PASS: TestOperationsUseOneBoundedContextAndHonorCancellation/delete (0.02s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore	1.425s
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/export
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/legacy
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/mixed_export_store
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/mixed_export_driver
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/nonempty_version
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/forged_driver_key
=== RUN   TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/scope_mismatch
--- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls (0.00s)
    --- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/export (0.00s)
    --- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/legacy (0.00s)
    --- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/mixed_export_store (0.00s)
    --- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/mixed_export_driver (0.00s)
    --- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/nonempty_version (0.00s)
    --- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/forged_driver_key (0.00s)
    --- PASS: TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls/scope_mismatch (0.00s)
=== RUN   TestPlannedObjectReferenceRejectsUninitializedDrivers
--- PASS: TestPlannedObjectReferenceRejectsUninitializedDrivers (0.00s)
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
--- PASS: TestExportReadRefusesCorruptedProviderAuthority (0.00s)
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
=== RUN   TestDriverAcceptsOnlyTheOwnedRecoveryMediaTypes
--- PASS: TestDriverAcceptsOnlyTheOwnedRecoveryMediaTypes (0.00s)
=== RUN   TestDriverPutIsCreateOnlyAndReconcilesLostAcknowledgement
--- PASS: TestDriverPutIsCreateOnlyAndReconcilesLostAcknowledgement (0.00s)
=== RUN   TestDriverGetPinsVersionAndValidatesEveryBoundary
--- PASS: TestDriverGetPinsVersionAndValidatesEveryBoundary (0.00s)
=== RUN   TestDriverBuildsTheObjectReferenceFromItsExactBucketAuthority
=== PAUSE TestDriverBuildsTheObjectReferenceFromItsExactBucketAuthority
=== RUN   TestDriverReadUsesThePersistedVersionAcrossNewerVersionsAndDeleteMarkers
--- PASS: TestDriverReadUsesThePersistedVersionAcrossNewerVersionsAndDeleteMarkers (0.00s)
=== RUN   TestDriverRejectsInvalidInputBeforeCloudAndNeverDeletesImmutableEvidence
--- PASS: TestDriverRejectsInvalidInputBeforeCloudAndNeverDeletesImmutableEvidence (0.00s)
=== RUN   TestDriverUsesOneAttemptAndContainsCancellationProviderErrorsAndPanics
--- PASS: TestDriverUsesOneAttemptAndContainsCancellationProviderErrorsAndPanics (0.00s)
=== RUN   TestNewRejectsHostileConfigurationAndTypedNilClient
--- PASS: TestNewRejectsHostileConfigurationAndTypedNilClient (0.00s)
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
=== CONT  TestDriverBuildsTheObjectReferenceFromItsExactBucketAuthority
--- PASS: TestDriverBuildsTheObjectReferenceFromItsExactBucketAuthority (0.00s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver	1.603s
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
=== RUN   TestComplianceExportsRepository
--- PASS: TestComplianceExportsRepository (0.05s)
=== RUN   TestComplianceHTTPMountedPublicLifecycle
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/controls
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence?framework=soc2_security
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/evidence/policy/policy-001?source_version=7
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download-grants
=== RUN   TestComplianceHTTPMountedPublicLifecycle//api/v1/compliance/exports/`ID`/download
--- PASS: TestComplianceHTTPMountedPublicLifecycle (0.29s)
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
--- PASS: TestComplianceHTTPMountedDenials (0.28s)
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
--- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume (0.38s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/bytes (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/version (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/scope (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/digest (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/size (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/error (0.04s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/revoked (0.05s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/expired (0.05s)
    --- PASS: TestComplianceHTTPDownloadNoDisclosureBeforeConsume/replay (0.05s)
=== RUN   TestComplianceHTTPStrictInputs
--- PASS: TestComplianceHTTPStrictInputs (0.28s)
=== RUN   TestComplianceReadFailureClassification
=== RUN   TestComplianceReadFailureClassification/head-outage
=== RUN   TestComplianceReadFailureClassification/head-outage/driver
=== RUN   TestComplianceReadFailureClassification/head-outage/store
=== RUN   TestComplianceReadFailureClassification/head-outage/http
=== RUN   TestComplianceReadFailureClassification/get-outage
=== RUN   TestComplianceReadFailureClassification/get-outage/driver
=== RUN   TestComplianceReadFailureClassification/get-outage/store
=== RUN   TestComplianceReadFailureClassification/get-outage/http
=== RUN   TestComplianceReadFailureClassification/body-outage
=== RUN   TestComplianceReadFailureClassification/body-outage/driver
=== RUN   TestComplianceReadFailureClassification/body-outage/store
=== RUN   TestComplianceReadFailureClassification/body-outage/http
=== RUN   TestComplianceReadFailureClassification/cancel
=== RUN   TestComplianceReadFailureClassification/cancel/driver
=== RUN   TestComplianceReadFailureClassification/cancel/store
=== RUN   TestComplianceReadFailureClassification/cancel/http
=== RUN   TestComplianceReadFailureClassification/deadline
=== RUN   TestComplianceReadFailureClassification/deadline/driver
=== RUN   TestComplianceReadFailureClassification/deadline/store
=== RUN   TestComplianceReadFailureClassification/deadline/http
=== RUN   TestComplianceReadFailureClassification/version
=== RUN   TestComplianceReadFailureClassification/version/driver
=== RUN   TestComplianceReadFailureClassification/version/store
=== RUN   TestComplianceReadFailureClassification/version/http
=== RUN   TestComplianceReadFailureClassification/metadata
=== RUN   TestComplianceReadFailureClassification/metadata/driver
=== RUN   TestComplianceReadFailureClassification/metadata/store
=== RUN   TestComplianceReadFailureClassification/metadata/http
=== RUN   TestComplianceReadFailureClassification/checksum
=== RUN   TestComplianceReadFailureClassification/checksum/driver
=== RUN   TestComplianceReadFailureClassification/checksum/store
=== RUN   TestComplianceReadFailureClassification/checksum/http
=== RUN   TestComplianceReadFailureClassification/body-mismatch
=== RUN   TestComplianceReadFailureClassification/body-mismatch/driver
=== RUN   TestComplianceReadFailureClassification/body-mismatch/store
=== RUN   TestComplianceReadFailureClassification/body-mismatch/http
=== RUN   TestComplianceReadFailureClassification/envelope
=== RUN   TestComplianceReadFailureClassification/envelope/driver
=== RUN   TestComplianceReadFailureClassification/envelope/store
=== RUN   TestComplianceReadFailureClassification/envelope/http
=== RUN   TestComplianceReadFailureClassification/valid
=== RUN   TestComplianceReadFailureClassification/valid/driver
=== RUN   TestComplianceReadFailureClassification/valid/store
=== RUN   TestComplianceReadFailureClassification/valid/http
=== RUN   TestComplianceReadFailureClassification/sdk-checksum
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/driver
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/store
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/http
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/driver
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/store
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/http
=== RUN   TestComplianceReadFailureClassification/sdk-spoof
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/driver
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/store
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/http
=== RUN   TestComplianceReadFailureClassification/sdk-cancel
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/driver
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/store
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/http
=== RUN   TestComplianceReadFailureClassification/sdk-valid
=== RUN   TestComplianceReadFailureClassification/sdk-valid/driver
=== RUN   TestComplianceReadFailureClassification/sdk-valid/store
=== RUN   TestComplianceReadFailureClassification/sdk-valid/http
--- PASS: TestComplianceReadFailureClassification (1.26s)
    --- PASS: TestComplianceReadFailureClassification/head-outage (0.09s)
        --- PASS: TestComplianceReadFailureClassification/head-outage/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/head-outage/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/head-outage/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/get-outage (0.08s)
        --- PASS: TestComplianceReadFailureClassification/get-outage/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/get-outage/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/get-outage/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/body-outage (0.08s)
        --- PASS: TestComplianceReadFailureClassification/body-outage/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/body-outage/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/body-outage/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/cancel (0.08s)
        --- PASS: TestComplianceReadFailureClassification/cancel/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/cancel/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/cancel/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/deadline (0.08s)
        --- PASS: TestComplianceReadFailureClassification/deadline/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/deadline/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/deadline/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/version (0.08s)
        --- PASS: TestComplianceReadFailureClassification/version/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/version/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/version/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/metadata (0.08s)
        --- PASS: TestComplianceReadFailureClassification/metadata/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/metadata/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/metadata/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/checksum (0.08s)
        --- PASS: TestComplianceReadFailureClassification/checksum/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/checksum/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/checksum/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/body-mismatch (0.07s)
        --- PASS: TestComplianceReadFailureClassification/body-mismatch/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/body-mismatch/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/body-mismatch/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/envelope (0.08s)
        --- PASS: TestComplianceReadFailureClassification/envelope/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/envelope/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/envelope/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/valid (0.08s)
        --- PASS: TestComplianceReadFailureClassification/valid/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/valid/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/valid/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/sdk-checksum (0.08s)
        --- PASS: TestComplianceReadFailureClassification/sdk-checksum/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-checksum/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-checksum/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/sdk-body-outage (0.08s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/sdk-spoof (0.08s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/sdk-cancel (0.08s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/http (0.04s)
    --- PASS: TestComplianceReadFailureClassification/sdk-valid (0.08s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/http (0.04s)
=== RUN   TestComplianceEvidenceStrictDecoding
--- PASS: TestComplianceEvidenceStrictDecoding (0.00s)
=== RUN   TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput
--- PASS: TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput (0.04s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/apiserver	4.598s

```

## fix2sql

Working directory: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task4-final-fix-2 --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task4-final-fix-2.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task4-final-fix-2-worker.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestCompliance(HTTPPostgresReadClassification|HTTPPostgresGrantLifecycle|GrantFreshAfterWaitPostgres|WorkerReplayPostgres|RuntimePollingPostgres)$' -test.v -test.timeout 240s
```

Exit: 0

```text
=== RUN   TestComplianceGrantFreshAfterWaitPostgres
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false
=== RUN   TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true
=== NAME  TestComplianceGrantFreshAfterWaitPostgres
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=23 data=/tmp/TestComplianceGrantFreshAfterWaitPostgres2934441662/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceGrantFreshAfterWaitPostgres (5.51s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/issue_grant_lock_false (0.11s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_false (0.09s)
    --- PASS: TestComplianceGrantFreshAfterWaitPostgres/read_grant_lock_true (0.08s)
=== RUN   TestComplianceWorkerReplayPostgres
    compliance_exports_fix_postgres_test.go:235: joined worker prepare: === RUN   TestComplianceReplayRestartProcess
            compliance_export_replay_test.go:184: registered worker committed exact v1 intent then exited before I/O
        --- PASS: TestComplianceReplayRestartProcess (1.21s)
        PASS
    compliance_exports_fix_postgres_test.go:253: joined worker replay: === RUN   TestComplianceReplayRestartProcess
            compliance_export_replay_test.go:232: fresh registered worker replayed SQL v1 bytes through NewExport.Put; renderer-v2 calls=0; Finish used renewed lease after original deadline
        --- PASS: TestComplianceReplayRestartProcess (2.10s)
        PASS
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=56 data=/tmp/TestComplianceWorkerReplayPostgres1566118871/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceWorkerReplayPostgres (7.97s)
=== RUN   TestComplianceHTTPPostgresGrantLifecycle
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=98 data=/tmp/TestComplianceHTTPPostgresGrantLifecycle1965153738/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresGrantLifecycle (5.80s)
=== RUN   TestComplianceHTTPPostgresReadClassification
=== RUN   TestComplianceHTTPPostgresReadClassification/head-outage
=== RUN   TestComplianceHTTPPostgresReadClassification/get-outage
=== RUN   TestComplianceHTTPPostgresReadClassification/body-outage
=== RUN   TestComplianceHTTPPostgresReadClassification/cancel
=== RUN   TestComplianceHTTPPostgresReadClassification/deadline
=== RUN   TestComplianceHTTPPostgresReadClassification/version
=== RUN   TestComplianceHTTPPostgresReadClassification/metadata
=== RUN   TestComplianceHTTPPostgresReadClassification/checksum
=== RUN   TestComplianceHTTPPostgresReadClassification/body-mismatch
=== RUN   TestComplianceHTTPPostgresReadClassification/envelope
=== RUN   TestComplianceHTTPPostgresReadClassification/valid
=== RUN   TestComplianceHTTPPostgresReadClassification/sdk-checksum
=== RUN   TestComplianceHTTPPostgresReadClassification/sdk-body-outage
=== RUN   TestComplianceHTTPPostgresReadClassification/sdk-spoof
=== RUN   TestComplianceHTTPPostgresReadClassification/sdk-cancel
=== RUN   TestComplianceHTTPPostgresReadClassification/sdk-valid
=== NAME  TestComplianceHTTPPostgresReadClassification
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=128 data=/tmp/TestComplianceHTTPPostgresReadClassification1217275051/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceHTTPPostgresReadClassification (9.38s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/head-outage (0.30s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/get-outage (0.27s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/body-outage (0.26s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/cancel (0.26s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/deadline (0.25s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/version (0.30s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/metadata (0.33s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/checksum (0.31s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/body-mismatch (0.31s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/envelope (0.34s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/valid (0.37s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/sdk-checksum (0.39s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/sdk-body-outage (0.28s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/sdk-spoof (0.29s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/sdk-cancel (0.27s)
    --- PASS: TestComplianceHTTPPostgresReadClassification/sdk-valid (0.34s)
=== RUN   TestComplianceRuntimePollingPostgres
    compliance_runtime_postgres_test.go:66: joined interrupt: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined interrupt polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.65s)
        PASS
    compliance_runtime_postgres_test.go:74: joined resume: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined resume polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.55s)
        PASS
    compliance_runtime_postgres_test.go:79: joined cleanup_denied: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined cleanup_denied polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.59s)
        PASS
    compliance_runtime_postgres_test.go:84: joined cleanup: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined cleanup polling worker; provider PUT=0; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.57s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.57s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.44s)
        PASS
    compliance_runtime_postgres_test.go:90: joined unknown: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined unknown polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.50s)
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
        --- PASS: TestComplianceRuntimeProcess (0.54s)
        PASS
    compliance_runtime_postgres_test.go:103: joined revoked: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined revoked polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.65s)
        PASS
    compliance_runtime_postgres_test.go:114: joined lease_lost: === RUN   TestComplianceRuntimeProcess
            compliance_export_process_test.go:244: joined lease_lost polling worker; provider PUT=1; transport is controlled HTTP, not live AWS
        --- PASS: TestComplianceRuntimeProcess (0.61s)
        PASS
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=157 data=/tmp/TestComplianceRuntimePollingPostgres1127877891/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- PASS: TestComplianceRuntimePollingPostgres (11.29s)
PASS

```
