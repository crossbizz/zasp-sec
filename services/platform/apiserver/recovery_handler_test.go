package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type recoveryAuthorityStub struct {
	backupInput   RecoveryBackupMutation
	restoreInput  RecoveryRestoreMutation
	backup        RecoveryBackup
	restore       RecoveryRestore
	backupResult  RecoveryBackupMutationResult
	restoreResult RecoveryRestoreMutationResult
	identity      RequestIdentity
	calls         int
}

func (stub *recoveryAuthorityStub) StartBackup(_ context.Context, identity RequestIdentity, input RecoveryBackupMutation) (RecoveryBackupMutationResult, error) {
	stub.calls++
	stub.identity, stub.backupInput = identity, input
	return stub.backupResult, nil
}

func (stub *recoveryAuthorityStub) GetBackup(_ context.Context, identity RequestIdentity, _ string) (RecoveryBackup, error) {
	stub.calls++
	stub.identity = identity
	return stub.backup, nil
}

func (stub *recoveryAuthorityStub) StartRestore(_ context.Context, identity RequestIdentity, input RecoveryRestoreMutation) (RecoveryRestoreMutationResult, error) {
	stub.calls++
	stub.identity, stub.restoreInput = identity, input
	return stub.restoreResult, nil
}

func (stub *recoveryAuthorityStub) GetRestore(_ context.Context, identity RequestIdentity, _ string) (RecoveryRestore, error) {
	stub.calls++
	stub.identity = identity
	return stub.restore, nil
}

func TestRecoveryHTTPStartsScopedBackupWithStableMutationAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	stub := &recoveryAuthorityStub{backupResult: RecoveryBackupMutationResult{
		Body:    RecoveryBackup{ID: testRecoveryBackupID, Version: 1, State: "queued", RetentionDays: 30, Attempt: 0, CreatedAt: now},
		AuditID: "pid_71000004-0000-4000-8000-000000000004", CorrelationID: testCorrelationID, ReceiptID: "pid_71000005-0000-4000-8000-000000000005",
	}}
	ids := []string{"pid_71000004-0000-4000-8000-000000000004", "pid_71000005-0000-4000-8000-000000000005"}
	handler, err := NewRecoveryPublicHTTPHandler(stub, RecoveryPublicHandlerConfig{NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil }})
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, testCorrelationID, "startRecoveryBackup", nil, http.MethodPost, "/api/v1/recovery/backups", `{"backup_id":"`+testRecoveryBackupID+`","retention_days":30}`)
	request.Header.Set("Idempotency-Key", "recovery-backup-0001")
	request.Header.Set("If-Match", `"0"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != stub.backupResult.AuditID || response.Header().Get("X-Mutation-Receipt-ID") != stub.backupResult.ReceiptID {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if stub.calls != 1 || stub.identity.Scope != identity.Scope || stub.backupInput.BackupID != testRecoveryBackupID || stub.backupInput.RetentionDays != 30 || len(stub.backupInput.RequestDigest) != 32 {
		t.Fatalf("calls=%d identity=%#v input=%#v", stub.calls, stub.identity, stub.backupInput)
	}
	if strings.Contains(response.Body.String(), "request_digest") || strings.Contains(response.Body.String(), "receipt_id") {
		t.Fatalf("internal authority leaked: %s", response.Body.String())
	}
}

func TestRecoveryHTTPReplaysBackupWithTheOriginalStableCorrelationAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	storedCorrelationID := "pid_71000008-0000-4000-8000-000000000008"
	stub := &recoveryAuthorityStub{backupResult: RecoveryBackupMutationResult{
		Body:    RecoveryBackup{ID: testRecoveryBackupID, Version: 1, State: "queued", RetentionDays: 30, Attempt: 0, CreatedAt: now},
		AuditID: "pid_71000004-0000-4000-8000-000000000004", CorrelationID: storedCorrelationID, ReceiptID: "pid_71000005-0000-4000-8000-000000000005", Replayed: true,
	}}
	ids := []string{"pid_71000006-0000-4000-8000-000000000006", "pid_71000007-0000-4000-8000-000000000007"}
	handler, err := NewRecoveryPublicHTTPHandler(stub, RecoveryPublicHandlerConfig{NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil }})
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, testCorrelationID, "startRecoveryBackup", nil, http.MethodPost, "/api/v1/recovery/backups", `{"backup_id":"`+testRecoveryBackupID+`","retention_days":30}`)
	request.Header.Set("Idempotency-Key", "recovery-backup-0001")
	request.Header.Set("If-Match", `"0"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("X-Audit-ID") != stub.backupResult.AuditID || response.Header().Get("X-Mutation-Receipt-ID") != "" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestRecoveryHTTPReplaysRestoreWithTheOriginalStableCorrelationAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	manifest := recoveryManifestFixture(identity)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	stub := &recoveryAuthorityStub{restoreResult: RecoveryRestoreMutationResult{
		Body:          RecoveryRestore{ID: testRecoveryRestoreID, Version: 1, State: "queued", TargetEnvironment: "recovery-e2e-01", Attempt: 0, Manifest: &manifest, CreatedAt: now},
		AuditID:       "pid_71000004-0000-4000-8000-000000000004",
		CorrelationID: "pid_71000008-0000-4000-8000-000000000008",
		ReceiptID:     "pid_71000005-0000-4000-8000-000000000005",
		Replayed:      true,
	}}
	ids := []string{"pid_71000006-0000-4000-8000-000000000006", "pid_71000007-0000-4000-8000-000000000007"}
	handler, err := NewRecoveryPublicHTTPHandler(stub, RecoveryPublicHandlerConfig{NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil }})
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, marshalErr := json.Marshal(manifest)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	request := workflowRequest(t, identity, testCorrelationID, "startRecoveryRestore", nil, http.MethodPost, "/api/v1/recovery/restores", `{"restore_id":"`+testRecoveryRestoreID+`","target_environment":"recovery-e2e-01","manifest":`+string(manifestJSON)+`}`)
	request.Header.Set("Idempotency-Key", "recovery-restore-0001")
	request.Header.Set("If-Match", `"0"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("X-Audit-ID") != stub.restoreResult.AuditID || response.Header().Get("X-Mutation-Receipt-ID") != "" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestRecoveryHTTPStartsOnlyDisposableStrictRestoreAndSuppressesPATReceipt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	manifest := recoveryManifestFixture(identity)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	stub := &recoveryAuthorityStub{restoreResult: RecoveryRestoreMutationResult{
		Body:    RecoveryRestore{ID: testRecoveryRestoreID, Version: 1, State: "queued", TargetEnvironment: "recovery-e2e-01", Attempt: 0, Manifest: &manifest, CreatedAt: now},
		AuditID: "pid_71000006-0000-4000-8000-000000000006", CorrelationID: testCorrelationID, ReceiptID: "pid_71000007-0000-4000-8000-000000000007",
	}}
	ids := []string{"pid_71000006-0000-4000-8000-000000000006", "pid_71000007-0000-4000-8000-000000000007"}
	handler, err := NewRecoveryPublicHTTPHandler(stub, RecoveryPublicHandlerConfig{NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil }})
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, marshalErr := json.Marshal(manifest)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	body := `{"restore_id":"` + testRecoveryRestoreID + `","target_environment":"recovery-e2e-01","manifest":` + string(manifestJSON) + `}`
	request := workflowRequest(t, identity, testCorrelationID, "startRecoveryRestore", nil, http.MethodPost, "/api/v1/recovery/restores", body)
	request.Header.Set("Idempotency-Key", "recovery-restore-0001")
	request.Header.Set("If-Match", `"0"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("X-Mutation-Receipt-ID") != "" || stub.restoreInput.TargetEnvironment != "recovery-e2e-01" || stub.restoreInput.Manifest != manifest {
		t.Fatalf("status=%d headers=%v input=%#v body=%s", response.Code, response.Header(), stub.restoreInput, response.Body.String())
	}
	for name, hostile := range map[string]string{
		"unknown scope":     strings.TrimSuffix(body, "}") + `,"organization_id":"` + identity.Scope.OrganizationID().String() + `"}`,
		"production target": strings.Replace(body, "recovery-e2e-01", "production", 1),
		"uppercase target":  strings.Replace(body, "recovery-e2e-01", "Recovery-E2E", 1),
		"raw key arn":       strings.Replace(body, `"signature":"`+manifest.Signature+`"`, `"signature":"`+manifest.Signature+`","signing_key_arn":"arn:aws:kms:us-west-2:123456789012:key/123e4567-e89b-42d3-a456-426614174000"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			request := workflowRequest(t, identity, testCorrelationID, "startRecoveryRestore", nil, http.MethodPost, "/api/v1/recovery/restores", hostile)
			request.Header.Set("Idempotency-Key", "recovery-restore-0002")
			request.Header.Set("If-Match", `"0"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || stub.calls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, stub.calls, response.Body.String())
			}
		})
	}
}

func TestRecoveryHTTPReadsScopedJobsAndRejectsUnknownOperations(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	manifest := recoveryManifestFixture(identity)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	stub := &recoveryAuthorityStub{
		backup:  RecoveryBackup{ID: testRecoveryBackupID, Version: 3, State: "succeeded", RetentionDays: 30, Attempt: 1, Manifest: &manifest, CreatedAt: now, StartedAt: recoveryTimePointer(now.Add(time.Second)), CompletedAt: recoveryTimePointer(now.Add(2 * time.Second))},
		restore: RecoveryRestore{ID: testRecoveryRestoreID, Version: 1, State: "queued", TargetEnvironment: "recovery-e2e-01", Attempt: 0, Manifest: &manifest, CreatedAt: now},
	}
	handler, err := NewRecoveryPublicHTTPHandler(stub)
	if err != nil {
		t.Fatal(err)
	}
	for operation, id := range map[string]string{"getRecoveryBackup": testRecoveryBackupID, "getRecoveryRestore": testRecoveryRestoreID} {
		request := workflowRequest(t, identity, testCorrelationID, operation, map[string]string{"id": id}, http.MethodGet, "/api/v1/recovery/jobs/"+id, "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("ETag") == "" {
			t.Fatalf("operation=%s status=%d headers=%v body=%s", operation, response.Code, response.Header(), response.Body.String())
		}
	}
	request := workflowRequest(t, identity, testCorrelationID, "unknownRecoveryOperation", nil, http.MethodGet, "/api/v1/recovery", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRecoveryHTTPRejectsAStartResultThatIsNotTheInitialQueuedJob(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	manifest := recoveryManifestFixture(identity)
	stub := &recoveryAuthorityStub{backupResult: RecoveryBackupMutationResult{
		Body: RecoveryBackup{
			ID: testRecoveryBackupID, Version: 2, State: "succeeded", RetentionDays: 30, Attempt: 1,
			Manifest: &manifest, CreatedAt: now, StartedAt: recoveryTimePointer(now), CompletedAt: recoveryTimePointer(now),
		},
		AuditID: "pid_71000004-0000-4000-8000-000000000004", CorrelationID: testCorrelationID, ReceiptID: "pid_71000005-0000-4000-8000-000000000005",
	}}
	ids := []string{"pid_71000004-0000-4000-8000-000000000004", "pid_71000005-0000-4000-8000-000000000005"}
	handler, err := NewRecoveryPublicHTTPHandler(stub, RecoveryPublicHandlerConfig{NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil }})
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, testCorrelationID, "startRecoveryBackup", nil, http.MethodPost, "/api/v1/recovery/backups", `{"backup_id":"`+testRecoveryBackupID+`","retention_days":30}`)
	request.Header.Set("Idempotency-Key", "recovery-backup-0001")
	request.Header.Set("If-Match", `"0"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func recoveryTimePointer(value time.Time) *time.Time { return &value }
