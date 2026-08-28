package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testRecoveryBackupID  = "pid_71000001-0000-4000-8000-000000000001"
	testRecoveryRestoreID = "pid_71000002-0000-4000-8000-000000000002"
)

func recoveryManifestFixture(identity RequestIdentity) RecoveryManifestLocator {
	return RecoveryManifestLocator{
		Reference: "s3://zasp-recovery/organizations/" + identity.Scope.OrganizationID().String() + "/workspaces/" + identity.Scope.WorkspaceID().String() + "/environments/" + identity.Scope.EnvironmentID().String() + "/artifacts/pid_71000003-0000-4000-8000-000000000003",
		VersionID: "version-recovery-0001", SHA256: strings.Repeat("a", sha256.Size*2), SizeBytes: 512,
		MediaType: "application/vnd.zasp.recovery-manifest+json", Schema: "recovery_signed_manifest_v1",
		SigningKeyID: "123e4567-e89b-42d3-a456-426614174000", Signature: strings.Repeat("A", 43),
	}
}

func newTestRecoveryPublicRepository(t *testing.T, database *discoveryCallDatabase) *RecoveryPublicRepository {
	t.Helper()
	database.schema = ProductionRecoverySchemaVersion
	database.responses[postgresProductionRecoveryReadinessSQL] = json.RawMessage(`true`)
	repository, err := NewRecoveryPublicRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestRecoveryRepositoryCreatesScopedBackupAndRestoreWithExactAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestRecoveryPublicRepository(t, database)
	digest := sha256.Sum256([]byte("recovery-request"))
	database.responses[postgresRecoveryStartBackupSQL] = json.RawMessage(`{"audit_id":"pid_71000004-0000-4000-8000-000000000004","body":{"id":"` + testRecoveryBackupID + `","version":1,"state":"queued","retention_days":30,"attempt":0,"created_at":"2026-08-25T12:00:00Z"},"correlation_id":"` + testCorrelationID + `","receipt_id":"pid_71000005-0000-4000-8000-000000000005","replayed":false}`)
	backupInput := RecoveryBackupMutation{
		BackupID: testRecoveryBackupID, RetentionDays: 30, IdempotencyKey: "recovery-backup-0001", RequestDigest: digest[:],
		AuditID: "pid_71000004-0000-4000-8000-000000000004", CorrelationID: testCorrelationID, ReceiptID: "pid_71000005-0000-4000-8000-000000000005",
	}
	backup, err := repository.StartBackup(context.Background(), identity, backupInput)
	if err != nil || backup.Body.ID != testRecoveryBackupID || backup.Body.CreatedAt != now || backup.Replayed {
		t.Fatalf("backup=%#v err=%v", backup, err)
	}
	wantBackupArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), backupInput.IdempotencyKey, backupInput.BackupID, backupInput.CorrelationID, backupInput.RetentionDays, backupInput.AuditID, backupInput.ReceiptID, backupInput.RequestDigest}
	if database.query != postgresRecoveryStartBackupSQL || !reflect.DeepEqual(database.args, wantBackupArgs) {
		t.Fatalf("backup query=%q args=%#v", database.query, database.args)
	}

	manifest := recoveryManifestFixture(identity)
	manifestJSON, marshalErr := json.Marshal(manifest)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	database.responses[postgresRecoveryStartRestoreSQL] = json.RawMessage(`{"audit_id":"pid_71000006-0000-4000-8000-000000000006","body":{"id":"` + testRecoveryRestoreID + `","version":1,"state":"queued","target_environment":"recovery-e2e-01","attempt":0,"manifest":` + string(manifestJSON) + `,"created_at":"2026-08-25T12:00:00Z"},"correlation_id":"` + testCorrelationID + `","receipt_id":"pid_71000007-0000-4000-8000-000000000007","replayed":false}`)
	restoreInput := RecoveryRestoreMutation{
		RestoreID: testRecoveryRestoreID, TargetEnvironment: "recovery-e2e-01", Manifest: manifest, IdempotencyKey: "recovery-restore-0001", RequestDigest: digest[:],
		AuditID: "pid_71000006-0000-4000-8000-000000000006", CorrelationID: testCorrelationID, ReceiptID: "pid_71000007-0000-4000-8000-000000000007",
	}
	restore, err := repository.StartRestore(context.Background(), identity, restoreInput)
	if err != nil || restore.Body.ID != testRecoveryRestoreID || restore.Body.TargetEnvironment != "recovery-e2e-01" || restore.Body.Manifest == nil || restore.Replayed {
		t.Fatalf("restore=%#v err=%v", restore, err)
	}
	wantRestoreArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), restoreInput.IdempotencyKey, restoreInput.RestoreID, restoreInput.TargetEnvironment, restoreInput.CorrelationID, restoreInput.AuditID, restoreInput.ReceiptID, restoreInput.RequestDigest, json.RawMessage(manifestJSON), digestBytes(t, manifest.SHA256)}
	if database.query != postgresRecoveryStartRestoreSQL || !reflect.DeepEqual(database.args, wantRestoreArgs) {
		t.Fatalf("restore query=%q args=%#v", database.query, database.args)
	}
}

func TestRecoveryRepositoryAcceptsReplayWithOriginalStableCorrelationAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestRecoveryPublicRepository(t, database)
	digest := sha256.Sum256([]byte("recovery-request"))
	storedCorrelationID := "pid_71000008-0000-4000-8000-000000000008"
	database.responses[postgresRecoveryStartBackupSQL] = json.RawMessage(`{"audit_id":"pid_71000004-0000-4000-8000-000000000004","body":{"id":"` + testRecoveryBackupID + `","version":1,"state":"queued","retention_days":30,"attempt":0,"created_at":"2026-08-25T12:00:00Z"},"correlation_id":"` + storedCorrelationID + `","receipt_id":"pid_71000005-0000-4000-8000-000000000005","replayed":true}`)
	result, err := repository.StartBackup(context.Background(), identity, RecoveryBackupMutation{
		BackupID: testRecoveryBackupID, RetentionDays: 30, IdempotencyKey: "recovery-backup-0001", RequestDigest: digest[:],
		AuditID: "pid_71000006-0000-4000-8000-000000000006", CorrelationID: testCorrelationID, ReceiptID: "pid_71000007-0000-4000-8000-000000000007",
	})
	if err != nil || !result.Replayed || result.CorrelationID != storedCorrelationID {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestRecoveryRepositoryStrictlyDecodesStateAndPublicLocator(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestRecoveryPublicRepository(t, database)
	manifestJSON, err := json.Marshal(recoveryManifestFixture(identity))
	if err != nil {
		t.Fatal(err)
	}
	database.responses[postgresRecoveryGetBackupSQL] = json.RawMessage(`{"id":"` + testRecoveryBackupID + `","version":3,"state":"succeeded","retention_days":30,"attempt":1,"manifest":` + string(manifestJSON) + `,"created_at":"2026-08-25T12:00:00Z","started_at":"2026-08-25T12:00:01Z","completed_at":"2026-08-25T12:00:02Z"}`)
	backup, err := repository.GetBackup(context.Background(), identity, testRecoveryBackupID)
	if err != nil || backup.Manifest == nil || backup.State != "succeeded" {
		t.Fatalf("backup=%#v err=%v", backup, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), testRecoveryBackupID}
	if database.query != postgresRecoveryGetBackupSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("query=%q args=%#v", database.query, database.args)
	}

	for name, payload := range map[string]string{
		"queued manifest": `{"id":"` + testRecoveryBackupID + `","version":1,"state":"queued","retention_days":30,"attempt":0,"manifest":` + string(manifestJSON) + `,"created_at":"2026-08-25T12:00:00Z"}`,
		"secret field":    `{"id":"` + testRecoveryBackupID + `","version":1,"state":"queued","retention_days":30,"attempt":0,"created_at":"2026-08-25T12:00:00Z","kms_key_arn":"secret"}`,
		"foreign locator": strings.Replace(`{"id":"`+testRecoveryBackupID+`","version":3,"state":"succeeded","retention_days":30,"attempt":1,"manifest":`+string(manifestJSON)+`,"created_at":"2026-08-25T12:00:00Z","started_at":"2026-08-25T12:00:01Z","completed_at":"2026-08-25T12:00:02Z"}`, identity.Scope.OrganizationID().String(), "pid_ffffffff-ffff-4fff-8fff-ffffffffffff", 1),
	} {
		t.Run(name, func(t *testing.T) {
			database.responses[postgresRecoveryGetBackupSQL] = json.RawMessage(payload)
			if _, err := repository.GetBackup(context.Background(), identity, testRecoveryBackupID); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRecoveryRepositoryAcceptsExactPrestartDispatchExhaustion(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestRecoveryPublicRepository(t, database)
	database.responses[postgresRecoveryGetBackupSQL] = json.RawMessage(`{"id":"` + testRecoveryBackupID + `","version":2,"state":"failed","retention_days":30,"attempt":0,"error_code":"exhausted","created_at":"2026-08-25T12:00:00Z","completed_at":"2026-08-25T12:00:02Z"}`)
	if backup, err := repository.GetBackup(context.Background(), identity, testRecoveryBackupID); err != nil || backup.State != "failed" || backup.Attempt != 0 || backup.StartedAt != nil {
		t.Fatalf("backup=%#v err=%v", backup, err)
	}
	manifestJSON, err := json.Marshal(recoveryManifestFixture(identity))
	if err != nil {
		t.Fatal(err)
	}
	database.responses[postgresRecoveryGetRestoreSQL] = json.RawMessage(`{"id":"` + testRecoveryRestoreID + `","version":2,"state":"failed","target_environment":"recovery-e2e-01","attempt":0,"manifest":` + string(manifestJSON) + `,"error_code":"exhausted","created_at":"2026-08-25T12:00:00Z","completed_at":"2026-08-25T12:00:02Z"}`)
	if restore, err := repository.GetRestore(context.Background(), identity, testRecoveryRestoreID); err != nil || restore.State != "failed" || restore.Attempt != 0 || restore.StartedAt != nil {
		t.Fatalf("restore=%#v err=%v", restore, err)
	}
}

func TestRecoveryRepositoryRejectsNonV27AndHostileInputs(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}, schema: AttackLabExecutionSchemaVersion}
	if _, err := NewRecoveryPublicRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("constructor error=%v", err)
	}
	database.schema = ProductionRecoverySchemaVersion
	database.responses[postgresProductionRecoveryReadinessSQL] = json.RawMessage(`false`)
	if _, err := NewRecoveryPublicRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("readiness error=%v", err)
	}
	database.responses[postgresProductionRecoveryReadinessSQL] = json.RawMessage(`true`)
	repository := newTestRecoveryPublicRepository(t, database)
	digest := sha256.Sum256([]byte("recovery-request"))
	input := RecoveryBackupMutation{BackupID: testRecoveryBackupID, RetentionDays: 6, IdempotencyKey: "recovery-backup-0001", RequestDigest: digest[:], AuditID: "pid_71000004-0000-4000-8000-000000000004", CorrelationID: testCorrelationID, ReceiptID: "pid_71000005-0000-4000-8000-000000000005"}
	if _, err := repository.StartBackup(context.Background(), identity, input); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("retention error=%v", err)
	}
}

func TestRecoveryRestoreRejectsExpectedAndObservedCountDrift(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	evidence := RecoveryArtifactLocator{
		Reference: "s3://zasp-recovery/organizations/" + identity.Scope.OrganizationID().String() + "/workspaces/" + identity.Scope.WorkspaceID().String() + "/environments/" + identity.Scope.EnvironmentID().String() + "/artifacts/pid_71000008-0000-4000-8000-000000000008",
		VersionID: "version-validation-1", SHA256: strings.Repeat("b", 64), SizeBytes: 128, MediaType: "application/json", Schema: "recovery_validation_v1",
	}
	validation := RecoveryValidationEvidence{State: "validated", ExpectedCounts: RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}, ObservedCounts: RecoveryCounts{Assets: 4, Findings: 2, Policies: 1}, Evidence: evidence}
	if validRecoveryValidationEvidence(validation, identity.Scope) {
		t.Fatal("count drift accepted")
	}
}

func digestBytes(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
