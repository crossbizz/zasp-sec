package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recoveryDatabaseFake struct {
	statements []string
	arguments  [][]any
}

func (fake *recoveryDatabaseFake) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	fake.statements = append(fake.statements, statement)
	fake.arguments = append(fake.arguments, append([]any(nil), arguments...))
	switch statement {
	case recoveryWorkerReadySQL:
		return json.RawMessage(`true`), nil
	case recoveryClaimOperationSQL:
		if len(arguments) > 0 && arguments[0] == "restore" {
			manifest := recoveryWorkerManifest(recoveryWorkerScopeFromConstants())
			return json.Marshal(map[string]any{"items": []map[string]any{{"attempt": 1, "environment_id": "pid_71000003-0000-4000-8000-000000000003", "lease_expires_at": time.Now().UTC().Add(30 * time.Second), "manifest": manifest, "manifest_digest": "\\x" + manifest.SHA256, "organization_id": "pid_71000001-0000-4000-8000-000000000001", "request_digest": "\\x2727272727272727272727272727272727272727272727272727272727272727", "restore_id": "pid_71000004-0000-4000-8000-000000000004", "target_environment": "recovery-test", "workspace_id": "pid_71000002-0000-4000-8000-000000000002"}}})
		}
		return json.Marshal(map[string]any{"items": []map[string]any{{"attempt": 1, "backup_id": "pid_71000001-0000-4000-8000-000000000001", "environment_id": "pid_71000003-0000-4000-8000-000000000003", "lease_expires_at": time.Now().UTC().Add(30 * time.Second), "organization_id": "pid_71000001-0000-4000-8000-000000000001", "request_digest": "\\x2727272727272727272727272727272727272727272727272727272727272727", "retention_days": 30, "workspace_id": "pid_71000002-0000-4000-8000-000000000002"}}})
	case recoveryHeartbeatOperationSQL:
		return json.Marshal(map[string]any{"lease_expires_at": time.Now().UTC().Add(30 * time.Second)})
	case recoveryBeginHoldSQL:
		return json.RawMessage(`{"epoch":1,"state":"held"}`), nil
	case recoveryReleaseHoldSQL:
		return json.RawMessage(`{"released":true}`), nil
	case recoveryCapturePageSQL:
		return json.RawMessage(`{"items":[],"next_cursor":null,"section":"configuration"}`), nil
	case recoveryFinishBackupSQL:
		return json.RawMessage(`{"manifest_digest":"\\xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","replayed":false,"state":"succeeded"}`), nil
	case recoveryCheckpointRestoreSQL:
		return json.Marshal(map[string]any{"state": arguments[7]})
	case recoveryFinishRestoreSQL:
		return json.RawMessage(`{"replayed":false,"state":"succeeded"}`), nil
	case recoveryFailOperationSQL:
		return json.RawMessage(`{"state":"retryable"}`), nil
	case recoveryCurrentLSNSQL:
		return json.RawMessage(`"0/27"`), nil
	default:
		return nil, fmt.Errorf("unknown statement")
	}
}

func recoveryWorkerScopeFromConstants() domain.Scope {
	organization, _ := domain.ParseProductID("pid_71000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_71000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_71000003-0000-4000-8000-000000000003")
	scope, _ := domain.NewScope(organization, workspace, environment)
	return scope
}

func TestPostgresRecoveryOperationAuthorityBindsEveryLeaseTransition(t *testing.T) {
	database := &recoveryDatabaseFake{}
	authority, err := newPostgresRecoveryOperationAuthority(database)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := authority.Claim(context.Background(), "backup", "recovery-worker-1", "0123456789abcdef0123456789abcdef", 30, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	lease := recoveryOperationLease{recoveryOperationClaim: claims[0], WorkerID: "recovery-worker-1", LeaseToken: "0123456789abcdef0123456789abcdef"}
	if authority.Heartbeat(context.Background(), lease, 30) != nil || authority.BeginHold(context.Background(), lease) != nil || authority.ReleaseHold(context.Background(), lease) != nil {
		t.Fatal("lease transition failed")
	}
	page, err := authority.CapturePage(context.Background(), lease, "configuration", nil, 100)
	if err != nil || page.Section != "configuration" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if authority.FinishBackup(context.Background(), lease, recoveryWorkerManifest(claims[0].Scope)) != nil || authority.Fail(context.Background(), lease, "outcome_unknown", 30*time.Second, nil) != nil {
		t.Fatal("terminal transition failed")
	}
	if lsn, err := authority.PostgresLSN(context.Background(), claims[0].Scope); err != nil || lsn != "0/27" {
		t.Fatalf("lsn=%q err=%v", lsn, err)
	}
	if len(database.statements) != 9 {
		t.Fatalf("statements=%v", database.statements)
	}
	for index, arguments := range database.arguments {
		if index == 0 || index == 8 {
			continue
		}
		found := false
		for _, argument := range arguments {
			if token, ok := argument.([]byte); ok && string(token) == lease.LeaseToken {
				found = true
			}
		}
		if !found {
			t.Fatalf("statement %s omitted bytea lease token: %#v", database.statements[index], arguments)
		}
	}
}

func TestPostgresRecoveryOperationAuthorityDecodesAndFencesRestore(t *testing.T) {
	database := &recoveryDatabaseFake{}
	authority, err := newPostgresRecoveryOperationAuthority(database)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := authority.Claim(context.Background(), "restore", "recovery-worker-1", "0123456789abcdef0123456789abcdef", 30, 1)
	if err != nil || len(claims) != 1 || claims[0].TargetEnvironment != "recovery-test" || claims[0].Manifest == nil {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	lease := recoveryOperationLease{recoveryOperationClaim: claims[0], WorkerID: "recovery-worker-1", LeaseToken: "0123456789abcdef0123456789abcdef"}
	validation := apiserver.RecoveryValidationEvidence{State: "validated", ExpectedCounts: apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}, ObservedCounts: apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}, Evidence: recoveryEvidenceLocator(claims[0].Scope, "pid_71000008-0000-4000-8000-000000000008", "recovery_validation_v1")}
	cleanup := apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: recoveryEvidenceLocator(claims[0].Scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}
	if authority.CheckpointRestore(context.Background(), lease, "validating", "rebuilding", validation) != nil || authority.FinishRestore(context.Background(), lease, validation.ObservedCounts, validation, cleanup) != nil || authority.Fail(context.Background(), lease, "cleanup_failed", 30*time.Second, &cleanup) != nil {
		t.Fatal("restore transition failed")
	}
}
