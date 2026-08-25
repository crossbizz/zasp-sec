package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
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
	case recoveryFailOperationSQL:
		return json.RawMessage(`{"state":"retryable"}`), nil
	case recoveryCurrentLSNSQL:
		return json.RawMessage(`"0/27"`), nil
	default:
		return nil, fmt.Errorf("unknown statement")
	}
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
	if authority.FinishBackup(context.Background(), lease, recoveryWorkerManifest(claims[0].Scope)) != nil || authority.Fail(context.Background(), lease, "outcome_unknown", 30*time.Second) != nil {
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
