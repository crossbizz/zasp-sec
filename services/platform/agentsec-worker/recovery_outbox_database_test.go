package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recoveryOutboxDatabaseFake struct {
	statements []string
	arguments  [][]any
	malformed  bool
}

func (fake *recoveryOutboxDatabaseFake) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	fake.statements = append(fake.statements, statement)
	fake.arguments = append(fake.arguments, append([]any(nil), arguments...))
	switch statement {
	case recoveryOutboxReadySQL:
		return json.RawMessage(`true`), nil
	case recoveryOutboxClaimSQL:
		if fake.malformed {
			return json.RawMessage(`{"items":[{"secret":"must-not-leak"}]}`), nil
		}
		event := recoveryBackupOutboxFixture()
		return json.Marshal(map[string]any{"items": []map[string]any{{
			"organization_id": event.OrganizationID, "workspace_id": event.WorkspaceID, "environment_id": event.EnvironmentID,
			"outbox_id": event.ID, "topic": event.Topic, "payload": event.Payload, "payload_digest": event.PayloadDigest,
			"attempt": event.Attempt, "lease_expires_at": event.LeaseExpiresAt,
		}}})
	case recoveryOutboxHeartbeatSQL:
		return json.Marshal(map[string]any{"lease_expires_at": time.Now().UTC().Add(30 * time.Second), "renewed": 1})
	case recoveryOutboxAckSQL:
		return json.RawMessage(`{"replayed":false}`), nil
	case recoveryOutboxRetrySQL:
		return json.RawMessage(`{"state":"retryable"}`), nil
	default:
		return nil, errWorkerExecution
	}
}

func TestPostgresRecoveryOutboxAuthorityBindsExactV27Calls(t *testing.T) {
	if !strings.HasPrefix(recoveryOutboxReadySQL, "SELECT to_jsonb(") {
		t.Fatalf("readiness query is not JSON-scannable: %s", recoveryOutboxReadySQL)
	}
	database := &recoveryOutboxDatabaseFake{}
	authority, err := newPostgresRecoveryOutboxAuthority(database)
	if err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdef0123456789abcdef"
	events, err := authority.Claim(context.Background(), recoveryBackupOutboxTopic, "recovery-outbox-01", token, 30, 1)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v error=%v", events, err)
	}
	if err := authority.Heartbeat(context.Background(), recoveryBackupOutboxTopic, "recovery-outbox-01", token, 30, 1); err != nil {
		t.Fatal(err)
	}
	scope, ok := recoveryScope(events[0].OrganizationID, events[0].WorkspaceID, events[0].EnvironmentID)
	if !ok {
		t.Fatal("scope")
	}
	ack := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := authority.Acknowledge(context.Background(), scope, events[0].ID, "recovery-outbox-01", token, ack); err != nil {
		t.Fatal(err)
	}
	if err := authority.Retry(context.Background(), scope, events[0].ID, "recovery-outbox-01", token, 30, "queue_publish_unknown"); err != nil {
		t.Fatal(err)
	}
	wantClaim := []any{recoveryBackupOutboxTopic, "recovery-outbox-01", []byte(token), 30, 1}
	if len(database.arguments) != 5 || !reflect.DeepEqual(database.arguments[1], wantClaim) {
		t.Fatalf("arguments=%#v", database.arguments)
	}
	if got := database.arguments[3]; len(got) != 7 || got[3] != events[0].ID || got[4] != "recovery-outbox-01" || string(got[5].([]byte)) != token || got[6] != ack {
		t.Fatalf("ack arguments=%#v", got)
	}
}

func TestPostgresRecoveryOutboxAuthorityRejectsMalformedRows(t *testing.T) {
	database := &recoveryOutboxDatabaseFake{malformed: true}
	authority, err := newPostgresRecoveryOutboxAuthority(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Claim(context.Background(), recoveryBackupOutboxTopic, "recovery-outbox-01", "0123456789abcdef0123456789abcdef", 30, 1); err == nil {
		t.Fatal("malformed claim accepted")
	}
}

func TestRecoveryOutboxDigestUsesCanonicalPayloadBytes(t *testing.T) {
	event := recoveryBackupOutboxEvent(t)
	digest := sha256.Sum256(event.Payload)
	if event.PayloadDigest != `\x`+fmt.Sprintf("%x", digest) {
		t.Fatalf("digest=%s want=%x", event.PayloadDigest, digest)
	}
}
