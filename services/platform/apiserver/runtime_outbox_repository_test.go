package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRuntimeOutboxRepositoryBindsExactV15TopicLifecycle(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	payload := json.RawMessage(`{"batch_id":"pid_75000001-0000-4000-8000-000000000001","job_id":"pid_75000002-0000-4000-8000-000000000002","generation":1,"pipeline_version":15,"artifact_reference":"s3://zasp-runtime/runtime/v15/raw.json","artifact_key":"runtime/v15/raw.json","artifact_version_id":"version-1","artifact_checksum":"` + strings.Repeat("a", 64) + `","artifact_size_bytes":4,"payload_media_type":"application/json","payload_schema_version":"runtime-event-v1","event_count":1,"request_digest":"` + strings.Repeat("b", 64) + `"}`)
	digest := sha256.Sum256(payload)
	id := "pid_75000003-0000-4000-8000-000000000003"
	leaseExpiration := time.Now().UTC().Add(30 * time.Second)
	providerAck := "sha256:" + strings.Repeat("c", 64)
	database := &discoveryCallDatabase{schema: RuntimeIngestReconciliationSchemaVersion, responses: map[string]json.RawMessage{
		postgresRuntimeOutboxReadySQL:     json.RawMessage(`{"ready":true}`),
		postgresRuntimeClaimOutboxSQL:     runtimeMustJSON(t, map[string]any{"items": []DiscoveryOutboxEvent{{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: id, Topic: RuntimeOutboxTopic, DeterministicKey: "runtime:pid_75000001-0000-4000-8000-000000000001", PayloadVersion: 15, Payload: payload, PayloadDigest: digest[:], Attempt: 1, LeaseExpiresAt: leaseExpiration}}}),
		postgresRuntimeHeartbeatOutboxSQL: json.RawMessage(`{"id":"runtime-events","lease_expires_at":"` + leaseExpiration.Format(time.RFC3339Nano) + `","remaining_count":1}`),
		postgresRuntimeAckOutboxSQL:       json.RawMessage(`{"id":"` + id + `","published_at":"2026-08-20T00:00:00Z","provider_ack":"` + providerAck + `","remaining_count":0}`),
		postgresRuntimeRetryOutboxSQL:     json.RawMessage(`{"id":"` + id + `","available_at":"` + time.Now().UTC().Add(30*time.Second).Format(time.RFC3339Nano) + `","remaining_count":0}`),
	}}
	repository, err := NewRuntimeOutboxRepository(database)
	if err != nil || repository.Ready(context.Background()) != nil {
		t.Fatalf("repository=%v err=%v", repository, err)
	}
	claimed, err := repository.ClaimOutboxTopic(context.Background(), RuntimeOutboxTopic, "runtime-outbox-01", "0123456789abcdef", 30, 10)
	if err != nil || len(claimed) != 1 || !bytes.Equal(claimed[0].Payload, payload) || !bytes.Equal(claimed[0].PayloadDigest, digest[:]) {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	if _, err := repository.HeartbeatOutboxTopic(context.Background(), RuntimeOutboxTopic, "runtime-outbox-01", "0123456789abcdef", 30, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.AcknowledgeOutboxTopic(context.Background(), RuntimeOutboxTopic, identity.Scope, id, "runtime-outbox-01", "0123456789abcdef", providerAck); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RetryOutboxTopic(context.Background(), RuntimeOutboxTopic, identity.Scope, id, "runtime-outbox-01", "0123456789abcdef", 30, "queue_publish_unknown"); err != nil {
		t.Fatal(err)
	}
	wantClaim := []any{RuntimeOutboxTopic, "runtime-outbox-01", "0123456789abcdef", 30, 10}
	if got := database.callsFor(postgresRuntimeClaimOutboxSQL); len(got) != 1 || !reflect.DeepEqual(got[0], wantClaim) {
		t.Fatalf("claim calls=%#v", got)
	}
}

func TestRuntimeOutboxRepositoryRejectsForeignTopicAndHostileOutput(t *testing.T) {
	if repository, err := NewRuntimeOutboxRepository(nil); repository != nil || !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("nil repository=%v err=%v", repository, err)
	}
	database := &discoveryCallDatabase{schema: RuntimeIngestReconciliationSchemaVersion, responses: map[string]json.RawMessage{postgresRuntimeOutboxReadySQL: json.RawMessage(`{"ready":true}`), postgresRuntimeClaimOutboxSQL: json.RawMessage(`{"items":[{"secret":"must-not-leak"}]}`)}}
	repository, err := NewRuntimeOutboxRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ClaimOutboxTopic(context.Background(), "discovery-jobs", "runtime-outbox-01", "0123456789abcdef", 30, 10); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("foreign topic error=%v", err)
	}
	if _, err := repository.ClaimOutboxTopic(context.Background(), RuntimeOutboxTopic, "runtime-outbox-01", "0123456789abcdef", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("hostile output error=%v", err)
	}
}

func (database *discoveryCallDatabase) callsFor(statement string) [][]any {
	var calls [][]any
	for index, query := range database.queries {
		if query == statement {
			calls = append(calls, database.arguments[index])
		}
	}
	return calls
}

func runtimeMustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
