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

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type legacyOutboxRepositoryFixture struct{}

func (*legacyOutboxRepositoryFixture) ClaimOutbox(context.Context, string, string, int, int) ([]DiscoveryOutboxEvent, error) {
	return nil, nil
}
func (*legacyOutboxRepositoryFixture) AcknowledgeOutbox(context.Context, domain.Scope, string, string, string, string) error {
	return nil
}
func (*legacyOutboxRepositoryFixture) RetryOutbox(context.Context, domain.Scope, string, string, string, int, string) error {
	return nil
}

var _ OutboxRepository = (*legacyOutboxRepositoryFixture)(nil)
var _ TopicOutboxRepository = (*DiscoveryRepository)(nil)

func TestDiscoveryRepositoryClaimsOnlyExactOutboxTopicAndPreservesPayloadBytes(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	payload, marshalErr := json.Marshal(map[string]string{
		"environment_id": identity.Scope.EnvironmentID().String(), "integration_id": "pid_40000005-0000-4000-8000-000000000005",
		"job_id": "pid_40000004-0000-4000-8000-000000000004", "organization_id": identity.Scope.OrganizationID().String(),
		"request_digest": strings.Repeat("a", 64), "sync_id": "pid_40000006-0000-4000-8000-000000000006", "workspace_id": identity.Scope.WorkspaceID().String(),
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	digest := sha256.Sum256(payload)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryRepository(t, database)
	envelope, marshalErr := json.Marshal(map[string]any{"items": []DiscoveryOutboxEvent{{
		OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(),
		ID: "pid_40000003-0000-4000-8000-000000000003", Topic: "discovery-jobs", DeterministicKey: "sync:pid_40000006-0000-4000-8000-000000000006",
		PayloadVersion: 1, Payload: payload, PayloadDigest: digest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(30 * time.Second),
	}}})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	database.responses[postgresExecutionClaimOutboxTopicSQL] = envelope
	claimed, err := repository.ClaimOutboxTopic(context.Background(), "discovery-jobs", "worker-a", "lease-token-00000001", 30, 10)
	if err != nil || len(claimed) != 1 || !bytes.Equal(claimed[0].Payload, payload) || !bytes.Equal(claimed[0].PayloadDigest, digest[:]) {
		t.Fatalf("claim=%#v err=%v", claimed, err)
	}
	if database.query != postgresExecutionClaimOutboxTopicSQL || !reflect.DeepEqual(database.args, []any{"discovery-jobs", "worker-a", "lease-token-00000001", 30, 10}) {
		t.Fatalf("query=%q args=%#v", database.query, database.args)
	}
	if _, err := repository.ClaimOutboxTopic(context.Background(), "runtime-events", "worker-a", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("foreign topic error=%v", err)
	}
}

func TestDiscoveryRepositoryHeartbeatsOnlyTheExactTopicLeaseSet(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresExecutionHeartbeatOutboxTopicSQL: json.RawMessage(`{"id":"discovery-jobs","lease_expires_at":"` + time.Now().UTC().Add(30*time.Second).Format(time.RFC3339Nano) + `","remaining_count":2}`),
	}}
	repository := newTestDiscoveryRepository(t, database)
	result, err := repository.HeartbeatOutboxTopic(context.Background(), "discovery-jobs", "worker-a", "lease-token-00000001", 30, 2)
	if err != nil || result.ID != "discovery-jobs" || result.LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("heartbeat=%#v err=%v", result, err)
	}
	want := []any{"discovery-jobs", "worker-a", "lease-token-00000001", 30, 2}
	if database.query != postgresExecutionHeartbeatOutboxTopicSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("query=%q args=%#v", database.query, database.args)
	}
	database.responses[postgresExecutionHeartbeatOutboxTopicSQL] = json.RawMessage(`{"id":"discovery-jobs","lease_expires_at":"` + time.Now().UTC().Add(30*time.Second).Format(time.RFC3339Nano) + `","remaining_count":1}`)
	if _, err := repository.HeartbeatOutboxTopic(context.Background(), "discovery-jobs", "worker-a", "lease-token-00000001", 30, 2); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("short lease-set response error=%v", err)
	}
	for _, input := range []struct {
		topic string
		count int
	}{{topic: "runtime-events", count: 2}, {topic: "discovery-jobs", count: 0}, {topic: "discovery-jobs", count: 11}} {
		if _, err := repository.HeartbeatOutboxTopic(context.Background(), input.topic, "worker-a", "lease-token-00000001", 30, input.count); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("topic=%q count=%d error=%v", input.topic, input.count, err)
		}
	}
}

func TestDiscoveryRepositoryUsesTopicFencedOutboxTransitions(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	id := "pid_40000013-0000-4000-8000-000000000013"
	providerAck := "sha256:" + strings.Repeat("a", 64)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresExecutionAckOutboxTopicSQL:   json.RawMessage(`{"id":"` + id + `","published_at":"2026-08-20T00:00:00Z","provider_ack":"` + providerAck + `","remaining_count":1}`),
		postgresExecutionRetryOutboxTopicSQL: json.RawMessage(`{"id":"` + id + `","available_at":"` + time.Now().UTC().Add(30*time.Second).Format(time.RFC3339Nano) + `","remaining_count":0}`),
	}}
	repository := newTestDiscoveryRepository(t, database)
	ack, err := repository.AcknowledgeOutboxTopic(context.Background(), "discovery-jobs", identity.Scope, id, "worker-a", "lease-token-00000001", providerAck)
	if err != nil || ack.RemainingCount != 1 {
		t.Fatalf("ack=%#v err=%v", ack, err)
	}
	retry, err := repository.RetryOutboxTopic(context.Background(), "discovery-jobs", identity.Scope, id, "worker-a", "lease-token-00000001", 30, "queue_publish_unknown")
	if err != nil || retry.RemainingCount != 0 {
		t.Fatalf("retry=%#v err=%v", retry, err)
	}
	for _, badAck := range []string{"secret-value", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63)} {
		if _, err := repository.AcknowledgeOutboxTopic(context.Background(), "discovery-jobs", identity.Scope, id, "worker-a", "lease-token-00000001", badAck); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("bad acknowledgement %q error=%v", badAck, err)
		}
	}
	if _, err := repository.RetryOutboxTopic(context.Background(), "discovery-jobs", identity.Scope, id, "worker-a", "lease-token-00000001", 30, "provider said secret-value"); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("raw retry code error=%v", err)
	}
}

type discoveryCallDatabase struct {
	workflowCallDatabase
	responses map[string]json.RawMessage
	errors    map[string]error
	schema    string
}

type blockingDiscoveryPrincipalDatabase struct{}

func (*blockingDiscoveryPrincipalDatabase) SchemaVersion(context.Context) (string, error) {
	return DiscoveryExecutionSchemaVersion, nil
}

func (*blockingDiscoveryPrincipalDatabase) QueryJSON(ctx context.Context, query string, _ ...any) (json.RawMessage, error) {
	if query == postgresExecutionReadySQL {
		return json.RawMessage(`true`), nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*blockingDiscoveryPrincipalDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected exec")
}

func (database *discoveryCallDatabase) SchemaVersion(context.Context) (string, error) {
	if database.schema != "" {
		return database.schema, nil
	}
	return DiscoverySchemaVersion, nil
}

func (database *discoveryCallDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	database.query, database.args = query, append([]any(nil), args...)
	if err := database.errors[query]; err != nil {
		return nil, err
	}
	if response, ok := database.responses[query]; ok {
		return response, nil
	}
	return json.RawMessage(`true`), nil
}

func newTestDiscoveryRepository(t *testing.T, database *discoveryCallDatabase) *DiscoveryRepository {
	t.Helper()
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestNewDiscoveryRepositoryRequiresLiveDiscoverySchema(t *testing.T) {
	database := &discoveryCallDatabase{schema: CoreSchemaVersion, responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`)}}
	if _, err := newDiscoveryRepositoryUnchecked(database); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("v9 schema accepted for discovery repository: %v", err)
	}
}

func TestDiscoveryRepositoryConstructorsBoundEveryReadinessProbe(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{name: "schema", run: func() error {
			_, err := newDiscoveryRepository(&blockingDiscoveryExecutionDatabase{}, 10*time.Millisecond)
			return err
		}},
		{name: "principal", run: func() error {
			_, err := newDiscoveryRepositoryForAuthority(&blockingDiscoveryPrincipalDatabase{}, DiscoveryDatabaseAuthorityAPI, 10*time.Millisecond)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := time.Now()
			if err := test.run(); !errors.Is(err, ErrRepositoryConfiguration) {
				t.Fatalf("error=%v", err)
			}
			if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
				t.Fatalf("unbounded constructor elapsed=%s", elapsed)
			}
		})
	}
}

func TestDiscoveryRepositoryCreatesReferenceOnlyIntegrationInExactScope(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresDiscoveryReadySQL:             json.RawMessage(`true`),
		postgresDiscoveryCreateIntegrationSQL: json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws","connector_version":"1.0.0","display_name":"Production AWS","state":"pending","version":1,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`),
	}}
	repository := newTestDiscoveryRepository(t, database)
	integration, err := repository.CreateIntegration(context.Background(), identity, IntegrationCreate{ID: "pid_40000001-0000-4000-8000-000000000001", Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "Production AWS", Configuration: json.RawMessage(`{"role_reference":"ref:aws/role/production"}`)})
	if err != nil || integration.State != "pending" {
		t.Fatalf("integration=%#v err=%v", integration, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integration.ID, "aws", "1.0.0", "Production AWS", json.RawMessage(`{"role_reference":"ref:aws/role/production"}`), ""}
	if database.query != postgresDiscoveryCreateIntegrationSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("query/args=%q/%#v", database.query, database.args)
	}
	if _, err := repository.CreateIntegration(context.Background(), identity, IntegrationCreate{ID: integration.ID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "Leaky", Configuration: json.RawMessage(`{"access_token":"plaintext"}`)}); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("secret config error=%v", err)
	}
}

func TestDiscoveryRepositoryStrictEntityKeysetsAndOutboxLeases(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	id := "pid_40000002-0000-4000-8000-000000000002"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`), postgresDiscoveryEntityPageSQL: json.RawMessage(`{"items":[{"id":"` + id + `","kind":"aws_account","display_name":"Production","stable_fields":{},"state":"active","first_seen_at":"2026-08-19T00:00:00Z","last_seen_at":"2026-08-19T00:01:00Z","version":1}],"next_id":"` + id + `"}`)}}
	repository := newTestDiscoveryRepository(t, database)
	page, err := repository.ListInventoryEntityPage(context.Background(), identity.Scope, "", 1)
	if err != nil || len(page.Items) != 1 || page.NextID != id {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	database.responses[postgresDiscoveryEntityPageSQL] = json.RawMessage(`{"items":[],"next_id":"` + id + `"}`)
	if _, err := repository.ListInventoryEntityPage(context.Background(), identity.Scope, "", 1); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("hostile keyset error=%v", err)
	}

	now := time.Now().Add(30 * time.Second).UTC()
	database.responses[postgresDiscoveryClaimOutboxSQL] = json.RawMessage(`{"items":[{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","id":"pid_40000003-0000-4000-8000-000000000003","topic":"discovery-jobs","deterministic_key":"sync:000000000001","payload_version":1,"payload":{"job_id":"` + id + `"},"payload_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":1,"lease_expires_at":"` + now.Format(time.RFC3339) + `"}]}`)
	claimed, err := repository.ClaimOutbox(context.Background(), "worker-a", "lease-token-00000001", 30, 10)
	if err != nil || len(claimed) != 1 || claimed[0].Attempt != 1 {
		t.Fatalf("claim=%#v err=%v", claimed, err)
	}
}

func TestDiscoveryRepositorySnapshotApplyCarriesOneCompleteCandidate(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`), postgresDiscoveryApplySnapshotSQL: json.RawMessage(`{"snapshot_id":"pid_40000004-0000-4000-8000-000000000004","discovered_count":1,"changed_count":0,"removed_count":0,"committed_at":"2026-08-19T00:00:00Z"}`)}}
	repository := newTestDiscoveryRepository(t, database)
	candidate := CompleteSnapshot{IntegrationID: "pid_40000001-0000-4000-8000-000000000001", SyncID: "pid_40000002-0000-4000-8000-000000000002", SnapshotID: "pid_40000004-0000-4000-8000-000000000004", Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/exact/manifest.json", ManifestChecksum: make([]byte, 32), CollectedAt: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC), CursorProvider: "aws", CursorValue: "cursor-1", Entities: json.RawMessage(`[{"id":"pid_40000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`)}
	result, err := repository.ApplyCompleteSnapshot(context.Background(), identity.Scope, candidate)
	if err != nil || result.DiscoveredCount != 1 {
		t.Fatalf("apply=%#v err=%v", result, err)
	}
	if database.query != postgresDiscoveryApplySnapshotSQL || len(database.args) != 16 {
		t.Fatalf("snapshot query/args=%q/%d", database.query, len(database.args))
	}
}

func TestDiscoveryRepositoryGatewayEnrollmentUsesTheDistinctAudienceContract(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`), postgresDiscoveryGatewayEnrollSQL: json.RawMessage(`{"id":"pid_40000008-0000-4000-8000-000000000008","device_id":"pid_40000006-0000-4000-8000-000000000006","audience":"runtime-gateway","issued_at":"` + now.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}`)}}
	repository := newTestDiscoveryRepository(t, database)
	input := GatewayEnrollment{DeviceID: "pid_40000006-0000-4000-8000-000000000006", EnrollmentID: "pid_40000007-0000-4000-8000-000000000007", CredentialID: "pid_40000008-0000-4000-8000-000000000008", Audience: "runtime-gateway", KeyReference: "ref:kms/gateway/key-0001", TokenHash: make([]byte, 32), Salt: make([]byte, 16), PublicKey: make([]byte, 32), ExpiresAt: expiresAt}
	result, err := repository.EnrollGateway(context.Background(), identity.Scope, input)
	if err != nil || result.Audience != "runtime-gateway" {
		t.Fatalf("enrollment=%#v err=%v", result, err)
	}
	if database.query != postgresDiscoveryGatewayEnrollSQL || len(database.args) != 11 {
		t.Fatalf("gateway query/args=%q/%d", database.query, len(database.args))
	}
}

func TestDiscoveryRepositoryRejectsHostileLeaseShapesAndTransitions(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`), postgresDiscoveryClaimJobsSQL: json.RawMessage(`{"items":[{"organization_id":"bad","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","id":"pid_40000001-0000-4000-8000-000000000001","kind":"discovery","authority_id":"pid_40000002-0000-4000-8000-000000000002","attempt":1,"lease_expires_at":"2026-08-19T01:00:00Z"}]}`)}}
	repository := newTestDiscoveryRepository(t, database)
	if _, err := repository.ClaimDiscoveryJobs(context.Background(), "worker", "lease-token-00000001", "discovery", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("malformed scope=%v", err)
	}
	database.responses[postgresDiscoveryClaimJobsSQL] = json.RawMessage(`{"items":[],"unexpected":true}`)
	if _, err := repository.ClaimDiscoveryJobs(context.Background(), "worker", "lease-token-00000001", "discovery", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unknown field=%v", err)
	}
	if _, err := repository.ClaimDiscoveryJobs(context.Background(), "", "short", "discovery", 1, 101); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("invalid claim=%v", err)
	}
	database.responses[postgresDiscoveryClaimSchedulesSQL] = json.RawMessage(`{"items":[{"organization_id":"bad","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","id":"pid_40000001-0000-4000-8000-000000000001","integration_id":"pid_40000002-0000-4000-8000-000000000002","next_run_at":"2026-08-19T00:00:00Z","lease_expires_at":"2026-08-19T01:00:00Z"}]}`)
	if _, err := repository.ClaimDiscoverySchedules(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("malformed schedule lease=%v", err)
	}
	database.responses[postgresDiscoveryClaimProjectionSQL] = json.RawMessage(`{"items":[{"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","snapshot_id":"bad","kind":"risk","version":"v1","input_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":1,"lease_expires_at":"2026-08-19T01:00:00Z"}]}`)
	if _, err := repository.ClaimProjectionWork(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("malformed projection lease=%v", err)
	}
	identity := fixtureRequestIdentity(t)
	database.responses[postgresDiscoveryCompleteJobSQL] = json.RawMessage(`{"id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff","state":"succeeded"}`)
	if err := repository.CompleteDiscoveryJob(context.Background(), identity.Scope, "pid_40000001-0000-4000-8000-000000000001", "worker", "lease-token-00000001", make([]byte, 32), false, ""); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("wrong transition result=%v", err)
	}
	validScope := `"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003"`
	database.responses[postgresDiscoveryClaimJobsSQL] = json.RawMessage(`{"items":[{` + validScope + `,"id":"pid_40000001-0000-4000-8000-000000000001","kind":"discovery","authority_id":"pid_40000002-0000-4000-8000-000000000002","attempt":101,"lease_expires_at":"2026-08-19T01:00:00-07:00"}]}`)
	if _, err := repository.ClaimDiscoveryJobs(context.Background(), "worker", "lease-token-00000001", "discovery", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("over-attempt job lease=%v", err)
	}
	database.responses[postgresDiscoveryClaimProjectionSQL] = json.RawMessage(`{"items":[{` + validScope + `,"snapshot_id":"pid_40000003-0000-4000-8000-000000000003","kind":"risk","version":"` + strings.Repeat("v", 65) + `","input_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":101,"lease_expires_at":"2026-08-19T01:00:00-07:00"}]}`)
	if _, err := repository.ClaimProjectionWork(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("oversized projection lease=%v", err)
	}
	database.responses[postgresDiscoveryClaimOutboxSQL] = json.RawMessage(`{"items":[{` + validScope + `,"id":"pid_40000004-0000-4000-8000-000000000004","topic":"discovery-jobs","deterministic_key":"` + strings.Repeat("k", 257) + `","payload_version":1,"payload":{},"payload_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":101,"lease_expires_at":"2026-08-19T01:00:00-07:00"}]}`)
	if _, err := repository.ClaimOutbox(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("hostile outbox lease=%v", err)
	}
}

func TestDiscoveryRepositoryRejectsMissingAndNullClaimItems(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresDiscoveryReadySQL:           json.RawMessage(`true`),
		postgresDiscoveryClaimJobsSQL:       json.RawMessage(`{}`),
		postgresDiscoveryClaimSchedulesSQL:  json.RawMessage(`{"items":null}`),
		postgresDiscoveryClaimProjectionSQL: json.RawMessage(`{}`),
	}}
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ClaimDiscoveryJobs(context.Background(), "worker", "lease-token-00000001", "discovery", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("missing job items error=%v", err)
	}
	if _, err := repository.ClaimDiscoverySchedules(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("null schedule items error=%v", err)
	}
	if _, err := repository.ClaimProjectionWork(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("missing projection items error=%v", err)
	}
}

func TestDiscoveryRepositoryRejectsImpossibleLeaseExpirations(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`)}}
	repository := newTestDiscoveryRepository(t, database)
	scope := `"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003"`
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	farFuture := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339Nano)
	database.responses[postgresDiscoveryClaimJobsSQL] = json.RawMessage(`{"items":[{` + scope + `,"id":"pid_40000001-0000-4000-8000-000000000001","kind":"discovery","authority_id":"pid_40000002-0000-4000-8000-000000000002","attempt":1,"lease_expires_at":"` + past + `"}]}`)
	if _, err := repository.ClaimDiscoveryJobs(context.Background(), "worker", "lease-token-00000001", "discovery", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("expired job lease=%v", err)
	}
	database.responses[postgresDiscoveryClaimSchedulesSQL] = json.RawMessage(`{"items":[{` + scope + `,"id":"pid_40000003-0000-4000-8000-000000000003","integration_id":"pid_40000004-0000-4000-8000-000000000004","next_run_at":"` + past + `","lease_expires_at":"` + farFuture + `"}]}`)
	if _, err := repository.ClaimDiscoverySchedules(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unbounded schedule lease=%v", err)
	}
	database.responses[postgresDiscoveryClaimProjectionSQL] = json.RawMessage(`{"items":[{` + scope + `,"snapshot_id":"pid_40000005-0000-4000-8000-000000000005","kind":"risk","version":"v1","input_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":1,"lease_expires_at":"` + past + `"}]}`)
	if _, err := repository.ClaimProjectionWork(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("expired projection lease=%v", err)
	}
	database.responses[postgresDiscoveryClaimOutboxSQL] = json.RawMessage(`{"items":[{` + scope + `,"id":"pid_40000006-0000-4000-8000-000000000006","topic":"discovery-jobs","deterministic_key":"sync:000000000001","payload_version":1,"payload":{},"payload_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":1,"lease_expires_at":"` + farFuture + `"}]}`)
	if _, err := repository.ClaimOutbox(context.Background(), "worker", "lease-token-00000001", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unbounded outbox lease=%v", err)
	}
}

func TestDiscoveryRepositoryRejectsMismatchedLifecycleResults(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`)}}
	repository := newTestDiscoveryRepository(t, database)
	nextRun := time.Now().Add(time.Hour).UTC()
	completedAt := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	database.responses[postgresDiscoveryCompleteScheduleSQL] = json.RawMessage(`{"id":"pid_41000001-0000-4000-8000-000000000001","state":"disabled","next_run_at":"` + nextRun.Format(time.RFC3339Nano) + `","version":2}`)
	if _, err := repository.CompleteDiscoverySchedule(context.Background(), identity.Scope, DiscoveryScheduleCompletion{ID: "pid_41000001-0000-4000-8000-000000000001", Worker: "worker", LeaseToken: "lease-token-00000001", Outcome: "advanced", NextRunAt: nextRun}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("mismatched schedule completion=%v", err)
	}
	database.responses[postgresDiscoveryFinishJobSQL] = json.RawMessage(`{"id":"pid_41000002-0000-4000-8000-000000000002","state":"failed","attempt":1,"completed_at":"` + completedAt + `"}`)
	if _, err := repository.FinishDiscoveryJob(context.Background(), identity.Scope, DiscoveryJobCompletion{ID: "pid_41000002-0000-4000-8000-000000000002", Worker: "worker", LeaseToken: "lease-token-00000001", Outcome: "succeeded"}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("mismatched job completion=%v", err)
	}
	database.responses[postgresDiscoveryFinishProjectionSQL] = json.RawMessage(`{"snapshot_id":"pid_41000003-0000-4000-8000-000000000003","kind":"risk","state":"failed","attempt":1}`)
	if _, err := repository.FinishProjectionWork(context.Background(), identity.Scope, ProjectionWorkCompletion{SnapshotID: "pid_41000003-0000-4000-8000-000000000003", Kind: "risk", Version: "v1", Worker: "worker", LeaseToken: "lease-token-00000001", Outcome: "succeeded"}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("mismatched projection completion=%v", err)
	}
}

func TestDiscoveryRepositoryRejectsExpiredIssuedRecords(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`)}}
	repository := newTestDiscoveryRepository(t, database)
	issued := time.Now().Add(-2 * time.Hour).UTC()
	expired := time.Now().Add(-time.Hour).UTC()
	times := `"issued_at":"` + issued.Format(time.RFC3339Nano) + `","expires_at":"` + expired.Format(time.RFC3339Nano) + `"`
	sensorID := "pid_42000001-0000-4000-8000-000000000001"
	tokenID := "pid_42000002-0000-4000-8000-000000000002"
	database.responses[postgresDiscoveryIssueSensorTokenSQL] = json.RawMessage(`{"id":"` + tokenID + `","sensor_id":"` + sensorID + `","audience":"event-ingest",` + times + `}`)
	if _, err := repository.IssueSensorToken(context.Background(), identity.Scope, SensorTokenIssue{SensorID: sensorID, TokenID: tokenID, Salt: make([]byte, 16), TokenHash: make([]byte, 32), ExpiresAt: expired}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("expired sensor token=%v", err)
	}
	deviceID := "pid_42000003-0000-4000-8000-000000000003"
	enrollmentID := "pid_42000004-0000-4000-8000-000000000004"
	database.responses[postgresDiscoveryIssueGatewayEnrollmentSQL] = json.RawMessage(`{"id":"` + enrollmentID + `","device_id":"` + deviceID + `","audience":"runtime-gateway-enroll",` + times + `}`)
	if _, err := repository.IssueGatewayEnrollmentToken(context.Background(), identity.Scope, GatewayEnrollmentTokenIssue{ID: enrollmentID, DeviceID: deviceID, Salt: make([]byte, 16), TokenHash: make([]byte, 32), ExpiresAt: expired}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("expired gateway enrollment=%v", err)
	}
	credentialID := "pid_42000005-0000-4000-8000-000000000005"
	database.responses[postgresDiscoveryGatewayEnrollSQL] = json.RawMessage(`{"id":"` + credentialID + `","device_id":"` + deviceID + `","audience":"runtime-gateway",` + times + `}`)
	if _, err := repository.EnrollGateway(context.Background(), identity.Scope, GatewayEnrollment{DeviceID: deviceID, EnrollmentID: enrollmentID, CredentialID: credentialID, Audience: "runtime-gateway", KeyReference: "ref:gateway/key-0001", TokenHash: make([]byte, 32), Salt: make([]byte, 16), PublicKey: make([]byte, 32), ExpiresAt: expired}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("expired gateway credential=%v", err)
	}
}

func TestDiscoveryRepositoryRejectsAmbiguousS3ObjectReferences(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	batchID := "pid_43000001-0000-4000-8000-000000000001"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresDiscoveryReadySQL:        json.RawMessage(`true`),
		postgresDiscoveryRuntimeBatchSQL: json.RawMessage(`{"batch_id":"` + batchID + `","replayed":false}`),
	}}
	repository := newTestDiscoveryRepository(t, database)
	for _, reference := range []string{"s3://bucket/key with space", "s3://bucket/key?version=1", "s3://bucket//key", "s3://bucket/../key", "s3://bucket/"} {
		input := RuntimeBatchCreate{SensorID: "pid_43000002-0000-4000-8000-000000000002", BatchID: batchID, JobID: "pid_43000003-0000-4000-8000-000000000003", OutboxID: "pid_43000004-0000-4000-8000-000000000004", IdempotencyKey: "runtime-batch-key-0001", PayloadDigest: make([]byte, 32), EventCount: 1, ObjectReference: reference, PayloadBytes: 1, MediaType: "application/json", SchemaVersion: "v1"}
		if _, err := repository.CreateRuntimeBatch(context.Background(), identity.Scope, input); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("reference %q error=%v", reference, err)
		}
	}
}

func TestDiscoveryRepositoryNormalizesAllLeaseInstantsToUTC(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`)}}
	repository := newTestDiscoveryRepository(t, database)
	scope := `"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003"`
	leaseExpiration := time.Now().Add(30 * time.Second).In(time.FixedZone("test", -7*60*60)).Format(time.RFC3339Nano)
	database.responses[postgresDiscoveryClaimJobsSQL] = json.RawMessage(`{"items":[{` + scope + `,"id":"pid_40000001-0000-4000-8000-000000000001","kind":"discovery","authority_id":"pid_40000002-0000-4000-8000-000000000002","attempt":1,"lease_expires_at":"` + leaseExpiration + `"}]}`)
	jobs, err := repository.ClaimDiscoveryJobs(context.Background(), "worker", "lease-token-00000001", "discovery", 30, 10)
	if err != nil || jobs[0].LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("job UTC=%v err=%v", jobs, err)
	}
	database.responses[postgresDiscoveryClaimSchedulesSQL] = json.RawMessage(`{"items":[{` + scope + `,"id":"pid_40000003-0000-4000-8000-000000000003","integration_id":"pid_40000004-0000-4000-8000-000000000004","next_run_at":"2026-08-19T00:00:00-07:00","lease_expires_at":"` + leaseExpiration + `"}]}`)
	schedules, err := repository.ClaimDiscoverySchedules(context.Background(), "worker", "lease-token-00000001", 30, 10)
	if err != nil || schedules[0].NextRunAt.Location() != time.UTC || schedules[0].LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("schedule UTC=%v err=%v", schedules, err)
	}
	database.responses[postgresDiscoveryClaimProjectionSQL] = json.RawMessage(`{"items":[{` + scope + `,"snapshot_id":"pid_40000005-0000-4000-8000-000000000005","kind":"risk","version":"v1","input_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":1,"lease_expires_at":"` + leaseExpiration + `"}]}`)
	projections, err := repository.ClaimProjectionWork(context.Background(), "worker", "lease-token-00000001", 30, 10)
	if err != nil || projections[0].LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("projection UTC=%v err=%v", projections, err)
	}
}

func TestDiscoveryRepositoryExposesStrictTypedParentLifecycles(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	offsetNow := now.In(time.FixedZone("test", -7*60*60)).Format(time.RFC3339)
	offsetNextRun := now.Add(5 * time.Minute).In(time.FixedZone("test", -7*60*60)).Format(time.RFC3339)
	offsetExpiry := now.Add(time.Hour).In(time.FixedZone("test", -7*60*60)).Format(time.RFC3339)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresDiscoveryReadySQL:                  json.RawMessage(`true`),
		postgresDiscoveryTransitionIntegrationSQL:  json.RawMessage(`{"id":"pid_60000001-0000-4000-8000-000000000001","state":"active","version":2,"updated_at":"` + offsetNow + `"}`),
		postgresDiscoveryPutConnectionSQL:          json.RawMessage(`{"id":"pid_60000002-0000-4000-8000-000000000002","integration_id":"pid_60000001-0000-4000-8000-000000000001","provider":"aws","state":"pending","created_at":"` + offsetNow + `"}`),
		postgresDiscoveryPutScheduleSQL:            json.RawMessage(`{"id":"pid_60000003-0000-4000-8000-000000000003","integration_id":"pid_60000001-0000-4000-8000-000000000001","state":"enabled","cadence_seconds":300,"next_run_at":"` + offsetNextRun + `","version":1}`),
		postgresDiscoveryCreateSensorSQL:           json.RawMessage(`{"id":"pid_60000004-0000-4000-8000-000000000004","kind":"otlp","name":"Sensor","state":"pending","version":1,"created_at":"` + offsetNow + `"}`),
		postgresDiscoveryCreateGatewayDeviceSQL:    json.RawMessage(`{"id":"pid_60000005-0000-4000-8000-000000000005","name":"Gateway","state":"pending","version":1,"replay_floor":0,"created_at":"` + offsetNow + `"}`),
		postgresDiscoveryIssueGatewayEnrollmentSQL: json.RawMessage(`{"id":"pid_60000006-0000-4000-8000-000000000006","device_id":"pid_60000005-0000-4000-8000-000000000005","audience":"runtime-gateway-enroll","issued_at":"` + offsetNow + `","expires_at":"` + offsetExpiry + `"}`),
	}}
	repository := newTestDiscoveryRepository(t, database)
	integrationID := "pid_60000001-0000-4000-8000-000000000001"
	if result, err := repository.TransitionIntegration(context.Background(), identity.Scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil || result.State != "active" || result.UpdatedAt.Location() != time.UTC {
		t.Fatalf("integration transition=%#v err=%v", result, err)
	}
	if result, err := repository.PutIntegrationConnection(context.Background(), identity.Scope, IntegrationConnectionPut{ID: "pid_60000002-0000-4000-8000-000000000002", IntegrationID: integrationID, Provider: "aws", ConnectionReference: "ref:aws/connection-0001"}); err != nil || result.State != "pending" || result.CreatedAt.Location() != time.UTC {
		t.Fatalf("connection=%#v err=%v", result, err)
	}
	if result, err := repository.PutDiscoverySchedule(context.Background(), identity.Scope, DiscoverySchedulePut{ID: "pid_60000003-0000-4000-8000-000000000003", IntegrationID: integrationID, CadenceSeconds: 300, NextRunAt: now.Add(5 * time.Minute)}); err != nil || result.Version != 1 || result.NextRunAt.Location() != time.UTC {
		t.Fatalf("schedule=%#v err=%v", result, err)
	}
	if result, err := repository.CreateSensor(context.Background(), identity.Scope, SensorCreate{ID: "pid_60000004-0000-4000-8000-000000000004", Name: "Sensor", Kind: "otlp"}); err != nil || result.State != "pending" || result.CreatedAt.Location() != time.UTC {
		t.Fatalf("sensor=%#v err=%v", result, err)
	}
	if result, err := repository.CreateGatewayDevice(context.Background(), identity.Scope, GatewayDeviceCreate{ID: "pid_60000005-0000-4000-8000-000000000005", Name: "Gateway"}); err != nil || result.State != "pending" || result.CreatedAt.Location() != time.UTC {
		t.Fatalf("device=%#v err=%v", result, err)
	}
	if result, err := repository.IssueGatewayEnrollmentToken(context.Background(), identity.Scope, GatewayEnrollmentTokenIssue{ID: "pid_60000006-0000-4000-8000-000000000006", DeviceID: "pid_60000005-0000-4000-8000-000000000005", Salt: make([]byte, 16), TokenHash: make([]byte, 32), ExpiresAt: now.Add(time.Hour)}); err != nil || result.Audience != "runtime-gateway-enroll" || result.IssuedAt.Location() != time.UTC || result.ExpiresAt.Location() != time.UTC {
		t.Fatalf("enrollment token=%#v err=%v", result, err)
	}
	database.responses[postgresDiscoveryCreateSensorSQL] = json.RawMessage(`{"id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff","kind":"otlp","name":"Sensor","state":"pending","version":1,"created_at":"2026-08-19T18:00:00Z","unknown":true}`)
	if _, err := repository.CreateSensor(context.Background(), identity.Scope, SensorCreate{ID: "pid_60000004-0000-4000-8000-000000000004", Name: "Sensor", Kind: "otlp"}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("hostile sensor response=%v", err)
	}
	if _, err := repository.PutIntegrationConnection(context.Background(), identity.Scope, IntegrationConnectionPut{ID: "pid_60000002-0000-4000-8000-000000000002", IntegrationID: integrationID, Provider: "aws", ConnectionReference: "ref:AWS/hostile"}); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("hostile reference=%v", err)
	}
}

func TestDiscoveryRepositoryExposesStrictWorkerStateTransitions(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Date(2026, 8, 19, 19, 0, 0, 0, time.UTC)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresDiscoveryReadySQL:            json.RawMessage(`true`),
		postgresDiscoveryCompleteScheduleSQL: json.RawMessage(`{"id":"pid_61000001-0000-4000-8000-000000000001","state":"enabled","next_run_at":"2026-08-19T19:05:00Z","version":3}`),
		postgresDiscoveryFinishJobSQL:        json.RawMessage(`{"id":"pid_61000002-0000-4000-8000-000000000002","state":"failed","attempt":5,"completed_at":"2026-08-19T19:00:00Z"}`),
		postgresDiscoveryFinishProjectionSQL: json.RawMessage(`{"snapshot_id":"pid_61000003-0000-4000-8000-000000000003","kind":"risk","state":"retryable","attempt":1}`),
	}}
	repository := newTestDiscoveryRepository(t, database)
	if result, err := repository.CompleteDiscoverySchedule(context.Background(), identity.Scope, DiscoveryScheduleCompletion{ID: "pid_61000001-0000-4000-8000-000000000001", Worker: "worker", LeaseToken: "lease-token-00000001", Outcome: "advanced", NextRunAt: now.Add(5 * time.Minute)}); err != nil || result.State != "enabled" {
		t.Fatalf("schedule completion=%#v err=%v", result, err)
	}
	if result, err := repository.FinishDiscoveryJob(context.Background(), identity.Scope, DiscoveryJobCompletion{ID: "pid_61000002-0000-4000-8000-000000000002", Worker: "worker", LeaseToken: "lease-token-00000001", Outcome: "retryable", LastError: "failed", RetryAfterSeconds: 5}); err != nil || result.State != "failed" || result.Attempt != 5 {
		t.Fatalf("job exhaustion=%#v err=%v", result, err)
	}
	if result, err := repository.FinishProjectionWork(context.Background(), identity.Scope, ProjectionWorkCompletion{SnapshotID: "pid_61000003-0000-4000-8000-000000000003", Kind: "risk", Version: "v1", Worker: "worker", LeaseToken: "lease-token-00000001", Outcome: "retryable", LastError: "failed", RetryAfterSeconds: 5}); err != nil || result.State != "retryable" {
		t.Fatalf("projection retry=%#v err=%v", result, err)
	}
	database.responses[postgresDiscoveryFinishProjectionSQL] = json.RawMessage(`{"snapshot_id":"wrong","kind":"risk","state":"retryable","attempt":1}`)
	if _, err := repository.FinishProjectionWork(context.Background(), identity.Scope, ProjectionWorkCompletion{SnapshotID: "pid_61000003-0000-4000-8000-000000000003", Kind: "risk", Version: "v1", Worker: "worker", LeaseToken: "lease-token-00000001", Outcome: "retryable", LastError: "failed", RetryAfterSeconds: 5}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("hostile projection transition=%v", err)
	}
}
