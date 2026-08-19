package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

type discoveryCallDatabase struct {
	workflowCallDatabase
	responses map[string]json.RawMessage
	errors    map[string]error
	schema    string
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
	repository, err := NewDiscoveryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestNewDiscoveryRepositoryRequiresLiveDiscoverySchema(t *testing.T) {
	database := &discoveryCallDatabase{schema: CoreSchemaVersion, responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`)}}
	if _, err := NewDiscoveryRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("v9 schema accepted for discovery repository: %v", err)
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

	now := time.Date(2026, 8, 19, 0, 2, 0, 0, time.UTC)
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
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`), postgresDiscoveryGatewayEnrollSQL: json.RawMessage(`{"id":"pid_40000008-0000-4000-8000-000000000008","device_id":"pid_40000006-0000-4000-8000-000000000006","audience":"runtime-gateway","issued_at":"2026-08-19T00:00:00Z","expires_at":"2026-08-20T00:00:00Z"}`)}}
	repository := newTestDiscoveryRepository(t, database)
	input := GatewayEnrollment{DeviceID: "pid_40000006-0000-4000-8000-000000000006", EnrollmentID: "pid_40000007-0000-4000-8000-000000000007", CredentialID: "pid_40000008-0000-4000-8000-000000000008", Audience: "runtime-gateway", KeyReference: "ref:kms/gateway/key-0001", TokenHash: make([]byte, 32), Salt: make([]byte, 16), PublicKey: make([]byte, 32), ExpiresAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
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
	identity := fixtureRequestIdentity(t)
	database.responses[postgresDiscoveryCompleteJobSQL] = json.RawMessage(`{"id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff","state":"succeeded"}`)
	if err := repository.CompleteDiscoveryJob(context.Background(), identity.Scope, "pid_40000001-0000-4000-8000-000000000001", "worker", "lease-token-00000001", make([]byte, 32), false, ""); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("wrong transition result=%v", err)
	}
}
