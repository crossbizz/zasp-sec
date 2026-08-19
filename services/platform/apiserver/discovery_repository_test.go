package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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

func TestDiscoveryRepositoryNormalizesAllLeaseInstantsToUTC(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresDiscoveryReadySQL: json.RawMessage(`true`)}}
	repository := newTestDiscoveryRepository(t, database)
	scope := `"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003"`
	database.responses[postgresDiscoveryClaimJobsSQL] = json.RawMessage(`{"items":[{` + scope + `,"id":"pid_40000001-0000-4000-8000-000000000001","kind":"discovery","authority_id":"pid_40000002-0000-4000-8000-000000000002","attempt":1,"lease_expires_at":"2026-08-19T01:00:00-07:00"}]}`)
	jobs, err := repository.ClaimDiscoveryJobs(context.Background(), "worker", "lease-token-00000001", "discovery", 30, 10)
	if err != nil || jobs[0].LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("job UTC=%v err=%v", jobs, err)
	}
	database.responses[postgresDiscoveryClaimSchedulesSQL] = json.RawMessage(`{"items":[{` + scope + `,"id":"pid_40000003-0000-4000-8000-000000000003","integration_id":"pid_40000004-0000-4000-8000-000000000004","next_run_at":"2026-08-19T00:00:00-07:00","lease_expires_at":"2026-08-19T01:00:00-07:00"}]}`)
	schedules, err := repository.ClaimDiscoverySchedules(context.Background(), "worker", "lease-token-00000001", 30, 10)
	if err != nil || schedules[0].NextRunAt.Location() != time.UTC || schedules[0].LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("schedule UTC=%v err=%v", schedules, err)
	}
	database.responses[postgresDiscoveryClaimProjectionSQL] = json.RawMessage(`{"items":[{` + scope + `,"snapshot_id":"pid_40000005-0000-4000-8000-000000000005","kind":"risk","version":"v1","input_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":1,"lease_expires_at":"2026-08-19T01:00:00-07:00"}]}`)
	projections, err := repository.ClaimProjectionWork(context.Background(), "worker", "lease-token-00000001", 30, 10)
	if err != nil || projections[0].LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("projection UTC=%v err=%v", projections, err)
	}
}

func TestDiscoveryRepositoryExposesStrictTypedParentLifecycles(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Date(2026, 8, 19, 18, 0, 0, 0, time.UTC)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresDiscoveryReadySQL:                  json.RawMessage(`true`),
		postgresDiscoveryTransitionIntegrationSQL:  json.RawMessage(`{"id":"pid_60000001-0000-4000-8000-000000000001","state":"active","version":2,"updated_at":"2026-08-19T18:00:00Z"}`),
		postgresDiscoveryPutConnectionSQL:          json.RawMessage(`{"id":"pid_60000002-0000-4000-8000-000000000002","integration_id":"pid_60000001-0000-4000-8000-000000000001","provider":"aws","state":"pending","created_at":"2026-08-19T18:00:00Z"}`),
		postgresDiscoveryPutScheduleSQL:            json.RawMessage(`{"id":"pid_60000003-0000-4000-8000-000000000003","integration_id":"pid_60000001-0000-4000-8000-000000000001","state":"enabled","cadence_seconds":300,"next_run_at":"2026-08-19T18:05:00Z","version":1}`),
		postgresDiscoveryCreateSensorSQL:           json.RawMessage(`{"id":"pid_60000004-0000-4000-8000-000000000004","kind":"otlp","name":"Sensor","state":"pending","version":1,"created_at":"2026-08-19T18:00:00Z"}`),
		postgresDiscoveryCreateGatewayDeviceSQL:    json.RawMessage(`{"id":"pid_60000005-0000-4000-8000-000000000005","name":"Gateway","state":"pending","version":1,"replay_floor":0,"created_at":"2026-08-19T18:00:00Z"}`),
		postgresDiscoveryIssueGatewayEnrollmentSQL: json.RawMessage(`{"id":"pid_60000006-0000-4000-8000-000000000006","device_id":"pid_60000005-0000-4000-8000-000000000005","audience":"runtime-gateway-enroll","issued_at":"2026-08-19T18:00:00Z","expires_at":"2026-08-19T19:00:00Z"}`),
	}}
	repository := newTestDiscoveryRepository(t, database)
	integrationID := "pid_60000001-0000-4000-8000-000000000001"
	if result, err := repository.TransitionIntegration(context.Background(), identity.Scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil || result.State != "active" {
		t.Fatalf("integration transition=%#v err=%v", result, err)
	}
	if result, err := repository.PutIntegrationConnection(context.Background(), identity.Scope, IntegrationConnectionPut{ID: "pid_60000002-0000-4000-8000-000000000002", IntegrationID: integrationID, Provider: "aws", ConnectionReference: "ref:aws/connection-0001"}); err != nil || result.State != "pending" {
		t.Fatalf("connection=%#v err=%v", result, err)
	}
	if result, err := repository.PutDiscoverySchedule(context.Background(), identity.Scope, DiscoverySchedulePut{ID: "pid_60000003-0000-4000-8000-000000000003", IntegrationID: integrationID, CadenceSeconds: 300, NextRunAt: now.Add(5 * time.Minute)}); err != nil || result.Version != 1 {
		t.Fatalf("schedule=%#v err=%v", result, err)
	}
	if result, err := repository.CreateSensor(context.Background(), identity.Scope, SensorCreate{ID: "pid_60000004-0000-4000-8000-000000000004", Name: "Sensor", Kind: "otlp"}); err != nil || result.State != "pending" {
		t.Fatalf("sensor=%#v err=%v", result, err)
	}
	if result, err := repository.CreateGatewayDevice(context.Background(), identity.Scope, GatewayDeviceCreate{ID: "pid_60000005-0000-4000-8000-000000000005", Name: "Gateway"}); err != nil || result.State != "pending" {
		t.Fatalf("device=%#v err=%v", result, err)
	}
	if result, err := repository.IssueGatewayEnrollmentToken(context.Background(), identity.Scope, GatewayEnrollmentTokenIssue{ID: "pid_60000006-0000-4000-8000-000000000006", DeviceID: "pid_60000005-0000-4000-8000-000000000005", Salt: make([]byte, 16), TokenHash: make([]byte, 32), ExpiresAt: now.Add(time.Hour)}); err != nil || result.Audience != "runtime-gateway-enroll" {
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
