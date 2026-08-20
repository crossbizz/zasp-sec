package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newTestDiscoveryPublicRepository(t *testing.T, database *discoveryCallDatabase) *DiscoveryRepository {
	t.Helper()
	database.schema = DiscoveryExecutionSchemaVersion
	database.responses[postgresExecutionReadySQL] = json.RawMessage(`true`)
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestDiscoveryPublicRepositoryStrictlyReadsSyncHistoryAndFreshness(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	syncID := "pid_82000002-0000-4000-8000-000000000002"
	snapshotID := "pid_82000003-0000-4000-8000-000000000003"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryPublicRepository(t, database)
	syncPayload := `{"id":"` + syncID + `","integration_id":"` + integrationID + `","trigger_kind":"manual","status":"succeeded","attempt":1,"requested_at":"2026-08-19T00:00:00Z","started_at":"2026-08-19T00:00:01Z","completed_at":"2026-08-19T00:00:02Z","discovered_count":7,"changed_count":2,"removed_count":1,"snapshot_id":"` + snapshotID + `","last_error_code":null,"retry_at":null}`
	database.responses[postgresExecutionPublicSyncDetailSQL] = json.RawMessage(`{"body":` + syncPayload + `,"version":3}`)

	result, err := repository.GetIntegrationSync(context.Background(), identity.Scope, integrationID, syncID)
	if err != nil || result.Value.ID != syncID || result.Value.Status != "succeeded" || result.Value.CompletedAt == nil || result.Value.CompletedAt.Location() != time.UTC || result.Version != 3 {
		t.Fatalf("sync=%#v err=%v", result, err)
	}
	wantArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID}
	if database.query != postgresExecutionPublicSyncDetailSQL || !reflect.DeepEqual(database.args, wantArgs) {
		t.Fatalf("query/args=%q/%#v", database.query, database.args)
	}

	database.responses[postgresExecutionPublicSyncHistorySQL] = json.RawMessage(`{"items":[` + syncPayload + `],"next_requested_at":"2026-08-19T00:00:00Z","next_id":"` + syncID + `"}`)
	page, err := repository.ListIntegrationSyncs(context.Background(), identity.Scope, integrationID, nil, "", 1)
	if err != nil || len(page.Items) != 1 || page.NextRequestedAt == nil || page.NextID != syncID {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if len(database.args) != 7 || database.args[5] != nil {
		t.Fatalf("first page cursor args=%#v", database.args)
	}

	database.responses[postgresExecutionPublicFreshnessSQL] = json.RawMessage(`{"integration_id":"` + integrationID + `","version":4,"last_good":{"snapshot_id":"` + snapshotID + `","collected_at":"2026-08-19T00:00:02Z","discovered_count":7,"changed_count":2,"removed_count":1},"latest_sync":` + syncPayload + `,"projections":{"risk":{"state":"current","snapshot_id":"` + snapshotID + `","completed_at":"2026-08-19T00:00:03Z","last_error_code":null},"graph":{"state":"pending","snapshot_id":"` + snapshotID + `","completed_at":null,"last_error_code":null},"search":{"state":"degraded","snapshot_id":"` + snapshotID + `","completed_at":"2026-08-19T00:00:03Z","last_error_code":"terminal"}},"updated_at":"2026-08-19T00:00:03Z"}`)
	freshness, err := repository.GetIntegrationFreshness(context.Background(), identity.Scope, integrationID)
	if err != nil || freshness.IntegrationID != integrationID || freshness.Version != 4 || freshness.LastGood == nil || freshness.Projections.Risk.State != "current" {
		t.Fatalf("freshness=%#v err=%v", freshness, err)
	}
}

func TestDiscoveryPublicRepositoryRejectsUnboundSyncHistoryPagination(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	newerID := "pid_82000003-0000-4000-8000-000000000003"
	olderID := "pid_82000002-0000-4000-8000-000000000002"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryPublicRepository(t, database)
	item := func(id, requested string) string {
		return `{"id":"` + id + `","integration_id":"` + integrationID + `","trigger_kind":"manual","status":"queued","attempt":0,"requested_at":"` + requested + `","started_at":null,"completed_at":null,"discovered_count":0,"changed_count":0,"removed_count":0,"snapshot_id":null,"last_error_code":null,"retry_at":null}`
	}
	for name, payload := range map[string]string{
		"ascending items":      `{"items":[` + item(olderID, "2026-08-19T00:00:00Z") + `,` + item(newerID, "2026-08-19T00:00:01Z") + `],"next_requested_at":null,"next_id":null}`,
		"cursor not last":      `{"items":[` + item(newerID, "2026-08-19T00:00:01Z") + `,` + item(olderID, "2026-08-19T00:00:00Z") + `],"next_requested_at":"2026-08-19T00:00:01Z","next_id":"` + newerID + `"}`,
		"cursor on short page": `{"items":[` + item(olderID, "2026-08-19T00:00:00Z") + `],"next_requested_at":"2026-08-19T00:00:00Z","next_id":"` + olderID + `"}`,
		"empty page cursor":    `{"items":[],"next_requested_at":"2026-08-19T00:00:00Z","next_id":"` + olderID + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			database.responses[postgresExecutionPublicSyncHistorySQL] = json.RawMessage(payload)
			if _, err := repository.ListIntegrationSyncs(context.Background(), identity.Scope, integrationID, nil, "", 2); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("error=%v payload=%s", err, payload)
			}
		})
	}

	inputAt := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	database.responses[postgresExecutionPublicSyncHistorySQL] = json.RawMessage(`{"items":[` + item(newerID, "2026-08-19T00:00:01Z") + `],"next_requested_at":null,"next_id":null}`)
	if _, err := repository.ListIntegrationSyncs(context.Background(), identity.Scope, integrationID, &inputAt, olderID, 2); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("cursor-bound error=%v", err)
	}
}

func TestDiscoveryPublicRepositoryRejectsHostileReadOutputs(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	syncID := "pid_82000002-0000-4000-8000-000000000002"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryPublicRepository(t, database)
	for name, payload := range map[string]string{
		"unknown field":       `{"id":"` + syncID + `","integration_id":"` + integrationID + `","trigger_kind":"manual","status":"queued","attempt":0,"requested_at":"2026-08-19T00:00:00Z","started_at":null,"completed_at":null,"discovered_count":0,"changed_count":0,"removed_count":0,"snapshot_id":null,"last_error_code":null,"retry_at":null,"job_id":"leak"}`,
		"foreign integration": `{"id":"` + syncID + `","integration_id":"pid_82000009-0000-4000-8000-000000000009","trigger_kind":"manual","status":"queued","attempt":0,"requested_at":"2026-08-19T00:00:00Z","started_at":null,"completed_at":null,"discovered_count":0,"changed_count":0,"removed_count":0,"snapshot_id":null,"last_error_code":null,"retry_at":null}`,
		"raw provider error":  `{"id":"` + syncID + `","integration_id":"` + integrationID + `","trigger_kind":"manual","status":"failed","attempt":1,"requested_at":"2026-08-19T00:00:00Z","started_at":null,"completed_at":"2026-08-19T00:00:01Z","discovered_count":0,"changed_count":0,"removed_count":0,"snapshot_id":null,"last_error_code":"dial tcp 10.0.0.1:443","retry_at":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			database.responses[postgresExecutionPublicSyncDetailSQL] = json.RawMessage(`{"body":` + payload + `,"version":1}`)
			if _, err := repository.GetIntegrationSync(context.Background(), identity.Scope, integrationID, syncID); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestDiscoveryPublicRepositoryReadsSingletonSchedule(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryPublicRepository(t, database)
	database.responses[postgresExecutionPublicScheduleDetailSQL] = json.RawMessage(`{"integration_id":"` + integrationID + `","cadence_seconds":3600,"state":"enabled","time_zone":"UTC","next_run_at":"2026-08-19T01:00:00Z","version":2,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:01Z"}`)
	schedule, err := repository.GetIntegrationSchedule(context.Background(), identity.Scope, integrationID)
	if err != nil || schedule.Version != 2 || schedule.NextRunAt == nil || schedule.NextRunAt.Location() != time.UTC {
		t.Fatalf("schedule=%#v err=%v", schedule, err)
	}
}

func TestDiscoveryPublicRepositoryStrictlyMutatesSyncAndSchedule(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	syncID := "pid_82000002-0000-4000-8000-000000000002"
	jobID := "pid_82000003-0000-4000-8000-000000000003"
	outboxID := "pid_82000004-0000-4000-8000-000000000004"
	auditID := "pid_82000005-0000-4000-8000-000000000005"
	correlationID := "pid_82000006-0000-4000-8000-000000000006"
	receiptID := "pid_82000007-0000-4000-8000-000000000007"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryPublicRepository(t, database)
	syncBody := `{"id":"` + syncID + `","integration_id":"` + integrationID + `","trigger_kind":"manual","status":"queued","attempt":0,"requested_at":"2026-08-19T00:00:00Z","started_at":null,"completed_at":null,"discovered_count":0,"changed_count":0,"removed_count":0,"snapshot_id":null,"last_error_code":null,"retry_at":null}`
	database.responses[postgresExecutionPublicRequestSyncSQL] = json.RawMessage(`{"body":` + syncBody + `,"version":1,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`)
	digest := sha256.Sum256([]byte("sync-intent"))
	request := PublicSyncRequest{IntegrationID: integrationID, IdempotencyKey: "sync-public-idempotency", ExpectedVersion: 1, SyncID: syncID, JobID: jobID, OutboxID: outboxID, RequestDigest: digest[:], ParserVersion: "parser-v1", ToolVersion: "tool-v1", AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	result, err := repository.RequestIntegrationSync(context.Background(), identity, request)
	if err != nil || result.Value.ID != syncID || result.Version != 1 || result.Replayed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	wantArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, request.IdempotencyKey, int64(1), syncID, jobID, outboxID, request.RequestDigest, "parser-v1", "tool-v1", auditID, correlationID, receiptID}
	if database.query != postgresExecutionPublicRequestSyncSQL || !reflect.DeepEqual(database.args, wantArgs) {
		t.Fatalf("query/args=%q/%#v", database.query, database.args)
	}

	scheduleBody := `{"integration_id":"` + integrationID + `","cadence_seconds":3600,"state":"enabled","time_zone":"UTC","next_run_at":"2026-08-19T01:00:00Z","version":1,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:01Z"}`
	database.responses[postgresExecutionPublicPutScheduleSQL] = json.RawMessage(`{"body":` + scheduleBody + `,"version":1,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`)
	schedule, err := repository.PutIntegrationSchedule(context.Background(), identity, PublicSchedulePut{IntegrationID: integrationID, IdempotencyKey: "schedule-public-idempotency", ExpectedVersion: 0, CadenceSeconds: 3600, State: "enabled", AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID})
	if err != nil || schedule.Version != 1 || schedule.Value.State != "enabled" {
		t.Fatalf("schedule=%#v err=%v", schedule, err)
	}

	deletedBody := `{"integration_id":"` + integrationID + `","cadence_seconds":3600,"state":"deleted","time_zone":"UTC","next_run_at":null,"version":2,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:02Z"}`
	database.responses[postgresExecutionPublicDeleteScheduleSQL] = json.RawMessage(`{"body":` + deletedBody + `,"version":2,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`)
	deleted, err := repository.DeleteIntegrationSchedule(context.Background(), identity, PublicScheduleDelete{IntegrationID: integrationID, IdempotencyKey: "schedule-delete-idempotency", ExpectedVersion: 1, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID})
	if err != nil || deleted.Value.State != "deleted" || deleted.Value.NextRunAt != nil {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
}

func TestDiscoveryPublicRepositoryRejectsHostileMutationOutputs(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	syncID := "pid_82000002-0000-4000-8000-000000000002"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryPublicRepository(t, database)
	digest := sha256.Sum256([]byte("sync-intent"))
	input := PublicSyncRequest{IntegrationID: integrationID, IdempotencyKey: "sync-public-idempotency", ExpectedVersion: 1, SyncID: syncID, JobID: "pid_82000003-0000-4000-8000-000000000003", OutboxID: "pid_82000004-0000-4000-8000-000000000004", RequestDigest: digest[:], ParserVersion: "parser-v1", ToolVersion: "tool-v1", AuditID: "pid_82000005-0000-4000-8000-000000000005", CorrelationID: "pid_82000006-0000-4000-8000-000000000006", ReceiptID: "pid_82000007-0000-4000-8000-000000000007"}
	base := `{"body":{"id":"` + syncID + `","integration_id":"` + integrationID + `","trigger_kind":"manual","status":"queued","attempt":0,"requested_at":"2026-08-19T00:00:00Z","started_at":null,"completed_at":null,"discovered_count":0,"changed_count":0,"removed_count":0,"snapshot_id":null,"last_error_code":null,"retry_at":null},"version":2,"audit_id":"` + input.AuditID + `","correlation_id":"` + input.CorrelationID + `","receipt_id":"` + input.ReceiptID + `","replayed":false}`
	for name, payload := range map[string]string{
		"missing required body field": strings.Replace(base, `,"retry_at":null`, "", 1),
		"unexpected envelope field":   strings.TrimSuffix(base, "}") + `,"provider_error":"leak"}`,
		"non replay identity drift":   strings.Replace(base, input.AuditID, "pid_82000008-0000-4000-8000-000000000008", 1),
	} {
		t.Run(name, func(t *testing.T) {
			database.responses[postgresExecutionPublicRequestSyncSQL] = json.RawMessage(payload)
			if _, err := repository.RequestIntegrationSync(context.Background(), identity, input); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestDiscoveryPublicRepositoryAcceptsReceiptFreePATMutation(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	identity.CSRFToken = ""
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	syncID := "pid_82000002-0000-4000-8000-000000000002"
	auditID := "pid_82000005-0000-4000-8000-000000000005"
	correlationID := "pid_82000006-0000-4000-8000-000000000006"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryPublicRepository(t, database)
	database.responses[postgresExecutionPublicRequestSyncSQL] = json.RawMessage(`{"body":{"id":"` + syncID + `","integration_id":"` + integrationID + `","trigger_kind":"manual","status":"queued","attempt":0,"requested_at":"2026-08-19T00:00:00Z","started_at":null,"completed_at":null,"discovered_count":0,"changed_count":0,"removed_count":0,"snapshot_id":null,"last_error_code":null,"retry_at":null},"version":1,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"","replayed":false}`)
	digest := sha256.Sum256([]byte("sync-intent"))
	result, err := repository.RequestIntegrationSync(context.Background(), identity, PublicSyncRequest{
		IntegrationID: integrationID, IdempotencyKey: "sync-pat-idempotency", ExpectedVersion: 1,
		SyncID: syncID, JobID: "pid_82000003-0000-4000-8000-000000000003", OutboxID: "pid_82000004-0000-4000-8000-000000000004",
		RequestDigest: digest[:], ParserVersion: "parser-v1", ToolVersion: "tool-v1", AuditID: auditID, CorrelationID: correlationID,
	})
	if err != nil || result.ReceiptID != "" || result.Value.ID != syncID {
		t.Fatalf("PAT result=%#v err=%v", result, err)
	}
}
