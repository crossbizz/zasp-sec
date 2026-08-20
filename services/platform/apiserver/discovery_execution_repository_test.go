package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type blockingDiscoveryExecutionDatabase struct{}

func (*blockingDiscoveryExecutionDatabase) SchemaVersion(ctx context.Context) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func (*blockingDiscoveryExecutionDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("unexpected query")
}

func (*blockingDiscoveryExecutionDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected exec")
}

func newTestDiscoveryExecutionRepository(t *testing.T, database *discoveryCallDatabase, authority string) *DiscoveryExecutionRepository {
	t.Helper()
	database.schema = DiscoveryExecutionSchemaVersion
	database.responses[postgresExecutionReadySQL] = json.RawMessage(`true`)
	database.responses[postgresExecutionPrincipalReadySQL] = json.RawMessage(`true`)
	repository, err := NewDiscoveryExecutionRepository(database, authority)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestDiscoveryExecutionRepositoryStrictlyHydratesCollectionInput(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Now().UTC().Add(30 * time.Second)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityWorker)
	jobID := "pid_80000001-0000-4000-8000-000000000001"
	integrationID := "pid_80000002-0000-4000-8000-000000000002"
	connectionID := "pid_80000003-0000-4000-8000-000000000003"
	snapshotID := "pid_80000005-0000-4000-8000-000000000005"
	database.responses[postgresExecutionJobInputSQL] = json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","job_id":"` + jobID + `","attempt":1,"lease_expires_at":"` + now.Format(time.RFC3339Nano) + `","sync_id":"pid_80000004-0000-4000-8000-000000000004","integration_id":"` + integrationID + `","connection_id":"` + connectionID + `","snapshot_id":"` + snapshotID + `","generation":1,"provider":"aws","collector_version":"collector_v1","credential_class":"aws_assume_role","credential_reference":"ref:aws/external-id/customer-0001","subject_kind":"aws_account","subject_id":"123456789012","cursor_provider":null,"cursor_version":null,"cursor_value":null,"parser_version":"parser_v1","tool_version":"tool_v1","configuration":{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}}`)
	input, err := repository.GetDiscoveryJobInput(context.Background(), identity.Scope, jobID, "worker-01", "lease-token-000000000001")
	if err != nil || input.JobID != jobID || input.ExpectedSubject.ID != "123456789012" || input.LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("input=%#v err=%v", input, err)
	}
	database.responses[postgresExecutionJobInputSQL] = json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","job_id":"` + jobID + `","attempt":2,"lease_expires_at":"` + now.Format(time.RFC3339Nano) + `","sync_id":"pid_80000004-0000-4000-8000-000000000004","integration_id":"` + integrationID + `","connection_id":"` + connectionID + `","snapshot_id":"` + snapshotID + `","generation":1,"provider":"aws","collector_version":"collector_v1","credential_class":"aws_assume_role","credential_reference":"ref:aws/external-id/customer-0001","subject_kind":"aws_account","subject_id":"123456789012","cursor_provider":"aws","cursor_version":"cursor_v1","cursor_value":"page-101","parser_version":"parser_v1","tool_version":"tool_v1","configuration":{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"},"checkpoint_version":1,"checkpoint_digest":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","checkpoint_manifest_reference":"s3://zasp-evidence/organizations/pid_00000001-0000-4000-8000-000000000001/workspaces/pid_00000002-0000-4000-8000-000000000002/environments/pid_00000003-0000-4000-8000-000000000003/artifacts/pid_80100002-0000-4000-8000-000000000002","checkpoint_manifest_key":"organizations/pid_00000001-0000-4000-8000-000000000001/workspaces/pid_00000002-0000-4000-8000-000000000002/environments/pid_00000003-0000-4000-8000-000000000003/artifacts/pid_80100002-0000-4000-8000-000000000002","checkpoint_manifest_version_id":"version-0001","checkpoint_manifest_checksum":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","checkpoint_manifest_size_bytes":128,"checkpoint_manifest_media_type":"application/json","checkpoint_manifest_schema_version":"raw-manifest-v1"}`)
	input, err = repository.GetDiscoveryJobInput(context.Background(), identity.Scope, jobID, "worker-01", "lease-token-000000000001")
	if err != nil || input.CheckpointVersion != 1 || input.CursorValue == nil || *input.CursorValue != "page-101" || input.CheckpointManifestVersionID != "version-0001" || len(input.CheckpointDigest) != 32 {
		t.Fatalf("checkpoint input=%#v err=%v", input, err)
	}
	database.responses[postgresExecutionJobInputSQL] = json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","job_id":"` + jobID + `","attempt":1,"lease_expires_at":"` + now.Format(time.RFC3339Nano) + `","sync_id":"pid_80000004-0000-4000-8000-000000000004","integration_id":"` + integrationID + `","connection_id":"` + connectionID + `","snapshot_id":"` + snapshotID + `","generation":1,"provider":"aws","collector_version":"collector_v1","credential_class":"aws_assume_role","credential_reference":"ref:aws/external-id/customer-0001","subject_kind":"aws_account","subject_id":"123456789012","cursor_provider":null,"cursor_version":null,"cursor_value":null,"parser_version":"parser_v1","tool_version":"tool_v1","configuration":{},"access_token":"leak"}`)
	if _, err := repository.GetDiscoveryJobInput(context.Background(), identity.Scope, jobID, "worker-01", "lease-token-000000000001"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unknown output field error=%v", err)
	}
}

func TestDiscoveryExecutionRepositoryCheckpointsPartialCollectionForReclaim(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	jobID := "pid_80100001-0000-4000-8000-000000000001"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityWorker)
	updated := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	digest := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	database.responses[postgresExecutionCheckpointPartialSQL] = json.RawMessage(`{"id":"` + jobID + `","version":1,"checkpoint_digest":"` + digest + `","cursor_provider":"aws","cursor_version":"cursor_v1","cursor_value":"page-101","manifest_version_id":"version-0001","updated_at":"` + updated + `"}`)
	input := ExecutionPartialCheckpoint{JobID: jobID, Worker: "worker-01", LeaseToken: "lease-token-000000000001", ExpectedVersion: 0, CursorProvider: collection.ProviderAWS, CursorVersion: "cursor_v1", CursorValue: "page-101", ManifestReference: "s3://zasp-evidence/organizations/pid_00000001-0000-4000-8000-000000000001/workspaces/pid_00000002-0000-4000-8000-000000000002/environments/pid_00000003-0000-4000-8000-000000000003/artifacts/pid_80100002-0000-4000-8000-000000000002", ManifestKey: "organizations/pid_00000001-0000-4000-8000-000000000001/workspaces/pid_00000002-0000-4000-8000-000000000002/environments/pid_00000003-0000-4000-8000-000000000003/artifacts/pid_80100002-0000-4000-8000-000000000002", ManifestVersionID: "version-0001", ManifestChecksum: bytes.Repeat([]byte{1}, 32), ManifestSizeBytes: 128, ManifestMediaType: "application/json", ManifestSchemaVersion: "raw-manifest-v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1"}
	result, err := repository.CheckpointPartialDiscoveryJob(context.Background(), identity.Scope, input)
	if err != nil || result.Version != 1 || len(result.CheckpointDigest) != 32 || result.UpdatedAt.Location() != time.UTC {
		t.Fatalf("partial checkpoint=%#v err=%v", result, err)
	}
	database.responses[postgresExecutionCheckpointPartialSQL] = json.RawMessage(`{"id":"` + jobID + `","version":1,"checkpoint_digest":"` + digest + `","cursor_provider":"aws","cursor_version":"cursor_v1","cursor_value":"page-101","manifest_version_id":"version-0001","updated_at":"` + updated + `","secret":"leak"}`)
	if _, err := repository.CheckpointPartialDiscoveryJob(context.Background(), identity.Scope, input); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("hostile checkpoint output error=%v", err)
	}
}

func TestDiscoveryExecutionRepositoryRejectsWrongAuthorityAndExpiredLease(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	database.schema = DiscoveryExecutionSchemaVersion
	database.responses[postgresExecutionReadySQL] = json.RawMessage(`true`)
	database.responses[postgresExecutionPrincipalReadySQL] = json.RawMessage(`true`)
	if _, err := NewDiscoveryExecutionRepository(database, "zasp_discovery_authority"); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("unsafe authority error=%v", err)
	}
	repository := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityWorker)
	identity := fixtureRequestIdentity(t)
	database.responses[postgresExecutionHeartbeatJobSQL] = json.RawMessage(`{"id":"pid_80000001-0000-4000-8000-000000000001","lease_expires_at":"` + time.Now().UTC().Add(-time.Millisecond).Format(time.RFC3339Nano) + `"}`)
	if _, err := repository.HeartbeatDiscoveryJob(context.Background(), identity.Scope, JobHeartbeat{JobID: "pid_80000001-0000-4000-8000-000000000001", Worker: "worker-01", LeaseToken: "lease-token-000000000001", LeaseSeconds: 30}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("expired heartbeat output error=%v", err)
	}
}

func TestDiscoveryExecutionRepositoryConstructorBoundsReadinessProbe(t *testing.T) {
	started := time.Now()
	if _, err := newDiscoveryExecutionRepository(&blockingDiscoveryExecutionDatabase{}, DiscoveryExecutionAuthorityWorker, 10*time.Millisecond); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("blocking readiness error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("bounded readiness elapsed=%s", elapsed)
	}
}

func TestDiscoveryExecutionScheduleCompletionValidationIsClockIndependent(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	scheduleID := "pid_80500001-0000-4000-8000-000000000001"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityScheduler)
	past := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	database.responses[postgresExecutionCompleteScheduleSQL] = json.RawMessage(`{"id":"` + scheduleID + `","state":"enabled","next_run_at":"` + past.Format(time.RFC3339Nano) + `","version":2}`)
	if result, err := repository.CompleteDiscoverySchedule(context.Background(), identity.Scope, DiscoveryScheduleCompletion{ID: scheduleID, Worker: "scheduler-01", LeaseToken: "schedule-token-000000001", Outcome: "released", NextRunAt: past}); err != nil || !result.NextRunAt.Equal(past) {
		t.Fatalf("past schedule completion result=%#v err=%v", result, err)
	}
	future := time.Now().UTC().Add(time.Hour).Round(time.Microsecond)
	database.responses[postgresExecutionCompleteScheduleSQL] = json.RawMessage(`{"id":"` + scheduleID + `","state":"disabled","next_run_at":"` + future.Format(time.RFC3339Nano) + `","version":3}`)
	if result, err := repository.CompleteDiscoverySchedule(context.Background(), identity.Scope, DiscoveryScheduleCompletion{ID: scheduleID, Worker: "scheduler-01", LeaseToken: "schedule-token-000000001", Outcome: "disabled", NextRunAt: future}); err != nil || result.State != "disabled" {
		t.Fatalf("disabled schedule completion result=%#v err=%v", result, err)
	}
	for _, invalid := range []time.Time{{}, future.In(time.FixedZone("skew", 3600))} {
		if _, err := repository.CompleteDiscoverySchedule(context.Background(), identity.Scope, DiscoveryScheduleCompletion{ID: scheduleID, Worker: "scheduler-01", LeaseToken: "schedule-token-000000001", Outcome: "advanced", NextRunAt: invalid}); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("invalid next run %v error=%v", invalid, err)
		}
	}
}

func TestDiscoveryExecutionScheduleInputUsesDatabaseCadenceBounds(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	scheduleID := "pid_80600001-0000-4000-8000-000000000001"
	integrationID := "pid_80600002-0000-4000-8000-000000000002"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityScheduler)
	lease := time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano)
	next := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)

	for _, cadence := range []int{300, 2678400} {
		database.responses[postgresExecutionScheduleInputSQL] = json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","schedule_id":"` + scheduleID + `","integration_id":"` + integrationID + `","cadence_seconds":` + fmt.Sprint(cadence) + `,"time_zone":"UTC","next_run_at":"` + next + `","version":1,"lease_expires_at":"` + lease + `"}`)
		if _, err := repository.GetDiscoveryScheduleInput(context.Background(), identity.Scope, scheduleID, "scheduler-01", "schedule-token-000000001"); err != nil {
			t.Fatalf("cadence %d rejected: %v", cadence, err)
		}
	}
	for _, cadence := range []int{299, 2678401} {
		database.responses[postgresExecutionScheduleInputSQL] = json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","schedule_id":"` + scheduleID + `","integration_id":"` + integrationID + `","cadence_seconds":` + fmt.Sprint(cadence) + `,"time_zone":"UTC","next_run_at":"` + next + `","version":1,"lease_expires_at":"` + lease + `"}`)
		if _, err := repository.GetDiscoveryScheduleInput(context.Background(), identity.Scope, scheduleID, "scheduler-01", "schedule-token-000000001"); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("cadence %d error=%v", cadence, err)
		}
	}
}

func TestDiscoveryExecutionRepositoryStrictDeliveryReplayAndProjectionStatus(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	jobID := "pid_81000001-0000-4000-8000-000000000001"
	snapshotID := "pid_81000002-0000-4000-8000-000000000002"
	digest := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	worker := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityWorker)
	database.responses[postgresExecutionClaimDeliverySQL] = json.RawMessage(`{"id":"` + jobID + `","disposition":"ack_terminal","state":"succeeded","attempt":1}`)
	claim, err := worker.ClaimDiscoveryDelivery(context.Background(), identity.Scope, jobID, "worker-01", "lease-token-000000000001", 30)
	if err != nil || claim.Disposition != "ack_terminal" {
		t.Fatalf("terminal claim=%#v err=%v", claim, err)
	}
	database.responses[postgresExecutionClaimDeliverySQL] = json.RawMessage(`{"id":"` + jobID + `","disposition":"claimed","state":"leased","attempt":1,"authority_id":"pid_81000003-0000-4000-8000-000000000003","lease_expires_at":"` + time.Now().UTC().Add(30*time.Second).Format(time.RFC3339Nano) + `","lease_owner":"leak"}`)
	if _, err := worker.ClaimDiscoveryDelivery(context.Background(), identity.Scope, jobID, "worker-01", "lease-token-000000000001", 30); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("hostile delivery output error=%v", err)
	}
	completedAt := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	database.responses[postgresExecutionFinishJobSQL] = json.RawMessage(`{"id":"` + jobID + `","state":"succeeded","attempt":1,"completed_at":"` + completedAt + `"}`)
	if completion, err := worker.FinishDiscoveryJob(context.Background(), identity.Scope, DiscoveryJobCompletion{ID: jobID, Worker: "worker-01", LeaseToken: "lease-token-000000000001", Outcome: "succeeded", ResultDigest: make([]byte, 32)}); err != nil || completion.State != "succeeded" || completion.CompletedAt == nil || completion.CompletedAt.Location() != time.UTC {
		t.Fatalf("job completion=%#v err=%v", completion, err)
	}

	database = &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	projection := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityProjectionGraph)
	database.responses[postgresExecutionProjectionStatusSQL] = json.RawMessage(`{"integration_id":"pid_81000004-0000-4000-8000-000000000004","source":"aws","snapshot_id":"` + snapshotID + `","generation":7,"input_digest":"` + digest + `","projections":[{"kind":"graph","work_state":"succeeded","work_version":"v1","work_input_digest":"` + digest + `","attempt":1,"current_snapshot_id":"` + snapshotID + `","current_generation":7,"current_input_digest":"` + digest + `","current":true},{"kind":"risk","work_state":"pending","work_version":"v1","work_input_digest":"` + digest + `","attempt":0,"current_snapshot_id":null,"current_generation":null,"current_input_digest":null,"current":false},{"kind":"search","work_state":"pending","work_version":"v1","work_input_digest":"` + digest + `","attempt":0,"current_snapshot_id":null,"current_generation":null,"current_input_digest":null,"current":false}]}`)
	status, err := projection.GetProjectionStatus(context.Background(), identity.Scope, snapshotID)
	if err != nil || len(status.Projections) != 3 || !status.Projections[0].Current || status.Projections[1].Current {
		t.Fatalf("projection status=%#v err=%v", status, err)
	}
	database.responses[postgresExecutionProjectionStatusSQL] = json.RawMessage(`{"integration_id":"pid_81000004-0000-4000-8000-000000000004","source":"aws","snapshot_id":"` + snapshotID + `","generation":7,"input_digest":"` + digest + `","projections":[]}`)
	if _, err := projection.GetProjectionStatus(context.Background(), identity.Scope, snapshotID); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("incomplete projection status error=%v", err)
	}
}

func TestDiscoveryExecutionProjectionClaimsAreKindBound(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		authority string
		kind      string
	}{
		{DiscoveryExecutionAuthorityProjectionRisk, "risk"},
		{DiscoveryExecutionAuthorityProjectionGraph, "graph"},
		{DiscoveryExecutionAuthorityProjectionSearch, "search"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
			repository := newTestDiscoveryExecutionRepository(t, database, test.authority)
			database.responses[postgresExecutionClaimProjectionSQL] = json.RawMessage(`{"items":[]}`)
			items, err := repository.ClaimProjectionWork(context.Background(), test.kind, "projection-worker-01", "projection-token-00000001", 30, 8)
			if err != nil || items == nil {
				t.Fatalf("ClaimProjectionWork(%s) items=%#v err=%v", test.kind, items, err)
			}
			if len(database.args) != 5 || database.args[0] != test.kind {
				t.Fatalf("claim args=%#v, want kind first", database.args)
			}
			other := map[string]string{"risk": "graph", "graph": "search", "search": "risk"}[test.kind]
			if _, err := repository.ClaimProjectionWork(context.Background(), other, "projection-worker-01", "projection-token-00000001", 30, 8); !errors.Is(err, ErrRepositoryOperation) {
				t.Fatalf("cross-kind claim error=%v", err)
			}
		})
	}
}

func TestDiscoveryExecutionProjectionAttemptLimitMatchesDatabase(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityProjectionRisk)
	lease := time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano)
	digest := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	database.responses[postgresExecutionClaimProjectionSQL] = json.RawMessage(`{"items":[{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","snapshot_id":"pid_82900001-0000-4000-8000-000000000001","kind":"risk","version":"v1","input_digest":"` + digest + `","attempt":6,"lease_expires_at":"` + lease + `"}]}`)
	if _, err := repository.ClaimProjectionWork(context.Background(), "risk", "projection-worker-01", "projection-token-00000001", 30, 8); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("attempt 6 claim output error=%v", err)
	}

	snapshotID := "pid_82900001-0000-4000-8000-000000000001"
	database.responses[postgresExecutionFinishProjectionSQL] = json.RawMessage(`{"snapshot_id":"` + snapshotID + `","kind":"risk","state":"failed","attempt":6}`)
	completion := ProjectionWorkCompletion{SnapshotID: snapshotID, Kind: "risk", Version: "v1", Worker: "projection-worker-01", LeaseToken: "projection-token-00000001", Outcome: "failed", LastError: "projection_failed"}
	if _, err := repository.FinishProjectionWork(context.Background(), identity.Scope, completion); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("attempt 6 completion output error=%v", err)
	}
}

func TestDiscoveryExecutionProjectionCompletionRequiresDurableDriverReceipt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	snapshotID := "pid_83000001-0000-4000-8000-000000000001"
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestDiscoveryExecutionRepository(t, database, DiscoveryExecutionAuthorityProjectionSearch)
	now := time.Now().UTC().Add(30 * time.Second)
	database.responses[postgresExecutionHeartbeatProjectionSQL] = json.RawMessage(`{"id":"` + snapshotID + `","lease_expires_at":"` + now.Format(time.RFC3339Nano) + `"}`)
	if result, err := repository.HeartbeatProjectionWork(context.Background(), identity.Scope, ProjectionHeartbeat{SnapshotID: snapshotID, Kind: "search", Version: "v1", Worker: "projection-worker-01", LeaseToken: "projection-token-00000001", LeaseSeconds: 30}); err != nil || result.ID != snapshotID {
		t.Fatalf("projection heartbeat=%#v err=%v", result, err)
	}
	database.responses[postgresExecutionFinishProjectionSQL] = json.RawMessage(`{"snapshot_id":"` + snapshotID + `","kind":"search","state":"succeeded","attempt":1}`)
	completion := ProjectionWorkCompletion{SnapshotID: snapshotID, Kind: "search", Version: "v1", Worker: "projection-worker-01", LeaseToken: "projection-token-00000001", Outcome: "succeeded", DriverReceipt: "search-receipt-00000001", DriverDigest: make([]byte, 32)}
	if result, err := repository.FinishProjectionWork(context.Background(), identity.Scope, completion); err != nil || result.State != "succeeded" {
		t.Fatalf("projection completion=%#v err=%v", result, err)
	}
	completion.DriverReceipt = ""
	if _, err := repository.FinishProjectionWork(context.Background(), identity.Scope, completion); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("missing result receipt error=%v", err)
	}
}
