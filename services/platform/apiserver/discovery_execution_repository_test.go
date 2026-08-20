package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

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
	database.responses[postgresExecutionJobInputSQL] = json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","job_id":"` + jobID + `","attempt":1,"lease_expires_at":"` + now.Format(time.RFC3339Nano) + `","sync_id":"pid_80000004-0000-4000-8000-000000000004","integration_id":"` + integrationID + `","connection_id":"` + connectionID + `","provider":"aws","collector_version":"collector_v1","credential_class":"aws_assume_role","credential_reference":"ref:aws/external-id/customer-0001","subject_kind":"aws_account","subject_id":"123456789012","cursor_provider":null,"cursor_version":null,"cursor_value":null,"parser_version":"parser_v1","tool_version":"tool_v1","configuration":{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}}`)
	input, err := repository.GetDiscoveryJobInput(context.Background(), identity.Scope, jobID, "worker-01", "lease-token-000000000001")
	if err != nil || input.JobID != jobID || input.ExpectedSubject.ID != "123456789012" || input.LeaseExpiresAt.Location() != time.UTC {
		t.Fatalf("input=%#v err=%v", input, err)
	}
	database.responses[postgresExecutionJobInputSQL] = json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","job_id":"` + jobID + `","attempt":1,"lease_expires_at":"` + now.Format(time.RFC3339Nano) + `","sync_id":"pid_80000004-0000-4000-8000-000000000004","integration_id":"` + integrationID + `","connection_id":"` + connectionID + `","provider":"aws","collector_version":"collector_v1","credential_class":"aws_assume_role","credential_reference":"ref:aws/external-id/customer-0001","subject_kind":"aws_account","subject_id":"123456789012","cursor_provider":null,"cursor_version":null,"cursor_value":null,"parser_version":"parser_v1","tool_version":"tool_v1","configuration":{},"access_token":"leak"}`)
	if _, err := repository.GetDiscoveryJobInput(context.Background(), identity.Scope, jobID, "worker-01", "lease-token-000000000001"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unknown output field error=%v", err)
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
