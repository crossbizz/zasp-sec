package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestApprovalNotificationRepositoryClaimsCompletesAndFailsExactScopedAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	lease := approvalNotificationFixture(t)
	expires := time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond)
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresApprovalNotificationClaimSQL:    json.RawMessage(`{"found":true,"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","delivery_id":"` + lease.DeliveryID + `","approval_id":"` + lease.ApprovalID + `","run_id":"` + lease.RunID + `","payload":` + string(mustJSONMarshal(t, lease.Payload)) + `,"payload_digest":"` + lease.PayloadDigest + `","destination_url":"` + lease.DestinationURL + `","secret_reference":"` + lease.SecretReference + `","lease_token":"` + lease.LeaseToken + `","lease_expires_at":"` + expires.Format(time.RFC3339Nano) + `","attempt":1}`),
		postgresApprovalNotificationCompleteSQL: json.RawMessage(`{"transition":"delivered"}`),
		postgresApprovalNotificationFailSQL:     json.RawMessage(`{"transition":"retryable"}`),
	}}
	repository := &PostgresRepository{database: database, schema: ProductionApprovalNotificationSchemaVersion, securityAgentExecution: true}
	claimed, err := repository.ClaimApprovalNotification(context.Background(), "agentsec-api:test", lease.LeaseToken, 30)
	if err != nil || claimed.DeliveryID != lease.DeliveryID || claimed.Scope != identity.Scope || claimed.Payload != lease.Payload || !claimed.LeaseExpiresAt.Equal(expires) {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	if err := repository.CompleteApprovalNotification(context.Background(), identity.Scope, lease.DeliveryID, lease.LeaseToken, lease.PayloadDigest); err != nil {
		t.Fatal(err)
	}
	if err := repository.FailApprovalNotification(context.Background(), identity.Scope, lease.DeliveryID, lease.LeaseToken, lease.PayloadDigest); err != nil {
		t.Fatal(err)
	}
	if len(database.statements) != 3 || database.statements[0] != postgresApprovalNotificationClaimSQL || database.statements[1] != postgresApprovalNotificationCompleteSQL || database.statements[2] != postgresApprovalNotificationFailSQL {
		t.Fatalf("statements=%#v", database.statements)
	}
	wantComplete := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), lease.DeliveryID, lease.LeaseToken, lease.PayloadDigest}
	if !reflect.DeepEqual(database.arguments[1], wantComplete) || !reflect.DeepEqual(database.arguments[2], wantComplete) {
		t.Fatalf("complete/fail args=%#v/%#v", database.arguments[1], database.arguments[2])
	}
}

func TestApprovalNotificationRepositoryConstructsOnlyWithExactV30PrincipalAuthority(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresApprovalNotificationAuthorityReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
	}}
	repository, err := NewApprovalNotificationPostgresRepository(database)
	if err != nil || repository.schema != ProductionApprovalNotificationSchemaVersion {
		t.Fatalf("repository=%#v err=%v", repository, err)
	}
	if err := repository.ReadyApprovalNotifications(context.Background()); err != nil || len(database.statements) != 2 {
		t.Fatalf("ready err=%v statements=%#v", err, database.statements)
	}
	for _, payload := range []json.RawMessage{json.RawMessage(`{"release":false,"principal":true}`), json.RawMessage(`{"release":true,"principal":false}`), json.RawMessage(`{"release":true,"principal":true,"extra":true}`)} {
		drift := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresApprovalNotificationAuthorityReadySQL: payload}}
		if _, err := NewApprovalNotificationPostgresRepository(drift); err != ErrRepositoryConfiguration {
			t.Fatalf("payload=%s err=%v", payload, err)
		}
	}
}

func TestApprovalNotificationRepositoryRejectsPayloadScopeDigestAndShapeDrift(t *testing.T) {
	lease := approvalNotificationFixture(t)
	identity := fixtureRequestIdentity(t)
	expires := time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano)
	actual := sha256.Sum256([]byte(lease.Payload))
	validDigest := "sha256:" + hex.EncodeToString(actual[:])
	base := `{"found":true,"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","delivery_id":"` + lease.DeliveryID + `","approval_id":"` + lease.ApprovalID + `","run_id":"` + lease.RunID + `","payload":` + string(mustJSONMarshal(t, lease.Payload)) + `,"payload_digest":"` + validDigest + `","destination_url":"` + lease.DestinationURL + `","secret_reference":"` + lease.SecretReference + `","lease_token":"` + lease.LeaseToken + `","lease_expires_at":"` + expires + `","attempt":1}`
	for _, payload := range []string{
		strings.Replace(base, identity.Scope.OrganizationID().String(), "pid_ffffffff-ffff-4fff-8fff-ffffffffffff", 1),
		strings.Replace(base, validDigest, "sha256:"+strings.Repeat("f", 64), 1),
		base[:len(base)-1] + `,"credential_reference":"secret"}`,
	} {
		database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresApprovalNotificationClaimSQL: json.RawMessage(payload)}}
		repository := &PostgresRepository{database: database, schema: ProductionApprovalNotificationSchemaVersion, securityAgentExecution: true}
		if _, err := repository.ClaimApprovalNotification(context.Background(), "agentsec-api:test", lease.LeaseToken, 30); err != ErrRepositoryUnavailable {
			t.Fatalf("payload=%s err=%v", payload, err)
		}
	}
}

func mustJSONMarshal(t *testing.T, value string) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
