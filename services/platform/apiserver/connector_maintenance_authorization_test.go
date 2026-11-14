package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestConnectorMaintenanceClassificationIsClosed(t *testing.T) {
	marked := withConnectorMaintenance(context.Background())
	admitted := []string{
		postgresConnectorRecoverFinalAttemptsSQL, postgresConnectorClaimReconciliationSQL,
		postgresConnectorCompleteReconciliationSQL, postgresConnectorFailReconciliationSQL,
		postgresConnectorCompleteRevocationSQL, postgresConnectorCompleteLeasedCleanupSQL,
		postgresConnectorCompletePKCECleanupSQL, postgresConnectorQuarantineSQL,
		postgresConnectorLeasedIntegrationSQL,
	}
	for _, statement := range admitted {
		if !connectorMaintenanceStatement(marked, statement) {
			t.Fatalf("reconciler statement refused: %s", statement)
		}
		// The same statement without the reconciler's mark stays refused.
		if connectorMaintenanceStatement(context.Background(), statement) {
			t.Fatalf("unmarked context admitted: %s", statement)
		}
	}
	// Statements that start connector work, change credentials or remediate a
	// quarantine need a request authorization even from a marked context.
	refused := []string{
		postgresConnectorStartOAuthSQL, postgresConnectorConsumeOAuthSQL, postgresConnectorBeginEffectSQL,
		postgresConnectorStagePKCECleanupSQL, postgresConnectorActivatePKCECleanupSQL, postgresConnectorResolveEffectSQL,
		postgresConnectorPutCredentialSQL, postgresConnectorCompleteOAuthSQL, postgresConnectorCompleteCleanupSQL,
		postgresConnectorGetQuarantineSQL, postgresConnectorRemediateQuarantineSQL,
		postgresApprovalNotificationClaimSQL, postgresAuthorizationSessionSQL,
		postgresConnectorClaimReconciliationSQL + " ", "SELECT 1",
	}
	for _, statement := range refused {
		if connectorMaintenanceStatement(marked, statement) {
			t.Fatalf("statement outside the classification admitted: %s", statement)
		}
	}
	if connectorMaintenanceStatement(nil, postgresConnectorClaimReconciliationSQL) || withConnectorMaintenance(nil) != nil {
		t.Fatal("nil context admitted")
	}
	// A value under another key, even the same shape, is not the mark.
	type foreign struct{}
	if connectorMaintenanceStatement(context.WithValue(context.Background(), foreign{}, true), postgresConnectorClaimReconciliationSQL) {
		t.Fatal("foreign context value admitted")
	}
}

// The reconciler reads the integration of an effect only through the
// statement that is bound to its lease, and only for the integration and
// scope that lease names.
func TestConnectorLeaseReadIsBoundToTheLease(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	integration := "pid_70004001-0000-4000-8000-000000000001"
	lease := ConnectorEffectLease{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ID: "pid_70004003-0000-4000-8000-000000000003", IntegrationID: integration, Provider: "aws", Operation: "revoke",
		IdempotencyKey: "delete-integration-0001", RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), ConnectionReference: "ref:aws/external-id/customer-0001", Attempt: 1,
		LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}
	marked := withConnectorLease(withConnectorMaintenance(context.Background()), lease)
	if got, ok := connectorLeaseRead(marked, o, w, e, "integration", integration); !ok || got.ID != lease.ID {
		t.Fatalf("leased read refused: %v", ok)
	}
	expired := lease
	expired.LeaseExpiresAt = time.Now().Add(-time.Second)
	for name, ctx := range map[string]context.Context{
		"no maintenance mark": withConnectorLease(context.Background(), lease),
		"no lease":            withConnectorMaintenance(context.Background()),
		"expired lease":       withConnectorLease(withConnectorMaintenance(context.Background()), expired),
		"request context":     context.WithValue(marked, requestAuthorizationContextKey{}, RequestAuthorization{OperationID: "getIntegration"}),
	} {
		if _, ok := connectorLeaseRead(ctx, o, w, e, "integration", integration); ok {
			t.Fatalf("%s: leased read admitted", name)
		}
	}
	if _, ok := connectorLeaseRead(marked, o, w, e, "integration", "pid_70004009-0000-4000-8000-000000000009"); ok {
		t.Fatal("another integration admitted")
	}
	if _, ok := connectorLeaseRead(marked, o, w, e, "policy", integration); ok {
		t.Fatal("another kind admitted")
	}
	if _, ok := connectorLeaseRead(marked, o, e, w, "integration", integration); ok {
		t.Fatal("another scope admitted")
	}
	if _, ok := connectorLeaseRead(nil, o, w, e, "integration", integration); ok || withConnectorLease(nil, lease) != nil {
		t.Fatal("nil context admitted")
	}
}
