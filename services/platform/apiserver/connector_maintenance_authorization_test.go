package apiserver

import (
	"context"
	"testing"
)

func TestConnectorMaintenanceClassificationIsClosed(t *testing.T) {
	marked := withConnectorMaintenance(context.Background())
	admitted := []string{
		postgresConnectorRecoverFinalAttemptsSQL, postgresConnectorClaimReconciliationSQL,
		postgresConnectorCompleteReconciliationSQL, postgresConnectorFailReconciliationSQL,
		postgresConnectorCompleteRevocationSQL, postgresConnectorCompleteLeasedCleanupSQL,
		postgresConnectorCompletePKCECleanupSQL, postgresConnectorQuarantineSQL,
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
