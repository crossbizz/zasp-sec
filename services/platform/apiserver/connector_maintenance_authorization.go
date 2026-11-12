package apiserver

import "context"

// Connector reconciliation is system maintenance of durable work that an
// authorized request already created: it finishes or cleans up connector
// effects whose leases the reconciler itself claims. It runs in the
// background, so it has no request and no request authorization.
//
// Current authorization refuses every product statement that carries no
// request authorization. Without a classification the reconciler could not
// claim its first lease, never reported ready, and the API never passed
// readiness. These statements are therefore classified here, explicitly:
//
//   - only the reconciler marks a context, and the mark is unexported;
//   - only the statements below are admitted, compared exactly;
//   - each of them is bound in SQL to the lease owner and lease token the
//     reconciler claimed, and none takes a caller-chosen principal or grant;
//   - a context that carries a request authorization never takes this path.
//
// Statements that start connector work (OAuth start, effect begin, credential
// writes, quarantine remediation) are not in the list. They stay behind
// request authorization.
type connectorMaintenanceKey struct{}

func withConnectorMaintenance(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, connectorMaintenanceKey{}, true)
}

func connectorMaintenanceStatement(ctx context.Context, statement string) bool {
	if ctx == nil {
		return false
	}
	if marked, _ := ctx.Value(connectorMaintenanceKey{}).(bool); !marked {
		return false
	}
	switch statement {
	case postgresConnectorRecoverFinalAttemptsSQL,
		postgresConnectorClaimReconciliationSQL,
		postgresConnectorCompleteReconciliationSQL,
		postgresConnectorFailReconciliationSQL,
		postgresConnectorCompleteRevocationSQL,
		postgresConnectorCompleteLeasedCleanupSQL,
		postgresConnectorCompletePKCECleanupSQL,
		postgresConnectorQuarantineSQL:
		return true
	}
	return false
}
