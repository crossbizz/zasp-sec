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
		postgresConnectorQuarantineSQL,
		postgresConnectorLeasedIntegrationSQL:
		return true
	}
	return false
}

// postgresConnectorLeasedIntegrationSQL reads the integration of a connector
// effect for the holder of its live lease: the reconciler needs the
// integration's connector and configuration to finish an authorization or a
// revocation. The function returns nothing unless the effect is leased to
// the named owner with the named token and the lease has not expired, so it
// reads only integrations the reconciler is already working on. The generic
// workflow read is a request statement and is refused without a request
// authorization, which left every leased effect unfinished.
const postgresConnectorLeasedIntegrationSQL = `SELECT zasp_authorization80.connector_leased_integration($1,$2,$3,$4,$5,$6)`

type connectorLeaseKey struct{}

// withConnectorLease names the lease a maintenance read is made for. Only
// the reconciler calls it, on its own marked context.
func withConnectorLease(ctx context.Context, lease ConnectorEffectLease) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, connectorLeaseKey{}, lease)
}

// connectorLeaseRead returns the lease of a marked maintenance context that
// carries no request authorization and whose lease names this integration in
// this scope.
func connectorLeaseRead(ctx context.Context, organizationID, workspaceID, environmentID, kind, id string) (ConnectorEffectLease, bool) {
	if ctx == nil {
		return ConnectorEffectLease{}, false
	}
	if marked, _ := ctx.Value(connectorMaintenanceKey{}).(bool); !marked {
		return ConnectorEffectLease{}, false
	}
	if _, requested := requestAuthorizationFromContext(ctx); requested {
		return ConnectorEffectLease{}, false
	}
	lease, ok := ctx.Value(connectorLeaseKey{}).(ConnectorEffectLease)
	if !ok || kind != "integration" || lease.IntegrationID != id || lease.OrganizationID != organizationID || lease.WorkspaceID != workspaceID || lease.EnvironmentID != environmentID || !validConnectorLease(lease) {
		return ConnectorEffectLease{}, false
	}
	return lease, true
}
