package apiserver

import (
	"context"
	"encoding/json"
	"testing"
)

func TestP7IntegrationMutationRouting(t *testing.T) {
	for _, op := range []string{"createIntegration", "updateIntegration"} {
		g := integrationRejectionGrant(t, op, CredentialBrowserSession)
		action, id, v := "create", integrationClientExisting, int64(0)
		if op == "updateIntegration" {
			action, id, v = "update", g.PathParameters["id"], 1
		}
		m := WorkflowMutation{Action: action, Kind: "integration", ID: id, Operation: op, IdempotencyKey: "client-routing-key", ExpectedVersion: v, Intent: json.RawMessage(`{"body":{}}`), Body: json.RawMessage(`{"name":"GitHub"}`), AuditID: "pid_78200006-0000-4000-8000-000000000006", CorrelationID: testCorrelationID, ReceiptID: "pid_78200007-0000-4000-8000-000000000007"}
		db := &workflowCallDatabase{response: json.RawMessage(`{"body":{"name":"GitHub"},"version":1,"audit_id":"pid_78200006-0000-4000-8000-000000000006","correlation_id":"` + testCorrelationID + `","receipt_id":"pid_78200007-0000-4000-8000-000000000007"}`)}
		repo := &PostgresRepository{database: db, currentAuthorization: true, connectorWorkflows: true}
		_, err := repo.MutateWorkflow(context.WithValue(context.Background(), requestAuthorizationContextKey{}, g), g.Identity, m)
		if err != nil || db.query != `SELECT zasp_authorization80.integration_mutate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14,$15)` {
			t.Errorf("%s query=%q error=%v", op, db.query, err)
		}
	}
}

func TestP7IntegrationMutationStatementBoundary(t *testing.T) {
	for _, op := range []string{"createIntegration", "updateIntegration"} {
		g := integrationRejectionGrant(t, op, CredentialBrowserSession)
		i := g.Identity
		action, id, target, version := "create", integrationClientExisting, "", int64(0)
		if op == "updateIntegration" {
			action, id, target, version = "update", g.PathParameters["id"], g.PathParameters["id"], 1
		}
		intent, _ := json.Marshal(map[string]any{"resource_id": target, "expected_version": version, "body": map[string]any{}})
		args := []any{action, "integration", id, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), op, "client-classifier-key", version, json.RawMessage(intent), json.RawMessage(`{}`), "audit", "correlation", "receipt"}
		if !authorizationStatementAllowed(g, postgresCurrentIntegrationMutateSQL, args) {
			t.Fatalf("%s valid closed contract denied", op)
		}
		for _, bad := range []struct {
			name  string
			index int
			value any
		}{
			{"action", 0, "delete"}, {"kind", 1, "policy"}, {"organization", 3, "other"}, {"workspace", 4, "other"}, {"environment", 5, "other"}, {"actor", 6, "other"}, {"operation", 7, "deleteIntegration"},
			{"intent target", 10, json.RawMessage(`{"resource_id":"wrong","expected_version":0,"body":{}}`)},
			{"intent version", 10, json.RawMessage(`{"resource_id":"` + target + `","expected_version":-1,"body":{}}`)},
		} {
			a := append([]any(nil), args...)
			a[bad.index] = bad.value
			if authorizationStatementAllowed(g, postgresCurrentIntegrationMutateSQL, a) {
				t.Errorf("%s admitted substituted %s", op, bad.name)
			}
		}
		for _, q := range []string{postgresWorkflowMutateSQL, postgresConnectorWorkflowMutateSQL} {
			if authorizationStatementAllowed(g, q, args) {
				t.Errorf("%s admitted legacy generic writer", op)
			}
		}
	}
}
