package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Each Security Agent write and single-object read, called with a checked
// request, executes exactly its one authorized statement inside the fenced
// transaction, never a family probe or a historical statement, and nothing at
// all under another operation's checked request.
func TestSecurityAgentCurrentWritesUseAuthorizedStatements(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.Permissions = []string{"view", "manage_workflows", "manage_identity"}
	i.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Microsecond)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const agent = "pid_20000001-0000-4000-8000-000000000001"
	const audit, correlation, receipt, run, trigger = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003", "pid_30000004-0000-4000-8000-000000000004", "pid_30000005-0000-4000-8000-000000000005"
	const key = "idempotency-key-0001"
	rev := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "security-agent-current", Digest: [32]byte{1}}
	resolver := authorizationTargetFunc(func(_ context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
		policy, err := authorizationTargetPolicy(route.OperationID)
		if err != nil {
			return AuthorizationTargets{}, err
		}
		if policy.Mode == "collection" {
			return AuthorizationTargets{Complete: true, Collection: true, Targets: []AuthorizationTarget{}}, nil
		}
		id := identity.Scope.EnvironmentID().String()
		if policy.Kind == "security_agent" || policy.Kind == "finding" {
			id = route.PathParameters["id"]
		}
		return AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{{Scope: identity.Scope, Kind: policy.Kind, ID: id, Version: 3}}}, nil
	})
	checker := authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: true, ModelID: rev.ModelID}, nil
	})
	authorizer := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: checker, Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	body := json.RawMessage(`{"id":"` + agent + `","name":"Agent","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + e + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"max_ai_cost_nano_credits":1000000,"concurrency_limit":1,"allowed_actions":["update_finding_response"],"verification_kind":"finding_state","definition_version":1,"enabled":false}`)
	intent := json.RawMessage(`{"resource_id":"` + agent + `","expected_version":3,"body":{}}`)
	definition := `{"body":{"id":"` + agent + `","name":"Agent"},"version":4,"secret_generation":1}`
	version, source := int64(1), "credential"
	for _, tc := range []struct {
		operation, statement, payload string
		path                          bool
		call                          func(context.Context, *PostgresRepository) error
	}{
		{"getSecurityAgent", currentSecurityAgentDefinitionValueSQL, definition, true, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.GetWorkflowForIdentity(ctx, i, "security_agent", agent)
			return err
		}},
		{"getSecurityAgentActivation", currentSecurityAgentActivationSQL, `{"organization_id":"` + o + `","workspace_id":"` + w + `","environment_id":"` + e + `","definition_id":"` + agent + `","activation":"draft","version":3,"definition_version":1,"body":` + string(body) + `,"updated_at":"2026-11-13T00:00:00.000000Z"}`, true, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.GetSecurityAgentActivation(ctx, i, agent)
			return err
		}},
		{"updateSecurityAgent", currentSecurityAgentDefinitionReplaySQL, `{"found":false}`, true, func(ctx context.Context, r *PostgresRepository) error {
			_, found, err := r.ReplayWorkflow(ctx, i, "updateSecurityAgent", key, intent)
			if err == nil && found {
				t.Fatal("replay reported a prior result")
			}
			return err
		}},
		{"updateSecurityAgent", currentSecurityAgentDefinitionMutateSQL, `{"body":` + string(body) + `,"version":4,"secret_generation":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}`, true, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.MutateWorkflow(ctx, i, WorkflowMutation{Action: "update", Kind: "security_agent", ID: agent, Operation: "updateSecurityAgent", IdempotencyKey: key, ExpectedVersion: 3, Intent: intent, Body: body, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			return err
		}},
		{"activateSecurityAgent", currentSecurityAgentActivateSQL, `{"family":"finding","result":{"id":"` + agent + `","activation":"supervised","enabled":true,"version":4,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`, true, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ActivateSecurityAgent(ctx, i, SecurityAgentActivation{DefinitionID: agent, IdempotencyKey: key, ExpectedVersion: 3, TargetActivation: "supervised", FreshAuthExpiresAt: i.FreshAuthExpiresAt, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			return err
		}},
		{"runSecurityAgent", currentSecurityAgentRunSQL, `{"family":"finding","result":{"id":"` + run + `","agent_id":"` + agent + `","state":"queued","evidence_ids":["` + trigger + `"],"definition_version":3,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`, true, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.RunSecurityAgent(ctx, i, SecurityAgentRunRequest{DefinitionID: agent, IdempotencyKey: key, ExpectedVersion: 3, RunID: run, TriggerKind: "finding", TriggerID: trigger, TriggerVersion: &version, TriggerSource: &source, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			return err
		}},
		{"setSecurityAgentExecutionControl", currentSecurityAgentSetExecutionControlSQL, `{"target":"action","action_key":"update_finding_response","enabled":true,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}`, false, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.SetSecurityAgentExecutionControl(ctx, i, SecurityAgentExecutionControlMutation{IdempotencyKey: key, Target: "action", ActionKey: "update_finding_response", Enabled: true, ExpectedVersion: 0, FreshAuthExpiresAt: i.FreshAuthExpiresAt, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			return err
		}},
	} {
		t.Run(tc.operation+"/"+tc.statement[28:60], func(t *testing.T) {
			exercise := func(operation string) (*completionTxFixture, *completionDriverFixture, error) {
				route := RoutedOperation{OperationID: operation}
				if tc.path {
					route.PathParameters = map[string]string{"id": agent}
				}
				grant, err := authorizer.Authorize(context.Background(), i, credential, route)
				if err != nil {
					t.Fatalf("authorize %s: %v", operation, err)
				}
				tx := &completionTxFixture{payload: tc.payload}
				driver := &completionDriverFixture{tx: tx, ready: true}
				database, err := NewPostgresJSONDatabase(driver)
				if err != nil {
					t.Fatal(err)
				}
				if err := database.RequireCurrentAuthorization(); err != nil {
					t.Fatal(err)
				}
				repository := &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion, securityAgentExecution: true}
				ctx := context.WithValue(context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant), requestAuthorizerContextKey{}, RequestAuthorizer(authorizer))
				return tx, driver, tc.call(ctx, repository)
			}
			tx, driver, err := exercise(tc.operation)
			if err != nil {
				t.Fatalf("authorized statement failed: %v", err)
			}
			if !slices.Equal(tx.steps, []string{"fence", "effect"}) || len(tx.statements) != 1 || tx.statements[0] != tc.statement {
				t.Fatalf("steps=%v statements=%v, want one fenced %s", tx.steps, tx.statements, tc.statement)
			}
			if len(driver.direct) != 0 {
				t.Fatalf("direct statements were used: %v", driver.direct)
			}
			found := map[string]bool{}
			for _, argument := range tx.arguments[0] {
				if value, ok := argument.(string); ok {
					found[value] = true
				}
			}
			for _, scope := range []string{o, w, e} {
				if !found[scope] {
					t.Fatalf("statement arguments lost the request scope: %v", tx.arguments[0])
				}
			}
			if tc.statement != currentSecurityAgentDefinitionValueSQL && !found[p] {
				t.Fatalf("statement arguments lost the request principal: %v", tx.arguments[0])
			}
			tx, driver, err = exercise("listSecurityAgentRuns")
			if err == nil || slices.Contains(tx.steps, "effect") || len(driver.direct) != 0 {
				t.Fatalf("statement under another operation: err=%v steps=%v direct=%v", err, tx.steps, driver.direct)
			}
		})
	}
}

// The repository refuses results that do not answer the request it sent.
func TestSecurityAgentCurrentRunRejectsForeignResults(t *testing.T) {
	i := fixtureRequestIdentity(t)
	const agent, run, trigger = "pid_20000001-0000-4000-8000-000000000001", "pid_30000004-0000-4000-8000-000000000004", "pid_30000005-0000-4000-8000-000000000005"
	const audit, correlation, receipt = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"
	if _, err := (&PostgresRepository{securityAgentExecution: true}).runSecurityAgentCurrent(context.Background(), i, SecurityAgentRunRequest{}); err != ErrRepositoryOperation {
		t.Fatalf("empty request err=%v", err)
	}
	request := SecurityAgentRunRequest{DefinitionID: agent, IdempotencyKey: "idempotency-key-0001", ExpectedVersion: 3, RunID: run, TriggerKind: "manual", AuditID: audit, CorrelationID: correlation, ReceiptID: receipt}
	database := &completionJSONFixture{}
	repository := &PostgresRepository{database: database, securityAgentExecution: true}
	if _, err := repository.runSecurityAgentCurrent(context.Background(), i, request); err != ErrRepositoryUnavailable || len(database.statements) != 0 {
		t.Fatalf("manual trigger err=%v statements=%v", err, database.statements)
	}
	request.TriggerKind, request.TriggerID = "finding", trigger
	for name, payload := range map[string]string{
		"another run":    `{"family":"finding","result":{"id":"` + trigger + `","agent_id":"` + agent + `","state":"queued","evidence_ids":["` + trigger + `"],"definition_version":3,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`,
		"another agent":  `{"family":"finding","result":{"id":"` + run + `","agent_id":"` + trigger + `","state":"queued","evidence_ids":["` + trigger + `"],"definition_version":3,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`,
		"unknown family": `{"family":"other","result":{}}`,
		"no envelope":    `{"id":"` + run + `"}`,
		"ordered ids":    `{"family":"ordered","result":{"contract_version":62,"id":"` + run + `","agent_id":"` + agent + `","state":"queued","evidence_ids":["` + trigger + `"],"definition_version":3,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`,
	} {
		database.payload = payload
		if name == "ordered ids" {
			version, source := int64(1), "credential"
			request.TriggerVersion, request.TriggerSource = &version, &source
		}
		if _, err := repository.runSecurityAgentCurrent(context.Background(), i, request); err != ErrRepositoryUnavailable {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

type completionJSONFixture struct {
	statements []string
	payload    string
}

func (f *completionJSONFixture) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	f.statements = append(f.statements, statement)
	return json.RawMessage(f.payload), nil
}
func (f *completionJSONFixture) Exec(context.Context, string, ...any) error { return nil }
func (f *completionJSONFixture) SchemaVersion(context.Context) (string, error) {
	return ProductionRecoverySchemaVersion, nil
}

// Under a checked request the family is chosen by the authorized statement,
// so run, activation and activation reads go straight to the handler that
// sends it: neither the family probes nor the ordered handler is consulted.
// Every other operation, and every request without a checked authorization,
// keeps its existing route.
func TestSecurityAgentCheckedRequestsBypassFamilyProbes(t *testing.T) {
	const agent = "pid_20000001-0000-4000-8000-000000000001"
	i := fixtureRequestIdentity(t)
	for _, tc := range []struct {
		operation string
		checked   bool
		want      string
	}{
		{"runSecurityAgent", true, "legacy"}, {"activateSecurityAgent", true, "legacy"}, {"getSecurityAgentActivation", true, "legacy"},
		{"decideSecurityAgentApproval", true, "next"}, {"listSecurityAgentRuns", true, "next"}, {"activateSecurityAgent", false, "next"}, {"getSecurityAgentActivation", false, "next"},
	} {
		served := ""
		handler := &securityAgentHumanHTTPHandler{
			legacy: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = "legacy" }),
			next:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = "next" }),
		}
		ctx := context.WithValue(context.Background(), routedOperationContextKey{}, RoutedOperation{OperationID: tc.operation, PathParameters: map[string]string{"id": agent}})
		if tc.checked {
			ctx = context.WithValue(ctx, requestAuthorizationContextKey{}, RequestAuthorization{OperationID: tc.operation, Identity: i})
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/security-agents/"+agent+"/runs", nil).WithContext(ctx)
		handler.ServeHTTP(httptest.NewRecorder(), request)
		if served != tc.want {
			t.Fatalf("%s checked=%v served by %q, want %q", tc.operation, tc.checked, served, tc.want)
		}
	}
}
