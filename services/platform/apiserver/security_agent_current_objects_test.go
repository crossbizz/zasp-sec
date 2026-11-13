package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Run detail, cancellation, approval detail and decision, simulation and the
// manual trigger, called with a checked request, each execute exactly their
// one authorized statement inside the fenced transaction: no family probe, no
// historical statement, and nothing at all under another operation's request.
func TestSecurityAgentCurrentObjectsUseAuthorizedStatements(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.Permissions = []string{"view", "manage_workflows"}
	i.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Microsecond)
	authenticated := i.FreshAuthExpiresAt.Add(-securityAgentFreshAuthenticationTTL)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const agent, evidence = "pid_78000001-0000-4000-8000-000000000001", "pid_78000005-0000-4000-8000-000000000005"
	const audit, correlation, receipt, simulated = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003", "pid_30000004-0000-4000-8000-000000000004"
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
		return AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{{Scope: identity.Scope, Kind: policy.Kind, ID: route.PathParameters["id"], Version: 1}}}, nil
	})
	checker := authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: true, ModelID: rev.ModelID}, nil
	})
	authorizer := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: checker, Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	approval, approvalContext := approvalContextFixture("update_finding_response")
	approvalDetail, _ := json.Marshal(approval)
	approvalBound, _ := json.Marshal(approvalContext)
	runDetail := string(runContextEnvelopeFixture(t, nil))
	cancelled := `{"id":"` + runContextTestRunID + `","agent_id":"` + agent + `","state":"cancelled","evidence_ids":["` + evidence + `"],"definition_version":1,"version":4,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}`
	expires := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)
	simulation := `{"run_id":"` + simulated + `","definition_id":"` + agent + `","definition_version":3,"plan_hash":"sha256:` + strings.Repeat("a", 64) + `","catalog_version":"security-agent-actions-v1","expires_at":"` + expires.Format("2006-01-02T15:04:05.000000Z") + `","matched_evidence_ids":["` + evidence + `"],"summary":"Planned 1 action(s) from 1 evidence record(s)","steps":[{"index":0,"action":"update_finding_response","authorization":"approval_required","approval_required":true}],"side_effects":0,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}`
	manual := `{"id":"` + simulated + `","agent_id":"` + agent + `","state":"queued","evidence_ids":[],"manual_trigger":{"kind":"manual","intent_digest":"sha256:` + strings.Repeat("a", 64) + `","version":1},"definition_version":3,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}`
	for _, tc := range []struct {
		operation, statement, object, payload string
		call                                  func(context.Context, *PostgresRepository) error
	}{
		{"getSecurityAgentRun", currentSecurityAgentRunDetailSQL, runContextTestRunID, `{"family":"finding","result":` + runDetail + `}`, func(ctx context.Context, r *PostgresRepository) error {
			detail, err := r.GetSecurityAgentRun(ctx, i, runContextTestRunID)
			if err == nil && (detail.Run.ID != runContextTestRunID || detail.Ordered != nil || detail.BudgetStopReason != "budget_usage_unknown") {
				t.Fatalf("run detail=%+v", detail)
			}
			return err
		}},
		{"cancelSecurityAgentRun", currentSecurityAgentCancelRunSQL, runContextTestRunID, `{"family":"legacy","result":` + cancelled + `}`, func(ctx context.Context, r *PostgresRepository) error {
			result, err := r.CancelSecurityAgentRun(ctx, i, SecurityAgentCancelRequest{RunID: runContextTestRunID, IdempotencyKey: key, ExpectedVersion: 3, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			if err == nil && (result.State != "cancelled" || result.Version != 4 || result.Ordered != nil) {
				t.Fatalf("cancellation=%+v", result)
			}
			return err
		}},
		{"getSecurityAgentApproval", currentSecurityAgentApprovalSQL, approval.ID, `{"family":"finding","result":{"detail":` + string(approvalDetail) + `,"context":` + string(approvalBound) + `}}`, func(ctx context.Context, r *PostgresRepository) error {
			result, err := r.GetSecurityAgentApproval(ctx, i, approval.ID)
			if err == nil && (result.ID != approval.ID || result.Context == nil || result.ordered) {
				t.Fatalf("approval=%+v", result)
			}
			return err
		}},
		{"decideSecurityAgentApproval", currentSecurityAgentDecideApprovalSQL, approval.ID, `{"family":"finding","result":{"id":"` + approval.ID + `","run_id":"` + approval.RunID + `","step_id":"` + approval.StepID + `","state":"approved","expires_at":"2030-01-01T00:00:00Z","version":2,"expected_effect":"Move finding to under review","reversible":true,"ttl_seconds":0,"evidence_summary":["pid_78000004-0000-4000-8000-000000000004"],"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.DecideSecurityAgentApproval(ctx, i, SecurityAgentApprovalDecisionRequest{ApprovalID: approval.ID, IdempotencyKey: key, ExpectedVersion: 1, Decision: "approved", FreshAuthAt: authenticated, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			return err
		}},
		{"simulateSecurityAgent", currentSecurityAgentSimulateSQL, agent, simulation, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.SimulateSecurityAgent(ctx, i, SecurityAgentSimulationRequest{DefinitionID: agent, IdempotencyKey: key, ExpectedVersion: 3, RunID: simulated, Goal: "Check the plan", EvidenceIDs: []string{evidence}, ExpiresAt: expires, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			return err
		}},
		{"runSecurityAgent", currentSecurityAgentManualRunSQL, agent, manual, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.RunSecurityAgent(ctx, i, SecurityAgentRunRequest{DefinitionID: agent, IdempotencyKey: key, ExpectedVersion: 3, RunID: simulated, TriggerKind: "manual", AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
			return err
		}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			exercise := func(operation string) (*completionTxFixture, *completionDriverFixture, error) {
				grant, err := authorizer.Authorize(context.Background(), i, credential, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": tc.object}})
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
			if arguments := tx.arguments[0]; len(arguments) < 5 || arguments[0] != o || arguments[1] != w || arguments[2] != e || arguments[3] != tc.object || arguments[4] != p {
				t.Fatalf("statement does not start with the request scope, object and principal: %v", tx.arguments[0])
			}
			other := "listSecurityAgentRuns"
			tx, driver, err = exercise(other)
			if err == nil || slices.Contains(tx.steps, "effect") || len(driver.direct) != 0 {
				t.Fatalf("statement under another operation: err=%v steps=%v direct=%v", err, tx.steps, driver.direct)
			}
		})
	}
}

// The repository refuses results that do not answer the request it sent,
// and decodes an ordered result by the ordered release's own rules.
func TestSecurityAgentCurrentObjectsRejectForeignResults(t *testing.T) {
	i := fixtureRequestIdentity(t)
	const agent, evidence, other = "pid_78000001-0000-4000-8000-000000000001", "pid_78000005-0000-4000-8000-000000000005", "pid_78000009-0000-4000-8000-000000000009"
	const audit, correlation, receipt = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"
	database := &completionJSONFixture{}
	repository := &PostgresRepository{database: database, securityAgentExecution: true}
	runDetail := string(runContextEnvelopeFixture(t, nil))
	for name, payload := range map[string]string{
		"unknown family": `{"family":"other","result":` + runDetail + `}`,
		"test family":    `{"family":"test","result":` + runDetail + `}`,
		"no envelope":    runDetail,
		"extra field":    `{"family":"finding","result":` + runDetail + `,"extra":1}`,
		"null result":    `{"family":"finding","result":null}`,
	} {
		database.payload = payload
		if _, err := repository.getSecurityAgentRunCurrent(context.Background(), i, runContextTestRunID); err != ErrRepositoryUnavailable {
			t.Fatalf("run detail with %s: err=%v", name, err)
		}
	}
	database.payload = `{"family":"legacy","result":` + runDetail + `}`
	if _, err := repository.getSecurityAgentRunCurrent(context.Background(), i, other); err != ErrRepositoryUnavailable {
		t.Fatalf("detail of another run: err=%v", err)
	}
	cancel := SecurityAgentCancelRequest{RunID: runContextTestRunID, IdempotencyKey: "idempotency-key-0001", ExpectedVersion: 3, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt}
	result := func(run, state string, version int, auditID string) string {
		return `{"family":"legacy","result":{"id":"` + run + `","agent_id":"` + agent + `","state":"` + state + `","evidence_ids":["` + evidence + `"],"definition_version":1,"version":` + string(rune('0'+version)) + `,"audit_id":"` + auditID + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`
	}
	database.payload = result(runContextTestRunID, "cancelled", 4, audit)
	if got, err := repository.cancelSecurityAgentRunCurrent(context.Background(), i, cancel); err != nil || got.Version != 4 {
		t.Fatalf("cancellation=%+v err=%v", got, err)
	}
	for name, payload := range map[string]string{
		"another run":     result(other, "cancelled", 4, audit),
		"another state":   result(runContextTestRunID, "needs_human", 4, audit),
		"another version": result(runContextTestRunID, "cancelled", 5, audit),
		"another audit":   result(runContextTestRunID, "cancelled", 4, other),
		"test envelope":   strings.Replace(result(runContextTestRunID, "cancelled", 4, audit), `"legacy"`, `"finding"`, 1),
	} {
		database.payload = payload
		if _, err := repository.cancelSecurityAgentRunCurrent(context.Background(), i, cancel); err != ErrRepositoryUnavailable {
			t.Fatalf("cancellation with %s: err=%v", name, err)
		}
	}
	decision := SecurityAgentApprovalDecisionRequest{ApprovalID: other, IdempotencyKey: "idempotency-key-0001", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: audit, CorrelationID: correlation, ReceiptID: receipt}
	database.statements = nil
	if _, err := repository.decideSecurityAgentApprovalCurrent(context.Background(), i, decision); err != ErrRepositoryOperation || len(database.statements) != 0 {
		t.Fatalf("decision with a time that is not the session's: err=%v statements=%v", err, database.statements)
	}
	database.payload = `{"family":"ordered","result":{}}`
	i.FreshAuthExpiresAt = decision.FreshAuthAt.Add(securityAgentFreshAuthenticationTTL)
	if _, err := repository.decideSecurityAgentApprovalCurrent(context.Background(), i, decision); err != ErrRepositoryUnavailable {
		t.Fatalf("ordered decision envelope: err=%v", err)
	}

	// Ordered results: a browser session only, verified by the ordered rules.
	id := orderedPublicIdentity()
	ordered := &PostgresRepository{database: database, securityAgentExecution: true}
	resource, _ := json.Marshal(orderedResourceFixture(id, public62Definition, true))
	database.payload = `{"family":"ordered","result":` + string(resource) + `}`
	detail, err := ordered.getSecurityAgentRunCurrent(context.Background(), id, public62Definition)
	if err != nil || detail.Ordered == nil || detail.Ordered.ContractVersion != 62 || len(detail.Ordered.Steps) != 2 || detail.Run.ID != public62Definition || len(detail.Approvals) != 1 {
		t.Fatalf("ordered detail=%+v err=%v", detail, err)
	}
	public, _ := json.Marshal(detail)
	if !strings.Contains(string(public), `"ordered":{"contract_version":62,"steps":[`) {
		t.Fatalf("ordered extension missing from the public detail: %s", public)
	}
	if _, err := ordered.getSecurityAgentRunCurrent(context.Background(), id, public62Finding); err != ErrRepositoryUnavailable {
		t.Fatalf("ordered detail of another run: err=%v", err)
	}
	token := id
	token.CredentialKind = CredentialBearerToken
	if _, err := ordered.getSecurityAgentRunCurrent(context.Background(), token, public62Definition); err != ErrRepositoryOperation {
		t.Fatalf("ordered detail for an API token: err=%v", err)
	}
	approval, err := ordered.getSecurityAgentApprovalCurrent(context.Background(), id, detail.Approvals[0].ID)
	if err != nil || !approval.ordered || approval.ID != detail.Approvals[0].ID {
		t.Fatalf("ordered approval=%+v err=%v", approval, err)
	}
	if _, err := ordered.getSecurityAgentApprovalCurrent(context.Background(), id, public62Finding); err != ErrRepositoryUnavailable {
		t.Fatalf("ordered approval that the resource does not hold: err=%v", err)
	}
	q := public62DecisionInput()
	mutation := public62DecisionFixture(id, q)
	for _, field := range []string{"approval_id", "approval_version", "decision"} {
		delete(mutation, field)
	}
	mutation["run_id"], mutation["run_state"], mutation["step_state"], mutation["step_id"], mutation["step_version"], mutation["cleanup_required"], mutation["outcome"], mutation["cancellation_phase"] = public62Definition, "needs_human", nil, nil, 0, false, "cancelled-request", "before-admission"
	mutation["audit_id"], _ = CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
	mutation["receipt_id"], _ = CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
	retained, _ := json.Marshal(mutation)
	database.payload = `{"family":"ordered","result":{"resource":` + string(resource) + `,"mutation":` + string(retained) + `}}`
	orderedCancel := SecurityAgentCancelRequest{RunID: public62Definition, IdempotencyKey: q.IdempotencyKey, ExpectedVersion: 3, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt}
	got, err := ordered.cancelSecurityAgentRunCurrent(context.Background(), id, orderedCancel)
	if err != nil || got.Ordered == nil || got.Ordered.CleanupRequired || got.State != "needs_human" || got.Version != 4 || got.ID != public62Definition || got.AuditID != mutation["audit_id"] {
		t.Fatalf("ordered cancellation=%+v err=%v", got, err)
	}
	orderedCancel.ExpectedVersion = 2
	if _, err := ordered.cancelSecurityAgentRunCurrent(context.Background(), id, orderedCancel); err != ErrRepositoryUnavailable {
		t.Fatalf("ordered cancellation of another version: err=%v", err)
	}
	orderedCancel.ExpectedVersion = 3
	if _, err := ordered.cancelSecurityAgentRunCurrent(context.Background(), token, orderedCancel); err != ErrRepositoryOperation {
		t.Fatalf("ordered cancellation for an API token: err=%v", err)
	}
}

// A cancellation of an ordered run answers with the ordered extension, and
// may leave the run for a human; any other run must end cancelled.
func TestSecurityAgentCancelHandlerPublishesOrderedExtension(t *testing.T) {
	i := fixtureRequestIdentity(t)
	const run, agent, evidence = "pid_78000006-0000-4000-8000-000000000006", "pid_78000001-0000-4000-8000-000000000001", "pid_78000005-0000-4000-8000-000000000005"
	for _, tc := range []struct {
		name, state string
		ordered     *SecurityAgentOrderedCancellation
		status      int
		body        string
	}{
		{"cancelled", "cancelled", nil, http.StatusOK, `"state":"cancelled"`},
		{"ordered needs human", "needs_human", &SecurityAgentOrderedCancellation{CleanupRequired: true}, http.StatusOK, `"ordered":{"cleanup_required":true}`},
		{"needs human without the ordered release", "needs_human", nil, http.StatusServiceUnavailable, ``},
	} {
		authority := &securityAgentCancelAuthority{result: SecurityAgentRunResult{ID: run, AgentID: agent, State: tc.state, EvidenceIDs: []string{evidence}, DefinitionVersion: 1, Version: 4, AuditID: "pid_30000001-0000-4000-8000-000000000001", CorrelationID: "pid_30000002-0000-4000-8000-000000000002", ReceiptID: "pid_30000003-0000-4000-8000-000000000003", Ordered: tc.ordered}}
		handler := &securityAgentPublicHTTPHandler{repository: authority, config: SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID}}
		ctx := context.WithValue(context.Background(), routedOperationContextKey{}, RoutedOperation{OperationID: "cancelSecurityAgentRun", PathParameters: map[string]string{"id": run}})
		ctx = context.WithValue(context.WithValue(ctx, identityContextKey{}, i), correlationContextKey{}, "pid_30000002-0000-4000-8000-000000000002")
		request := httptest.NewRequest(http.MethodPost, "/api/v1/security-agent-runs/"+run+"/cancel", nil).WithContext(ctx)
		request.Header.Set("Idempotency-Key", "idempotency-key-0001")
		request.Header.Set("If-Match", `"3"`)
		response := httptest.NewRecorder()
		handler.cancelRun(response, request, RoutedOperation{OperationID: "cancelSecurityAgentRun", PathParameters: map[string]string{"id": run}})
		if response.Code != tc.status || tc.body != "" && !strings.Contains(response.Body.String(), tc.body) || tc.ordered == nil && strings.Contains(response.Body.String(), `"ordered"`) {
			t.Fatalf("%s: status=%d body=%s", tc.name, response.Code, response.Body.String())
		}
	}
}

type securityAgentCancelAuthority struct {
	SecurityAgentPublicAuthority
	result SecurityAgentRunResult
}

func (a *securityAgentCancelAuthority) CancelSecurityAgentRun(context.Context, RequestIdentity, SecurityAgentCancelRequest) (SecurityAgentRunResult, error) {
	return a.result, nil
}
