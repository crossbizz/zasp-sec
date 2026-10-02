package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type exportDefinitionDenialDatabase struct {
	*exportDefinitionRouteDatabase
	statement string
	denial    error
}

func (d *exportDefinitionDenialDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	if query == d.statement {
		return nil, d.denial
	}
	return d.exportDefinitionRouteDatabase.QueryJSON(ctx, query, args...)
}

// Only a current caller permission denial is a 403. Infrastructure uses the
// same SQLSTATE, so code-only matching would misreport principal outages.
func TestSecurityAgentExportDefinitionAuthorityErrors(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.FreshAuthenticated, identity.FreshAuthExpiresAt = true, time.Now().UTC().Add(time.Minute)
	id, audit, receipt := "pid_8be50000-0000-4000-8000-000000000001", "pid_8be50000-0000-4000-8000-000000000002", "pid_8be50000-0000-4000-8000-000000000003"
	body, _ := json.Marshal(exportDefinitionTestBody(t, identity, id))
	retained, _ := json.Marshal(WorkflowValue{Body: body, Version: 1})
	for _, failure := range []struct {
		code, message string
		status        int
	}{
		{"42501", "export definition permission rejected", 403},
		{"42501", "export definition principal unavailable", 503},
		{"42501", "permission denied for function zasp_sa_export_controls", 503},
		{"55000", "export definition release unavailable", 503},
		{"55000", "export definition permission rejected", 503},
		{"42501", "export definition scope rejected", 503},
		{"23505", "existing unique conflict", 409},
		{"22023", "existing invalid input", 400},
	} {
		for _, operation := range []string{"create", "replay", "controls", "control", "detail", "activate", "value", "page"} {
			t.Run(failure.code+"/"+failure.message+"/"+operation, func(t *testing.T) {
				db := &exportDefinitionDenialDatabase{exportDefinitionRouteDatabase: &exportDefinitionRouteDatabase{installed: true, connected: true, retained: retained}, denial: classifyPostgresError(&pgconn.PgError{Code: failure.code, Message: failure.message})}
				repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: ProductionRecoverySchemaVersion}
				var err error
				switch operation {
				case "create":
					db.statement = postgresExportDefinitionMutateSQL
					_, err = repo.MutateWorkflow(context.Background(), identity, WorkflowMutation{Action: "create", Kind: "security_agent", ID: id, Operation: "createSecurityAgent", IdempotencyKey: "export-denial-create-0001", Intent: json.RawMessage(`{}`), Body: body, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				case "replay":
					db.statement = postgresExportDefinitionReplaySQL
					_, _, err = repo.ReplayWorkflow(context.Background(), identity, "deleteSecurityAgent", "export-denial-delete-0001", json.RawMessage(`{}`))
				case "controls":
					db.statement = postgresExportControlsSQL
					_, err = repo.GetSecurityAgentExecutionControls(context.Background(), identity)
				case "control":
					db.statement = postgresExportSetControlSQL
					_, err = repo.SetSecurityAgentExecutionControl(context.Background(), identity, SecurityAgentExecutionControlMutation{Target: "action", ActionKey: "create_evidence_export", Enabled: false, IdempotencyKey: "export-denial-control-001", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				case "detail":
					db.statement = postgresExportDefinitionDetailSQL
					_, err = repo.GetSecurityAgentActivation(context.Background(), identity, id)
				case "activate":
					db.statement = postgresExportActivateSQL
					_, err = repo.ActivateSecurityAgent(context.Background(), identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "export-denial-activate-01", ExpectedVersion: 1, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				case "value":
					db.statement = postgresExportDefinitionValueSQL
					_, err = repo.GetWorkflowForIdentity(context.Background(), identity, "security_agent", id)
				case "page":
					db.statement = postgresExportDefinitionPageSQL
					_, err = repo.ListWorkflowPageForIdentity(context.Background(), identity, "security_agent", "", 20)
				}
				if errors.Is(err, ErrRepositoryAuthorization) != (failure.status == 403) || failure.status == 503 && !errors.Is(err, ErrRepositoryUnavailable) {
					t.Errorf("repository error=%v, want HTTP %d classification", err, failure.status)
				}
				if operation == "create" {
					return
				} // Replay precedes public create.
				definitions, _ := newWorkflowHTTPHandler(repo, securityAgentTestSigningKey, time.Now)
				ids := []string{audit, receipt}
				h, handlerErr := NewSecurityAgentPublicHTTPHandler(repo, definitions, SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil }})
				if handlerErr != nil {
					t.Fatal(handlerErr)
				}
				method, input := http.MethodGet, ""
				route := map[string]string{"replay": "deleteSecurityAgent", "controls": "getSecurityAgentExecutionControls", "control": "setSecurityAgentExecutionControl", "detail": "getSecurityAgentActivation", "activate": "activateSecurityAgent", "value": "getSecurityAgent", "page": "listSecurityAgents"}[operation]
				switch operation {
				case "replay":
					method = http.MethodDelete
				case "control":
					method, input = http.MethodPut, `{"target":"action","action_key":"create_evidence_export","enabled":false}`
				case "activate":
					method, input = http.MethodPost, `{"activation":"validated"}`
				}
				request := workflowRequest(t, identity, testCorrelationID, route, map[string]string{"id": id}, method, "/api/v1/security-agents", input)
				request.Header.Set("Idempotency-Key", "export-denial-http-000001")
				request.Header.Set("If-Match", `"1"`)
				request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
				response := httptest.NewRecorder()
				h.ServeHTTP(response, request)
				if response.Code != failure.status {
					t.Fatalf("HTTP %d, want %d: %s", response.Code, failure.status, response.Body.String())
				}
				if failure.status == 403 && (!strings.Contains(response.Body.String(), `"code":"authorization_rejected"`) || !strings.Contains(response.Body.String(), `"retryable":false`)) {
					t.Fatalf("wrong denial envelope: %s", response.Body.String())
				}
			})
		}
	}
}

func TestSecurityAgentExportDefinitionAuthorityErrorScope(t *testing.T) {
	denial := classifyPostgresError(&pgconn.PgError{Code: "42501", Message: "export definition permission rejected"})
	for _, statement := range []string{postgresWorkflowReplaySQL, postgresSecurityAgentDefinitionReplaySQL, postgresExistingTestControlsSQL, postgresSecurityAgentActivateSQL, postgresSecurityAgentManualRunSQL} {
		if got := exportDefinitionError(statement, denial); got != denial {
			t.Fatalf("unrelated statement error changed: %s: %v", statement, got)
		}
	}
}

func exportDefinitionTestBody(t *testing.T, identity RequestIdentity, id string) map[string]any {
	t.Helper()
	body := map[string]any{"name": "Export selected evidence", "trigger_kind": "schedule", "trigger_source": "daily", "environment_ids": []string{identity.Scope.EnvironmentID().String()}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 1, "allowed_actions": []string{"create_evidence_export"}, "verification_kind": "export", "definition_version": 1, "enabled": false}
	if id != "" {
		body["id"] = id
	}
	return body
}

type exportDefinitionRouteDatabase struct {
	workflowCallDatabase
	installed, connected bool
	admissionErr         error
	retained             json.RawMessage
}

func (d *exportDefinitionRouteDatabase) SecurityAgentExportDefinitionsAvailable(context.Context) (bool, error) {
	return d.installed, d.admissionErr
}
func (d *exportDefinitionRouteDatabase) SecurityAgentExportsWorkflowAvailable(context.Context) (bool, error) {
	return d.connected, d.admissionErr
}
func (d *exportDefinitionRouteDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	if strings.Contains(query, "definition_value(") {
		d.query, d.args = query, args
		return d.retained, nil
	}
	return d.workflowCallDatabase.QueryJSON(ctx, query, args...)
}

// Catch a known export write selecting predecessor authority, dropping the
// caller on reads, or allowing worker outages to prevent a safe withdrawal.
func TestSecurityAgentExportDefinitionRepositoryRouting(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.FreshAuthenticated, identity.FreshAuthExpiresAt = true, time.Now().UTC().Add(time.Minute)
	id := "pid_8be20000-0000-4000-8000-000000000001"
	audit, receipt := "pid_8be20000-0000-4000-8000-000000000002", "pid_8be20000-0000-4000-8000-000000000003"
	body, _ := json.Marshal(exportDefinitionTestBody(t, identity, id))
	retained, _ := json.Marshal(WorkflowValue{Body: body, Version: 1})
	boundary := errors.New("SQL boundary")
	for _, op := range []string{"create", "update", "delete", "replay", "activate", "disable", "control enable", "control disable", "controls", "detail", "value", "page"} {
		t.Run(op, func(t *testing.T) {
			db := &exportDefinitionRouteDatabase{workflowCallDatabase: workflowCallDatabase{err: boundary}, installed: true, connected: true, retained: retained}
			repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: ProductionRecoverySchemaVersion}
			var err error
			want, n := "", 0
			switch op {
			case "create", "update", "delete":
				input := WorkflowMutation{Action: op, Kind: "security_agent", ID: id, Operation: op + "SecurityAgent", IdempotencyKey: "export-repository-routing-01", ExpectedVersion: 1, Intent: json.RawMessage(`{}`), Body: body, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt}
				if op == "create" {
					input.ExpectedVersion = 0
				}
				if op == "delete" {
					input.Body = json.RawMessage(`{}`)
					db.connected = false
				}
				_, err = repo.MutateWorkflow(context.Background(), identity, input)
				want, n = `SELECT public.zasp_sa_export_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14,$15,$16)`, 16
			case "replay":
				intent, _ := json.Marshal(map[string]any{"body": json.RawMessage(`{}`), "resource_id": id, "expected_version": 1})
				db.connected = false
				_, _, err = repo.ReplayWorkflow(context.Background(), identity, "deleteSecurityAgent", "export-repository-routing-01", intent)
				want, n = `SELECT public.zasp_sa_export_replay_definition($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, 9
			case "activate", "disable":
				mode := "supervised"
				if op == "disable" {
					mode = "validated"
					db.connected = false
				}
				_, err = repo.ActivateSecurityAgent(context.Background(), identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "export-repository-routing-01", ExpectedVersion: 1, TargetActivation: mode, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				want, n = `SELECT public.zasp_sa_export_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, 14
			case "control enable", "control disable":
				enabled := op == "control enable"
				db.connected = enabled
				_, err = repo.SetSecurityAgentExecutionControl(context.Background(), identity, SecurityAgentExecutionControlMutation{Target: "action", ActionKey: "create_evidence_export", Enabled: enabled, IdempotencyKey: "export-repository-routing-01", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				want, n = `SELECT public.zasp_sa_export_set_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, 15
			case "controls":
				db.connected = false
				_, err = repo.GetSecurityAgentExecutionControls(context.Background(), identity)
				want, n = `SELECT public.zasp_sa_export_controls($1,$2,$3,$4,$5,$6)`, 6
			case "detail":
				db.connected = false
				_, err = repo.GetSecurityAgentActivation(context.Background(), identity, id)
				want, n = `SELECT public.zasp_sa_export_definition_detail($1,$2,$3,$4,$5,$6,$7)`, 7
			case "value", "page":
				db.connected = false
				h, _ := newWorkflowHTTPHandler(repo, securityAgentTestSigningKey, time.Now)
				operation := "getSecurityAgent"
				if op == "page" {
					operation = "listSecurityAgents"
				}
				response := httptest.NewRecorder()
				h.ServeHTTP(response, workflowRequest(t, identity, testCorrelationID, operation, map[string]string{"id": id}, http.MethodGet, "/api/v1/security-agents", ""))
				if op == "value" {
					want, n = `SELECT public.zasp_sa_export_definition_value($1,$2,$3,$4,$5,$6,$7)`, 7
				} else {
					want, n = `SELECT public.zasp_sa_export_definition_page($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8)`, 8
				}
				// The SQL fixture returns a retained value; page reaches the failure boundary.
				err = boundary
			}
			if !errors.Is(err, boundary) || db.query != want || len(db.args) != n {
				t.Fatalf("%s route=%s args=%d err=%v", op, db.query, len(db.args), err)
			}
			if db.args[n-2] != migrations.ProductionSecurityAgentExports().Checksum() || db.args[n-1] != migrations.SecurityAgentExportsFingerprint() {
				t.Fatal("route lost compiled58 pins")
			}
			if op == "value" || op == "detail" {
				if db.args[4] != identity.PrincipalID.String() {
					t.Fatal("read lost actor")
				}
			}
			if op == "controls" || op == "page" {
				if db.args[3] != identity.PrincipalID.String() {
					t.Fatal("read lost actor")
				}
			}
		})
	}
}

// These cases catch export intent falling through the static production-action
// guard, retained state depending on workers, and the obsolete seven-key fence.
func TestSecurityAgentExportDefinitionBoundary(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	id := "pid_8be10000-0000-4000-8000-000000000001"
	t.Run("ready draft create and update", func(t *testing.T) {
		r := &exportCatalogRepository{workflowRepositoryStub: &workflowRepositoryStub{}, ready: true}
		h, err := newWorkflowHTTPHandler(r, securityAgentTestSigningKey, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		for _, create := range []bool{true, false} {
			operation, bodyID := "updateSecurityAgent", id
			if create {
				operation, bodyID = "createSecurityAgent", ""
			}
			raw, _ := json.Marshal(exportDefinitionTestBody(t, identity, bodyID))
			request := workflowRequest(t, identity, testCorrelationID, operation, map[string]string{"id": bodyID}, http.MethodPost, "/api/v1/security-agents", string(raw))
			request.Header.Set("If-Match", `"1"`)
			mutation, _, _, err := h.buildMutation(request, identity, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": bodyID}}, "export-definition-boundary-01", id, testCorrelationID)
			if err != nil || !json.Valid(mutation.Body) {
				t.Fatalf("ready export draft %s rejected: %v", operation, err)
			}
		}
	})
	t.Run("export outage does not block unrelated draft", func(t *testing.T) {
		r := &exportCatalogRepository{workflowRepositoryStub: &workflowRepositoryStub{}, err: errors.New("export worker unavailable")}
		h, _ := newWorkflowHTTPHandler(r, securityAgentTestSigningKey, time.Now)
		body := exportDefinitionTestBody(t, identity, "")
		body["allowed_actions"], body["verification_kind"] = []string{"update_finding_response"}, "finding_state"
		raw, _ := json.Marshal(body)
		request := workflowRequest(t, identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(raw))
		if _, _, _, err := h.buildMutation(request, identity, RoutedOperation{OperationID: "createSecurityAgent"}, "export-unrelated-boundary-01", id, testCorrelationID); err != nil {
			t.Fatalf("export outage blocked unrelated intent: %v", err)
		}
	})
	t.Run("retained activation during outage", func(t *testing.T) {
		for _, mode := range []string{"draft", "validated", "supervised", "autonomous", "supervised-autonomous"} {
			activation := mode
			if mode == "supervised-autonomous" {
				activation = "supervised"
			}
			body := exportDefinitionTestBody(t, identity, id)
			enabled := activation == "supervised" || activation == "autonomous"
			body["enabled"] = enabled
			if enabled {
				body["autonomy"] = activation
			}
			if mode == "supervised-autonomous" {
				body["autonomy"] = "autonomous"
			}
			raw, _ := json.Marshal(map[string]any{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "definition_id": id, "activation": activation, "version": 3, "definition_version": 1, "body": body, "updated_at": "2026-09-19T12:00:00Z"})
			db := &workflowCallDatabase{response: raw}
			repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: ProductionRecoverySchemaVersion}
			got, err := repo.GetSecurityAgentActivation(context.Background(), identity, id)
			if err != nil || got.Activation != activation || got.Enabled != enabled {
				t.Errorf("retained %s rejected: %+v %v", activation, got, err)
			}
		}
	})
	t.Run("eight controls", func(t *testing.T) {
		value := exportDefinitionTestControls()
		if !validSecurityAgentExecutionControls(value) {
			t.Fatal("eight sorted controls rejected")
		}
		value.Actions[0].Enabled = true
		if validSecurityAgentExecutionControls(value) {
			t.Fatal("enabled version-zero export control accepted")
		}
		value = exportDefinitionTestControls()
		value.Actions[1].ActionKey = "create_evidence_export"
		if validSecurityAgentExecutionControls(value) {
			t.Fatal("duplicate export control accepted")
		}
	})
	t.Run("export control HTTP", func(t *testing.T) {
		now := time.Now().UTC()
		audit, receipt := "pid_8be10000-0000-4000-8000-000000000002", "pid_8be10000-0000-4000-8000-000000000003"
		for _, enabled := range []bool{false, true} {
			stub := &securityAgentPublicAuthorityStub{controlResult: SecurityAgentExecutionControlResult{Target: "action", ActionKey: "create_evidence_export", Enabled: enabled, Version: 1, AuditID: audit, ReceiptID: receipt, CorrelationID: testCorrelationID}}
			ids := []string{audit, receipt}
			h, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil }})
			if err != nil {
				t.Fatal(err)
			}
			identity.FreshAuthenticated, identity.FreshAuthExpiresAt = true, now.Add(time.Minute)
			raw, _ := json.Marshal(map[string]any{"target": "action", "action_key": "create_evidence_export", "enabled": enabled})
			request := workflowRequest(t, identity, testCorrelationID, "setSecurityAgentExecutionControl", nil, http.MethodPut, "/api/v1/security-agent-execution-controls", string(raw))
			request.Header.Set("Idempotency-Key", "export-definition-control-01")
			request.Header.Set("If-Match", `"0"`)
			request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != 200 || response.Header().Get("X-Mutation-Receipt-ID") != receipt || response.Header().Get("ETag") != `"1"` {
				t.Fatalf("export control rejected: %d %s", response.Code, response.Body.String())
			}
		}
	})
	t.Run("draft readiness and malformed intent", func(t *testing.T) {
		for _, name := range []string{"absent", "outage", "drift", "enabled", "composite", "existing_test", "wrong verification", "foreign environment", "multiple steps", "missing cost", "outage malformed"} {
			t.Run(name, func(t *testing.T) {
				r := &exportCatalogRepository{workflowRepositoryStub: &workflowRepositoryStub{}, ready: true}
				body := exportDefinitionTestBody(t, identity, "")
				switch name {
				case "absent", "outage":
					r.ready = false
				case "drift":
					r.err = errors.New("admission drift")
				case "enabled":
					body["enabled"] = true
				case "composite":
					body["allowed_actions"] = []string{"create_evidence_export", "update_finding_response"}
				case "existing_test":
					body["existing_test"] = map[string]any{"definition_id": id, "definition_version": 1}
				case "wrong verification":
					body["verification_kind"] = "test_run"
				case "foreign environment":
					body["environment_ids"] = []string{id}
				case "multiple steps":
					body["max_steps"] = 2
				case "missing cost":
					delete(body, "max_ai_cost_nano_credits")
				case "outage malformed":
					r.ready = false
					body["enabled"] = true
				}
				h, _ := newWorkflowHTTPHandler(r, securityAgentTestSigningKey, time.Now)
				raw, _ := json.Marshal(body)
				request := workflowRequest(t, identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(raw))
				_, _, _, err := h.buildMutation(request, identity, RoutedOperation{OperationID: "createSecurityAgent"}, "export-definition-boundary-01", id, testCorrelationID)
				if err == nil {
					t.Fatal("unsafe export intent accepted")
				}
				if stringIn(name, "absent", "outage", "drift") && !errors.Is(err, ErrRepositoryUnavailable) {
					t.Fatalf("unavailable export intent misclassified: %v", err)
				}
				if name == "outage malformed" && !errors.Is(err, ErrRepositoryOperation) {
					t.Fatalf("malformed intent reported as outage: %v", err)
				}
			})
		}
	})
}

func exportDefinitionTestControls() SecurityAgentExecutionControls {
	value := SecurityAgentExecutionControls{Global: SecurityAgentExecutionControl{Target: "global", ActionKey: "*", Version: 1}, Environment: SecurityAgentExecutionControl{Target: "environment", ActionKey: "*"}}
	for _, key := range []string{"create_evidence_export", "create_temporary_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "start_attack_lab", "update_finding_response"} {
		value.Actions = append(value.Actions, SecurityAgentExecutionControl{Target: "action", ActionKey: key})
	}
	return value
}

func TestSecurityAgentExportDefinitionAdmissionRefusals(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.FreshAuthenticated, identity.FreshAuthExpiresAt = true, time.Now().UTC().Add(time.Minute)
	id, audit, receipt := "pid_8be30000-0000-4000-8000-000000000001", "pid_8be30000-0000-4000-8000-000000000002", "pid_8be30000-0000-4000-8000-000000000003"
	body, _ := json.Marshal(exportDefinitionTestBody(t, identity, id))
	retained, _ := json.Marshal(WorkflowValue{Body: body, Version: 1})
	for _, state := range []string{"absent", "drift", "workers down"} {
		for _, operation := range []string{"create", "control", "activate", "delete"} {
			if state == "workers down" && operation == "delete" {
				continue
			}
			t.Run(state+"/"+operation, func(t *testing.T) {
				db := &exportDefinitionRouteDatabase{installed: state != "absent", connected: false, retained: retained}
				if state == "drift" {
					db.admissionErr = ErrRepositoryUnavailable
				}
				repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: ProductionRecoverySchemaVersion}
				var err error
				switch operation {
				case "delete":
					_, err = repo.MutateWorkflow(context.Background(), identity, WorkflowMutation{Action: "delete", Kind: "security_agent", ID: id, Operation: "deleteSecurityAgent", IdempotencyKey: "export-refusal-delete-0001", ExpectedVersion: 1, Intent: json.RawMessage(`{}`), Body: json.RawMessage(`{}`), AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				case "create":
					_, err = repo.MutateWorkflow(context.Background(), identity, WorkflowMutation{Action: "create", Kind: "security_agent", ID: id, Operation: "createSecurityAgent", IdempotencyKey: "export-refusal-create-0001", Intent: json.RawMessage(`{}`), Body: body, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				case "control":
					_, err = repo.SetSecurityAgentExecutionControl(context.Background(), identity, SecurityAgentExecutionControlMutation{Target: "action", ActionKey: "create_evidence_export", Enabled: true, IdempotencyKey: "export-refusal-control-001", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				case "activate":
					_, err = repo.ActivateSecurityAgent(context.Background(), identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "export-refusal-activate-01", ExpectedVersion: 1, TargetActivation: "supervised", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt})
				}
				if err == nil || strings.Contains(db.query, "mutate_definition(") || strings.Contains(db.query, "set_control(") || strings.Contains(db.query, "activate(") {
					t.Fatalf("unsafe admission reached write: query=%s err=%v", db.query, err)
				}
			})
		}
	}
	for _, installed := range []bool{false, true} {
		t.Run(fmt.Sprintf("controls installed=%t", installed), func(t *testing.T) {
			raw, _ := json.Marshal(exportDefinitionTestControls())
			db := &exportDefinitionRouteDatabase{installed: installed, workflowCallDatabase: workflowCallDatabase{response: raw}}
			repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: ProductionRecoverySchemaVersion}
			_, err := repo.GetSecurityAgentExecutionControls(context.Background(), identity)
			if (err == nil) != installed {
				t.Fatalf("eight-key admission installed=%t err=%v", installed, err)
			}
		})
	}
}
