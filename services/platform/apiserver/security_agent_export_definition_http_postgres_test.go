package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// The registered DB supplies admission and settlement readiness. This fixture
// controls only worker health; it is not a deployed runtime or browser login.
type exportDefinitionHTTPDatabase struct {
	*PostgresJSONDatabase
	workersReady    bool
	lastFailedQuery string
	lastError       error
	driver          *exportDefinitionHTTPDriver
}

type exportDefinitionHTTPDriver struct {
	*integrationPostgresDriver
	lastError error
}
type exportDefinitionHTTPRow struct {
	PostgresRow
	driver *exportDefinitionHTTPDriver
}

func (d *exportDefinitionHTTPDriver) QueryRow(ctx context.Context, query string, args ...any) PostgresRow {
	return &exportDefinitionHTTPRow{PostgresRow: d.integrationPostgresDriver.QueryRow(ctx, query, args...), driver: d}
}
func (r *exportDefinitionHTTPRow) Scan(values ...any) error {
	err := r.PostgresRow.Scan(values...)
	if err != nil {
		r.driver.lastError = err
	}
	return err
}

func (d *exportDefinitionHTTPDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	value, err := d.PostgresJSONDatabase.QueryJSON(ctx, query, args...)
	if err != nil {
		d.lastFailedQuery, d.lastError = query, err
	}
	return value, err
}

func (d *exportDefinitionHTTPDatabase) SecurityAgentExportsWorkflowAvailable(ctx context.Context) (bool, error) {
	installed, err := d.SecurityAgentExportDefinitionsAvailable(ctx)
	if err != nil || !installed {
		return false, err
	}
	settlement, err := d.SecurityAgentExportsAvailable(ctx)
	return settlement && d.workersReady, err
}

// Catch public setup requiring owner-seeded definitions, receipts changing on
// replay, or worker failure blocking read/withdrawal. Every export definition,
// activation, action control and manual run below comes through the real router.
func TestSecurityAgentExportDefinitionHTTPPostgres(t *testing.T) {
	runExportDefinitionFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		var seeded int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'create_evidence_export')+(SELECT count(*) FROM zasp_security_agent_definition_versions WHERE definition->'allowed_actions' ? 'create_evidence_export')+(SELECT count(*) FROM zasp_security_agent_kill_switches WHERE action_key='create_evidence_export')+(SELECT count(*) FROM zasp_security_agent_runs)`).Scan(&seeded); err != nil || seeded != 0 {
			t.Fatalf("public fixture already has export authority: %d %v", seeded, err)
		}
		driver := &exportDefinitionHTTPDriver{integrationPostgresDriver: &integrationPostgresDriver{connection: api}}
		native, err := NewPostgresJSONDatabase(driver)
		if err != nil {
			t.Fatal(err)
		}
		db := &exportDefinitionHTTPDatabase{PostgresJSONDatabase: native, workersReady: true, driver: driver}
		repo, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		parse := func(s string) domain.ProductID {
			t.Helper()
			v, err := domain.ParseProductID(s)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		identity.Scope, err = domain.NewScope(parse(o), parse(w), parse(e))
		if err != nil {
			t.Fatal(err)
		}
		identity.PrincipalID = parse(actor)
		identity.Permissions = []string{"view", "manage_workflows", "manage_identity", "view_audit"}
		now := time.Now().UTC().Truncate(time.Microsecond)
		identity.FreshAuthenticated, identity.FreshAuthExpiresAt = true, now.Add(4*time.Minute)
		definitions, err := newWorkflowHTTPHandler(repo, securityAgentTestSigningKey, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		public, err := NewSecurityAgentPublicHTTPHandler(repo, definitions, SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
		if err != nil {
			t.Fatal(err)
		}
		router, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: public, Connector: handlerResponse("connector")})
		if err != nil {
			t.Fatal(err)
		}
		requestSequence := 0
		call := func(method, path, body, version, key string, change ...func(*http.Request)) *httptest.ResponseRecorder {
			t.Helper()
			requestSequence++
			correlation := fmt.Sprintf("pid_8be40000-0000-4000-8000-%012d", requestSequence)
			r := workflowRequest(t, identity, correlation, "", nil, method, path, body)
			if identity.CredentialKind == CredentialBrowserSession {
				r = r.WithContext(context.WithValue(r.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
				r.Header.Set("Origin", "https://app.zasp.test")
				r.Header.Set("X-CSRF-Token", identity.CSRFToken)
				r.Header.Set(expectedScopeHeader, o+"/"+w+"/"+e)
				r.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
			}
			if version != "" {
				r.Header.Set("If-Match", version)
			}
			if key != "" {
				r.Header.Set("Idempotency-Key", key)
			}
			for _, f := range change {
				f(r)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, r)
			return response
		}
		must := func(response *httptest.ResponseRecorder, status int) {
			t.Helper()
			if response.Code != status {
				t.Fatalf("HTTP status=%d want=%d body=%s SQL=%s error=%v provider=%v", response.Code, status, response.Body.String(), db.lastFailedQuery, db.lastError, db.driver.lastError)
			}
		}
		marshal := func(v any) string {
			t.Helper()
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
		// Bearer CRUD must retain original idempotency/audit results without
		// creating browser receipts or bypassing current actor authority.
		if !t.Run("bearer CRUD and original request retries", func(t *testing.T) {
			browserIdentity := identity
			identity.CredentialKind, identity.CSRFToken = CredentialBearerToken, ""
			identity.FreshAuthenticated, identity.FreshAuthExpiresAt = false, time.Time{}
			defer func() { identity = browserIdentity }()
			check := func(response *httptest.ResponseRecorder, status int) {
				t.Helper()
				if response.Code != status || response.Header().Get("X-Mutation-Receipt-ID") != "" {
					t.Fatalf("bearer HTTP status=%d want=%d receipt=%q body=%s SQL=%s error=%v provider=%v", response.Code, status, response.Header().Get("X-Mutation-Receipt-ID"), response.Body.String(), db.lastFailedQuery, db.lastError, db.driver.lastError)
				}
			}
			checkRetry := func(original, retry *httptest.ResponseRecorder, status int) {
				t.Helper()
				check(retry, status)
				if retry.Body.String() != original.Body.String() || retry.Header().Get("X-Audit-ID") != original.Header().Get("X-Audit-ID") || retry.Header().Get("ETag") != original.Header().Get("ETag") {
					t.Fatalf("bearer retry changed original response: original=%v %s retry=%v %s", original.Header(), original.Body.String(), retry.Header(), retry.Body.String())
				}
			}
			draft := exportDefinitionTestBody(t, identity, "")
			createBody := marshal(draft)
			created := call(http.MethodPost, "/api/v1/security-agents", createBody, "", "http-export-pat-create-01")
			check(created, 201)
			var saved map[string]any
			if json.Unmarshal(created.Body.Bytes(), &saved) != nil {
				t.Fatal(created.Body.String())
			}
			id, _ := saved["id"].(string)
			if !validProductID(id) || !validProductID(created.Header().Get("X-Audit-ID")) || created.Header().Get("ETag") != `"1"` {
				t.Fatal("bearer create lost definition/audit/version")
			}
			path := "/api/v1/security-agents/" + id
			checkRetry(created, call(http.MethodPost, "/api/v1/security-agents", createBody, "", "http-export-pat-create-01"), 201)
			draft["id"], draft["name"] = id, "Bearer updated export"
			updateBody := marshal(draft)
			updated := call(http.MethodPatch, path, updateBody, `"1"`, "http-export-pat-update-01")
			check(updated, 200)
			if updated.Header().Get("ETag") != `"2"` || !validProductID(updated.Header().Get("X-Audit-ID")) || updated.Header().Get("X-Audit-ID") == created.Header().Get("X-Audit-ID") {
				t.Fatal("bearer update lost distinct audit/CAS")
			}
			checkRetry(updated, call(http.MethodPatch, path, updateBody, `"1"`, "http-export-pat-update-01"), 200)
			check(call(http.MethodPatch, path, updateBody, `"1"`, "http-export-pat-stale-001"), 409)
			check(call(http.MethodGet, path, "", "", ""), 200)
			check(call(http.MethodGet, "/api/v1/security-agents?limit=10", "", "", ""), 200)
			deleted := call(http.MethodDelete, path, "", `"2"`, "http-export-pat-delete-01")
			check(deleted, 204)
			if !validProductID(deleted.Header().Get("X-Audit-ID")) {
				t.Fatal("bearer delete lost audit")
			}
			checkRetry(deleted, call(http.MethodDelete, path, "", `"2"`, "http-export-pat-delete-01"), 204)
			checkRetry(created, call(http.MethodPost, "/api/v1/security-agents", createBody, "", "http-export-pat-create-01"), 201)
			checkRetry(updated, call(http.MethodPatch, path, updateBody, `"1"`, "http-export-pat-update-01"), 200)
			check(call(http.MethodGet, path, "", "", ""), 404)
			if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
					t.Error(err)
				}
			}()
			check(call(http.MethodPost, "/api/v1/security-agents", createBody, "", "http-export-pat-create-01"), 403)
			check(call(http.MethodPatch, path, updateBody, `"1"`, "http-export-pat-update-01"), 403)
			check(call(http.MethodDelete, path, "", `"2"`, "http-export-pat-delete-01"), 403)
			check(call(http.MethodPost, "/api/v1/security-agents", createBody, "", "http-export-pat-revoked-01"), 403)
			var receipts, mutations, audits int
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_receipts WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)),(SELECT count(*) FROM zasp_workflow_idempotency WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)),(SELECT count(*) FROM zasp_workflow_audit WHERE (organization_id,workspace_id,environment_id,principal_id,resource_id)=($1,$2,$3,$4,$5))`, o, w, e, actor, id).Scan(&receipts, &mutations, &audits); err != nil || receipts != 0 || mutations != 3 || audits != 3 {
				t.Fatalf("bearer persisted receipts=%d mutations=%d audits=%d, want0/3/3: %v", receipts, mutations, audits, err)
			}
		}) {
			return
		}
		body := exportDefinitionTestBody(t, identity, "")
		body["concurrency_limit"] = 2
		created := call(http.MethodPost, "/api/v1/security-agents", marshal(body), "", "http-export-create-0001")
		must(created, 201)
		var saved map[string]any
		if json.Unmarshal(created.Body.Bytes(), &saved) != nil {
			t.Fatal(created.Body.String())
		}
		id, _ := saved["id"].(string)
		if !validProductID(id) || created.Header().Get("ETag") != `"1"` || !validProductID(created.Header().Get("X-Mutation-Receipt-ID")) {
			t.Fatal("create lost original definition/receipt")
		}
		path := "/api/v1/security-agents/" + id
		retry := call(http.MethodPost, "/api/v1/security-agents", marshal(body), "", "http-export-create-0001")
		must(retry, 201)
		if retry.Body.String() != created.Body.String() || retry.Header().Get("X-Mutation-Receipt-ID") != created.Header().Get("X-Mutation-Receipt-ID") {
			t.Fatal("create retry changed original receipt")
		}
		body["id"], body["name"] = id, "Updated public export"
		updated := call(http.MethodPatch, path, marshal(body), `"1"`, "http-export-update-0001")
		must(updated, 200)
		if updated.Header().Get("ETag") != `"2"` || !validProductID(updated.Header().Get("X-Mutation-Receipt-ID")) {
			t.Fatal("browser update lost CAS version/receipt")
		}
		must(call(http.MethodPatch, path, marshal(body), `"1"`, "http-export-update-stale-01"), 409)
		controlPage := call(http.MethodGet, "/api/v1/security-agent-execution-controls", "", "", "")
		must(controlPage, 200)
		var controls SecurityAgentExecutionControls
		if json.Unmarshal(controlPage.Body.Bytes(), &controls) != nil || len(controls.Actions) != 8 || controls.Actions[0].ActionKey != "create_evidence_export" || controls.Actions[0].Enabled || controls.Actions[0].Version != 0 {
			t.Fatalf("invalid original controls: %s", controlPage.Body.String())
		}
		setControl := func(target, key string, enabled bool, version int64, idem string) *httptest.ResponseRecorder {
			return call(http.MethodPut, "/api/v1/security-agent-execution-controls", marshal(map[string]any{"target": target, "action_key": key, "enabled": enabled}), fmt.Sprintf(`"%d"`, version), idem)
		}
		must(setControl("environment", "*", true, controls.Environment.Version, "http-export-environment-01"), 200)
		control := setControl("action", "create_evidence_export", true, 0, "http-export-control-0001")
		must(control, 200)
		controlRetry := setControl("action", "create_evidence_export", true, 0, "http-export-control-0001")
		must(controlRetry, 200)
		if controlRetry.Header().Get("X-Mutation-Receipt-ID") != control.Header().Get("X-Mutation-Receipt-ID") {
			t.Fatal("control retry lost receipt")
		}
		must(call(http.MethodPost, path+"/activation", `{"activation":"validated"}`, `"2"`, "http-export-validate-0001"), 200)
		activated := call(http.MethodPost, path+"/activation", `{"activation":"supervised"}`, `"3"`, "http-export-activate-0001")
		must(activated, 200)
		activationRetry := call(http.MethodPost, path+"/activation", `{"activation":"supervised"}`, `"3"`, "http-export-activate-0001")
		must(activationRetry, 200)
		if activationRetry.Header().Get("X-Mutation-Receipt-ID") != activated.Header().Get("X-Mutation-Receipt-ID") {
			t.Fatal("activation retry lost receipt")
		}
		body["name"] = "Edited after activation"
		reset := call(http.MethodPatch, path, marshal(body), `"4"`, "http-export-reset-draft-01")
		must(reset, 200)
		state := call(http.MethodGet, path+"/activation", "", "", "")
		must(state, 200)
		var activation SecurityAgentActivationState
		if json.Unmarshal(state.Body.Bytes(), &activation) != nil || activation.Activation != "draft" || activation.Enabled || activation.Version != 5 {
			t.Fatal("update did not reset activation")
		}
		must(call(http.MethodPost, path+"/activation", `{"activation":"validated"}`, `"5"`, "http-export-validate-0002"), 200)
		must(call(http.MethodPost, path+"/activation", `{"activation":"supervised"}`, `"6"`, "http-export-activate-0002"), 200)
		manualBody := `{"environment_id":"` + e + `"}`
		started := call(http.MethodPost, path+"/runs", manualBody, `"7"`, "http-export-manual-0001")
		must(started, 202)
		var run SecurityAgentRun
		if json.Unmarshal(started.Body.Bytes(), &run) != nil || run.AgentID != id || run.DefinitionVersion != 7 || run.ManualTrigger == nil {
			t.Fatalf("manual lost public definition: %s", started.Body.String())
		}
		manualRetry := call(http.MethodPost, path+"/runs", manualBody, `"7"`, "http-export-manual-0001")
		must(manualRetry, 202)
		if manualRetry.Body.String() != started.Body.String() || manualRetry.Header().Get("X-Mutation-Receipt-ID") != started.Header().Get("X-Mutation-Receipt-ID") {
			t.Fatal("manual retry changed original run")
		}
		must(call(http.MethodPost, path+"/runs", manualBody, `"7"`, "http-export-manual-0002"), 202)
		assertManualExportConnected(t, ctx, owner, api, o, w, e, run.ID, run.ManualTrigger)
		db.workersReady = false
		must(call(http.MethodGet, path, "", "", ""), 200)
		must(call(http.MethodGet, "/api/v1/security-agents?limit=10", "", "", ""), 200)
		must(call(http.MethodGet, path+"/activation", "", "", ""), 200)
		must(call(http.MethodPatch, path, marshal(body), `"7"`, "http-export-down-update-01"), 503)
		must(setControl("action", "create_evidence_export", false, 1, "http-export-down-disable-01"), 200)
		must(setControl("action", "create_evidence_export", true, 2, "http-export-down-enable-01"), 503)
		must(call(http.MethodPost, path+"/activation", `{"activation":"validated"}`, `"7"`, "http-export-down-withdraw-01"), 200)
		must(call(http.MethodPost, path+"/activation", `{"activation":"supervised"}`, `"8"`, "http-export-down-activate-01"), 503)
		badCSRF := call(http.MethodDelete, path, "", `"8"`, "http-export-bad-csrf-0001", func(r *http.Request) { r.Header.Del("X-CSRF-Token") })
		if badCSRF.Code < 400 || badCSRF.Header().Get("X-Mutation-Receipt-ID") != "" {
			t.Fatal("CSRF refusal lost")
		}
		deleted := call(http.MethodDelete, path, "", `"8"`, "http-export-delete-0001")
		must(deleted, 204)
		if !validProductID(deleted.Header().Get("X-Mutation-Receipt-ID")) {
			t.Fatal("browser delete lost receipt")
		}
		deleteRetry := call(http.MethodDelete, path, "", `"8"`, "http-export-delete-0001")
		must(deleteRetry, 204)
		if deleteRetry.Header().Get("X-Mutation-Receipt-ID") != deleted.Header().Get("X-Mutation-Receipt-ID") {
			t.Fatal("deleted-resource replay lost receipt")
		}
		var browserReceipts int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4) AND receipt_id IN ($5,$6,$7)`, o, w, e, actor, created.Header().Get("X-Mutation-Receipt-ID"), updated.Header().Get("X-Mutation-Receipt-ID"), deleted.Header().Get("X-Mutation-Receipt-ID")).Scan(&browserReceipts); err != nil || browserReceipts != 3 {
			t.Fatalf("browser CRUD receipt rows=%d want3: %v", browserReceipts, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		must(call(http.MethodDelete, path, "", `"8"`, "http-export-delete-0001"), 403)
		must(call(http.MethodGet, "/api/v1/security-agent-execution-controls", "", "", ""), 403)
	})
}
