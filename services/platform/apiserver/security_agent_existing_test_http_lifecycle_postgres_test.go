package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Catches a replay incorrectly binding the handler's newly generated expiry or
// IDs instead of the durable original receipt. Authentication identity is supplied
// at the router boundary; this is not browser-session or deployed proof.
func TestSecurityAgentExistingTestHTTPLifecyclePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		const id = "pid_89f00100-0000-4000-8000-000000000001"
		const finding = "pid_89f00200-0000-4000-8000-000000000001"
		createExistingTestLifecycleDraft(t, ctx, api, org, ws, env, id, testID, actor, "run_test")
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','HTTP simulation evidence','high','open')`, org, ws, env, finding); err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		o, _ := domain.ParseProductID(org)
		w, _ := domain.ParseProductID(ws)
		e, _ := domain.ParseProductID(env)
		identity.Scope, _ = domain.NewScope(o, w, e)
		identity.PrincipalID, _ = domain.ParseProductID(actor)
		identity.Permissions = []string{"view", "manage_workflows"}
		now := time.Now().UTC().Truncate(time.Microsecond)
		identity.FreshAuthExpiresAt = now.Add(4 * time.Minute)
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		public, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
		if err != nil {
			t.Fatal(err)
		}
		router, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: public, Connector: handlerResponse("connector")})
		if err != nil {
			t.Fatal(err)
		}
		call := func(suffix, body, version, key string) *httptest.ResponseRecorder {
			t.Helper()
			request := workflowRequest(t, identity, "pid_89f00300-0000-4000-8000-000000000001", "", nil, http.MethodPost, "/api/v1/security-agents/"+id+suffix, body)
			request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
			request.Header.Set("Origin", "https://app.zasp.test")
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
			request.Header.Set(expectedScopeHeader, org+"/"+ws+"/"+env)
			request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
			request.Header.Set("If-Match", version)
			request.Header.Set("Idempotency-Key", key)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			return response
		}
		activation := call("/activation", `{"activation":"validated"}`, `"1"`, "http-existing-validate-0001")
		if activation.Code != http.StatusOK || activation.Header().Get("ETag") != `"2"` {
			t.Fatalf("HTTP validation: %d %s", activation.Code, activation.Body.String())
		}
		simulationBody := `{"goal":"Verify pinned existing test","environment_id":"` + env + `","evidence_ids":["` + finding + `"]}`
		original := call("/simulate", simulationBody, `"2"`, "http-existing-simulate-0001")
		if original.Code != http.StatusOK {
			t.Fatalf("HTTP simulation: %d %s", original.Code, original.Body.String())
		}
		var result struct {
			RunID             string `json:"run_id"`
			SideEffects       int    `json:"side_effects"`
			DefinitionVersion int    `json:"definition_version"`
		}
		if err := json.Unmarshal(original.Body.Bytes(), &result); err != nil || !validProductID(result.RunID) || result.SideEffects != 0 || result.DefinitionVersion != 2 {
			t.Fatalf("HTTP simulation result: %s %v", original.Body.String(), err)
		}
		before := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
		now = now.Add(time.Second)
		for _, pair := range []struct {
			suffix, body, version, key string
			original                   *httptest.ResponseRecorder
		}{
			{"/activation", `{"activation":"validated"}`, `"1"`, "http-existing-validate-0001", activation},
			{"/simulate", simulationBody, `"2"`, "http-existing-simulate-0001", original},
		} {
			replay := call(pair.suffix, pair.body, pair.version, pair.key)
			if replay.Code != http.StatusOK || !equalIntegrationJSON(replay.Body.Bytes(), pair.original.Body.Bytes()) {
				t.Fatalf("HTTP %s replay with new generated IDs/expiry: %d %s", pair.suffix, replay.Code, replay.Body.String())
			}
			for _, header := range []string{"ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"} {
				if replay.Header().Get(header) == "" || replay.Header().Get(header) != pair.original.Header().Get(header) {
					t.Fatalf("replay changed %s", header)
				}
			}
		}
		if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
			t.Fatal("HTTP replay changed durable state")
		}
		for _, test := range []struct{ name, body, version string }{
			{"changed_goal", `{"goal":"Different goal","environment_id":"` + env + `","evidence_ids":["` + finding + `"]}`, `"2"`},
			{"changed_evidence", `{"goal":"Verify pinned existing test","environment_id":"` + env + `","evidence_ids":["pid_89f00200-0000-4000-8000-000000000002"]}`, `"2"`},
			{"changed_version", simulationBody, `"1"`},
		} {
			response := call("/simulate", test.body, test.version, "http-existing-simulate-0001")
			if response.Code != http.StatusConflict || !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
				t.Fatalf("%s replay intent accepted or mutated state: %d %s", test.name, response.Code, response.Body.String())
			}
		}
		identity.Permissions = []string{"view"}
		if response := call("/simulate", simulationBody, `"2"`, "http-existing-simulate-0001"); response.Code != http.StatusForbidden {
			t.Fatalf("read-only user replay accepted: %d %s", response.Code, response.Body.String())
		}
		identity.Permissions = []string{"view", "manage_workflows"}
		identity.FreshAuthenticated = false
		if response := call("/activation", `{"activation":"validated"}`, `"1"`, "http-existing-validate-0001"); response.Code != http.StatusForbidden {
			t.Fatalf("stale fresh-auth replay accepted: %d %s", response.Code, response.Body.String())
		}
		if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
			t.Fatal("HTTP authority refusals changed durable state")
		}
		// Owner-only expiry injection avoids a fifteen-minute wall-clock wait.
		// The HTTP caller still uses a newer, otherwise valid candidate deadline.
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_request_receipts SET created_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=($1,$2,$3,$4,'simulateSecurityAgent','http-existing-simulate-0001')`, org, ws, env, actor); err != nil {
			t.Fatal(err)
		}
		expired := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
		if response := call("/simulate", simulationBody, `"2"`, "http-existing-simulate-0001"); response.Code != http.StatusConflict || !equalIntegrationJSON(expired, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
			t.Fatalf("new candidate expiry revived expired receipt: %d %s", response.Code, response.Body.String())
		}
	})
}
