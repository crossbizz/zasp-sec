package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTemporalHumanAdmissionLivePostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalHumanAdmission(ctx); err != nil {
			t.Fatal(err)
		}
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalAutomaticSources(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":false}');CREATE ROLE temporal_test_executor_login LOGIN;CREATE ROLE temporal_test_compensation_login LOGIN;SELECT zasp_temporal68.register_principals('temporal_test_executor_login','temporal_test_compensation_login');UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		cfg := owner.Config().Copy()
		cfg.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		policy := orderedPricingAdminRequest(o, w, e, actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
		encoded, _ := json.Marshal(selection)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		// Independent automatic delegation is revoked. Human execution must
		// neither consult that service grant nor manufacture a replacement.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal74.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id) SELECT organization_id,workspace_id,environment_id,definition_id,definition_version,grantor_id,'pid_f0760000-0000-4000-8000-000000090001' FROM zasp_temporal74.service_grants WHERE definition_id=$1`, temporalTestLegacyProved); err != nil {
			t.Fatal(err)
		}

		authority, identity := orderedResourceGo(t, api, o, w, e, actor)
		repository := &PostgresRepository{database: authority.repository.database, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		sequence := 0
		handler, err := newSecurityAgentProductionHTTPHandler(ctx, repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) {
			sequence++
			return fmt.Sprintf("pid_f0760000-0000-4000-8000-%012d", 900+sequence), nil
		}}, true)
		if err != nil {
			t.Fatal(err)
		}
		request := workflowRequest(t, identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": temporalTestLegacyProved}, http.MethodPost, "/api/v1/security-agents/"+temporalTestLegacyProved+"/runs", `{"environment_id":"`+e+`","trigger_kind":"finding","trigger_id":"`+public62Finding+`","trigger_version":1,"trigger_source":"credential"}`)
		request.Header.Set("Idempotency-Key", "human-connected-finding-admission")
		request.Header.Set("If-Match", `"4"`)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatal("actual human HTTP admission", response.Code, response.Body.String())
		}
		var run SecurityAgentRun
		if err := json.Unmarshal(response.Body.Bytes(), &run); err != nil || run.ID == "" {
			t.Fatal("human typed queued response", run, err)
		}
		t.Setenv("ZASP_TEST76_LIVE", "true")
		t.Setenv("ZASP_TEST76_DEFINITION", temporalTestLegacyProved)
		assertTemporalTestTransport(t, ctx, owner, run.ID, testID, 4, encoded)
		detail, err := repository.GetSecurityAgentRun(ctx, identity, run.ID)
		if err != nil || detail.Run.State != "needs_human" || len(detail.ActionDetails) != 1 || detail.ActionDetails[0].ExistingTest == nil || detail.ActionDetails[0].ExistingTest.Verification == nil {
			t.Fatal("human terminal API readback", detail, err)
		}
		read := workflowRequest(t, identity, testCorrelationID, "getSecurityAgentRun", map[string]string{"id": run.ID}, http.MethodGet, "/api/v1/security-agent-runs/"+run.ID, "")
		readResponse := httptest.NewRecorder()
		handler.ServeHTTP(readResponse, read)
		if readResponse.Code != http.StatusOK {
			t.Fatal("selected handler terminal read", readResponse.Code, readResponse.Body.String())
		}
		t.Log("actual selected HTTP terminal read", readResponse.Body.String())
	})
}
