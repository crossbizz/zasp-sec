package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

// This test borrows only the separately verified local pinned Temporal server.
// Product PostgreSQL and both worker processes are owned by this test. Provider,
// object storage and FGA HTTP remain controlled boundaries, not deployment proof.
func TestTemporalAutomaticNativePostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":86400,"enabled":true}');CREATE ROLE temporal_test_executor_login LOGIN;CREATE ROLE temporal_test_compensation_login LOGIN;SELECT zasp_temporal68.register_principals('temporal_test_executor_login','temporal_test_compensation_login');UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1;UPDATE zasp_risk_findings SET severity='low'`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		c := owner.Config().Copy()
		c.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(context.Background())
		pricingPolicy := orderedPricingAdminRequest(o, w, e, actor)
		bindTemporalTestPlannerPricing(pricingPolicy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", pricingPolicy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, pricingPolicy["policy"].(map[string]any), pricing)
		encoded, _ := json.Marshal(selection)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(context.Background())
		defer adapter.Close(context.Background())
		definition, finding := automaticSourceID(8000), automaticSourceID(8001)
		var base json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		json.Unmarshal(base, &body)
		body["id"] = definition
		body["enabled"] = false
		body["trigger_rules"] = map[string]any{"version": 1, "mode": "automatic", "cooldown_seconds": 1, "finding": map[string]any{"family": "credential", "minimum_severity": "high"}}
		raw, _ := json.Marshal(body)
		delete(body, "id")
		intent, _ := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": body})
		var result json.RawMessage
		if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write('create',$1,$2,$3,$4,$5,'createSecurityAgent',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`, definition, o, w, e, actor, "automatic77-native-create", intent, raw, automaticSourceID(8002), automaticSourceID(8003), automaticSourceID(8004)).Scan(&result); err != nil {
			t.Fatal(err)
		}
		activateAutomaticPageDefinition(t, ctx, api, o, w, e, actor, definition, 8010)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Native canonical source','high','under_review');INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, pgx.QueryExecModeSimpleProtocol, o, w, e, finding, automaticSourceID(8020)); err != nil {
			t.Fatal(err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: admin})
		if err != nil {
			t.Fatal(err)
		}
		repo := &PostgresRepository{database: db}
		identity := automaticSourceIdentity(t, o, w, e, actor)
		mutation := RiskFindingMutation{Operation: "updateFinding", FindingID: finding, ExpectedVersion: 1, Status: "open", IdempotencyKey: "automatic77-native-open", AuditID: automaticSourceID(8021), CorrelationID: automaticSourceID(8022), ReceiptID: automaticSourceID(8023)}
		written, err := repo.MutateRiskFinding(ctx, identity, mutation)
		if err != nil || written.Version != 2 {
			t.Fatal("actual registered finding writer", written, err)
		}
		var event, parent string
		if err := owner.QueryRow(ctx, `SELECT event_id,zasp_discovery_canonical_id($1,$2,$3,'security_agent_run',concat_ws(chr(31),$4::text,4,'finding',$5::text,2)) FROM zasp_temporal77.source_events WHERE source_kind='finding' AND source_id=$5 AND source_version=2`, o, w, e, definition, finding).Scan(&event, &parent); err != nil {
			t.Fatal(err)
		}
		// Signed gateway HTTP reaches real credential/77 persistence and capture.
		// Runtime admission remains capability-gated; its dispatcher must complete
		// without inventing an eligible responder or changing requested outcome.
		_, gateway, key, runtimeEvent := seedAutomaticRuntimeGateway(t, ctx, owner, o, w, e)
		handler, err := gatewaycontrol.NewHTTPHandler(gatewaycontrol.HTTPHandlerConfig{Repository: gateway, Clock: func() time.Time { return time.Now().UTC().Truncate(time.Second) }, OperationTimeout: 10 * time.Second, MaximumBodyBytes: 16384})
		if err != nil {
			t.Fatal(err)
		}
		runtimeBody, _ := json.Marshal(runtimeEvent)
		request := httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+gatewaycontrol.DecisionPath, bytes.NewReader(runtimeBody)).WithContext(ctx)
		request.Header.Set("Content-Type", gatewaycontrol.JSONMediaType)
		if err := gatewaycontrol.SignRequest(request, runtimeBody, runtimeEvent.CredentialID, key, time.Now().UTC().Truncate(time.Second)); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatal("authenticated runtime source", response.Code, response.Body.String())
		}
		var runtimeSource string
		if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE source_kind='runtime_decision' AND source_id=$1`, runtimeEvent.EventID).Scan(&runtimeSource); err != nil {
			t.Fatal(err)
		}
		namespace := fmt.Sprintf("automatic-source77-%d", time.Now().UnixNano())
		nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
		if err != nil {
			t.Fatal(err)
		}
		err = nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
		nc.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("ZASP_TEST77_LIVE", "true")
		t.Setenv("ZASP_TEST77_NAMESPACE", namespace)
		t.Setenv("ZASP_TEST77_ADDRESS", "127.0.0.1:7233")
		t.Setenv("ZASP_TEST77_DEFINITION", definition)
		t.Setenv("ZASP_TEST77_FINDING", finding)
		t.Setenv("ZASP_TEST77_EVENT", event)
		t.Setenv("ZASP_TEST77_RUNTIME_EVENT", runtimeSource)
		t.Setenv("ZASP_TEST77_ACTOR", actor)
		t.Setenv("ZASP_TEST77_PHASE", "ambiguous-start")
		assertTemporalTestTransport(t, ctx, owner, parent, testID, 4, encoded)
		var pending bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal77.source_pending WHERE event_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_acceptances WHERE event_id=$1)`, event).Scan(&pending); err != nil || !pending {
			t.Fatal("first process acknowledged ambiguous start", pending, err)
		}
		t.Setenv("ZASP_TEST77_PHASE", "recover")
		assertTemporalTestTransport(t, ctx, owner, parent, testID, 4, encoded)
		authority, readIdentity := orderedResourceGo(t, api, o, w, e, actor)
		readRepo := &PostgresRepository{database: authority.repository.database, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		detail, err := readRepo.GetSecurityAgentRun(ctx, readIdentity, parent)
		if err != nil || detail.Run.State != "needs_human" || len(detail.ActionDetails) != 1 || detail.ActionDetails[0].ExistingTest == nil || detail.ActionDetails[0].ExistingTest.Verification == nil {
			t.Fatal("automatic typed terminal readback", detail, err)
		}
		readHandler, err := newSecurityAgentProductionHTTPHandler(ctx, readRepo, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { return automaticSourceID(8500), nil }}, true)
		if err != nil {
			t.Fatal("mounted automatic run read handler", err)
		}
		read := workflowRequest(t, readIdentity, testCorrelationID, "getSecurityAgentRun", map[string]string{"id": parent}, http.MethodGet, "/api/v1/security-agent-runs/"+parent, "")
		read.Header.Set("X-Zasp-Action-Details", "v1")
		readResponse := httptest.NewRecorder()
		readHandler.ServeHTTP(readResponse, read)
		if readResponse.Code != http.StatusOK {
			t.Fatal("mounted automatic HTTP read", readResponse.Code, readResponse.Body.String())
		}
		var wire SecurityAgentRunDetail
		if json.Unmarshal(readResponse.Body.Bytes(), &wire) != nil || wire.Run.ID != parent || wire.Run.State != "needs_human" || len(wire.ActionDetails) != 1 || wire.ActionDetails[0].ExistingTest == nil || wire.ActionDetails[0].ExistingTest.Verification == nil {
			t.Fatal("automatic HTTP projection lost exact parent/state/existing-test verification")
		}
		linked, expected := wire.ActionDetails[0].ExistingTest, detail.ActionDetails[0].ExistingTest
		t.Logf("HTTP link=%s definition=%s version=%d outcome=%s reason=%s digest_present=%t; repository link=%s definition=%s version=%d outcome=%s reason=%s digest_present=%t; digest_equal=%t", linked.TestRunID, linked.DefinitionID, linked.DefinitionVersion, linked.Verification.Outcome, linked.Verification.Reason, linked.Verification.ProofDigest != "", expected.TestRunID, expected.DefinitionID, expected.DefinitionVersion, expected.Verification.Outcome, expected.Verification.Reason, expected.Verification.ProofDigest != "", linked.Verification.ProofDigest == expected.Verification.ProofDigest)
		// The controlled native endpoint reports protected=false. The actual
		// comparison maps current verdict fail before consulting any baseline.
		if !validProductID(linked.TestRunID) || linked.TestRunID != expected.TestRunID || linked.DefinitionID != expected.DefinitionID || linked.DefinitionVersion != expected.DefinitionVersion || linked.Verification.ProofDigest == "" || linked.Verification.ProofDigest != expected.Verification.ProofDigest || linked.Verification.Outcome != expected.Verification.Outcome || linked.Verification.Reason != expected.Verification.Reason || linked.Verification.Reason != "test_condition_persists" {
			t.Fatal("automatic HTTP projection changed authoritative test link/verification")
		}
		t.Log("mounted automatic terminal HTTP read", wire.Run.ID, wire.Run.State, linked.TestRunID, linked.Verification.Outcome, linked.Verification.Reason)
		t.Log("connected source writer -> atomic77 pending -> first worker-process ambiguous accepted start -> second production worker/Temporal ->73/74 execution -> typed terminal read", namespace, parent)
	})
}
