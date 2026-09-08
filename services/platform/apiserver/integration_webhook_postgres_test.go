package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestIntegrationWebhookPostgresFencesTenantReplayVersionAndCompletion(t *testing.T) {
	up, err := os.ReadFile("../migrations/sql/0035_production_integration_webhook.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_e2e"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(up) == 0 {
		t.Fatal("missing migration")
	}
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	if _, err := probe.Exec(ctx, string(up)); err != nil {
		t.Fatal(err)
	}
	var candidate string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_integration_webhook_live_fingerprint()`).Scan(&candidate); err != nil {
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if candidate != migrations.ProductionIntegrationWebhookSemanticFingerprint() {
		t.Fatalf("candidate v35 fingerprint=%s", candidate)
	}
	if err := runner.UpProductionIntegrationWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	if err := connection.QueryRow(ctx, `SELECT zasp_production_integration_webhook_live_fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	t.Logf("v35 live fingerprint: %s", fingerprint)
	var pinned string
	if err := connection.QueryRow(ctx, `SELECT value FROM zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint'`).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if pinned != fingerprint {
		t.Fatalf("v35 fingerprint=%s pinned=%s", fingerprint, pinned)
	}
	if version, err := runner.Version(ctx); err != nil || version != 35 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	if pinned != migrations.ProductionIntegrationWebhookSemanticFingerprint() {
		t.Fatal("semantic fingerprint mismatch")
	}
	if err := runner.DownProductionIntegrationWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionIntegrationWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	const otherOrg = "pid_8d000001-0000-4000-8000-000000000001"
	for _, organization := range []string{org, otherOrg} {
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'integration',$4,3,jsonb_build_object('id',$4::text,'connector_key','generic-webhook','name','Webhook','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_webhook_prod'),'status','configured','created_at','2026-08-21T00:00:00Z','updated_at','2026-08-21T00:00:00Z'))`, organization, workspace, environment, workflowIntegrationID); err != nil {
			t.Fatal(err)
		}
	}
	query := func(statement string, args ...any) json.RawMessage {
		t.Helper()
		tx, err := connection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_api`); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		if err = tx.QueryRow(ctx, statement, args...).Scan(&result); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return result
	}
	reserve := func(organization, key, delivery, token string, version int64) json.RawMessage {
		return query(postgresIntegrationWebhookTestReserveSQL, organization, workspace, environment, fixtureRequestIdentity(t).PrincipalID.String(), workflowIntegrationID, version, key, workflowAuditID, testCorrelationID, delivery, token, 15)
	}
	const delivery = "pid_41000001-0000-4000-8000-000000000001"
	token := strings.Repeat("b", 64)
	first := reserve(org, "webhook-pg-test-0001", delivery, token, 3)
	var dispatch struct {
		State   string `json:"state"`
		Payload string `json:"payload"`
		Digest  string `json:"payload_digest"`
	}
	if json.Unmarshal(first, &dispatch) != nil || dispatch.State != "dispatch" || !strings.Contains(dispatch.Payload, org) || strings.Contains(dispatch.Payload, "secret_ref") {
		t.Fatalf("dispatch=%s", first)
	}
	busy := reserve(org, "webhook-pg-test-0001", "pid_41000002-0000-4000-8000-000000000002", strings.Repeat("c", 64), 3)
	if !strings.Contains(string(busy), `"busy"`) || strings.Contains(string(busy), "secret_ref") {
		t.Fatalf("busy=%s", busy)
	}
	completed := query(postgresIntegrationWebhookTestCompleteSQL, org, workspace, environment, delivery, token, dispatch.Digest, true)
	var status IntegrationWebhookTestStatus
	if json.Unmarshal(completed, &status) != nil || !validIntegrationWebhookTestStatus(status, workflowIntegrationID) || status.DeliveryStatus != "succeeded" {
		t.Fatalf("completion=%s", completed)
	}
	// Updating configuration cannot change an already completed result on exact retry.
	if _, err := connection.Exec(ctx, `UPDATE zasp_workflow_records SET version=4 WHERE organization_id=$1 AND id=$2`, org, workflowIntegrationID); err != nil {
		t.Fatal(err)
	}
	replay := reserve(org, "webhook-pg-test-0001", "pid_41000003-0000-4000-8000-000000000003", strings.Repeat("d", 64), 3)
	if !strings.Contains(string(replay), `"succeeded"`) || !strings.Contains(string(replay), delivery) || strings.Contains(string(replay), "secret_ref") {
		t.Fatalf("replay=%s", replay)
	}
	for _, test := range []struct {
		statement string
		args      []any
	}{
		{postgresIntegrationWebhookTestReserveSQL, []any{org, workspace, environment, fixtureRequestIdentity(t).PrincipalID.String(), workflowIntegrationID, int64(3), "webhook-pg-stale-0002", workflowAuditID, testCorrelationID, delivery, token, 15}},
		{postgresIntegrationWebhookTestReserveSQL, []any{org, workspace, environment, fixtureRequestIdentity(t).PrincipalID.String(), workflowIntegrationID, int64(4), "webhook-pg-test-0001", workflowAuditID, testCorrelationID, delivery, token, 15}},
		{postgresIntegrationWebhookTestCompleteSQL, []any{otherOrg, workspace, environment, delivery, token, dispatch.Digest, true}},
		{postgresIntegrationWebhookTestCompleteSQL, []any{org, workspace, environment, delivery, strings.Repeat("f", 64), dispatch.Digest, true}},
	} {
		if err := connection.QueryRow(ctx, test.statement, test.args...).Scan(new(json.RawMessage)); err == nil {
			t.Fatalf("hostile call accepted: %s", test.statement)
		}
	}
	var deliveries, audits int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_integration_webhook_tests WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),(SELECT count(*) FROM zasp_workflow_audit WHERE (organization_id,workspace_id,environment_id,operation)=($1,$2,$3,'testIntegrationWebhook'))`, org, workspace, environment).Scan(&deliveries, &audits); err != nil || deliveries != 1 || audits != 1 {
		t.Fatalf("counts=%d/%d err=%v", deliveries, audits, err)
	}
	if err := runner.DownProductionIntegrationWebhook(ctx); err == nil {
		t.Fatal("rollback discarded delivery history")
	}

	// Run the real HTTP handler, service, PostgreSQL repository and signed TLS
	// sender together. Only the receiver address and secret store are local fixtures.
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := strings.Repeat("test", 8)
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		mac := hmac.New(sha256.New, []byte(signingKey))
		_, _ = mac.Write(body)
		if request.Header.Get("X-Zasp-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) || request.Header.Get("X-Zasp-Event") != "integration.webhook.test" || !strings.Contains(string(body), org) || strings.Contains(string(body), "secret_ref_") {
			t.Errorf("invalid signed test: %s", body)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	// The fixture dialer maps the public test name onto the local receiver;
	// verify the receiver's trusted loopback certificate instead of disabling TLS.
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client.Transport = transport
	defer transport.CloseIdleConnections()
	sender, err := newProductionFindingTicketWebhook([]string{"8.8.8.8/32"}, 2*time.Second,
		func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host != "hooks.example.test" {
				t.Errorf("unexpected DNS host: %s", host)
			}
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
		func(host, pinnedIP string, _ time.Duration) http.RoundTripper {
			if host != "hooks.example.test" || pinnedIP != "8.8.8.8" {
				t.Errorf("unbound transport: %s %s", host, pinnedIP)
			}
			return transport
		})
	if err != nil {
		t.Fatal(err)
	}
	for index, destination := range []string{"https://hooks.example.test", "https://hooks.example.test:443/zasp"} {
		integrationID := []string{"pid_43000001-0000-4000-8000-000000000001", "pid_43000002-0000-4000-8000-000000000002"}[index]
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'integration',$4,3,jsonb_build_object('id',$4::text,'connector_key','generic-webhook','name','Webhook URL regression','configuration',jsonb_build_object('destination_url',$5::text,'signing_secret_reference','secret_ref_webhook_prod'),'status','configured','created_at','2026-08-21T00:00:00Z','updated_at','2026-08-21T00:00:00Z'))`, org, workspace, environment, integrationID, destination); err != nil {
			t.Fatal(err)
		}
		service, err := NewIntegrationWebhookTestService(IntegrationWebhookTestServiceConfig{Repository: repository, Secrets: &integrationWebhookSecretStub{material: []byte(signingKey)}, Webhook: sender, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return newWorkflowProductID() }, NewLeaseToken: func() (string, error) { return strings.Repeat("e", 64), nil }})
		if err != nil {
			t.Fatal(err)
		}
		handler, err := newWorkflowHTTPHandler(repository, []byte(signingKey), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		handler.webhookTests = service
		var firstStatus IntegrationWebhookTestStatus
		for attempt := 0; attempt < 2; attempt++ {
			request := workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "testIntegrationWebhook", map[string]string{"id": integrationID}, http.MethodPost, "/api/v1/integrations/"+integrationID+"/test-delivery", `{}`)
			request.Header.Set("Idempotency-Key", "webhook-url-regression-"+integrationID)
			request.Header.Set("If-Match", `"3"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var result IntegrationWebhookTestStatus
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !validIntegrationWebhookTestStatus(result, integrationID) || result.DeliveryStatus != "succeeded" || response.Header().Get("X-Audit-ID") != result.AuditID {
				t.Fatalf("destination=%s response=%d %s", destination, response.Code, response.Body.String())
			}
			if attempt == 0 {
				firstStatus = result
			} else if firstStatus.DeliveryID != result.DeliveryID || firstStatus.AuditID != result.AuditID {
				t.Fatal("replay changed authority")
			}
		}
		read := workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "getIntegrationWebhookStatus", map[string]string{"id": integrationID}, http.MethodGet, "/api/v1/integrations/"+integrationID+"/delivery-status", "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, read)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), firstStatus.DeliveryID) || strings.Contains(response.Body.String(), "secret_ref_") {
			t.Fatalf("durable status=%d %s", response.Code, response.Body.String())
		}
	}
	if received.Load() != 2 {
		t.Fatalf("received=%d want=2", received.Load())
	}
}
