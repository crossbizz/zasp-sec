package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func seedAutomaticRuntimeGateway(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string) (*pgx.Conn, *gatewaycontrol.PostgresRepository, ed25519.PrivateKey, gatewaycontrol.DecisionEvent) {
	t.Helper()
	for _, name := range []string{"source77_coordinator", "source77_archive", "source77_index", "source77_correlation", "source77_projection", "source77_gateway"} {
		if _, err := owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
	}
	var registered bool
	if err := owner.QueryRow(ctx, `SELECT zasp_runtime_register_principals(session_user,'source77_coordinator','source77_archive','source77_index','source77_correlation','source77_projection','source77_gateway')`).Scan(&registered); err != nil || !registered {
		t.Fatal("runtime principal binding", registered, err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, enrollment, credential := automaticSourceID(40), automaticSourceID(41), automaticSourceID(42)
	if _, err := owner.Exec(ctx, `
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Automatic source gateway','active');
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at,consumed_at,format_version,locator_digest,token_generation,device_version_at_issue,v15_issued_at)
VALUES($1,$2,$3,$5,$4,'runtime-gateway-enroll',decode(repeat('51',16),'hex'),digest(convert_to($5,'UTF8'),'sha256'),transaction_timestamp()+interval '1 hour',transaction_timestamp(),1,digest(convert_to($5||':locator','UTF8'),'sha256'),1,1,transaction_timestamp());
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at)
VALUES($1,$2,$3,$6,$4,$5,digest(convert_to($5||':credential','UTF8'),'sha256'),'runtime-gateway','ref:gateway/public/automatic-source-1',$7,date_trunc('second',transaction_timestamp())+interval '1 hour',1,1,'automatic-source-1','Ed25519',transaction_timestamp())`, pgx.QueryExecModeSimpleProtocol, o, w, e, device, enrollment, credential, []byte(public)); err != nil {
		t.Fatal("gateway source prerequisites", err)
	}
	config := owner.Config().Copy()
	config.User = "source77_gateway"
	gateway, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gateway.Close(context.Background()) })
	repo, err := gatewaycontrol.NewPostgresRepository(riskIngestDiagnosticDB{conn: gateway, t: t}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evaluation := &gatewaycontrol.EvaluationEvidence{Version: 1, Action: "tool_execute", AgentID: automaticSourceID(44), SessionID: automaticSourceID(45), ContributingPolicyIDs: []string{"policy-risk"}, Risk: "high"}
	event := gatewaycontrol.DecisionEvent{CredentialID: credential, DeviceID: device, EventID: automaticSourceID(43), ExpectedFloor: 0, NextFloor: 1, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", PolicyIDs: []string{"policy-risk"}, Classification: map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": "requested", "session_id": evaluation.SessionID}, OccurredAt: time.Now().UTC().Truncate(time.Second), Evaluation: evaluation}
	return gateway, repo, private, event
}

func exerciseAutomaticRuntimeCapture(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string) {
	gateway, repo, key, event := seedAutomaticRuntimeGateway(t, ctx, owner, o, w, e)
	var recoveryReady, principalReady bool
	readinessErr := gateway.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2),zasp_runtime_principal_ready('zasp_gateway_control')`, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()).Scan(&recoveryReady, &principalReady)
	t.Logf("actual gateway readiness: recovery=%v principal=%v query_error=%v repository_error=%v", recoveryReady, principalReady, readinessErr, repo.Ready(ctx))
	for _, signature := range []string{"public.zasp_recovery_execution_readiness(text,text)", "public.zasp_policy_deployment_execution_readiness(text,text)"} {
		var definition string
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, signature).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		t.Logf("effective readiness %s: %s", signature, definition)
	}
	_, authorityErr := repo.Authority(ctx, event.CredentialID)
	t.Logf("actual gateway credential authority error=%v", authorityErr)
	handler, err := gatewaycontrol.NewHTTPHandler(gatewaycontrol.HTTPHandlerConfig{Repository: repo, Clock: func() time.Time { return time.Now().UTC().Truncate(time.Second) }, OperationTimeout: 10 * time.Second, MaximumBodyBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(event)
	requestStatus := func(method, path string, body, signatureBody []byte) int {
		request := httptest.NewRequest(method, "https://gateway-control.zasp.example"+path, bytes.NewReader(body)).WithContext(ctx)
		request.Header.Set("Content-Type", gatewaycontrol.JSONMediaType)
		if err := gatewaycontrol.SignRequest(request, signatureBody, event.CredentialID, key, time.Now().UTC().Truncate(time.Second)); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Logf("signed runtime status=%d body=%s", response.Code, response.Body.String())
		}
		return response.Code
	}
	send := func(body, signatureBody []byte) int {
		return requestStatus(http.MethodPost, gatewaycontrol.DecisionPath, body, signatureBody)
	}
	if status := requestStatus(http.MethodGet, gatewaycontrol.AuthorityPath, nil, nil); status != http.StatusOK {
		t.Fatal("signed authority through real readiness", status)
	}
	policyPath := gatewaycontrol.PolicyPathPrefix + e + "?after_sequence=0"
	if status := requestStatus(http.MethodGet, policyPath, nil, nil); status != http.StatusNoContent {
		t.Fatal("signed policy no update through real readiness", status)
	}
	count := func() int {
		var n int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_gateway_events WHERE event_id=$1)+(SELECT count(*) FROM zasp_temporal77.runtime_evaluations WHERE event_id=$1)+(SELECT count(*) FROM zasp_temporal77.source_events WHERE source_kind='runtime_decision' AND source_id=$1)`, event.EventID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := gateway.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	status := send(body, body)
	invisible := count()
	if _, err := gateway.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusNoContent || invisible != 0 || count() != 0 {
		t.Fatal("signed writer rollback/visibility", status, invisible)
	}
	if status := send(body, body); status != http.StatusNoContent {
		t.Fatal("signed HTTP→actual77 ingestion", status)
	}
	if status := send(body, body); status != http.StatusNoContent || count() != 3 {
		t.Fatal("signed replay duplicated occurrence", status, count())
	}
	var sourceAt time.Time
	var annotation json.RawMessage
	var canonicalID string
	if err := owner.QueryRow(ctx, `SELECT s.source_at,a.evaluation,s.event_id FROM zasp_temporal77.source_events s JOIN zasp_runtime_gateway_events v ON(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=(s.organization_id,s.workspace_id,s.environment_id,s.source_id) JOIN zasp_temporal77.runtime_evaluations a ON(a.organization_id,a.workspace_id,a.environment_id,a.event_id)=(v.organization_id,v.workspace_id,v.environment_id,v.event_id) WHERE s.source_kind='runtime_decision' AND s.source_id=$1`, event.EventID).Scan(&sourceAt, &annotation, &canonicalID); err != nil {
		t.Fatal("committed authenticated capture", err)
	}
	wantID, err := CanonicalDiscoveryID(automaticSourceIdentity(t, o, w, e, automaticSourceID(99)).Scope, "automatic_source_v1", "runtime_decision\x1f"+event.EventID+"\x1f1")
	if err != nil || canonicalID != wantID || !sourceAt.Equal(event.OccurredAt) {
		t.Fatal("canonical source identity/time", canonicalID, wantID, sourceAt, err)
	}
	want, _ := json.Marshal(event.Evaluation)
	assertAutomaticRuleJSON(t, "signed captured annotation", annotation, want)
	tampered := bytes.Replace(body, []byte(`"risk":"high"`), []byte(`"risk":"critical"`), 1)
	if status := send(tampered, body); status != http.StatusUnauthorized || count() != 3 {
		t.Fatal("unauthenticated risk reached capture", status, count())
	}
	legacy := event
	legacy.EventID = automaticSourceID(46)
	legacy.ExpectedFloor = 1
	legacy.NextFloor = 2
	legacy.Evaluation = nil
	legacyBody, _ := json.Marshal(legacy)
	if status := send(legacyBody, legacyBody); status != http.StatusNoContent {
		t.Fatal("signed omitted event through original27 writer", status)
	}
	var legacyRows, legacyAnnotations int
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_gateway_events WHERE event_id=$1)+(SELECT count(*) FROM zasp_temporal77.source_events WHERE source_kind='runtime_decision' AND source_id=$1),(SELECT count(*) FROM zasp_temporal77.runtime_evaluations WHERE event_id=$1)`, legacy.EventID).Scan(&legacyRows, &legacyAnnotations); err != nil || legacyRows != 2 || legacyAnnotations != 0 {
		t.Fatal("legacy source must not fabricate risk", legacyRows, legacyAnnotations, err)
	}
	if _, err := owner.Exec(ctx, `ALTER FUNCTION zasp_temporal77.gateway_ready(text,text) COST 123`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{gatewaycontrol.AuthorityPath, policyPath} {
		if status := requestStatus(http.MethodGet, path, nil, nil); status != http.StatusServiceUnavailable {
			t.Fatal("invalid77 read route downgraded", path, status)
		}
	}
	if status := send(body, body); status != http.StatusServiceUnavailable {
		t.Fatal("invalid77 annotated route downgraded", status)
	}
	if status := send(legacyBody, legacyBody); status != http.StatusServiceUnavailable {
		t.Fatal("invalid77 omitted route downgraded", status)
	}
	if _, err := owner.Exec(ctx, `ALTER FUNCTION zasp_temporal77.gateway_ready(text,text) COST 100`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=transaction_timestamp() WHERE id=$1`, event.CredentialID); err != nil {
		t.Fatal(err)
	}
	if status := requestStatus(http.MethodGet, gatewaycontrol.AuthorityPath, nil, nil); status != http.StatusUnauthorized {
		t.Fatal("revoked credential authority", status)
	}
}
