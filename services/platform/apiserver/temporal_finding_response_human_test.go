package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func assertFindingHumanAdmission(t *testing.T, ctx context.Context, owner *pgx.Conn, handler http.Handler, identity RequestIdentity, o, w, e, definition, actor string, next func() string) string {
	t.Helper()
	finding := next()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Human finding prerequisite','high','open');UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows"]' WHERE principal_id=$5`, pgx.QueryExecModeSimpleProtocol, o, w, e, finding, actor); err != nil {
		t.Fatal(err)
	}
	call := func(version int, key string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"environment_id": e, "trigger_kind": "finding", "trigger_id": finding, "trigger_version": version, "trigger_source": "credential"})
		r := workflowRequest(t, identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": definition}, http.MethodPost, "/api/v1/security-agents/"+definition+"/runs", string(body))
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("If-Match", `"4"`)
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, r)
		return result
	}
	if result := call(2, "finding78-stale-human"); result.Code != http.StatusConflict {
		t.Fatalf("stale human finding status=%d", result.Code)
	}
	first := call(1, "finding78-human-request")
	if first.Code != http.StatusAccepted {
		t.Fatalf("human finding admission status=%d", first.Code)
	}
	var admitted SecurityAgentRun
	if json.Unmarshal(first.Body.Bytes(), &admitted) != nil || admitted.State != "queued" || admitted.DefinitionVersion != 4 || admitted.AgentID != definition {
		t.Fatal("human finding response")
	}
	replay := call(1, "finding78-human-request")
	if replay.Code != http.StatusAccepted {
		t.Fatal("human finding replay", replay.Code)
	}
	assertAutomaticRuleJSON(t, "human finding HTTP replay", first.Body.Bytes(), replay.Body.Bytes())
	if changed := call(2, "finding78-human-request"); changed.Code != http.StatusConflict {
		t.Fatal("human replay changed source accepted", changed.Code)
	}
	var proof bool
	if err := owner.QueryRow(ctx, `SELECT r.requested_by=$2 AND x.source_kind='human78' AND x.trigger_id=$3 AND x.trigger_version=1 AND x.snapshot_digest=digest(convert_to(x.snapshot::text,'UTF8'),'sha256')
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences WHERE run_id=$1)
 AND EXISTS(SELECT 1 FROM zasp_temporal78.commands WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='start')
 AND (SELECT count(*)=1 FROM zasp_security_agent_request_receipts WHERE principal_id=$2 AND operation='runSecurityAgent' AND idempotency_key='finding78-human-request')
 FROM zasp_temporal78.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, admitted.ID, actor, finding).Scan(&proof); err != nil || !proof {
		t.Fatal("human finding provenance", proof, err)
	}
	assertFindingHumanExclusion(t, ctx, owner, o, w, e, admitted.ID)
	// Settle the first owned run through its real compensation endpoint, so the
	// second route test does not manufacture capacity or terminal receipts.
	var start json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, admitted.ID).Scan(&start); err != nil {
		t.Fatal(err)
	}
	cfg := owner.Config().Copy()
	cfg.User = "finding78_compensation"
	compensation, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer compensation.Close(context.Background())
	var cleanup json.RawMessage
	if err := compensation.QueryRow(ctx, `SELECT zasp_temporal78.cleanup($1::jsonb||'{"reason":"workflow_cancelled"}'::jsonb)`, start).Scan(&cleanup); err != nil {
		t.Fatal("human queued cleanup", err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal66.admission_routes VALUES($1,$2,$3,'temporal')`, o, w, e); err != nil {
		t.Fatal(err)
	}
	finding = next()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Configured route prerequisite','high','open')`, o, w, e, finding); err != nil {
		t.Fatal(err)
	}
	second := call(1, "finding78-human-temporal-route")
	if second.Code != http.StatusAccepted {
		t.Fatal("configured66 human finding admission", second.Code)
	}
	var routed SecurityAgentRun
	if json.Unmarshal(second.Body.Bytes(), &routed) != nil || routed.ID == admitted.ID || routed.State != "queued" {
		t.Fatal("configured66 finding response")
	}
	assertFindingHumanExclusion(t, ctx, owner, o, w, e, routed.ID)
	if replay := call(1, "finding78-human-temporal-route"); replay.Code != http.StatusAccepted {
		t.Fatal("configured66 replay", replay.Code)
	} else {
		assertAutomaticRuleJSON(t, "configured66 exact replay", second.Body.Bytes(), replay.Body.Bytes())
	}
	return routed.ID
}

func assertFindingHumanExclusion(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run string) {
	t.Helper()
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(c.execution_owner='legacy' AND c.definition_version=x.definition_version AND c.input_digest=x.input_digest AND m.execution_owner='legacy' AND m.input_digest=x.input_digest AND m.definition_version=x.definition_version AND x.source_kind='human78') FROM zasp_temporal78.run_owners x JOIN zasp_temporal66.run_owners c USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal65.commands m USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1 AND m.kind='start'`, run).Scan(&exact); err != nil || !exact {
		t.Fatal("exact78/66/65 owner", exact, err)
	}
	cfg := owner.Config().Copy()
	cfg.User = "security_agent_v33_worker_login"
	worker, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	retained, err := NewSecurityAgentWorkerRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := retained.ClaimSecurityAgentRuns(ctx, "finding78-retained-check", "finding78-retained-token", 30, 10); err != nil {
		t.Fatal("retained claim", err)
	} else {
		for _, claim := range claims {
			if claim.RunID == run {
				t.Fatal("retained worker claimed78")
			}
		}
	}
	var pending json.RawMessage
	if err := worker.QueryRow(ctx, `SELECT zasp_temporal65.pending()`).Scan(&pending); err != nil || strings.Contains(string(pending), run) {
		t.Fatal("generic ordered dispatch includes78", err)
	}
	// The bootstrap session under SET ROLE is intentionally invisible to the
	// existing restrictive RLS. Confirm it before testing a real authority write.
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM public.zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback(ctx)
	if visible != 0 {
		t.Fatal("unexpected bootstrap-session visibility", visible)
	}
	t.Log("bootstrap SET ROLE sees zero owned rows; lease test uses registered executor session and a transaction-local domain-authority fixture")
	for _, sql := range []string{
		`UPDATE public.zasp_security_agent_runs SET lease_owner='finding78-forbidden',lease_token='finding78-forbidden',lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE run_id=$1`,
		`INSERT INTO public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,attempt) SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,decode(input_digest,'hex'),'leased',1 FROM zasp_temporal78.run_owners WHERE run_id=$1`,
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// This helper exists only in the rolled-back fixture transaction. It
		// preserves session_user and delegates the exact forbidden domain write.
		if _, err = tx.Exec(ctx, `CREATE FUNCTION pg_temp.finding78_forbidden(text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $fixture$ BEGIN IF current_user<>'zasp_discovery_authority' OR session_user<>'finding78_executor' OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE run_id=$1) THEN RAISE EXCEPTION 'fixture authority mismatch';END IF; `+sql+`; END $fixture$; ALTER FUNCTION pg_temp.finding78_forbidden(text) OWNER TO zasp_discovery_authority; SET LOCAL SESSION AUTHORIZATION finding78_executor`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SELECT pg_temp.finding78_forbidden($1)`, run)
		var pgError *pgconn.PgError
		valid := errors.As(err, &pgError) && pgError.Code == "42501" && pgError.Message == "finding owner rejects legacy lease"
		_ = tx.Rollback(ctx)
		if !valid {
			t.Fatal("78 lease-free authority backstop", err)
		}
	}
}
