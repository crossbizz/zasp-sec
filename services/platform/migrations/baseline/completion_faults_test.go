package baseline

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sections V1 to V5 of completion.sql against an installed and completed
// catalog. Everything happens in transactions that are rolled back.
//
// ZASP_BASELINE_RELEASE_TEST_DSN names a superuser connection to a database
// that holds at least one integration and one committed discovery run, and
// in which no discovery run is collecting while the test runs.
func completionFaultsConnection(t *testing.T) (context.Context, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("ZASP_BASELINE_RELEASE_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_BASELINE_RELEASE_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return ctx, conn
}

func sqlState(err error) string {
	var provider *pgconn.PgError
	if errors.As(err, &provider) {
		return provider.Code
	}
	return ""
}

// V1: the reconciler's read of an integration is bound to the lease it holds.
func TestLeasedConnectorIntegrationReadIsBoundToTheLease(t *testing.T) {
	ctx, conn := completionFaultsConnection(t)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var o, w, e, integration, effect string
	const owner, token = "agentsec-api:test:0000000000000001", "00000000000000000000000000000000000000000000000000000000000000aa"
	if err := tx.QueryRow(ctx, `
WITH chosen AS(SELECT r.organization_id o,r.workspace_id w,r.environment_id e,r.id i FROM public.zasp_workflow_records r
 JOIN public.zasp_integrations x ON(x.organization_id,x.workspace_id,x.environment_id,x.id)=(r.organization_id,r.workspace_id,r.environment_id,r.id)
 WHERE r.kind='integration' AND r.deleted_at IS NULL ORDER BY r.updated_at DESC LIMIT 1)
INSERT INTO public.zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,connection_reference,attempt,last_error_code,lease_owner,lease_token,lease_expires_at)
SELECT o,w,e,'pid_'||gen_random_uuid(),i,'aws','revoke','completion-faults-test-0001',digest('x','sha256'),'unknown','ref:aws/external-id/completion-test',1,'revocation_requested',$1,$2,transaction_timestamp()+interval '30 seconds' FROM chosen
RETURNING organization_id,workspace_id,environment_id,integration_id,id`, owner, token).Scan(&o, &w, &e, &integration, &effect); err != nil {
		t.Fatalf("no integration to lease: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET SESSION AUTHORIZATION zasp_svc_api`); err != nil {
		t.Fatal(err)
	}
	read := func(effectID, ownerValue, tokenValue string) (string, string) {
		inner, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer inner.Rollback(context.Background())
		var id string
		err = inner.QueryRow(ctx, `SELECT zasp_authorization80.connector_leased_integration($1,$2,$3,$4,$5,$6)#>>'{body,id}'`, o, w, e, effectID, ownerValue, tokenValue).Scan(&id)
		return id, sqlState(err)
	}
	if id, state := read(effect, owner, token); state != "" || id != integration {
		t.Fatalf("lease holder read id=%q state=%q", id, state)
	}
	for name, attempt := range map[string][3]string{
		"another token":  {effect, owner, strings.Repeat("b", 64)},
		"another owner":  {effect, "agentsec-api:test:0000000000000002", token},
		"another effect": {"pid_00000000-0000-4000-8000-00000000dead", owner, token},
	} {
		if id, state := read(attempt[0], attempt[1], attempt[2]); state != "P0002" || id != "" {
			t.Fatalf("%s: id=%q state=%q", name, id, state)
		}
	}
	if id, state := read(effect, owner, "not-a-token"); state != "22023" || id != "" {
		t.Fatalf("malformed token: id=%q state=%q", id, state)
	}
	// The API login cannot read the integration or the effect on its own.
	for _, statement := range []string{`SELECT count(*) FROM public.zasp_connector_effects`, `SELECT public.zasp_workflow_get('integration','` + integration + `','` + o + `','` + w + `','` + e + `')`} {
		inner, _ := tx.Begin(ctx)
		var ignored any
		if state := sqlState(inner.QueryRow(ctx, statement).Scan(&ignored)); state != "42501" {
			t.Fatalf("%s: state=%q", statement, state)
		}
		inner.Rollback(context.Background())
	}
	// An expired lease reads nothing.
	if _, err := tx.Exec(ctx, `RESET SESSION AUTHORIZATION`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.zasp_connector_effects SET updated_at=transaction_timestamp()-interval '2 minutes',lease_expires_at=transaction_timestamp()-interval '1 minute' WHERE id=$1`, effect); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET SESSION AUTHORIZATION zasp_svc_api`); err != nil {
		t.Fatal(err)
	}
	if id, state := read(effect, owner, token); state != "P0002" || id != "" {
		t.Fatalf("expired lease: id=%q state=%q", id, state)
	}
}

// V4: the scheduler's sweep releases exactly the runs the release of section
// N releases, without a later run asking, and only the scheduler may sweep.
func TestSchedulerSweepReleasesAbandonedDiscoveryRuns(t *testing.T) {
	ctx, conn := completionFaultsConnection(t)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	seed, _, found := strings.Cut(discoveryReleaseScenario, "\nDO $run$")
	if !found {
		t.Fatal("release scenario has no seed part")
	}
	if _, err := tx.Exec(ctx, seed, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sweep := func(login string) (int, int, string) {
		inner, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inner.Exec(ctx, `SET SESSION AUTHORIZATION `+login); err != nil {
			t.Fatal(err)
		}
		var examined, released int
		err = inner.QueryRow(ctx, `SELECT(r->>'examined')::int,(r->>'released')::int FROM zasp_temporal72.release_abandoned_due(100) r`).Scan(&examined, &released)
		if err != nil {
			state := sqlState(err)
			inner.Rollback(context.Background())
			return 0, 0, state
		}
		if _, err := inner.Exec(ctx, `RESET SESSION AUTHORIZATION`); err != nil {
			t.Fatal(err)
		}
		if err := inner.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return examined, released, ""
	}
	if _, _, state := sweep("zasp_svc_api"); state != "42501" {
		t.Fatalf("API login swept: state=%q", state)
	}
	if _, _, state := sweep("zasp_svc_discovery"); state != "42501" {
		t.Fatalf("discovery login swept: state=%q", state)
	}
	examined, released, state := sweep("zasp_svc_scheduler")
	if state != "" || examined < 1 {
		t.Fatalf("sweep examined=%d state=%q", examined, state)
	}
	// Scenario 14 is the run that asks in the test of section N. Nothing asks
	// here, and it is an admitted, published run that has been quiet for two
	// hours: the sweep releases it as never started.
	rows, err := tx.Query(ctx, `
SELECT s.label,s.want_released OR s.label LIKE '14%',d.job_id IS NOT NULL,COALESCE(d.reason,''),COALESCE(CASE WHEN s.label LIKE '14%' THEN 'never_started' ELSE s.want_reason END,''),
 COALESCE(d.released_by_job_id IN(SELECT r.job_id FROM zasp_temporal72.runs r),false),y.state
FROM pg_temp.release_seed s
JOIN public.zasp_discovery_syncs y ON y.id=s.sync_id
LEFT JOIN zasp_temporal72.releases d ON d.job_id=s.job_id ORDER BY s.label`)
	if err != nil {
		t.Fatal(err)
	}
	checked, expected := 0, 0
	for rows.Next() {
		var label, reason, wantReason, syncState string
		var want, got, byRun bool
		if err := rows.Scan(&label, &want, &got, &reason, &wantReason, &byRun, &syncState); err != nil {
			t.Fatal(err)
		}
		checked++
		if want {
			expected++
		}
		if want != got || reason != wantReason || byRun || got && syncState != "failed" {
			t.Errorf("%s: released=%v want %v, reason=%q want %q, released by a run=%v, sync=%s", label, got, want, reason, wantReason, byRun, syncState)
		}
	}
	rows.Close()
	if rows.Err() != nil || checked != 14 || released < expected {
		t.Fatalf("checked=%d released=%d expected at least %d err=%v", checked, released, expected, rows.Err())
	}
	if _, again, state := sweep("zasp_svc_scheduler"); state != "" || again != 0 {
		t.Fatalf("second sweep released=%d state=%q", again, state)
	}
}

// V2, V3 and V5 change or derive function bodies. Their behaviour needs a
// sealed request proof and is exercised through the API; this checks what
// the catalog must hold for it.
func TestCompletionFaultSectionsAreInstalled(t *testing.T) {
	ctx, conn := completionFaultsConnection(t)
	for name, query := range map[string]string{
		"V2 run completes the short form": `SELECT position('security agent trigger source mismatch' in d)>0 AND position($$jsonb_build_object('trigger_version',finding_version,'trigger_source',definition_source)$$ in d)>0
 FROM pg_get_functiondef('zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb)'::regprocedure) d`,
		"V2 run body is not executable by the API role": `SELECT NOT has_function_privilege('zasp_security_agent_api','zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb)','EXECUTE')
 AND has_function_privilege('zasp_security_agent_api','zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb,text)','EXECUTE')`,
		"V3 schedule create replaces an acknowledged deleted row": `SELECT position('discovery schedule withdrawal pending' in d)>0 AND position($$IF FOUND AND s.state<>'deleted' THEN RAISE$$ in d)>0 AND position('DELETE FROM zasp_temporal72.schedules' in d)>0
 FROM pg_get_functiondef('zasp_temporal72.public_put_schedule(text,text,text,text,text,text,bigint,integer,text,text,text,text)'::regprocedure) d`,
		"V5 cores do not ask the release-35 predicate": `SELECT count(*)=3 AND bool_and(position('zasp_production_integration_webhook_readiness' in p.prosrc)=0 AND position('zasp_authorization80.integration_current_ready()' in p.prosrc)>0
  AND position('zasp_authorization80.direct_guard(' in p.prosrc)>0 AND p.prosecdef AND r.rolname='zasp_discovery_authority'
  AND NOT has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE') AND NOT has_function_privilege('public',p.oid,'EXECUTE'))
 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.pronamespace='zasp_authorization80'::regnamespace AND p.proname IN('integration_webhook_test_status_core','integration_webhook_test_reserve_core','integration_webhook_test_complete_core')`,
		"V5 authorized webhook functions call the cores": `SELECT count(*)=3 AND bool_and(position('_core(' in p.prosrc)>0 AND position('zasp_authorization80.product_request(' in p.prosrc)>0 AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE'))
 FROM pg_proc p WHERE p.pronamespace='zasp_authorization80'::regnamespace AND p.proname IN('integration_webhook_status','integration_webhook_test_reserve','integration_webhook_test_complete')`,
		"V1 and V4 grants are narrow": `SELECT has_function_privilege('zasp_discovery_api','zasp_authorization80.connector_leased_integration(text,text,text,text,text,text)','EXECUTE')
 AND NOT has_function_privilege('public','zasp_authorization80.connector_leased_integration(text,text,text,text,text,text)','EXECUTE')
 AND has_function_privilege('zasp_discovery_scheduler','zasp_temporal72.release_abandoned_due(integer)','EXECUTE')
 AND NOT has_function_privilege('zasp_discovery_api','zasp_temporal72.release_abandoned_due(integer)','EXECUTE')
 AND NOT has_function_privilege('zasp_discovery_worker','zasp_temporal72.release_abandoned_due(integer)','EXECUTE')
 AND NOT has_function_privilege('public','zasp_temporal72.release_abandoned_due(integer)','EXECUTE')`,
		"every new function has a fixed search path and its owner": `SELECT count(*)=5 AND bool_and(p.prosecdef AND r.rolname='zasp_discovery_authority' AND p.proconfig @> ARRAY['search_path=pg_catalog, public'])
 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE(p.pronamespace::regnamespace::text,p.proname) IN(('zasp_authorization80','connector_leased_integration'),('zasp_temporal72','release_abandoned_due'),
  ('zasp_authorization80','integration_webhook_test_status_core'),('zasp_authorization80','integration_webhook_test_reserve_core'),('zasp_authorization80','integration_webhook_test_complete_core'))`,
		"the catalog is intact": `SELECT zasp_baseline.intact()`,
	} {
		var ok bool
		if err := conn.QueryRow(ctx, query).Scan(&ok); err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
	}
}
