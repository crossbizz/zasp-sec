package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestP7HomeAuthorizationPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	migrateP7Authorization(t, ctx, admin)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	i := fixtureRequestIdentity(t)
	i.CSRFToken = strings.Repeat("x", 32)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Home','home80.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Home')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-home80','member-home80','read_only_viewer',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('home80-credential','sha256'),'session-home80',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	const visible = "pid_89400001-0000-4000-8000-000000000001"
	const hidden = "pid_89400002-0000-4000-8000-000000000002"
	const pathVisible = "pid_89400003-0000-4000-8000-000000000003"
	const pathHidden = "pid_89400004-0000-4000-8000-000000000004"
	const foreignEnvironment = "pid_89400005-0000-4000-8000-000000000005"
	const pathForeign = "pid_89400006-0000-4000-8000-000000000006"
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Foreign','production')`, o, w, foreignEnvironment)
	for _, row := range []struct{ environment, id string }{{e, pathVisible}, {e, pathHidden}, {foreignEnvironment, pathForeign}} {
		exec(`INSERT INTO zasp_risk_attack_paths(organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES($1,$2,$3,$4,'pid_73000001-0000-4000-8000-000000000001','pid_73000002-0000-4000-8000-000000000002','verified')`, o, w, row.environment, row.id)
		exec(`INSERT INTO zasp_risk_attack_path_nodes(organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES($1,$2,$3,$4,1,'pid_73000001-0000-4000-8000-000000000001')`, o, w, row.environment, row.id)
		exec(`INSERT INTO zasp_risk_attack_path_evidence(organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES($1,$2,$3,$4,1,'pid_73000002-0000-4000-8000-000000000002')`, o, w, row.environment, row.id)
		exec(`INSERT INTO zasp_risk_break_options(organization_id,workspace_id,environment_id,path_id,rank,target_id,evidence_id,kind) VALUES($1,$2,$3,$4,1,'pid_73000001-0000-4000-8000-000000000001','pid_73000002-0000-4000-8000-000000000002','remove_node')`, o, w, row.environment, row.id)
		exec(`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$4,'posture','Bounded risk test','high','open')`, o, w, row.environment, row.id)
		exec(`INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,'pid_73000002-0000-4000-8000-000000000002')`, o, w, row.environment, row.id)
		exec(`INSERT INTO zasp_risk_finding_factors(organization_id,workspace_id,environment_id,finding_id,position,name,evidence_id) VALUES($1,$2,$3,$4,1,'bounded','pid_73000002-0000-4000-8000-000000000002')`, o, w, row.environment, row.id)
	}
	for _, id := range []string{visible, hidden} {
		exec(`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,created_at,updated_at) VALUES($1,$2,$3,$4,'pid_73000001-0000-4000-8000-000000000001',1,'pid_73000002-0000-4000-8000-000000000002',$5,'failed',transaction_timestamp(),transaction_timestamp())`, o, w, e, id, p)
	}
	config, _ := pgxpool.ParseConfig(dsn)
	config.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	store, model := "01K00000000000000000000001", "01K00000000000000000000002"
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model)
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	database.currentAuthorization = true
	repository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := NewPostgresAuthorizationResolver(database)
	checker := authorizationDecisionFixture{allow: map[string]bool{visible: true}, model: model}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	binding := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-home80", Digest: sha256.Sum256([]byte("home80-credential"))}
	checked := func(t *testing.T) context.Context {
		t.Helper()
		grant, err := authorizer.Authorize(ctx, i, binding, RoutedOperation{OperationID: "getHomeSummary"})
		if err != nil {
			t.Fatal(err)
		}
		return context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	}
	t.Run("raw API no proof cannot read risk rows", func(t *testing.T) {
		var count int
		if err := api.QueryRow(ctx, `SELECT count(*) FROM zasp_risk_attack_paths`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("raw API visible risk rows=%d error=%v", count, err)
		}
	})
	t.Run("raw API forged GUC cannot authorize risk rows", func(t *testing.T) {
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		fake, _ := json.Marshal(map[string]any{"allowed": []map[string]string{{"organization_id": o, "workspace_id": w, "environment_id": e, "kind": "attack_path", "id": pathHidden}}})
		if _, err = tx.Exec(ctx, `SELECT set_config('zasp.authorization80',$1,true)`, string(fake)); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM zasp_risk_attack_paths`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("forged GUC visible risk rows=%d error=%v", count, err)
		}
	})
	t.Run("raw API legacy mutation cannot bypass current authority", func(t *testing.T) {
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		_, err = tx.Exec(ctx, `SELECT public.zasp_risk_mutate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, "updateFinding", pathHidden, o, w, e, p, "raw-legacy-authority-proof", int64(1), "under_review", nil, "pid_88700001-0000-4000-8000-000000000001", "pid_88700002-0000-4000-8000-000000000002", "pid_88700003-0000-4000-8000-000000000003")
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "55000" {
			t.Fatalf("legacy API mutation reached effects: %v", err)
		}
	})
	t.Run("raw API cannot mint expanded Check evidence", func(t *testing.T) {
		grant, _ := requestAuthorizationFromContext(checked(t))
		original, err := authorizationProofJSON(grant)
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Body    []byte `json:"body"`
			Version string `json:"version"`
			MAC     string `json:"mac"`
		}
		if json.Unmarshal(original, &envelope) != nil {
			t.Fatal("invalid test envelope")
		}
		var claims map[string]json.RawMessage
		if json.Unmarshal(envelope.Body, &claims) != nil {
			t.Fatal("invalid test claims")
		}
		for _, target := range grant.Targets {
			if target.Kind == "attack_path" && target.ID == pathHidden {
				grant.Allowed = append(grant.Allowed, target)
			}
		}
		if _, err = authorizationProofJSON(grant); err == nil {
			t.Fatal("mutated private grant retained valid attestation")
		}
		changed, _ := authorizationDecisionJSON(grant)
		var mutated map[string]json.RawMessage
		_ = json.Unmarshal(changed, &mutated)
		claims["allowed"] = mutated["allowed"]
		envelope.Body, _ = json.Marshal(claims)
		proof, _ := json.Marshal(envelope)
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err == nil {
			t.Fatal("API minted expanded allowed targets without their Check")
		}
	})
	t.Run("signed risk rows and transaction bound context", func(t *testing.T) {
		checker.allow[pathVisible] = true
		defer delete(checker.allow, pathVisible)
		grant, _ := requestAuthorizationFromContext(checked(t))
		exerciseAuthorizationAttestation(t, ctx, admin, api, grant, pathVisible, pathHidden)
	})
	t.Run("home source security rollback drift", func(t *testing.T) {
		for _, statement := range []string{
			`ALTER TABLE zasp_risk_attack_paths DISABLE ROW LEVEL SECURITY`,
			`ALTER TABLE zasp_risk_attack_paths NO FORCE ROW LEVEL SECURITY`,
			`ALTER TABLE zasp_risk_attack_paths OWNER TO zasp_discovery_authority`,
			`GRANT SELECT ON zasp_inventory_entities TO zasp_discovery_api`,
			`GRANT EXECUTE ON FUNCTION zasp_inventory_home_summary_v29(text,text,text) TO PUBLIC`,
			`CREATE POLICY forbidden80 ON zasp_risk_attack_paths TO zasp_discovery_api USING(true)`,
		} {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, statement); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			var ready bool
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80.home_source_ready()`).Scan(&ready)
			_ = tx.Rollback(ctx)
			if err != nil || ready {
				t.Fatalf("drift remained ready for %s: %v %v", statement, ready, err)
			}
		}
		var ready bool
		if err := admin.QueryRow(ctx, `SELECT zasp_authorization80.home_source_ready()`).Scan(&ready); err != nil || !ready {
			t.Fatalf("rollback changed readiness: %v %v", ready, err)
		}
	})
	read := func(t *testing.T, c context.Context, want int64, null bool) {
		t.Helper()
		summary, err := repository.GetHomeSummary(c, i.Scope)
		if err != nil {
			_, providerErr := database.QueryJSON(c, `SELECT zasp_authorization80.home_summary($1,$2,$3)`, o, w, e)
			probe, probeErr := database.QueryJSON(c, `SELECT jsonb_build_object('allowed_run',zasp_authorization80.allowed($1,$2,$3,'security_agent_run',$4))`, o, w, e, visible)
			var components json.RawMessage
			_ = admin.QueryRow(ctx, `SELECT jsonb_build_object('home_ready',zasp_authorization80.home_source_ready(),'inventory_security',zasp_inventory_security_ready())`).Scan(&components)
			var security json.RawMessage
			_ = admin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('table',relname,'owner',relowner::regrole::text,'rls',relrowsecurity,'forced',relforcerowsecurity,'api_select',has_table_privilege('zasp_discovery_api',oid,'SELECT'))) FROM pg_class WHERE oid IN('zasp_inventory_entities'::regclass,'zasp_risk_attack_paths'::regclass,'zasp_security_agent_approvals'::regclass,'zasp_security_agent_runs'::regclass)`).Scan(&security)
			t.Fatalf("home error=%v provider=%v components=%s context=%s context_error=%v source security=%s", err, providerErr, components, probe, probeErr, security)
		}
		body, _ := json.Marshal(summary)
		var wire map[string]json.RawMessage
		_ = json.Unmarshal(body, &wire)
		if summary.FailedRuns != want || summary.HighRiskPaths != 0 || (string(wire["healthy"]) == "null") != null || (string(wire["attention_required"]) == "null") != null {
			t.Fatalf("home count/health leak: %s", body)
		}
		if !null && (summary.Healthy || !summary.AttentionRequired) {
			t.Fatalf("full degraded status changed: %s", body)
		}
	}
	t.Run("restricted counts and unavailable status", func(t *testing.T) { read(t, checked(t), 1, true) })
	t.Run("empty authorized set", func(t *testing.T) {
		delete(checker.allow, visible)
		read(t, checked(t), 0, true)
		checker.allow[visible] = true
	})
	t.Run("separate current environment decision", func(t *testing.T) {
		checker.allow[e] = true
		checker.allow[hidden] = true
		read(t, checked(t), 2, false)
		delete(checker.allow, e)
		delete(checker.allow, hidden)
	})
	t.Run("source cutover phase remains required", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest,legacy_digest,typed_digest,backfilled_at,equivalent_at,cutover_at) VALUES($1,$2,$3,'cutover','44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30',decode(repeat('11',32),'hex'),decode(repeat('11',32),'hex'),transaction_timestamp(),transaction_timestamp(),transaction_timestamp())`, o, w, e); err != nil {
			t.Fatal(err)
		}
		read(t, checked(t), 1, true)
		c := checked(t)
		if _, err := admin.Exec(ctx, `UPDATE zasp_inventory_cutover_state SET phase='equivalent',cutover_at=NULL WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.GetHomeSummary(c, i.Scope); err == nil {
			t.Fatal("home read accepted an unfinished typed scope")
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_inventory_cutover_state SET phase='cutover',cutover_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e); err != nil {
			t.Fatal(err)
		}
		read(t, checked(t), 1, true)
	})
	t.Run("revision change refuses old summary proof", func(t *testing.T) {
		c := checked(t)
		if _, err := admin.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='inconclusive',version=version+1 WHERE run_id=$1`, visible); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.GetHomeSummary(c, i.Scope); !errors.Is(err, ErrRepositoryConflict) {
			t.Fatalf("stale summary error=%v", err)
		}
	})
}
