package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Exercises the installed reverse candidate SELECT. Coverage integrity and
// envelope expansion are separate costs; this is not production load proof.
func TestSecurityAgentActivityReverseTriggerAccessPathPostgres(t *testing.T) {
	testSecurityAgentActivityReverseAccessPath(t, "attack_path", false)
}

func TestSecurityAgentActivityReverseActionAccessPathPostgres(t *testing.T) {
	for _, kind := range []string{"finding", "session"} {
		t.Run(kind, func(t *testing.T) { testSecurityAgentActivityReverseAccessPath(t, kind, false) })
	}
}

func TestSecurityAgentActivityReverseRegisteredScalePostgres(t *testing.T) {
	testSecurityAgentActivityReverseAccessPath(t, "attack_path", true)
}

func testSecurityAgentActivityReverseAccessPath(t *testing.T, kind string, registered bool) {
	t.Helper()
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const workspace = "pid_6a000002-0000-4000-8000-000000000002"
		const environment = "pid_6a000003-0000-4000-8000-000000000003"
		const entity = "pid_8e00ffff-0000-4000-8000-00000000ffff"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs
		 (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,created_at)
		 SELECT organization_id,workspace_id,environment_id,
		 'pid_8e'||lpad(to_hex(n),6,'0')||'-0000-4000-8000-'||lpad(to_hex(n),12,'0'),
		 'pid_8c'||lpad(to_hex((n-1)/50),6,'0')||'-0000-4000-8000-'||lpad(to_hex((n-1)/50),12,'0'),1,
		 CASE WHEN n>4950 THEN $1 ELSE 'pid_8d'||lpad(to_hex(n),6,'0')||'-0000-4000-8000-'||lpad(to_hex(n),12,'0') END,
		 'activity-reverse-fixture','needs_human','2000-01-01T00:00:00Z'::timestamptz+n*interval '1 second'
		 FROM zasp_security_agent_definitions CROSS JOIN generate_series(1,5000) n`, entity); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions
		 SELECT (jsonb_populate_record(NULL::zasp_security_agent_definitions,to_jsonb(d)||jsonb_build_object('definition_id','pid_8c'||lpad(to_hex(n),6,'0')||'-0000-4000-8000-'||lpad(to_hex(n),12,'0')))).*
		 FROM zasp_security_agent_definitions d CROSS JOIN generate_series(0,99) n;
		 INSERT INTO zasp_security_agent_trigger_receipts
		 (organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
		 SELECT organization_id,workspace_id,environment_id,definition_id,trigger_id,'attack_path',
		 row_number() OVER(PARTITION BY organization_id,workspace_id,environment_id ORDER BY run_id),decode(repeat('a',64),'hex'),run_id
		 FROM zasp_security_agent_runs WHERE requested_by='activity-reverse-fixture';
		 ANALYZE zasp_security_agent_runs; ANALYZE zasp_security_agent_trigger_receipts`); err != nil {
			t.Fatal(err)
		}
		var total, scoped, matching, definitions int
		if err := owner.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),count(*) FILTER(WHERE (organization_id,workspace_id,environment_id,trigger_id)=($1,$2,$3,$4)),count(DISTINCT definition_id) FILTER(WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)) FROM zasp_security_agent_runs WHERE requested_by='activity-reverse-fixture'`, org, workspace, environment, entity).Scan(&total, &scoped, &matching, &definitions); err != nil || total != 10000 || scoped != 5000 || matching != 50 || definitions != 100 {
			t.Fatalf("fixture total=%d scoped=%d matching=%d definitions=%d error=%v", total, scoped, matching, definitions, err)
		}
		if kind != "attack_path" {
			action := "update_finding_response"
			if kind == "session" {
				action = "isolate_session"
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_plans
			 (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
			 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,1,decode(repeat('a',64),'hex'),'security-agent-actions-v1',
			 projected.body,digest(projected.body::text,'sha256'),now()+interval '1 hour'
			 FROM zasp_security_agent_runs CROSS JOIN LATERAL
			 (SELECT jsonb_build_object('run_id',run_id,'steps',jsonb_build_array(jsonb_build_object('action',$1::text,'target_id',trigger_id,'session_id',trigger_id))) AS body) projected
			 WHERE requested_by='activity-reverse-fixture'`, action); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `ANALYZE zasp_security_agent_plans`); err != nil {
				t.Fatal(err)
			}
			var planCount int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_plans`).Scan(&planCount); err != nil || planCount != 10000 {
				t.Fatalf("action fixture plans=%d error=%v", planCount, err)
			}
		}
		if registered {
			exerciseSecurityAgentRegisteredScale(t, ctx, owner, dsn, org, workspace, environment, entity)
			return
		}
		var definition string
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_production_security_agent_run_context_related_runs(text,text,text,text,bytea,text,text,text,timestamptz,text,integer)'::regprocedure)`).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		_, candidate, found := strings.Cut(definition, "FOR candidate IN\n")
		candidate, _, end := strings.Cut(candidate, "\n LOOP")
		if !found || !end {
			t.Fatal("installed reverse SELECT not found")
		}
		candidate = strings.NewReplacer("org_value", "$1", "workspace_value", "$2", "environment_value", "$3", "kind_value", "$4", "entity_value", "$5", "before_created_value", "$6", "before_id_value", "$7", "limit_value", "$8").Replace(candidate)
		if _, err := owner.Exec(ctx, `PREPARE reverse_page(text,text,text,text,text,timestamptz,text,integer) AS `+candidate); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
			if _, err := owner.Exec(ctx, "SET plan_cache_mode="+mode); err != nil {
				t.Fatal(err)
			}
			for _, next := range []bool{false, true} {
				var beforeTime, beforeID any
				if next {
					beforeTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(4981 * time.Second)
					beforeID = fmt.Sprintf("pid_8e%06x-0000-4000-8000-%012x", 4981, 4981)
				}
				var raw json.RawMessage
				if err := owner.QueryRow(ctx, `EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) EXECUTE reverse_page($1,$2,$3,$4,$5,$6,$7,$8)`, pgx.QueryExecModeSimpleProtocol, org, workspace, environment, kind, entity, beforeTime, beforeID, 20).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var plan []map[string]any
				if err := json.Unmarshal(raw, &plan); err != nil {
					t.Fatal(err)
				}
				wideScan := false
				observedSearches := false
				removed, searches := float64(0), float64(0)
				var inspect func(map[string]any)
				inspect = func(node map[string]any) {
					loops, _ := node["Actual Loops"].(float64)
					rows, _ := node["Actual Rows"].(float64)
					if value, ok := node["Index Searches"].(float64); ok {
						observedSearches = true
						searches += value
						t.Logf("index=%v searches=%.0f rows=%.0f loops=%.0f", node["Index Name"], value, rows, loops)
					}
					if node["Node Type"] == "Seq Scan" && rows*loops > 100 {
						wideScan = true
					}
					if value, ok := node["Rows Removed by Filter"].(float64); ok {
						removed += value * loops
					}
					if value, ok := node["Rows Removed by Index Recheck"].(float64); ok {
						removed += value * loops
					}
					if children, ok := node["Plans"].([]any); ok {
						for _, child := range children {
							inspect(child.(map[string]any))
						}
					}
				}
				root := plan[0]["Plan"].(map[string]any)
				inspect(root)
				t.Logf("reverse kind=%s mode=%s next=%v removed=%.0f searches=%.0f execution_ms=%v", kind, mode, next, removed, searches, plan[0]["Execution Time"])
				if root["Actual Rows"] != float64(21) || wideScan || !observedSearches || removed > 50 || searches > 100 {
					t.Fatalf("reverse kind=%s mode=%s next=%v lacks selective access: %s", kind, mode, next, raw)
				}
			}
		}
	})
}

// Measures the real registered-login repository path, including pinned readiness,
// browser authorization, whole-scope coverage and decoded envelopes. Identity
// and stopped-run prerequisites are owner fixtures, not live production proof.
func exerciseSecurityAgentRegisteredScale(t *testing.T, ctx context.Context, owner *pgx.Conn, dsn, org, workspace, environment, entity string) {
	t.Helper()
	const principal = "pid_8b000001-0000-4000-8000-000000000001"
	csrf := strings.Repeat("a", 32)
	digest := sha256.Sum256([]byte("activity-scale-session"))
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'activity-scale-org','activity-scale-member','security_admin',true)`, []any{org, principal}},
		{`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Activity scale','["view"]',true)`, []any{org, workspace, environment, principal}},
		{`INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,session_id,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view"]',$6,clock_timestamp()+interval '1 hour','session-activity-scale',clock_timestamp())`, []any{org, workspace, environment, principal, digest[:], csrf}},
	} {
		if _, err := owner.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "security_agent_v33_api_login"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	parseID := func(value string) domain.ProductID {
		id, err := domain.ParseProductID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	scope, err := domain.NewScope(parseID(org), parseID(workspace), parseID(environment))
	if err != nil {
		t.Fatal(err)
	}
	identity := RequestIdentity{PrincipalID: parseID(principal), Scope: scope, Permissions: []string{"view"}, CSRFToken: csrf, CredentialKind: CredentialBrowserSession}
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		if _, err := api.Exec(ctx, "SET plan_cache_mode="+mode); err != nil {
			t.Fatal(err)
		}
		request := SecurityAgentActivityRunRequest{Kind: "attack_path", EntityID: entity, Limit: 20}
		for pageIndex, wantCount := range []int{20, 20, 10} {
			started := time.Now()
			page, err := repository.ListSecurityAgentActivityRuns(ctx, identity, request, digest[:])
			elapsed := time.Since(started)
			if err != nil || page.Coverage != "complete" || len(page.Items) != wantCount {
				t.Fatalf("registered mode=%s page=%d elapsed=%s count=%d coverage=%s err=%v", mode, pageIndex, elapsed, len(page.Items), page.Coverage, err)
			}
			for i, run := range page.Items {
				n := 5000 - pageIndex*20 - i
				want := fmt.Sprintf("pid_8e%06x-0000-4000-8000-%012x", n, n)
				if run.ID != want {
					t.Fatalf("registered page=%d item=%d got=%s want=%s", pageIndex, i, run.ID, want)
				}
			}
			if pageIndex < 2 {
				wantTime := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(5000-pageIndex*20-wantCount+1) * time.Second)
				if page.NextCreatedAt == nil || !page.NextCreatedAt.Equal(wantTime) || page.NextID != page.Items[len(page.Items)-1].ID {
					t.Fatal("missing exact continuation")
				}
				request.BeforeCreatedAt = *page.NextCreatedAt
				request.BeforeID = page.NextID
			} else if page.NextCreatedAt != nil || page.NextID != "" {
				t.Fatal("unexpected terminal continuation")
			}
			t.Logf("registered mode=%s page=%d rows=%d coverage=%s elapsed=%s", mode, pageIndex, wantCount, page.Coverage, elapsed)
		}
	}
	// Remove only an unrelated, off-page receipt in each owned scope. A foreign
	// integrity gap must not taint this tenant; its own gap must not be hidden.
	for _, check := range []struct{ organization, coverage string }{
		{"pid_9a000001-0000-4000-8000-000000000001", "complete"},
		{org, "partial"},
	} {
		result, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_trigger_receipts WHERE organization_id=$1 AND run_id='pid_8e000001-0000-4000-8000-000000000001'`, check.organization)
		if err != nil || result.RowsAffected() != 1 {
			t.Fatalf("owned receipt mutation count=%d err=%v", result.RowsAffected(), err)
		}
		page, err := repository.ListSecurityAgentActivityRuns(ctx, identity, SecurityAgentActivityRunRequest{Kind: "attack_path", EntityID: entity, Limit: 20}, digest[:])
		if err != nil || page.Coverage != check.coverage || len(page.Items) != 20 {
			t.Fatalf("scope coverage=%s want=%s rows=%d err=%v", page.Coverage, check.coverage, len(page.Items), err)
		}
		for i, run := range page.Items {
			n := 5000 - i
			if run.ID != fmt.Sprintf("pid_8e%06x-0000-4000-8000-%012x", n, n) {
				t.Fatal("integrity gap changed related page")
			}
		}
	}
}
