package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are genuine decisions from the request authorizer with a controlled
// permission-specific Check. No signed grant is edited to manufacture a denial.
func exerciseP7FoundationReadContracts(t *testing.T, ctx context.Context, owner, api *pgx.Conn, database *PostgresJSONDatabase, authorizer *OpenFGAAuthorizer, identity RequestIdentity, binding CredentialBinding, projection *authorization.PostgresProjectionRepository, findings, policies []string) {
	t.Helper()
	oldChecker := authorizer.Checker
	defer func() { authorizer.Checker = oldChecker }()
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	const other = "pid_98000001-0000-4000-8000-000000000001"
	const receipt = "pid_98000002-0000-4000-8000-000000000002"
	const audit = "pid_98000003-0000-4000-8000-000000000003"
	const session = "pid_98000004-0000-4000-8000-000000000004"
	const agent = "pid_98000005-0000-4000-8000-000000000005"
	const integration = "pid_98000006-0000-4000-8000-000000000006"
	const syncID = "pid_98000007-0000-4000-8000-000000000007"
	const snapshot = "pid_98000008-0000-4000-8000-000000000008"
	const evidence = "pid_98000009-0000-4000-8000-000000000009"
	exec(`INSERT INTO zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest,legacy_digest,typed_digest,backfilled_at,equivalent_at,cutover_at) VALUES($1,$2,$3,'cutover','44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30',decode(repeat('11',32),'hex'),decode(repeat('11',32),'hex'),transaction_timestamp(),transaction_timestamp(),transaction_timestamp())`, o, w, e)
	exec(`INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version) VALUES($1,$2,$3,$4,$4,$5,'createPolicy','policy',$6,1)`, o, w, e, audit, p, policies[1])
	exec(`INSERT INTO zasp_workflow_idempotency(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,response) VALUES($1,$2,$3,$4,'createPolicy','foreign-owner-key',digest('receipt','sha256'),'{}')`, o, w, e, other)
	exec(`INSERT INTO zasp_workflow_receipts(organization_id,workspace_id,environment_id,principal_id,receipt_id,operation,idempotency_key,intent,result,resource_kind,resource_id,resource_version,audit_id,correlation_id) VALUES($1,$2,$3,$4,$5,'createPolicy','foreign-owner-key','{}','{}','policy',$6,1,$7,$7)`, o, w, e, other, receipt, policies[1], audit)
	exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$4,$5,'exact','otlp','tool','invoke','Native purpose',$4,clock_timestamp())`, o, w, e, session, p)
	// The unchanged typed detail reader requires a complete, last-good source
	// snapshot, its evidence and exactly one winning observation, not just a row.
	exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,state) VALUES($1,$2,$3,$4,'kubernetes','1.0.0','Native purpose provenance','active')`, o, w, e, integration)
	exec(`INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'native-purpose-provenance',decode(repeat('ab',32),'hex'),'manual',$6,'parser_v1','tool_v1')`, o, w, e, syncID, integration, p)
	exec(`INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'kubernetes','s3://zasp-evidence/native-purpose/manifest.json',decode(repeat('ab',32),'hex'),'complete',decode(repeat('ab',32),'hex'),'{}',true,true,now(),now())`, o, w, e, snapshot, integration, syncID)
	exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,projection_version,winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection) VALUES($1,$2,$3,$4,'agent_endpoint','Native purpose','active',now(),now(),'agent',now(),now()+interval '1 hour','{}',9500,$5,$6,1,1,$7,'kubernetes','kubernetes','native-purpose-agent',1,1)`, o, w, e, agent, evidence, snapshot, integration)
	exec(`INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version) VALUES($1,$2,$3,$4,$5,$6,$7,'s3://zasp-evidence/native-purpose/page.json',decode(repeat('ab',32),'hex'),'application/json','raw_v1','parser_v1',now(),'kubernetes',1,$4,'native-purpose/page.json','version-1',128,'tool_v1')`, o, w, e, evidence, integration, snapshot, agent)
	exec(`INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version) VALUES($1,$2,$3,$4,'kubernetes',$5,'native-purpose-agent',$6,'present','{}',now(),now(),'kubernetes','kubernetes_agent','Native purpose','{}','kubernetes_agent','agent',1,decode(repeat('ab',32),'hex'),$7,9500,now(),now()+interval '1 hour',1,80,1)`, o, w, e, integration, agent, snapshot, evidence)
	exec(`INSERT INTO zasp_risk_finding_factors(organization_id,workspace_id,environment_id,finding_id,position,name,evidence_id) VALUES($1,$2,$3,$4,1,'native purpose',$5)`, o, w, e, findings[1], audit)
	exec(`INSERT INTO zasp_risk_attack_paths(organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES($1,$2,$3,$4,$5,$6,'verified')`, o, w, e, findings[1], agent, session)
	exec(`INSERT INTO zasp_risk_attack_path_nodes(organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES($1,$2,$3,$4,1,$5)`, o, w, e, findings[1], agent)
	exec(`INSERT INTO zasp_risk_attack_path_evidence(organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, o, w, e, findings[1], audit)
	exec(`INSERT INTO zasp_risk_break_options(organization_id,workspace_id,environment_id,path_id,rank,target_id,evidence_id,kind) VALUES($1,$2,$3,$4,1,$5,$6,'remove_node')`, o, w, e, findings[1], agent, audit)
	reconcile := func() {
		t.Helper()
		if _, err := authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, authorizer.StoreID, authorizer.ModelID); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	allowed := map[string]bool{findings[1]: true, findings[2]: true, session: true, agent: true}
	for _, id := range policies[1:] {
		var canonical string
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80.object_id($1,$2,$3,'policy',$4)`, o, w, e, id).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		allowed[canonical] = true
	}
	grant := func(t *testing.T, op, permission string, empty bool) RequestAuthorization {
		t.Helper()
		authorizer.Checker = authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
			return authorization.Decision{Allowed: !empty && allowed[q.ResourceID] && (permission == "all" || q.Permission == permission), ModelID: authorizer.ModelID}, nil
		})
		c := ctx
		if op == "listSessions" {
			c = context.WithValue(c, authorizationQueryContextKey{}, url.Values{"kind": {"runtime"}})
		}
		g, err := authorizer.Authorize(c, identity, binding, RoutedOperation{OperationID: op})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	native := func(t *testing.T, g RequestAuthorization, q string, a ...any) ([]byte, error) {
		t.Helper()
		proof, err := authorizationProofJSON(g)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
			t.Fatal(err)
		}
		var body []byte
		err = tx.QueryRow(ctx, q, a...).Scan(&body)
		return body, err
	}
	t.Run("native read consumers refuse a valid home decision", func(t *testing.T) {
		g := grant(t, "getHomeSummary", "view", false)
		cases := []struct {
			name, q string
			a       []any
		}{
			{"audit", `SELECT zasp_authorization80.audit_page($1,$2,$3,$4,$5,$6,'{}',NULL,NULL,10,$7,$8)`, []any{o, w, e, p, binding.Digest[:], identity.CSRFToken, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}},
			{"workflow list", `SELECT zasp_authorization80.workflow_list('policy',$1,$2,$3,NULL,NULL)`, []any{o, w, e}},
			{"workflow page", `SELECT zasp_authorization80.workflow_page('policy',$1,$2,$3,NULL,10)`, []any{o, w, e}},
			{"risk page", `SELECT zasp_authorization80.risk_page('finding',$1,$2,$3,NULL,10)`, []any{o, w, e}},
			{"risk count", `SELECT to_jsonb(zasp_authorization80.high_path_count($1,$2,$3))`, []any{o, w, e}},
			{"inventory", `SELECT zasp_authorization80.inventory_page($1,$2,$3,'agent',NULL,10)`, []any{o, w, e}},
			{"search", `SELECT zasp_authorization80.global_search($1,$2,$3,'finding',10)`, []any{o, w, e}},
		}
		for _, name := range []string{"runtime_session", "runtime_sandbox"} {
			cases = append(cases, struct {
				name, q string
				a       []any
			}{name + " status", `SELECT zasp_authorization80.` + name + `_query_status($1,$2,$3,$4)`, []any{o, w, e, p}}, struct {
				name, q string
				a       []any
			}{name + " hydrate", `SELECT zasp_authorization80.` + name + `_query_hydrate($1,$2,$3,$4,$5)`, []any{o, w, e, p, []string{session}}})
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				body, err := native(t, g, c.q, c.a...)
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Errorf("cross-operation native disclosure: error=%v body=%s", err, body)
				}
			})
		}
	})
	t.Run("audit-only grant cannot read native product risk rows", func(t *testing.T) {
		g := grant(t, "listAuditEvents", "view_audit", false)
		for _, table := range []string{"zasp_risk_findings", "zasp_risk_finding_evidence", "zasp_risk_finding_factors", "zasp_risk_attack_paths", "zasp_risk_attack_path_nodes", "zasp_risk_attack_path_evidence", "zasp_risk_break_options"} {
			body, err := native(t, g, `SELECT to_jsonb(count(*)) FROM `+table)
			if err != nil || string(body) != "0" {
				t.Errorf("audit key exposed %s: %s %v", table, body, err)
			}
		}
	})
	t.Run("legitimate read purposes preserve native filtered reads", func(t *testing.T) {
		for _, c := range []struct {
			op, q, contains string
			args            []any
		}{
			{"listAuditEvents", `SELECT zasp_authorization80.audit_page($1,$2,$3,$4,$5,$6,'{}',NULL,NULL,10,$7,$8)`, audit, []any{o, w, e, p, binding.Digest[:], identity.CSRFToken, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}},
			{"listAgents", `SELECT zasp_authorization80.inventory_page($1,$2,$3,'agent',NULL,10)`, agent, []any{o, w, e}},
			{"globalSearch", `SELECT zasp_authorization80.global_search($1,$2,$3,'Native',10)`, agent, []any{o, w, e}},
			{"listPolicies", `SELECT zasp_authorization80.workflow_list('policy',$1,$2,$3,NULL,NULL)`, policies[1], []any{o, w, e}},
			{"listAttackPaths", `SELECT to_jsonb(zasp_authorization80.high_path_count($1,$2,$3))`, "", []any{o, w, e}},
		} {
			t.Run(c.op, func(t *testing.T) {
				g := grant(t, c.op, "all", false)
				body, err := native(t, g, c.q, c.args...)
				if err != nil || len(body) == 0 || !strings.Contains(string(body), c.contains) {
					t.Fatalf("current native read=%s %v", body, err)
				}
			})
		}
	})
	t.Run("receipt actor matches signed principal", func(t *testing.T) {
		g := grant(t, "listWorkflowMutationReceipts", "view", false)
		body, err := native(t, g, `SELECT zasp_authorization80.receipt_page($1,$2,$3,$4,10)`, o, w, e, other)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatalf("foreign actor receipt exposed: %s %v", body, err)
		}
		body, err = native(t, g, `SELECT zasp_authorization80.receipt_page($1,$2,$3,$4,10)`, o, w, e, p)
		if err != nil || !strings.Contains(string(body), `"items": []`) {
			t.Fatalf("own empty receipt list refused: %s %v", body, err)
		}
	})
	t.Run("native restricted search reveals no environment metadata", func(t *testing.T) {
		for _, empty := range []bool{false, true} {
			g := grant(t, "listSessions", "investigate_sessions", empty)
			for _, name := range []string{"runtime_session", "runtime_sandbox"} {
				body, err := native(t, g, `SELECT zasp_authorization80.`+name+`_query_status($1,$2,$3,$4)`, o, w, e, p)
				var result map[string]any
				if err != nil || json.Unmarshal(body, &result) != nil || len(result) != 1 || result["visibility"] != "resource_only" {
					t.Errorf("restricted native status contains scope metadata: %s %v", body, err)
				}
			}
		}
	})
	source, err := NewComplianceRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	request := func(t *testing.T, h http.Handler, op, path string, g RequestAuthorization) *httptest.ResponseRecorder {
		t.Helper()
		r := workflowRequest(t, identity, testCorrelationID, op, nil, http.MethodGet, path, "")
		r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "p7-current-session"})
		r = r.WithContext(context.WithValue(r.Context(), requestAuthorizationContextKey{}, g))
		response := httptest.NewRecorder()
		h.ServeHTTP(response, r)
		return response
	}
	for _, c := range []struct{ op, path string }{{"listComplianceControls", "/api/v1/compliance/controls"}, {"listComplianceEvidence", "/api/v1/compliance/evidence"}} {
		t.Run("mounted "+c.op, func(t *testing.T) {
			h := &complianceHTTPHandler{source: source, signingKey: key}
			g := grant(t, c.op, "all", false)
			response := request(t, h, c.op, c.path+"?limit=1", g)
			if response.Code != 200 {
				t.Fatalf("current composed list=%d %s", response.Code, response.Body.String())
			}
			var page struct {
				Items    []json.RawMessage `json:"items"`
				PageInfo struct {
					Next string `json:"next_cursor"`
				} `json:"page_info"`
			}
			if json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
				t.Fatalf("nonempty composed page=%s", response.Body.String())
			}
			if page.PageInfo.Next == "" {
				t.Fatalf("fixture did not exercise continuation: %s", response.Body.String())
			}
			if page.PageInfo.Next != "" {
				response = request(t, h, c.op, c.path+"?limit=1&cursor="+url.QueryEscape(page.PageInfo.Next), grant(t, c.op, "all", false))
				if response.Code != 200 {
					t.Fatalf("continuation=%d %s", response.Code, response.Body.String())
				}
			}
			response = request(t, h, c.op, c.path+"?limit=1", grant(t, c.op, "all", true))
			if response.Code != 200 {
				t.Fatalf("empty parent set=%d %s", response.Code, response.Body.String())
			}
		})
	}
	t.Run("workflow cursor crosses enforcing database", func(t *testing.T) {
		repository := &PostgresRepository{database: database, currentAuthorization: true}
		h, err := newWorkflowHTTPHandler(repository, key, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		g := grant(t, "listPolicies", "view", false)
		response := request(t, h, "listPolicies", "/api/v1/policies?limit=1", g)
		var page struct {
			PageInfo struct {
				Next string `json:"next_cursor"`
			} `json:"page_info"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.PageInfo.Next == "" {
			t.Fatalf("workflow first=%d %s", response.Code, response.Body.String())
		}
		next := "/api/v1/policies?limit=1&cursor=" + url.QueryEscape(page.PageInfo.Next)
		response = request(t, h, "listPolicies", next, grant(t, "listPolicies", "view", false))
		if response.Code != 200 {
			t.Fatalf("same revision cursor=%d %s", response.Code, response.Body.String())
		}
		exec(`UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1`, p)
		reconcile()
		response = request(t, h, "listPolicies", next, grant(t, "listPolicies", "view", false))
		if response.Code == 200 {
			t.Fatal("changed current revision reused workflow cursor")
		}
	})
}
