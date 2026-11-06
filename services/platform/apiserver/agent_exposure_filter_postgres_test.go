package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentExposureFilterNormalMountedPostgres(t *testing.T) {
	runAgentExposureFilterMounted(t, false)
}
func TestAgentExposureFilterAuditMountedPostgres(t *testing.T) {
	runAgentExposureFilterMounted(t, true)
}

// Controlled persisted collector-shaped metadata exercises actual SQL and the
// current mounted read path. It is not provider ingestion, ownership mutation,
// deployed acceptance, or a comprehensive negative risk assessment.
func runAgentExposureFilterMounted(t *testing.T, audit bool) {
	t.Helper()
	if audit {
		t.Setenv("ZASP_P7_AUDIT_TEST", "1")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	} else {
		t.Setenv("ZASP_P7_AUDIT_TEST", "")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "")
	}
	f := newEnvironmentClassNativeFixture(t)
	ctx, i := f.ctx, f.identity
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	const agent = "pid_81000001-0000-4000-8000-000000000001"
	const other = "pid_81000002-0000-4000-8000-000000000002"
	const sa = "pid_84000001-0000-4000-8000-000000000001"
	const binding = "pid_84000002-0000-4000-8000-000000000002"
	const role = "pid_84000003-0000-4000-8000-000000000003"
	const namespace = "pid_84000004-0000-4000-8000-000000000004"
	const losingIntegration = "pid_76000009-0000-4000-8000-000000000009"
	const losingSnapshot = "pid_78000009-0000-4000-8000-000000000009"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.bootstrap.Exec(ctx, q, args...); err != nil {
			t.Fatal("controlled exposure fixture statement refused")
		}
	}
	pin := migrations.AgentExposureFilterProfileChecksum()
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: f.owner})
	if err != nil {
		t.Fatal("exposure runner refused")
	}
	install := runner.UpProductionAgentExposureFilterProfile
	if audit {
		pin = migrations.AgentExposureFilterAuditProfileChecksum()
		install = runner.UpProductionAgentExposureFilterAuditProfile
	}
	if err = install(ctx); err != nil {
		t.Fatal("selected exposure installer refused")
	}
	seedAgentReadNativeInventory(t, ctx, f.bootstrap, i)
	seedAgentReadNativeCapabilityGraph(t, ctx, f.bootstrap, i)
	// All additional objects are data in this disposable fixture, not roles or
	// grants. Thus shared exact pg_auth_members cleanup remains unchanged.
	clone := func(table, key, source string, changes map[string]any) {
		t.Helper()
		raw, err := json.Marshal(changes)
		if err != nil {
			t.Fatal("fixture metadata encoding refused")
		}
		allowed := map[string]string{"zasp_inventory_entities": "id", "zasp_inventory_evidence": "id", "zasp_inventory_source_observations": "entity_id", "zasp_integrations": "id", "zasp_discovery_syncs": "id", "zasp_discovery_snapshots": "id"}
		if allowed[table] != key {
			t.Fatal("fixture clone target refused")
		}
		exec(`INSERT INTO public.`+pgx.Identifier{table}.Sanitize()+` SELECT (jsonb_populate_record(NULL::public.`+pgx.Identifier{table}.Sanitize()+`,to_jsonb(original)||$1::jsonb)).* FROM public.`+pgx.Identifier{table}.Sanitize()+` original WHERE organization_id=$2 AND workspace_id=$3 AND environment_id=$4 AND `+pgx.Identifier{key}.Sanitize()+`=$5`, string(raw), o, w, e, source)
	}
	clone("zasp_inventory_entities", "id", role, map[string]any{"id": namespace, "winning_source_native_id": "target", "winning_evidence_id": "pid_85000004-0000-4000-8000-000000000004"})
	clone("zasp_inventory_evidence", "id", "pid_85000003-0000-4000-8000-000000000003", map[string]any{"id": "pid_85000004-0000-4000-8000-000000000004", "entity_id": namespace, "object_reference": "s3://zasp-evidence/typed/exposure/namespace.json", "artifact_key": "typed/exposure/namespace.json"})
	clone("zasp_inventory_source_observations", "entity_id", role, map[string]any{"entity_id": namespace, "source_native_id": "target", "source_kind": "kubernetes_namespace", "identity_namespace": "kubernetes_namespace", "evidence_id": "pid_85000004-0000-4000-8000-000000000004"})
	// A separate complete last-good source snapshot makes a losing-source edge
	// genuinely fresh. The winner-path test must reject it for provenance, not age.
	clone("zasp_integrations", "id", "pid_76000001-0000-4000-8000-000000000001", map[string]any{"id": losingIntegration})
	clone("zasp_discovery_syncs", "id", "pid_77000001-0000-4000-8000-000000000001", map[string]any{"id": "pid_77000009-0000-4000-8000-000000000009", "integration_id": losingIntegration, "idempotency_key": "exposure-losing-source"})
	clone("zasp_discovery_snapshots", "id", "pid_78000001-0000-4000-8000-000000000001", map[string]any{"id": losingSnapshot, "integration_id": losingIntegration, "sync_id": "pid_77000009-0000-4000-8000-000000000009"})
	clone("zasp_inventory_evidence", "id", "pid_91000001-0000-4000-8000-000000000001", map[string]any{"id": "pid_95000009-0000-4000-8000-000000000009", "integration_id": losingIntegration, "snapshot_id": losingSnapshot, "object_reference": "s3://zasp-evidence/typed/exposure/losing.json", "artifact_key": "typed/exposure/losing.json"})
	clone("zasp_inventory_source_observations", "entity_id", agent, map[string]any{"integration_id": losingIntegration, "snapshot_id": losingSnapshot, "evidence_id": "pid_95000009-0000-4000-8000-000000000009"})
	// Losing binding edges require genuine fresh SA/binding observations in the
	// losing source as well; absence alone must not make this provenance control pass.
	for index, entity := range []string{sa, binding} {
		oldEvidence := []string{"pid_85000001-0000-4000-8000-000000000001", "pid_85000002-0000-4000-8000-000000000002"}[index]
		newEvidence := []string{"pid_95000010-0000-4000-8000-000000000010", "pid_95000011-0000-4000-8000-000000000011"}[index]
		clone("zasp_inventory_evidence", "id", oldEvidence, map[string]any{"id": newEvidence, "integration_id": losingIntegration, "snapshot_id": losingSnapshot, "object_reference": "s3://zasp-evidence/typed/exposure/" + newEvidence + ".json", "artifact_key": "typed/exposure/" + newEvidence + ".json"})
		clone("zasp_inventory_source_observations", "entity_id", entity, map[string]any{"integration_id": losingIntegration, "snapshot_id": losingSnapshot, "evidence_id": newEvidence})
	}
	setFacts := func(id string, stable, attributes any) {
		t.Helper()
		s, _ := json.Marshal(stable)
		a, _ := json.Marshal(attributes)
		exec(`UPDATE public.zasp_inventory_entities SET stable_fields=$5::jsonb,winning_attributes=$6::jsonb WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, id, string(s), string(a))
		exec(`UPDATE public.zasp_inventory_source_observations ob SET stable_fields=$5::jsonb,attributes=$6::jsonb FROM public.zasp_inventory_entities v WHERE (v.organization_id,v.workspace_id,v.environment_id,v.id)=($1,$2,$3,$4) AND(ob.organization_id,ob.workspace_id,ob.environment_id,ob.entity_id,ob.integration_id,ob.snapshot_id)=(v.organization_id,v.workspace_id,v.environment_id,v.id,v.winning_integration_id,v.winning_snapshot_id)`, o, w, e, id, string(s), string(a))
	}
	agentStable := map[string]any{"cluster": "owned-cluster", "namespace": "subject", "name": "agent", "service_account": "agent-sa", "resource_kind": "Pod", "api_group": "core"}
	identityStable := map[string]any{"cluster": "owned-cluster", "namespace": "subject", "name": "agent-sa"}
	bindingStable := map[string]any{"cluster": "owned-cluster", "namespace": "target", "name": "agent-binding", "scope": "namespace", "role": "ClusterRole/agent-role"}
	roleStable := map[string]any{"cluster": "owned-cluster", "name": "agent-role"}
	rule := func(group string, resources, verbs []any) map[string]any {
		return map[string]any{"api_groups": []any{group}, "resources": resources, "verbs": verbs, "resource_names": []any{}, "non_resource_urls": []any{}}
	}
	setRules := func(rules []any) { setFacts(role, roleStable, map[string]any{"namespaced": false, "rules": rules}) }
	reset := func() {
		setFacts(agent, agentStable, map[string]any{"posture": map[string]any{"shell_execution": true, "production_secret_reach": true}})
		setFacts(sa, identityStable, map[string]any{})
		setFacts(binding, bindingStable, map[string]any{})
		setFacts(namespace, map[string]any{"cluster": "owned-cluster", "namespace": "target", "name": "target"}, map[string]any{})
		setRules([]any{rule("", []any{"pods/exec"}, []any{"create"})})
		exec(`UPDATE public.zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '15 minutes' WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e)
		exec(`UPDATE public.zasp_inventory_source_observations SET fresh_until=clock_timestamp()+interval '15 minutes' WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e)
		exec(`UPDATE public.zasp_inventory_relationships SET integration_id='pid_76000001-0000-4000-8000-000000000001',snapshot_id='pid_78000001-0000-4000-8000-000000000001' WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e)
	}
	reset()
	exec(`INSERT INTO public.zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value,team_value,tags) VALUES($1,$2,$3,$4,' Team A ','','[]'),($1,$2,$3,$5,'','','[]')`, o, w, e, agent, other)
	findings := []string{automaticSourceID(181001), automaticSourceID(181002), automaticSourceID(181003), automaticSourceID(181004), automaticSourceID(181005)}
	for index, id := range findings {
		severity := []string{"critical", "high", "medium", "low", "critical"}[index]
		status := []string{"open", "under_review", "accepted", "open", "resolved"}[index]
		target := agent
		if index == 4 {
			target = other
		}
		exec(`INSERT INTO public.zasp_risk_findings(organization_id,workspace_id,environment_id,id,agent_id,source,rule,title,severity,status,acceptance_reason) VALUES($1,$2,$3,$4,$5,'posture','exposure-native','Controlled recorded finding',$6,$7,CASE WHEN $7='accepted' THEN 'Controlled fixture acceptance' ELSE NULL END)`, o, w, e, id, target, severity, status)
	}
	f.reconcile()
	inventory, err := NewPostgresInventoryRepository(f.db)
	if err != nil {
		t.Fatal("actual typed inventory constructor refused")
	}
	if err = f.repository.RequireAgentExposureFilterProfile(pin); err != nil {
		t.Fatal("actual selected profile configuration refused")
	}
	// Same explicit repository-to-inventory copy as productionOperations.
	inventory.agentExposureFilterProfileChecksum = f.repository.agentExposureFilterProfileChecksum
	resolver, err := NewAgentExposureFilterResolver(f.authorizer.Resolver, f.db, pin)
	if err != nil {
		t.Fatal("actual exposure resolver refused")
	}
	f.authorizer.Resolver = resolver
	h, err := newInventoryHTTPHandler(inventory, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal("actual exposure handler refused")
	}
	policy, err := authorization.LookupOperation("listAgents")
	if err != nil {
		t.Fatal("listAgents operation absent")
	}
	router, err := NewRouter([]Operation{{Method: policy.Method, Pattern: policy.Path, OperationID: "listAgents", Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, Handler: h}})
	if err != nil {
		t.Fatal("mounted exposure router refused")
	}
	router.(*operationRouter).authorizer = f.authorizer
	call := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?"+query, nil)
		req.Header.Set(expectedScopeHeader, expectedScopeValue(i.Scope))
		r := httptest.NewRecorder()
		router.ServeHTTP(r, req.WithContext(context.WithValue(ctx, identityContextKey{}, i)))
		return r
	}
	page := func(query string) ([]InventorySummary, string) {
		t.Helper()
		r := call(query)
		var result struct {
			Items []InventorySummary `json:"items"`
			Page  struct {
				Next string `json:"next_cursor"`
			} `json:"page_info"`
		}
		if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &result) != nil || result.Items == nil {
			t.Fatal("mounted exposure page unavailable")
		}
		return result.Items, result.Page.Next
	}
	expect := func(query string, ids ...string) {
		t.Helper()
		items, _ := page(query)
		got := []string{}
		for _, item := range items {
			got = append(got, item.ID)
		}
		if !slices.Equal(got, ids) {
			t.Fatal("live filtered membership differs from controlled expected IDs")
		}
	}
	capture := func(query string) context.Context {
		t.Helper()
		values, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal("fixture query refused")
		}
		c := context.WithValue(ctx, authorizationQueryContextKey{}, values)
		g, err := f.authorizer.Authorize(c, i, i.credentialBinding, RoutedOperation{OperationID: "listAgents"})
		if err != nil {
			t.Fatal("actual complete current exposure proof refused")
		}
		return context.WithValue(c, requestAuthorizationContextKey{}, g)
	}
	t.Run("selected_profile_current_page_and_private_boundary", func(t *testing.T) {
		if err := install(ctx); err != nil {
			t.Fatal("actual selected installer replay refused")
		}
		ready, err := f.db.AgentExposureFilterProfileReady(ctx, pin)
		if err != nil || !ready {
			t.Fatal("actual caller readiness refused")
		}
		expect("execution=shell", agent)
		var raw []byte
		driver := f.db.driver.(*authorizationConnectionDriver)
		if err := driver.conn.QueryRow(ctx, `SELECT zasp_agent_exposure_filter_v1.classify($1,$2,$3,$4,$5)`, o, w, e, agent, pin).Scan(&raw); err == nil {
			t.Fatal("API executed private classifier without its mounted authority frame")
		}
		if _, err := inventory.ListAgentExposurePage(capture("execution=shell"), i.Scope, json.RawMessage(`{"execution":"shell"}`), "", 2); err != nil {
			t.Fatal("actual seven-argument authorized SQL page refused")
		}
		foreign, err := domain.NewScope(i.Scope.OrganizationID(), mustProductID(t, "pid_78000009-0000-4000-8000-000000000009"), mustProductID(t, "pid_78000007-0000-4000-8000-000000000007"))
		if err != nil {
			t.Fatal("owned foreign scope fixture refused")
		}
		if _, err := inventory.ListAgentExposurePage(capture("execution=shell"), foreign, json.RawMessage(`{"execution":"shell"}`), "", 2); err == nil {
			t.Fatal("page reused proof across scoped tenant target")
		}
		objectGrant, err := f.authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: "getAgent", PathParameters: map[string]string{"id": agent}})
		if err != nil {
			t.Fatal("actual original object proof refused")
		}
		if _, err := inventory.ListAgentExposurePage(context.WithValue(ctx, requestAuthorizationContextKey{}, objectGrant), i.Scope, json.RawMessage(`{"execution":"shell"}`), "", 2); err == nil {
			t.Fatal("page reused other-operation proof")
		}
		prior := inventory.agentExposureFilterProfileChecksum
		inventory.agentExposureFilterProfileChecksum = strings.Repeat("0", 64)
		if call("execution=shell").Code == http.StatusOK {
			t.Fatal("unselected profile fell back")
		}
		inventory.agentExposureFilterProfileChecksum = prior
	})
	t.Run("recorded_severity_status_and_real_finding_denial", func(t *testing.T) {
		expect("risk=critical", agent)
		expect("risk=unknown", other)
		for index, want := range []string{"high", "medium", "low", "unknown"} {
			exec(`UPDATE public.zasp_risk_findings SET status='resolved',acceptance_reason=NULL WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, findings[index])
			expect("risk="+want, func() []string {
				if want == "unknown" {
					return []string{agent, other}
				}
				return []string{agent}
			}()...)
		}
		for index, id := range findings[:4] {
			exec(`UPDATE public.zasp_risk_findings SET status=$5,acceptance_reason=CASE WHEN $5='accepted' THEN 'Controlled fixture acceptance' ELSE NULL END WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, id, []string{"open", "under_review", "accepted", "open"}[index])
		}
		// Borrow an authenticated owned-test SDK connection. Its freshly created
		// auxiliary store is explicitly deleted by its exact returned ID. All tuple
		// mutations below target ONLY this fixture's exact existing store/model.
		client, auxiliary := newAuthorizationProjectionFGA(t)
		if auxiliary.StoreID == "" || auxiliary.StoreID == f.authorizer.StoreID {
			t.Fatal("auxiliary owned store identity collision")
		}
		// The explicit owned helper already closes its auxiliary store using the
		// client's default store. NEVER change that default to the primary fixture.
		// The retained-local helper has no store cleanup, so close only its returned
		// auxiliary ID here. Both branches keep tuple writes on explicit overrides.
		if os.Getenv("ZASP_P6_NATIVE_OPENFGA_URL") == "" && os.Getenv("ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE") == "" {
			t.Cleanup(func() {
				bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := client.DeleteStore(bounded).Options(fga.ClientDeleteStoreOptions{StoreId: &auxiliary.StoreID}).Execute(); err != nil {
					t.Error("auxiliary owned store cleanup refused")
				}
			})
		}

		tuples := []fga.ClientTupleKey{{User: "user:" + i.PrincipalID.String(), Relation: "security_admin", Object: "environment:" + o + "/" + w + "/" + e}, {User: "user:" + i.PrincipalID.String(), Relation: "security_admin", Object: "organization:" + o}}
		direct := []fga.ClientTupleKey{}
		for _, resource := range []struct{ kind, id string }{{"agent", agent}, {"agent", other}, {"finding", findings[3]}} {
			direct = append(direct, fga.ClientTupleKey{User: "user:" + i.PrincipalID.String(), Relation: "direct_view", Object: "resource:" + o + "/" + w + "/" + e + "/" + resource.kind + "/" + resource.id})
		}
		write := func(add, remove []fga.ClientTupleKey) {
			t.Helper()
			deletes := []fga.ClientTupleKeyWithoutCondition{}
			for _, v := range remove {
				deletes = append(deletes, fga.ClientTupleKeyWithoutCondition{User: v.User, Relation: v.Relation, Object: v.Object})
			}
			if _, err := client.Write(ctx).Body(fga.ClientWriteRequest{Writes: add, Deletes: deletes}).Options(fga.ClientWriteOptions{StoreId: &f.authorizer.StoreID, AuthorizationModelId: &f.authorizer.ModelID}).Execute(); err != nil {
				t.Fatal("owned FGA permission fixture write refused")
			}
		}
		write(direct, tuples)
		defer write(tuples, direct)
		expect("risk=low", agent)
		expect("risk=critical")
		expect("risk=unknown", other)
		g, _ := requestAuthorizationFromContext(capture("risk=low"))
		foundDenied := false
		for _, target := range g.Targets {
			if target.Kind == "finding" && target.ID == findings[0] {
				foundDenied = true
				for _, allowed := range g.Allowed {
					if allowed.Kind == "finding" && allowed.ID == target.ID {
						t.Fatal("denied finding became allowed")
					}
				}
			}
		}
		if !foundDenied {
			t.Fatal("complete proof omitted denied related finding")
		}
	})
	t.Run("literal_owner_conjunction_before_limit_and_cursor", func(t *testing.T) {
		reset()
		expect("owner="+url.QueryEscape(" Team A ")+"&execution=code&impact=high&risk=critical&limit=1", agent)
		expect("owner=Team+A&execution=shell")
		expect("owner=&execution=unknown", other)
		// First row fails this predicate. A match beyond it must still be returned
		// with n=1, which rules out post-filtering an already limited first page.
		expect("execution=unknown&limit=1", other)
		items, cursor := page("execution=shell_or_code&limit=1")
		if len(items) != 1 || items[0].ID != agent {
			t.Fatal("positive classifier first page refused")
		}
		// Give the second real agent an independent observed shell fact to produce
		// a genuine second page without forging a cursor.
		setFacts(other, map[string]any{}, map[string]any{"posture": map[string]any{"shell_execution": true}})
		_, cursor = page("execution=shell&limit=1")
		if cursor == "" {
			t.Fatal("actual filtered n+1 cursor absent")
		}
		expect("execution=shell&limit=1&cursor="+url.QueryEscape(cursor), other)
		if call("execution=code&limit=1&cursor="+url.QueryEscape(cursor)).Code == http.StatusOK {
			t.Fatal("cursor crossed filter binding")
		}
		setFacts(other, map[string]any{}, map[string]any{})
	})
	t.Run("winning_source_role_reference_and_cross_namespace_subject", func(t *testing.T) {
		reset()
		defer reset()
		expect("execution=code", agent)
		// Subject is in namespace subject, RoleBinding targets namespace target.
		// That legitimate cross-namespace SA grant must remain positive.
		exec(`UPDATE public.zasp_inventory_relationships SET integration_id=$4,snapshot_id=$5 WHERE (organization_id,workspace_id,environment_id,kind)=($1,$2,$3,'uses_identity')`, o, w, e, losingIntegration, losingSnapshot)
		expect("execution=code")
		reset()
		exec(`UPDATE public.zasp_inventory_relationships SET integration_id=$4,snapshot_id=$5 WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND kind IN('assigned_to','binds')`, o, w, e, losingIntegration, losingSnapshot)
		expect("execution=code")
		reset()
		changed := map[string]any{}
		for k, v := range agentStable {
			changed[k] = v
		}
		changed["service_account"] = "replacement-sa"
		setFacts(agent, changed, map[string]any{})
		expect("execution=code")
		reset()
		changedBinding := map[string]any{}
		for k, v := range bindingStable {
			changedBinding[k] = v
		}
		changedBinding["role"] = "ClusterRole/replacement-role"
		setFacts(binding, changedBinding, map[string]any{})
		expect("execution=code")
		reset()
		changedBinding["role"] = "Role/agent-role"
		setFacts(binding, changedBinding, map[string]any{})
		expect("execution=code")
		reset()
		exec(`UPDATE public.zasp_inventory_entities SET fresh_until=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, sa)
		expect("execution=code")
	})
	t.Run("same_rule_code_positives_and_unproved_unknown", func(t *testing.T) {
		reset()
		defer reset()
		setFacts(agent, agentStable, map[string]any{})
		for _, r := range []map[string]any{rule("batch", []any{"jobs"}, []any{"create"}), rule("", []any{"pods"}, []any{"create"}), rule("", []any{"pods/exec"}, []any{"create"})} {
			setRules([]any{r})
			expect("execution=code", agent)
		}
		for _, r := range []map[string]any{rule("", []any{"pods/attach"}, []any{"create"}), rule("", []any{"pods"}, []any{"delete"})} {
			setRules([]any{r})
			expect("execution=code")
			expect("execution=unknown", agent, other)
		}
		setRules([]any{rule("batch", []any{"pods/exec"}, []any{"create"}), rule("", []any{"jobs"}, []any{"create"})})
		expect("execution=code")
	})
	t.Run("fresh_high_impact_and_malformed_source_rules", func(t *testing.T) {
		reset()
		defer reset()
		expect("impact=high", agent)
		setFacts(agent, agentStable, map[string]any{})
		setRules([]any{rule("", []any{"pods/attach"}, []any{"create"})})
		expect("impact=high")
		setRules([]any{rule("batch", []any{"jobs"}, []any{"create"})})
		expect("impact=high", agent)
		setRules([]any{rule("", []any{"pods/exec", 7}, []any{"create"})})
		expect("execution=code")
		expect("impact=high")
		// A populated allow-looking rule array with a non-string member remains
		// unproved rather than partially granting its valid-looking fields.
		bad := rule("", []any{"pods/exec"}, []any{"create"})
		bad["resource_names"] = []any{false}
		setRules([]any{bad})
		expect("execution=code")
		reset()
		exec(`UPDATE public.zasp_inventory_source_observations SET fresh_until=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,entity_id)=($1,$2,$3,$4)`, o, w, e, agent)
		expect("impact=high")
		expect("execution=shell")
	})
	t.Run("private_classifier_own_body_acl_and_catalog_drift", func(t *testing.T) {
		for _, mutation := range []string{
			`ALTER FUNCTION zasp_agent_exposure_filter_v1.classify(text,text,text,text,text) SET search_path=pg_catalog`,
			`GRANT EXECUTE ON FUNCTION zasp_agent_exposure_filter_v1.classify(text,text,text,text,text) TO zasp_discovery_api`,
			`CREATE TYPE zasp_agent_exposure_filter_v1.unexpected_type AS ENUM ('extra')`,
			`CREATE OR REPLACE FUNCTION zasp_agent_exposure_filter_v1.classify(o text,w text,e text,agent text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$ BEGIN RETURN '{}'::jsonb; END $body$`,
		} {
			tx, err := f.owner.Begin(ctx)
			if err != nil {
				t.Fatal("owned drift transaction refused")
			}
			if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("owned drift frame refused")
			}
			if _, err = tx.Exec(ctx, mutation); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("controlled own catalog mutation refused")
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT zasp_agent_exposure_filter_v1.catalog_ready($1)`, pin).Scan(&ready); err != nil || ready {
				_ = tx.Rollback(ctx)
				t.Fatal("own catalog accepted body ACL or extra type drift")
			}
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal("owned drift rollback unconfirmed")
			}
		}
		expect("execution=shell", agent)
	})
	t.Run("complete_target_drift_bound_and_live_revocation", func(t *testing.T) {
		g := capture("risk=critical")
		exec(`UPDATE public.zasp_risk_findings SET version=version+1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, findings[0])
		if _, err := inventory.ListAgentExposurePage(g, i.Scope, json.RawMessage(`{"risk":"critical"}`), "", 10); err == nil {
			t.Fatal("unchecked changed finding version survived exact live target closure")
		}
		exec(`UPDATE public.zasp_risk_findings SET version=version-1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, findings[0])
		g = capture("risk=critical")
		exec(`INSERT INTO public.zasp_risk_findings(organization_id,workspace_id,environment_id,id,agent_id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,$5,'posture','exposure-new','Controlled new candidate','high','open')`, o, w, e, automaticSourceID(182000), agent)
		if _, err := inventory.ListAgentExposurePage(g, i.Scope, json.RawMessage(`{"risk":"critical"}`), "", 10); err == nil {
			t.Fatal("new unchecked related finding survived captured grant")
		}
		exec(`DELETE FROM public.zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, automaticSourceID(182000))
		f.reconcile()
		// Combined candidates include agents as well as findings. No truncated first
		// 10k may be authorized and treated as the complete collection.
		// Four original unresolved +9,996 new findings reach exactly10,000; adding
		// the two real agent targets exceeds the combined bound without exceeding
		// the resolver's individual finding bound first.
		exec(`INSERT INTO public.zasp_risk_findings(organization_id,workspace_id,environment_id,id,agent_id,source,rule,title,severity,status) SELECT $1,$2,$3,format('pid_af%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),$4,'posture','exposure-bound','Controlled bound candidate','low','open' FROM generate_series(1,9996) item`, o, w, e, agent)
		if call("risk=low").Code == http.StatusOK {
			t.Fatal("oversized complete target union was truncated")
		}
		exec(`DELETE FROM public.zasp_risk_findings WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND rule='exposure-bound'`, o, w, e)
		f.reconcile()
		g = capture("execution=shell")
		exec(`UPDATE public.zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, i.PrincipalID.String(), o)
		if _, err := inventory.ListAgentExposurePage(g, i.Scope, json.RawMessage(`{"execution":"shell"}`), "", 10); err == nil {
			t.Fatal("captured exposure grant survived actual live revocation")
		}
		if call("execution=shell").Code == http.StatusOK {
			t.Fatal("mounted exposure request survived membership revocation")
		}
	})
}
