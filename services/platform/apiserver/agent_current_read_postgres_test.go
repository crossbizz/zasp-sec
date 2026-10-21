package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func TestAgentCurrentReadNormalMountedPostgres(t *testing.T) { runAgentCurrentReadMounted(t, false) }
func TestAgentCurrentReadAuditMountedPostgres(t *testing.T)  { runAgentCurrentReadMounted(t, true) }

// Each head owns one genuine PostgreSQL/OpenFGA fixture. No provider/native
// success may be inferred from these unexecuted sources or controlled archives.
func runAgentCurrentReadMounted(t *testing.T, audit bool) {
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
	pin := migrations.AgentReadProfileChecksum()
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: f.owner})
	if err != nil {
		t.Fatal("native profile runner refused")
	}
	install := runner.UpProductionAgentReadProfile
	if audit {
		pin = migrations.AgentReadAuditProfileChecksum()
		install = runner.UpProductionAgentReadAuditProfile
	}
	if err = install(ctx); err != nil {
		t.Fatal("native selected agent read installer refused")
	}
	seedAgentReadNativeInventory(t, ctx, f.bootstrap, i)
	seedAgentReadNativeCapabilityGraph(t, ctx, f.bootstrap, i)
	agent := mustProductID(t, "pid_81000001-0000-4000-8000-000000000001")
	otherAgent := mustProductID(t, "pid_81000002-0000-4000-8000-000000000002")
	// Prepare only the original six purpose logins; register through the actual
	// original source LOGIN under its legitimate existing authority membership.
	names := []string{"agentread_coordinator", "agentread_archive", "agentread_index", "agentread_correlation", "agentread_projection", "agentread_gateway"}
	authorities := []string{"zasp_runtime_coordinator", "zasp_runtime_archive_worker", "zasp_runtime_index_worker", "zasp_runtime_correlation_worker", "zasp_runtime_projection_worker", "zasp_gateway_control"}
	createdRuntimeNames := []string{}
	// Registered before the coordinator Close cleanup: LIFO closes the connection,
	// then removes only these new owned roles/bindings before the shared fixture
	// verifies its exact original membership snapshot. No original grant is changed.
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for index, name := range createdRuntimeNames {
			if _, err := f.bootstrap.Exec(cleanupContext, `DELETE FROM public.zasp_runtime_principal_bindings WHERE principal_name=$1 AND authority_role=$2`, name, authorities[index]); err != nil {
				t.Error("owned new runtime binding cleanup refused")
				continue
			}
			if _, err := f.bootstrap.Exec(cleanupContext, `REVOKE `+pgx.Identifier{authorities[index]}.Sanitize()+` FROM `+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Error("owned new runtime membership cleanup refused")
				continue
			}
			if _, err := f.bootstrap.Exec(cleanupContext, `DROP ROLE `+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Error("owned newly created runtime role cleanup refused")
			}
		}
	})
	for _, name := range names {
		if _, err = f.bootstrap.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal("owned runtime principal preparation refused")
		}
		createdRuntimeNames = append(createdRuntimeNames, name)
	}
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal("runtime registration transaction refused")
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		t.Fatal("original runtime registration frame refused")
	}
	var registered bool
	if err = tx.QueryRow(ctx, `SELECT public.zasp_runtime_register_principals(session_user,$1,$2,$3,$4,$5,$6)`, names[0], names[1], names[2], names[3], names[4], names[5]).Scan(&registered); err != nil || !registered {
		_ = tx.Rollback(ctx)
		t.Fatal("actual runtime registration refused")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("runtime registration commit unconfirmed")
	}
	coordinator := connectRuntimeDataPlanePrincipal(t, ctx, f.configDSN, names[0])
	t.Cleanup(func() { _ = coordinator.Close(context.Background()) })
	pipeline, err := runtimeevent.NewPostgresCurrentRuntimePipelineRepository(workerRuntimeProjectionDatabase{coordinator}, runtimeevent.ProductionPipelineAuthorityCoordinator)
	if err != nil {
		t.Fatal("actual current projection repository refused")
	}
	sessions := []string{automaticSourceID(122001), automaticSourceID(122002), automaticSourceID(122003)}
	project := func(scope domain.Scope, agent string, sequence int, selected []string) {
		t.Helper()
		args, projected := seedAgentReadNativeProjection(t, ctx, f.bootstrap, scope, agent, false, false, sequence, selected)
		var input, resultDigest [32]byte
		copy(input[:], args[8].([]byte))
		copy(resultDigest[:], args[14].([]byte))
		request := runtimeevent.StageFinishRequest{Lease: runtimeevent.StageLease{Scope: scope, BatchID: mustProductID(t, args[3].(string)), Generation: 1, Stage: runtimeevent.RuntimeStageComplete, Attempt: 1, ImplementationVersion: "runtime-complete-v1", InputDigest: input, InputReference: fmt.Sprintf("s3://zasp-evidence/runtime/projection-%d/projected.json", sequence), InputVersionID: "projected-v1", LeaseExpiresAt: time.Now().Add(time.Hour)}, WorkerID: "session-worker", LeaseToken: "session-lease-token-0001", Outcome: runtimeevent.StageOutcomeSucceeded, EffectDigest: projected.ContentDigest, ResultReference: args[12].(string), ResultVersionID: args[13].(string), ResultDigest: resultDigest, ProjectionReceipt: string(args[17].([]byte))}
		result, finishErr := pipeline.FinishStage(ctx, request)
		if finishErr != nil || result.State != runtimeevent.StageOutcomeSucceeded {
			t.Fatal("actual current source40 completion refused")
		}
	}
	project(i.Scope, agent.String(), 123010, sessions[:2])
	project(i.Scope, otherAgent.String(), 123020, []string{sessions[0], sessions[2]})
	// No session summary/event INSERTs: all visible associations and unattributed
	// rows above must be materialized by the original completion/projection path.
	f.reconcile()
	inventory, err := NewPostgresInventoryRepository(f.db)
	if err != nil {
		t.Fatal("native inventory repository refused")
	}
	if err = inventory.RequireAgentReadProfile(pin); err != nil {
		t.Fatal("native current agent mount refused")
	}
	h, err := newInventoryHTTPHandler(inventory, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal("native inventory handler refused")
	}
	var operations []Operation
	for _, name := range []string{"listAgents", "getAgent", "getAgentCapabilities", "getAgentRelationships", "listAgentSessions"} {
		policy, lookupErr := authorization.LookupOperation(name)
		if lookupErr != nil {
			t.Fatal("native operation absent")
		}
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: name, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, Handler: h})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal("native drawer router refused")
	}
	router.(*operationRouter).authorizer = f.authorizer
	call := func(identity RequestIdentity, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		c := context.WithValue(ctx, identityContextKey{}, identity)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req.WithContext(c))
		return res
	}
	grant := func(operation, parent string) context.Context {
		t.Helper()
		g, e := f.authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": parent}})
		if e != nil {
			t.Fatal("actual current agent authorization refused")
		}
		return context.WithValue(ctx, requestAuthorizationContextKey{}, g)
	}
	t.Run("normal_selected_catalog_and_restricted_installer", func(t *testing.T) {
		if err := install(ctx); err != nil {
			t.Fatal("actual selected installer replay refused")
		}
		var own bool
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal("catalog transaction refused")
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			t.Fatal("catalog frame refused")
		}
		if err = tx.QueryRow(ctx, `SELECT zasp_agent_read_v1.catalog_ready($1)`, pin).Scan(&own); err != nil || !own {
			t.Fatal("selected actual catalog unavailable")
		}
	})
	t.Run("mounted_five_request_current_drawer", func(t *testing.T) {
		// Traverse the actual mounted HMAC pages, rather than accepting HTTP200 with
		// empty capability/relationship fixtures as equivalence evidence.
		var capabilities []Capability
		cursor := ""
		for pageNumber := 0; pageNumber < 4; pageNumber++ {
			path := "/api/v1/agents/" + agent.String() + "/capabilities?limit=2"
			if cursor != "" {
				path += "&cursor=" + url.QueryEscape(cursor)
			}
			response := call(i, path)
			var page struct {
				Items    []Capability `json:"items"`
				PageInfo struct {
					NextCursor string `json:"next_cursor"`
				} `json:"page_info"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) == 0 {
				t.Fatal("actual nonempty current capability page unavailable")
			}
			capabilities = append(capabilities, page.Items...)
			cursor = page.PageInfo.NextCursor
			if cursor == "" {
				break
			}
		}
		if cursor != "" || len(capabilities) != 6 {
			t.Fatal("actual bounded capability traversal lost canonical six edges")
		}
		wantCategories := []string{"identity_assume", "action_execute", "administration", "data_read", "data_write", "network_egress"}
		priorKey := ""
		for index, c := range capabilities {
			key := c.TargetID + "~" + c.Category + "~" + c.Outcome
			if c.AgentID != agent.String() || c.Category != wantCategories[index] || !c.Reachable || len(c.EvidenceIDs) < 2 || (priorKey != "" && key <= priorKey) {
				t.Fatal("current capability identity evidence reachability or ordering changed")
			}
			priorKey = key
			if index == 0 {
				if c.State != "blocked" || !slices.Contains(c.EvidenceIDs, "pid_87000002-0000-4000-8000-000000000002") {
					t.Fatal("blocked reachable capability precedence/evidence changed")
				}
			} else if c.State != "observed" {
				t.Fatal("unobserved provider state invented")
			}
			for j := 1; j < len(c.EvidenceIDs); j++ {
				if c.EvidenceIDs[j] <= c.EvidenceIDs[j-1] {
					t.Fatal("capability evidence order/dedup changed")
				}
			}
		}
		relationshipResponse := call(i, "/api/v1/agents/"+agent.String()+"/relationships?limit=1")
		var relationships struct {
			Items []Relationship `json:"items"`
		}
		if relationshipResponse.Code != http.StatusOK || json.Unmarshal(relationshipResponse.Body.Bytes(), &relationships) != nil || len(relationships.Items) != 1 {
			t.Fatal("actual nonempty current relationship page unavailable")
		}
		relation := relationships.Items[0]
		if relation.ID != "pid_86000001-0000-4000-8000-000000000001" || relation.FromID != agent.String() || relation.ToID != "pid_84000001-0000-4000-8000-000000000001" || relation.Type != "uses_identity" || relation.EvidenceID != "pid_91000001-0000-4000-8000-000000000001" {
			t.Fatal("current relationship target/type/source evidence changed")
		}

		for _, path := range []string{"/api/v1/agents?limit=1", "/api/v1/agents/" + agent.String(), "/api/v1/agents/" + agent.String() + "/capabilities?limit=1", "/api/v1/agents/" + agent.String() + "/relationships?limit=1", "/api/v1/agents/" + agent.String() + "/sessions?limit=1"} {
			if call(i, path).Code != http.StatusOK {
				t.Fatal("actual current mounted drawer read refused")
			}
		}
		detail, err := inventory.GetInventory(grant("getAgent", agent.String()), i.Scope, agent, InventoryKindAgent)
		if err != nil || detail.Summary.ID != agent.String() || len(detail.Sources) != 1 || len(detail.Evidence) != 1 {
			t.Fatal("actual detail source/evidence changed")
		}
	})
	t.Run("real_projection_sessions_second_page_and_mixed_agent", func(t *testing.T) {
		first, err := inventory.ListAgentSessionsPage(grant("listAgentSessions", agent.String()), i.Scope, agent, "", 1)
		if err != nil || len(first.Items) != 1 || first.NextKey == "" {
			t.Fatal("actual n plus one first page absent")
		}
		second, err := inventory.ListAgentSessionsPage(grant("listAgentSessions", agent.String()), i.Scope, agent, first.NextKey, 1)
		if err != nil || len(second.Items) != 1 || second.NextKey != "" || first.Items[0].ID == second.Items[0].ID {
			t.Fatal("actual second sessions page absent")
		}
		got := []string{first.Items[0].ID, second.Items[0].ID}
		slices.Sort(got)
		want := append([]string(nil), sessions[:2]...)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatal("unattributed/other agent association escaped scope")
		}
		mixed, err := inventory.ListAgentSessionsPage(grant("listAgentSessions", otherAgent.String()), i.Scope, otherAgent, "", 100)
		if err != nil || len(mixed.Items) != 2 {
			t.Fatal("mixed session association unavailable")
		}
	})
	t.Run("exact_operation_parent_scope_and_expiry_refusal", func(t *testing.T) {
		wrong := grant("getAgent", agent.String())
		if _, err := inventory.ListAgentSessionsPage(wrong, i.Scope, agent, "", 1); err == nil {
			t.Fatal("borrowed operation admitted sessions")
		}
		if _, err := inventory.GetInventory(wrong, i.Scope, otherAgent, InventoryKindAgent); err == nil {
			t.Fatal("borrowed parent admitted sibling")
		}
		var originalAuthentication, originalExpiry time.Time
		if err := f.bootstrap.QueryRow(ctx, `SELECT authenticated_at,expires_at FROM public.zasp_product_sessions WHERE session_id='session-hierarchy80'`).Scan(&originalAuthentication, &originalExpiry); err != nil {
			t.Fatal("owned session boundary unavailable")
		}
		if _, err := f.bootstrap.Exec(ctx, `UPDATE public.zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE session_id='session-hierarchy80'`); err != nil {
			t.Fatal("owned session expiration refused")
		}
		defer func() {
			if _, err := f.bootstrap.Exec(ctx, `UPDATE public.zasp_product_sessions SET authenticated_at=$1,expires_at=$2 WHERE session_id='session-hierarchy80'`, originalAuthentication, originalExpiry); err != nil {
				t.Error("owned session boundary restoration refused")
			}
			f.reconcile()
		}()
		if call(i, "/api/v1/agents/"+agent.String()).Code == http.StatusOK {
			t.Fatal("expired stored identity admitted drawer")
		}
		foreign := i
		foreign.Scope, _ = domain.NewScope(i.Scope.OrganizationID(), mustProductID(t, "pid_78000009-0000-4000-8000-000000000009"), mustProductID(t, "pid_78000007-0000-4000-8000-000000000007"))
		if call(foreign, "/api/v1/agents/"+agent.String()).Code == http.StatusOK {
			t.Fatal("sibling scope disclosed agent")
		}
	})
	t.Run("cursor_stays_bound_to_current_parent_and_operation", func(t *testing.T) {
		res := call(i, "/api/v1/agents/"+agent.String()+"/sessions?limit=1")
		var page struct {
			PageInfo struct {
				NextCursor string `json:"next_cursor"`
			} `json:"page_info"`
		}
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &page) != nil || page.PageInfo.NextCursor == "" {
			t.Fatal("actual session cursor unavailable")
		}
		q := "?limit=1&cursor=" + url.QueryEscape(page.PageInfo.NextCursor)
		for _, path := range []string{"/api/v1/agents/" + otherAgent.String() + "/sessions" + q, "/api/v1/agents/" + agent.String() + "/relationships" + q} {
			if call(i, path).Code == http.StatusOK {
				t.Fatal("cursor crossed current parent/operation")
			}
		}
	})
	t.Run("catalog_body_acl_and_projection_drift_refused", func(t *testing.T) {
		var definition string
		if err := f.bootstrap.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_agent_read_v1.sessions(text,text,text,text,text,integer,text)'::regprocedure)`).Scan(&definition); err != nil || strings.Count(definition, "agent read target refused") != 1 {
			t.Fatal("own fixed function body source unavailable")
		}
		changedBody := strings.Replace(definition, "agent read target refused", "agent read target refusal changed", 1)
		for _, mutation := range []string{changedBody, `GRANT EXECUTE ON FUNCTION zasp_agent_read_v1.fingerprint() TO zasp_discovery_api`, `ALTER FUNCTION zasp_agent_read_v1.sessions(text,text,text,text,text,integer,text) RESET ALL`, `CREATE TYPE zasp_agent_read_v1.unexpected AS ENUM('closed')`, `ALTER TABLE public.zasp_runtime_session_events DISABLE TRIGGER zasp_runtime_session_summary_projection`, `GRANT SELECT ON public.zasp_runtime_session_summaries TO zasp_discovery_api`} {
			tx, err := f.bootstrap.Begin(ctx)
			if err != nil {
				t.Fatal("owned drift transaction refused")
			}
			if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("owned catalog authority frame refused")
			}
			if _, err = tx.Exec(ctx, mutation); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("owned catalog drift setup refused")
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT zasp_agent_read_v1.catalog_ready($1)`, pin).Scan(&ready); err != nil || ready {
				_ = tx.Rollback(ctx)
				t.Fatal("catalog accepted changed body ACL or projection")
			}
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal("owned drift rollback unconfirmed")
			}
		}
	})
	t.Run("current_membership_revocation_denies_all_drawer_reads", func(t *testing.T) {
		old := grant("getAgent", agent.String())
		if _, err = f.bootstrap.Exec(ctx, `UPDATE public.zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, i.PrincipalID.String(), i.Scope.OrganizationID().String()); err != nil {
			t.Fatal("owned revocation refused")
		}
		if _, err = inventory.GetInventory(old, i.Scope, agent, InventoryKindAgent); err == nil {
			t.Fatal("stale captured proof survived current revocation")
		}
		for _, path := range []string{"/api/v1/agents/" + agent.String(), "/api/v1/agents/" + agent.String() + "/capabilities", "/api/v1/agents/" + agent.String() + "/relationships", "/api/v1/agents/" + agent.String() + "/sessions"} {
			if call(i, path).Code == http.StatusOK {
				t.Fatal("revoked principal retained drawer read")
			}
		}
	})
}

// Controlled persisted source/evidence rows follow the existing typed inventory
// fixture. They are not an assertion of real provider discovery or deployment.
func seedAgentReadNativeInventory(t *testing.T, ctx context.Context, connection *pgx.Conn, identity RequestIdentity) {
	t.Helper()
	scope := identity.Scope
	observed := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	seedAuthority := func(sequence int) {
		integrationID := fmt.Sprintf("pid_76%06x-0000-4000-8000-%012x", sequence, sequence)
		syncID := fmt.Sprintf("pid_77%06x-0000-4000-8000-%012x", sequence, sequence)
		snapshotID := fmt.Sprintf("pid_78%06x-0000-4000-8000-%012x", sequence, sequence)
		if _, err := connection.Exec(ctx, `INSERT INTO public.zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,state) VALUES($1,$2,$3,$4,'kubernetes','1.0.0','Controlled agent source','active')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID); err != nil {
			t.Fatal("controlled source fixture refused")
		}

		requestDigest := sha256.Sum256([]byte(fmt.Sprintf("typed-inventory-page-%d", sequence)))
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,$6,$7,'manual',$8,'parser_v1','tool_v1')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), syncID, integrationID, fmt.Sprintf("typed-inventory-page-%04d", sequence), requestDigest[:], identity.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'kubernetes',$7,$8,'complete',$8,'{}'::jsonb,true,true,$9,$9)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), snapshotID, integrationID, syncID, fmt.Sprintf("s3://zasp-evidence/typed/manifest-%d.json", sequence), bytes32(byte(sequence)), observed); err != nil {
			t.Fatalf("snapshot %d: %v", sequence, err)
		}
	}
	seedAuthority(1)
	organizationID := scope.OrganizationID().String()
	workspaceID := scope.WorkspaceID().String()
	environmentID := scope.EnvironmentID().String()
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_entities(
 organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,
 product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,
 winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection)
SELECT $1,$2,$3,
 format('pid_81%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 'agent',format('Agent %s',lpad(item::text,4,'0')),'{}'::jsonb,'active',$4,$4,1,
 'agent',9500,format('pid_91%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('pid_78%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),12,'0')),
 1,$4,$5,1,
 format('pid_76%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),12,'0')),
 'kubernetes','kubernetes',format('agent-%s',lpad(item::text,4,'0')),1,1
FROM generate_series(1,2) item`, organizationID, workspaceID, environmentID, observed, observed.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_evidence(
 organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,
 source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
SELECT $1,$2,$3,
 format('pid_91%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('pid_76%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),12,'0')),
 format('pid_78%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),12,'0')),
 format('pid_81%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('s3://zasp-evidence/typed/pages/%s.json',lpad(item::text,4,'0')),digest(convert_to(item::text,'UTF8'),'sha256'),
 'application/json','raw_v1','parser_v1',$4,'kubernetes',1,'pid_79999999-0000-4000-8000-000000000999',
 format('typed/pages/%s.json',lpad(item::text,4,'0')),format('version-%s',lpad(item::text,4,'0')),128,'tool_v1'
FROM generate_series(1,2) item`, organizationID, workspaceID, environmentID, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_source_observations(
 organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,
 provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,
 identity_rule_version,identity_priority,source_projection_version)
SELECT $1,$2,$3,
 format('pid_76%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),12,'0')),
 'kubernetes',format('pid_81%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('agent-%s',lpad(item::text,4,'0')),
 format('pid_78%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=2 THEN 1 ELSE 2 END),12,'0')),
 'present','{}'::jsonb,$4,$4,'kubernetes','kubernetes_agent',format('Agent %s',lpad(item::text,4,'0')),'{}'::jsonb,'kubernetes_agent','agent',1,
 digest(convert_to(format('typed-agent-%s',item),'UTF8'),'sha256'),
 format('pid_91%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 9500,$4,$5,1,80,1
FROM generate_series(1,2) item`, organizationID, workspaceID, environmentID, observed, observed.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'expanded',NULL,NULL)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'backfilled',NULL,NULL)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	digest := bytes32(99)
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'equivalent',$4,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), digest); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'cutover',$4,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), digest); err != nil {
		t.Fatal(err)
	}
}

// Controlled canonical typed14 identity/binding/role/evidence graph follows the
// existing native fixture exactly; no fabricated classifier or provider assertion.
func seedAgentReadNativeCapabilityGraph(t *testing.T, ctx context.Context, connection *pgx.Conn, identity RequestIdentity) {
	t.Helper()
	organizationID, workspaceID, environmentID := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	agentID := "pid_81000001-0000-4000-8000-000000000001"
	observed := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	const (
		serviceAccountID = "pid_84000001-0000-4000-8000-000000000001"
		bindingID        = "pid_84000002-0000-4000-8000-000000000002"
		roleID           = "pid_84000003-0000-4000-8000-000000000003"
		integrationID    = "pid_76000001-0000-4000-8000-000000000001"
		snapshotID       = "pid_78000001-0000-4000-8000-000000000001"
	)
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_entities(
 organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,
 product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,
 winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection)
VALUES
 ($1,$2,$3,$4,'identity','agent-service-account','{}','active',$10,$10,1,'identity',9500,$7,$9,1,$10,$11,1,$8,'kubernetes','kubernetes','default/agent',1,1),
 ($1,$2,$3,$5,'asset','agent-role-binding','{}','active',$10,$10,1,'asset',9500,$12,$9,1,$10,$11,1,$8,'kubernetes','kubernetes','default/agent-binding',1,1),
 ($1,$2,$3,$6,'asset','agent-role','{}','active',$10,$10,1,'asset',9500,$13,$9,1,$10,$11,1,$8,'kubernetes','kubernetes','agent-role',1,1)`,
		organizationID, workspaceID, environmentID, serviceAccountID, bindingID, roleID,
		"pid_85000001-0000-4000-8000-000000000001", integrationID, snapshotID, observed, observed.Add(15*time.Minute),
		"pid_85000002-0000-4000-8000-000000000002", "pid_85000003-0000-4000-8000-000000000003"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_evidence(
 organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,
 source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
SELECT $1,$2,$3,item.evidence_id,$4,$5,item.entity_id,'s3://zasp-evidence/typed/capabilities/'||item.ordinal||'.json',digest(convert_to(item.ordinal,'UTF8'),'sha256'),
 'application/json','raw_v1','parser_v1',$6,'kubernetes',1,'pid_79999999-0000-4000-8000-000000000999','typed/capabilities/'||item.ordinal||'.json','version-'||item.ordinal,128,'tool_v1'
FROM (VALUES
 ('1',$7,$10),('2',$8,$11),('3',$9,$12)
) item(ordinal,entity_id,evidence_id)`, organizationID, workspaceID, environmentID, integrationID, snapshotID, observed,
		serviceAccountID, bindingID, roleID,
		"pid_85000001-0000-4000-8000-000000000001", "pid_85000002-0000-4000-8000-000000000002", "pid_85000003-0000-4000-8000-000000000003"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_source_observations(
 organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,
 provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,
 identity_rule_version,identity_priority,source_projection_version)
VALUES
 ($1,$2,$3,$4,'kubernetes',$6,'default/agent',$5,'present','{}',$12,$12,'kubernetes','kubernetes_service_account','agent-service-account','{}','kubernetes_service_account','identity',1,digest(convert_to('service-account','UTF8'),'sha256'),$9,9500,$12,$13,1,80,1),
 ($1,$2,$3,$4,'kubernetes',$7,'default/agent-binding',$5,'present','{}',$12,$12,'kubernetes','kubernetes_role_binding','agent-role-binding','{}','kubernetes_role_binding','asset',1,digest(convert_to('binding','UTF8'),'sha256'),$10,9500,$12,$13,1,80,1),
 ($1,$2,$3,$4,'kubernetes',$8,'agent-role',$5,'present',jsonb_build_object('namespaced',false,'rules',jsonb_build_array(jsonb_build_object('api_groups',jsonb_build_array(''),'non_resource_urls',jsonb_build_array('/metrics'),'resource_names','[]'::jsonb,'resources',jsonb_build_array('pods','pods/exec','services/proxy'),'verbs',jsonb_build_array('bind','create','get','impersonate','patch')))),$12,$12,'kubernetes','kubernetes_cluster_role','agent-role','{}','kubernetes_cluster_role','asset',1,digest(convert_to('role','UTF8'),'sha256'),$11,9500,$12,$13,1,80,1)`,
		organizationID, workspaceID, environmentID, integrationID, snapshotID, serviceAccountID, bindingID, roleID,
		"pid_85000001-0000-4000-8000-000000000001", "pid_85000002-0000-4000-8000-000000000002", "pid_85000003-0000-4000-8000-000000000003", observed, observed.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,state,attributes,first_seen_at,last_seen_at)
VALUES
 ($1,$2,$3,'pid_86000001-0000-4000-8000-000000000001',$4,'kubernetes',$5,$6,$7,'uses_identity','agent:uses_identity:service-account','present','{}',$10,$10),
 ($1,$2,$3,'pid_86000002-0000-4000-8000-000000000002',$4,'kubernetes',$5,$7,$8,'assigned_to','service-account:assigned_to:binding','present','{}',$10,$10),
 ($1,$2,$3,'pid_86000003-0000-4000-8000-000000000003',$4,'kubernetes',$5,$8,$9,'binds','binding:binds:role','present','{}',$10,$10)`,
		organizationID, workspaceID, environmentID, integrationID, snapshotID, agentID, serviceAccountID, bindingID, roleID, observed); err != nil {
		t.Fatal(err)
	}
	// Real released capability-evidence operation stores a controlled verified and
	// blocked observation of the same reachable edge; blocked precedence is read,
	// never interpreted as removal or actual provider enforcement proof.
	for _, proof := range []struct{ kind, id string }{{"attack_lab", "pid_87000001-0000-4000-8000-000000000001"}, {"runtime_policy", "pid_87000002-0000-4000-8000-000000000002"}} {
		var raw json.RawMessage
		if err := connection.QueryRow(ctx, `SELECT public.zasp_inventory_record_capability_evidence($1,$2,$3,$4,$5,'identity_assume','assume',$6,$7,$8)`, organizationID, workspaceID, environmentID, agentID, serviceAccountID, proof.kind, proof.id, observed).Scan(&raw); err != nil {
			t.Fatal("controlled typed14 capability observation refused")
		}
	}
}

func seedAgentReadNativeProjection(t *testing.T, ctx context.Context, connection *pgx.Conn, scope domain.Scope, agent string, sandbox, precise bool, identityBase int, sessions []string) ([]any, runtimeprojection.ProjectedBatch) {
	t.Helper()
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	batchID := mustProductID(t, "pid_96000001-0000-4000-8000-000000000001")
	sensorID, tokenID := "pid_96000002-0000-4000-8000-000000000002", "pid_96000003-0000-4000-8000-000000000003"
	tokenHash := bytes.Repeat([]byte{0x96}, 32)
	eventPrefix := ""
	archiveReference, artifactKey := "s3://zasp-evidence/runtime/sessions.json", "runtime/session-projection-fixture.json"
	correlationReference, projectedReference, completionReference := "s3://zasp-evidence/correlation.json", "s3://zasp-evidence/projected.json", "s3://zasp-evidence/completed.json"
	if identityBase != 0 {
		batchID = mustProductID(t, automaticSourceID(identityBase))
		sensorID, tokenID = automaticSourceID(identityBase+1), automaticSourceID(identityBase+2)
		uniqueToken := sha256.Sum256([]byte(tokenID))
		tokenHash = uniqueToken[:]
		eventPrefix = fmt.Sprintf("projection-%d-", identityBase)
		artifactKey = fmt.Sprintf("runtime/projection-%d/sessions.json", identityBase)
		archiveReference = "s3://zasp-evidence/" + artifactKey
		correlationReference = fmt.Sprintf("s3://zasp-evidence/runtime/projection-%d/correlation.json", identityBase)
		projectedReference = fmt.Sprintf("s3://zasp-evidence/runtime/projection-%d/projected.json", identityBase)
		completionReference = fmt.Sprintf("s3://zasp-evidence/runtime/projection-%d/completed.json", identityBase)
	}
	body := []byte(`{"source":"tetragon","events":[` + strings.Join([]string{
		`{"event_id":"late","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-09-09T10:00:03.000Z","evidence_id":"pid_96000004-0000-4000-8000-000000000004","content":{}}`,
		`{"event_id":"early","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-09-09T10:00:01.000Z","evidence_id":"pid_96000005-0000-4000-8000-000000000005","content":{}}`,
		`{"event_id":"unknown","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-09-09T10:00:02.000Z","evidence_id":"pid_96000006-0000-4000-8000-000000000006","content":{}}`,
	}, ",") + `]}`)
	if eventPrefix != "" {
		body = bytes.ReplaceAll(body, []byte(`"event_id":"`), []byte(`"event_id":"`+eventPrefix))
	}
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, body)
	if err != nil {
		t.Fatal(err)
	}
	if precise {
		var old struct {
			Source string
			Events []sensoradapter.RuntimeEvent
		}
		if err := json.Unmarshal(body, &old); err != nil {
			t.Fatal(err)
		}
		events := make([]sensoradapter.PreciseRuntimeEvent, len(old.Events))
		for i, event := range old.Events {
			events[i] = sensoradapter.PreciseRuntimeEvent{RuntimeEvent: event}
		}
		body, err = json.Marshal(struct {
			Version string                              `json:"version"`
			Source  string                              `json:"source"`
			Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
		}{"runtime-archive-v2", old.Source, events})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtimeevent.DecodePreciseArchivedBatch(scope, body); err != nil {
			t.Fatal(err)
		}
	}
	correlations := make([]runtimecorrelation.Result, len(decoded.Records))
	for index, record := range decoded.Records {
		confidence := domain.EvidenceConfidenceExact
		if record.SourceEventID == eventPrefix+"early" || precise {
			confidence = domain.EvidenceConfidenceStrong
		}
		correlations[index] = runtimecorrelation.Result{EventID: record.ID, SessionID: mustProductID(t, sessions[index%len(sessions)]), AgentID: mustProductID(t, agent), Confidence: confidence}
		if record.SourceEventID == eventPrefix+"unknown" {
			correlations[index] = runtimecorrelation.Result{EventID: record.ID, Confidence: domain.EvidenceConfidenceUnattributed}
		} else if sandbox {
			correlations[index].SandboxID = "session-sandbox"
			correlations[index].SandboxSourceSensorID = mustProductID(t, sandboxSemantic)
		}
	}
	archiveDigest := sha256.Sum256(body)
	projector, projectionVersion, completionVersion := runtimeprojection.Project, "runtime-projection-v1", "runtime-complete-v1"
	if sandbox {
		projector, projectionVersion, completionVersion = runtimeprojection.ProjectSandbox, "runtime-projection-v2", "runtime-complete-v2"
	}
	encode := runtimeprojection.EncodeReceipt
	if precise {
		projector, projectionVersion, completionVersion, encode = runtimeprojection.ProjectPrecise, "runtime-projection-v3", "runtime-complete-v3", runtimeprojection.EncodePreciseReceipt
	}
	projected, err := projector(runtimeprojection.Batch{Scope: scope, BatchID: batchID, Generation: 1, ArchiveReference: archiveReference, ArchiveVersionID: "archive-v1", ArchiveDigest: archiveDigest, Body: body, Correlations: correlations})
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, receiptDigest, _, err := encode(runtimeprojection.Receipt{ImplementationVersion: projectionVersion, Scope: scope, BatchID: batchID, Generation: 1, InputReference: correlationReference, InputVersionID: "correlation-v1", InputDigest: archiveDigest, ArchiveReference: archiveReference, ArchiveVersionID: "archive-v1", ArchiveDigest: archiveDigest, EffectDigest: projected.ContentDigest, Items: projected.Items})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,$4,'Session proof sensor','tetragon')`, []any{org, workspace, environment, sensorID}},
		{`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,decode(repeat('aa',16),'hex'),$6,transaction_timestamp()+interval '1 day')`, []any{org, workspace, environment, tokenID, sensorID, tokenHash}},
		{`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version,state) VALUES($1,$2,$3,$4,$5,'session-projection-fixture',$6,3,$7,100,'application/json','runtime-v1','processing')`, []any{org, workspace, environment, batchID.String(), sensorID, archiveDigest[:], archiveReference}},
		{`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,$4,$5,$6,1,1,'session-projection-fixture',$7,$7,'tetragon','application/json','runtime-v1',100,3,$8,$9,'archive-v1',$7,100,'fixture-kms-reference',transaction_timestamp(),'processing')`, []any{org, workspace, environment, batchID.String(), sensorID, tokenID, archiveDigest[:], artifactKey, archiveReference}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) VALUES($1,$2,$3,$4,1,'project',4,$8,$5,'succeeded',1,$6,$9,'projected-v1',$7,transaction_timestamp())`, []any{org, workspace, environment, batchID.String(), archiveDigest[:], projected.ContentDigest[:], receiptDigest[:], projectionVersion, projectedReference}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,1,'complete',5,$6,$5,$5,'leased',1,'session-worker','session-lease-token-0001',transaction_timestamp()+interval '1 hour')`, []any{org, workspace, environment, batchID.String(), projected.ContentDigest[:], completionVersion}},
	} {
		if _, err := connection.Exec(ctx, query.sql, query.args...); err != nil {
			t.Fatal(fmt.Errorf("session completion fixture: %w", err))
		}
	}
	resultDigest := sha256.Sum256([]byte("completion"))
	return []any{org, workspace, environment, batchID.String(), int64(1), "session-worker", "session-lease-token-0001", 1, projected.ContentDigest[:], completionVersion, "succeeded", projected.ContentDigest[:], completionReference, "completed-v1", resultDigest[:], nil, 0, receiptBytes}, projected
}
