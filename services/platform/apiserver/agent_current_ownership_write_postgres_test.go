package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentCurrentOwnershipWriteNormalPostgres(t *testing.T) {
	runAgentCurrentOwnershipWrite(t, false)
}
func TestAgentCurrentOwnershipWriteAuditPostgres(t *testing.T) {
	runAgentCurrentOwnershipWrite(t, true)
}

// These fixtures use real stored browser/PAT credentials, current OpenFGA,
// PostgreSQL transactions and mounted HTTP handlers. Inventory is controlled
// persisted metadata: no collector, external identity provider, deployed browser
// or provider acceptance is inferred. No service startup or new roles here.
func runAgentCurrentOwnershipWrite(t *testing.T, audit bool) {
	t.Helper()
	if audit {
		t.Setenv("ZASP_P7_AUDIT_TEST", "1")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	} else {
		t.Setenv("ZASP_P7_AUDIT_TEST", "")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "")
	}
	f := newEnvironmentClassNativeFixture(t)
	ctx, identity := f.ctx, f.identity
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	const agent = "pid_81000001-0000-4000-8000-000000000001"
	agentID := mustProductID(t, agent)
	const patID = "pid_99000001-0000-4000-8000-000000000001"
	const patValue = "owned-ownership-pat-credential"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.bootstrap.Exec(ctx, q, args...); err != nil {
			t.Fatal("controlled ownership fixture statement refused")
		}
	}
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: f.owner})
	if err != nil {
		t.Fatal("ownership native runner refused")
	}
	pin := migrations.AgentOwnershipWriteProfileChecksum()
	readPin, ownerPin, exposurePin := migrations.AgentReadProfileChecksum(), migrations.AgentOwnerFilterProfileChecksum(), migrations.AgentExposureFilterProfileChecksum()
	install := runner.UpProductionAgentOwnershipWriteProfile
	readInstall, ownerInstall, exposureInstall := runner.UpProductionAgentReadProfile, runner.UpProductionAgentOwnerFilterProfile, runner.UpProductionAgentExposureFilterProfile
	if audit {
		pin = migrations.AgentOwnershipWriteAuditProfileChecksum()
		readPin, ownerPin, exposurePin = migrations.AgentReadAuditProfileChecksum(), migrations.AgentOwnerFilterAuditProfileChecksum(), migrations.AgentExposureFilterAuditProfileChecksum()
		install = runner.UpProductionAgentOwnershipWriteAuditProfile
		readInstall, ownerInstall, exposureInstall = runner.UpProductionAgentReadAuditProfile, runner.UpProductionAgentOwnerFilterAuditProfile, runner.UpProductionAgentExposureFilterAuditProfile
	}
	for _, up := range []func(context.Context) error{readInstall, ownerInstall, exposureInstall, install} {
		if err = up(ctx); err != nil {
			t.Fatal("selected ownership/read parent recipe refused")
		}
	}
	seedAgentReadNativeInventory(t, ctx, f.bootstrap, identity)
	// The other real seeded agent is ownerless. The canonical scope posture
	// refresh must INSERT its genuine finding and advance79 during the first
	// successful ownership write, without invalidating that same write afterward.
	exec(`INSERT INTO public.zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest($1,'sha256'),$2,'Owned native ownership token',$3,$4,$5,$6,'["view","manage_workflows"]'::jsonb,clock_timestamp()+interval '1 hour')`, patValue, patID, identity.PrincipalID.String(), o, w, e)
	f.reconcile()
	if err = f.repository.RequireAgentOwnershipWriteProfile(pin); err != nil {
		t.Fatal("selected ownership repository profile refused")
	}
	if err = f.repository.RequireAgentReadProfile(readPin); err != nil {
		t.Fatal("selected current read repository refused")
	}
	if err = f.repository.RequireAgentOwnerFilterProfile(ownerPin); err != nil {
		t.Fatal("selected owner repository refused")
	}
	if err = f.repository.RequireAgentExposureFilterProfile(exposurePin); err != nil {
		t.Fatal("selected exposure repository refused")
	}
	inventory, err := NewPostgresInventoryRepository(f.db)
	if err != nil || inventory.RequireAgentOwnershipWriteProfile(pin) != nil || inventory.RequireAgentReadProfile(readPin) != nil {
		t.Fatal("actual current inventory configuration refused")
	}
	// Exact production repository-to-inventory configuration copy; no fake pin.
	inventory.agentOwnerProfileChecksum = f.repository.agentOwnerProfileChecksum
	inventory.agentExposureFilterProfileChecksum = f.repository.agentExposureFilterProfileChecksum
	resolver, err := NewAgentExposureFilterResolver(f.authorizer.Resolver, f.db, exposurePin)
	if err != nil {
		t.Fatal("current exposure resolver composition refused")
	}
	f.authorizer.Resolver = resolver
	handler, err := newInventoryHTTPHandler(inventory, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal("ownership native HTTP handler refused")
	}
	var operations []Operation
	for _, name := range []string{"updateAgent", "getAgent", "listAgents"} {
		policy, err := authorization.LookupOperation(name)
		if err != nil {
			t.Fatal("actual ownership operation contract absent")
		}
		if name == "updateAgent" && (policy.Permission != "manage_workflows" || policy.FreshAuth) {
			t.Fatal("original ownership permission or freshness contract changed")
		}
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: name, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken}, RequireCSRF: name == "updateAgent", Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal("ownership native router refused")
	}
	router.(*operationRouter).authorizer = f.authorizer
	app, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example", MaximumBodyBytes: 65536, Authenticate: f.repository.Authenticate, GenerateCorrelationID: func() string {
		id, _ := newWorkflowProductID()
		return id
	}}, router)
	if err != nil {
		t.Fatal("actual credential middleware refused")
	}
	call := func(method, path, credential, key string, version int64, input AgentOwnershipInput, change func(*http.Request)) *httptest.ResponseRecorder {
		t.Helper()
		var body []byte
		if method == http.MethodPatch {
			body, _ = json.Marshal(input)
		}
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		request.Header.Set("Content-Type", "application/json")
		if credential == "browser" {
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "hierarchy80-session"})
			request.Header.Set("Origin", "https://console.example")
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
		} else {
			request.Header.Set("Authorization", "Bearer "+patValue)
		}
		if method == http.MethodPatch {
			request.Header.Set("If-Match", quoteVersion(version))
			request.Header.Set("Idempotency-Key", key)
		}
		if change != nil {
			change(request)
		}
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request.WithContext(ctx))
		return response
	}
	input := AgentOwnershipInput{Owner: "Team Alpha", Team: "Security", Tags: []string{"managed", "native"}}
	version := func() int64 {
		t.Helper()
		var v int64
		if err := f.bootstrap.QueryRow(ctx, `SELECT annotation_version FROM public.zasp_inventory_entities WHERE(organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, agent).Scan(&v); err != nil {
			t.Fatal("ownership fixture version unavailable")
		}
		return v
	}
	counts := func() [3]int64 {
		t.Helper()
		var n [3]int64
		if err := f.bootstrap.QueryRow(ctx, `SELECT (SELECT count(*) FROM public.zasp_workflow_audit WHERE organization_id=$1 AND operation='updateAgent'),(SELECT count(*) FROM public.zasp_workflow_idempotency WHERE organization_id=$1 AND operation='updateAgent'),(SELECT annotation_version FROM public.zasp_inventory_entities WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4)`, o, w, e, agent).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal("ownership atomic evidence unavailable")
		}
		return n
	}
	decodeACK := func(response *httptest.ResponseRecorder) AgentMutationResult {
		t.Helper()
		var result AgentMutationResult
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Agent.ID != agent || !validProductID(result.AuditID) || response.Header().Get("ETag") != quoteVersion(result.Agent.Version) || response.Header().Get("X-Audit-ID") != result.AuditID {
			t.Fatal("actual canonical ownership acknowledgment unavailable")
		}
		return result
	}
	capture := func(id RequestIdentity, operation string) context.Context {
		t.Helper()
		grant, err := f.authorizer.Authorize(ctx, id, id.credentialBinding, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": agent}})
		if err != nil {
			t.Fatal("actual current ownership Check refused")
		}
		return context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	}
	write := func(c context.Context, repository *PostgresInventoryRepository, id RequestIdentity, v int64, key string, body AgentOwnershipInput) (AgentMutationResult, error) {
		audit, err := newWorkflowProductID()
		if err != nil {
			return AgentMutationResult{}, err
		}
		correlation, err := newWorkflowProductID()
		if err != nil {
			return AgentMutationResult{}, err
		}
		return repository.UpdateAgentOwnership(c, id, agentID, v, key, body, audit, correlation)
	}
	parentCatalog := func() []byte {
		t.Helper()
		var raw []byte
		if err := f.bootstrap.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('signature',p.oid::regprocedure::text,'definition',pg_get_functiondef(p.oid),'owner',p.proowner,'acl',p.proacl::text) ORDER BY p.oid::regprocedure::text) FROM pg_proc p WHERE p.oid IN('public.zasp_inventory_update_agent(text,text,text,text,text,text,bigint,text,text,jsonb,text,text)'::regprocedure,'public.zasp_inventory_security_ready()'::regprocedure,'zasp_authorization79.ready(text)'::regprocedure,'zasp_authorization80.ready(text)'::regprocedure)`).Scan(&raw); err != nil {
			t.Fatal("exact retained parent catalog evidence unavailable")
		}
		return raw
	}
	parentBefore := parentCatalog()
	var first AgentMutationResult
	t.Run("selected_profile_private_acl_and_browser_transport_guards", func(t *testing.T) {
		if err := install(ctx); err != nil {
			t.Fatal("selected installer replay refused")
		}
		before := counts()
		for _, mutate := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }, func(r *http.Request) { r.Header.Set(expectedScopeHeader, "foreign") }} {
			if call(http.MethodPatch, "/api/v1/agents/"+agent, "browser", "ownership-denied-0001", 1, input, mutate).Code < 400 {
				t.Fatal("browser transport guard accepted invalid request")
			}
		}
		var ignored []byte
		api := f.db.driver.(*authorizationConnectionDriver).conn
		if err := api.QueryRow(ctx, `SELECT zasp_agent_ownership_write_v1.require_api($1,$2,$3,$4,$5,$6)`, o, w, e, identity.PrincipalID.String(), agent, pin).Scan(&ignored); err == nil {
			t.Fatal("API directly executed private require_api")
		}
		if err := api.QueryRow(ctx, `SELECT checksum FROM zasp_agent_ownership_write_v1.registration`).Scan(&ignored); err == nil {
			t.Fatal("API read private profile registration")
		}
		if err := api.QueryRow(ctx, postgresAgentOwnershipWriteSQL, o, w, e, identity.PrincipalID.String(), agent, "ownership-unfenced-0001", int64(1), input.Owner, input.Team, json.RawMessage(`["managed","native"]`), automaticSourceID(192001), automaticSourceID(192002), pin).Scan(&ignored); err == nil {
			t.Fatal("API mutation without sealed current proof succeeded")
		}
		if counts() != before {
			t.Fatal("refused requests committed ownership evidence")
		}
	})
	t.Run("browser_patch_atomic_posture_revision_and_fresh_refetch", func(t *testing.T) {
		before := counts()
		first = decodeACK(call(http.MethodPatch, "/api/v1/agents/"+agent, "browser", "ownership-browser-0001", before[2], input, nil))
		after := counts()
		if after != [3]int64{before[0] + 1, before[1] + 1, before[2] + 1} || first.Agent.Owner != input.Owner || first.Agent.Team != input.Team {
			t.Fatal("canonical ownership write was not atomic")
		}
		var pending bool
		if err := f.bootstrap.QueryRow(ctx, `SELECT desired>applied AND EXISTS(SELECT 1 FROM public.zasp_risk_findings WHERE organization_id=$1 AND source='posture') FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&pending); err != nil || !pending {
			t.Fatal("canonical posture INSERT did not retain real pending79 revision")
		}
		// A new read cannot borrow the pre-mutation proof while projection is pending.
		if call(http.MethodGet, "/api/v1/agents/"+agent, "browser", "", 0, input, nil).Code == http.StatusOK {
			t.Fatal("read bypassed self-generated pending authorization projection")
		}
		f.reconcile()
		if call(http.MethodGet, "/api/v1/agents/"+agent, "browser", "", 0, input, nil).Code != http.StatusOK {
			t.Fatal("new proof current GET refetch refused")
		}
		for _, query := range []string{"owner=" + url.QueryEscape(input.Owner), "owner=" + url.QueryEscape(input.Owner) + "&execution=unknown"} {
			r := call(http.MethodGet, "/api/v1/agents?"+query, "browser", "", 0, input, nil)
			var page struct {
				Items []InventorySummary `json:"items"`
			}
			if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != agent || page.Items[0].Owner != input.Owner {
				t.Fatal("real owner/exposure filtered refetch lost committed owner")
			}
		}
	})
	t.Run("same_intent_replay_original_receipt_and_conflicting_intent_cas", func(t *testing.T) {
		before := counts()
		replay := decodeACK(call(http.MethodPatch, "/api/v1/agents/"+agent, "browser", "ownership-browser-0001", 1, input, nil))
		if replay.AuditID != first.AuditID || replay.Agent.Version != first.Agent.Version || counts() != before {
			t.Fatal("same intent replay changed canonical receipt or effect counts")
		}
		var original AgentMutationResult
		var raw []byte
		if err := f.bootstrap.QueryRow(ctx, `SELECT response FROM public.zasp_workflow_idempotency WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND principal_id=$4 AND operation='updateAgent' AND idempotency_key='ownership-browser-0001'`, o, w, e, identity.PrincipalID.String()).Scan(&raw); err != nil || json.Unmarshal(raw, &original) != nil || original.AuditID != first.AuditID || !validProductID(original.CorrelationID) {
			t.Fatal("original immutable audit/correlation response unavailable")
		}
		storedReplay, err := write(capture(identity, "updateAgent"), inventory, identity, 1, "ownership-browser-0001", input)
		if err != nil || !storedReplay.Replayed || storedReplay.AuditID != original.AuditID || storedReplay.CorrelationID != original.CorrelationID || counts() != before {
			t.Fatal("fresh current replay replaced historical audit/correlation IDs")
		}
		changed := input
		changed.Owner = "Conflicting Owner"
		for _, request := range []struct {
			key  string
			v    int64
			body AgentOwnershipInput
		}{{"ownership-browser-0001", 1, changed}, {"ownership-cas-stale-0001", 1, input}} {
			if call(http.MethodPatch, "/api/v1/agents/"+agent, "browser", request.key, request.v, request.body, nil).Code < 400 || counts() != before {
				t.Fatal("conflicting intent or stale CAS committed")
			}
		}
	})
	t.Run("actual_pat_permission_ceiling_fresh_auth_false_and_revocation", func(t *testing.T) {
		pat, err := f.repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: patValue})
		if err != nil || pat.CredentialKind != CredentialBearerToken || pat.credentialBinding.Kind != CredentialBearerToken || pat.credentialBinding.ID != patID {
			t.Fatal("actual stored PAT authentication refused")
		}
		before := counts()
		exec(`UPDATE public.zasp_product_api_tokens SET permissions='["view"]'::jsonb WHERE id=$1`, patID)
		if call(http.MethodPatch, "/api/v1/agents/"+agent, "pat", "ownership-pat-denied-0001", version(), input, nil).Code < 400 || counts() != before {
			t.Fatal("PAT view-only ceiling authorized ownership")
		}
		exec(`UPDATE public.zasp_product_api_tokens SET permissions='["view","manage_workflows"]'::jsonb WHERE id=$1`, patID)
		changed := input
		changed.Owner = "PAT Owner"
		decodeACK(call(http.MethodPatch, "/api/v1/agents/"+agent, "pat", "ownership-pat-accepted-0001", version(), changed, nil))
		f.reconcile()
		// Original updateAgent explicitly does not require fresh browser authentication.
		exec(`UPDATE public.zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '1 day' WHERE session_id='session-hierarchy80'`)
		changed.Owner = "Older Browser Owner"
		decodeACK(call(http.MethodPatch, "/api/v1/agents/"+agent, "browser", "ownership-browser-oldauth-0001", version(), changed, nil))
		f.reconcile()
		exec(`UPDATE public.zasp_product_sessions SET authenticated_at=clock_timestamp() WHERE session_id='session-hierarchy80'`)
		g := capture(pat, "updateAgent")
		before = counts()
		exec(`UPDATE public.zasp_product_api_tokens SET revoked_at=clock_timestamp() WHERE id=$1`, patID)
		if _, err := write(g, inventory, pat, 1, "ownership-browser-0001", input); err == nil || counts() != before {
			t.Fatal("revoked actual PAT replayed a receipt")
		}
		exec(`UPDATE public.zasp_product_api_tokens SET revoked_at=NULL WHERE id=$1`, patID)
	})
	t.Run("captured_scope_actor_read_profile_and_live_membership_refuse_replay", func(t *testing.T) {
		before := counts()
		g := capture(identity, "updateAgent")
		foreign, err := domain.NewScope(identity.Scope.OrganizationID(), mustProductID(t, "pid_78000009-0000-4000-8000-000000000009"), mustProductID(t, "pid_78000007-0000-4000-8000-000000000007"))
		if err != nil {
			t.Fatal("foreign owned scope unavailable")
		}
		wrong := identity
		wrong.Scope = foreign
		if _, err := write(g, inventory, wrong, 1, "ownership-browser-0001", input); err == nil {
			t.Fatal("scope-mismatched captured grant replayed")
		}
		wrong = identity
		wrong.PrincipalID = mustProductID(t, automaticSourceID(193001))
		if _, err := write(g, inventory, wrong, 1, "ownership-browser-0001", input); err == nil {
			t.Fatal("actor-mismatched captured grant replayed")
		}
		if _, err := write(capture(identity, "getAgent"), inventory, identity, 1, "ownership-browser-0001", input); err == nil {
			t.Fatal("read proof authorized ownership replay")
		}
		prior := inventory.agentOwnershipWriteProfileChecksum
		inventory.agentOwnershipWriteProfileChecksum = strings.Repeat("0", 64)
		_, err = write(g, inventory, identity, 1, "ownership-browser-0001", input)
		inventory.agentOwnershipWriteProfileChecksum = prior
		if err == nil {
			t.Fatal("unselected profile replayed")
		}
		exec(`UPDATE public.zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, o, identity.PrincipalID.String())
		if _, err := write(g, inventory, identity, 1, "ownership-browser-0001", input); err == nil || counts() != before {
			t.Fatal("revoked membership replayed canonical effects")
		}
		exec(`UPDATE public.zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, o, identity.PrincipalID.String())
		f.reconcile()
		g = capture(identity, "updateAgent")
		exec(`UPDATE public.zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-hierarchy80'`)
		if _, err := write(g, inventory, identity, 1, "ownership-browser-0001", input); err == nil || call(http.MethodPatch, "/api/v1/agents/"+agent, "browser", "ownership-browser-0001", 1, input, nil).Code < 400 || counts() != before {
			t.Fatal("revoked stored browser session replayed canonical receipt")
		}
		exec(`UPDATE public.zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-hierarchy80'`)
		// A live identity with view permission is not a management grant. Use
		// the real projection/reconciliation path, not a fake Checker result.
		exec(`UPDATE public.zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, o, identity.PrincipalID.String())
		f.reconcile()
		if call(http.MethodPatch, "/api/v1/agents/"+agent, "browser", "ownership-browser-0001", 1, input, nil).Code < 400 || counts() != before {
			t.Fatal("actual viewer FGA permission replayed ownership")
		}
		exec(`UPDATE public.zasp_identity_memberships SET role='security_admin' WHERE organization_id=$1 AND principal_id=$2`, o, identity.PrincipalID.String())
		f.reconcile()
	})
	t.Run("actual_key_and_entity_wait_expiry_refuse_before_receipt", func(t *testing.T) {
		api := f.db.driver.(*authorizationConnectionDriver).conn
		for _, kind := range []string{"key", "entity"} {
			before := counts()
			exec(`UPDATE public.zasp_product_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE session_id='session-hierarchy80'`)
			fresh, err := f.repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "hierarchy80-session"})
			if err != nil {
				t.Fatal("short-lived stored session refused before wait")
			}
			g := capture(fresh, "updateAgent")
			lock, err := f.bootstrap.Begin(ctx)
			if err != nil {
				t.Fatal("owned wait transaction unavailable")
			}
			if kind == "key" {
				_, err = lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1::text,$2::text,$3::text,$4::text,'updateAgent','ownership-browser-0001'),0))`, o, w, e, identity.PrincipalID.String())
			} else {
				_, err = lock.Exec(ctx, `SELECT 1 FROM public.zasp_inventory_entities WHERE(organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4) FOR UPDATE`, o, w, e, agent)
			}
			if err != nil {
				_ = lock.Rollback(ctx)
				t.Fatal("owned exact wait lock refused")
			}
			done := make(chan error, 1)
			waitContext, cancelWait := context.WithTimeout(g, 8*time.Second)
			finished := false
			t.Cleanup(func() {
				cancelWait()
				_ = lock.Rollback(context.Background())
				if !finished {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("canceled owned waiter did not join")
					}
				}
			})
			go func() {
				_, err := write(waitContext, inventory, fresh, 1, "ownership-browser-0001", input)
				done <- err
			}()
			// Observe the real API backend waiting, rather than assuming a timer
			// proves admission reached the intended lock boundary.
			deadline := time.NewTimer(4 * time.Second)
			ticker := time.NewTicker(10 * time.Millisecond)
			observed, expired := false, false
			for !observed || !expired {
				// The locker is a transaction too; refresh its statistics snapshot
				// so an initially runnable backend is not cached as never waiting.
				if _, err := lock.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
					_ = lock.Rollback(ctx)
					cancelWait()
					t.Fatal("owned wait statistics refresh refused")
				}
				var waiting, dead bool
				if err := f.bootstrap.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids($1))),(SELECT expires_at<=clock_timestamp() FROM public.zasp_product_sessions WHERE session_id='session-hierarchy80')`, api.PgConn().PID(), f.bootstrap.PgConn().PID()).Scan(&waiting, &dead); err != nil {
					_ = lock.Rollback(ctx)
					t.Fatal("exact wait observation unavailable")
				}
				observed = observed || waiting
				expired = dead
				if observed && expired {
					break
				}
				select {
				case <-ticker.C:
				case <-deadline.C:
					ticker.Stop()
					_ = lock.Rollback(ctx)
					cancelWait()
					select {
					case <-done:
						finished = true
					case <-time.After(5 * time.Second):
					}
					t.Fatal("did not observe exact lock wait across credential expiry")
				}
			}
			ticker.Stop()
			deadline.Stop()
			if err := lock.Rollback(ctx); err != nil {
				t.Fatal("owned wait release unconfirmed")
			}
			select {
			case err := <-done:
				finished = true
				cancelWait()
				if err == nil {
					t.Fatal("expired waiter replayed receipt")
				}
			case <-time.After(5 * time.Second):
				cancelWait()
				t.Fatal("expired API waiter did not finish")
			}
			if counts() != before {
				t.Fatal("expired wait changed canonical evidence")
			}
			exec(`UPDATE public.zasp_product_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE session_id='session-hierarchy80'`)
		}
	})
	t.Run("two_actual_connections_cas_and_same_key_exactly_once", func(t *testing.T) {
		api := f.db.driver.(*authorizationConnectionDriver).conn
		second, err := pgx.ConnectConfig(ctx, api.Config().Copy())
		if err != nil {
			t.Fatal("second actual API connection unavailable")
		}
		defer second.Close(context.Background())
		db, err := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: second})
		if err != nil || db.RequireCurrentAuthorization() != nil {
			t.Fatal("second current database refused")
		}
		otherRepo, err := NewPostgresInventoryRepository(db)
		if err != nil || otherRepo.RequireAgentOwnershipWriteProfile(pin) != nil {
			t.Fatal("second selected ownership repository refused")
		}
		for _, sameKey := range []bool{false, true} {
			v, before := version(), counts()
			g1, g2 := capture(identity, "updateAgent"), capture(identity, "updateAgent")
			g1, cancelFirst := context.WithTimeout(g1, 8*time.Second)
			g2, cancelSecond := context.WithTimeout(g2, 8*time.Second)
			defer cancelFirst()
			defer cancelSecond()
			key1, key2 := "ownership-concurrent-cas-a", "ownership-concurrent-cas-b"
			if sameKey {
				key1, key2 = "ownership-concurrent-replay", "ownership-concurrent-replay"
			}
			body := input
			body.Owner = "Concurrent Owner"
			type outcome struct {
				result AgentMutationResult
				err    error
			}
			done := make(chan outcome, 2)
			start := make(chan struct{})
			go func() { <-start; r, e := write(g1, inventory, identity, v, key1, body); done <- outcome{r, e} }()
			go func() { <-start; r, e := write(g2, otherRepo, identity, v, key2, body); done <- outcome{r, e} }()
			close(start)
			results := []outcome{}
			for len(results) < 2 {
				select {
				case r := <-done:
					results = append(results, r)
				case <-time.After(10 * time.Second):
					t.Fatal("concurrent current ownership calls did not finish")
				}
			}
			cancelFirst()
			cancelSecond()
			ok := 0
			for _, r := range results {
				if r.err == nil {
					ok++
				}
			}
			if !sameKey && ok != 1 || sameKey && ok < 1 || counts() != [3]int64{before[0] + 1, before[1] + 1, before[2] + 1} {
				t.Fatal("concurrent CAS or same-key replay duplicated effects")
			}
			var acceptedAudit string
			for _, r := range results {
				if r.err == nil {
					if acceptedAudit != "" && acceptedAudit != r.result.AuditID {
						t.Fatal("same-key concurrent successes returned different receipts")
					}
					acceptedAudit = r.result.AuditID
				}
			}
			// A canonical posture INSERT may legitimately advance79 even for an
			// existing finding. Never retry a rejected captured proof implicitly.
			// Only after real reconciliation and a new Check may the same-key
			// caller receive its exact original canonical receipt.
			f.reconcile()
			if sameKey {
				replayed, err := write(capture(identity, "updateAgent"), inventory, identity, v, key1, body)
				if err != nil || !replayed.Replayed || replayed.AuditID != acceptedAudit || counts() != [3]int64{before[0] + 1, before[1] + 1, before[2] + 1} {
					t.Fatal("fresh same-key retry did not preserve exactly one receipt")
				}
			}
		}
	})
	t.Run("own_catalog_drift_parent_immutability_and_no_extra_effects", func(t *testing.T) {
		before := counts()
		for _, q := range []string{
			`GRANT EXECUTE ON FUNCTION zasp_agent_ownership_write_v1.require_api(text,text,text,text,text,text) TO zasp_discovery_api`,
			`ALTER FUNCTION zasp_agent_ownership_write_v1.update_agent(text,text,text,text,text,text,bigint,text,text,jsonb,text,text,text) SET search_path=pg_catalog`,
			`CREATE TYPE zasp_agent_ownership_write_v1.unexpected AS ENUM ('extra')`,
		} {
			tx, err := f.owner.Begin(ctx)
			if err != nil {
				t.Fatal("own drift transaction refused")
			}
			if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("own drift authority refused")
			}
			if _, err = tx.Exec(ctx, q); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("own controlled drift refused")
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT zasp_agent_ownership_write_v1.catalog_ready($1)`, pin).Scan(&ready); err != nil || ready {
				_ = tx.Rollback(ctx)
				t.Fatal("own catalog accepted private ACL/body/type drift")
			}
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal("own catalog rollback unconfirmed")
			}
		}
		// The canonical annotation security guard is inventory-authority-owned.
		// Only the disposable bootstrap controls this rollback-only drift; never
		// grant the product API or source operator that authority.
		tx, err := f.bootstrap.Begin(ctx)
		if err != nil {
			t.Fatal("owned parent drift transaction unavailable")
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_inventory_authority`); err != nil {
			t.Fatal("owned parent identity frame refused")
		}
		if _, err = tx.Exec(ctx, `CREATE OR REPLACE FUNCTION public.zasp_inventory_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $controlled$ SELECT true $controlled$`); err != nil {
			t.Fatal("rollback-only canonical guard drift refused")
		}
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			t.Fatal("owned readiness frame refused")
		}
		var ready bool
		if err = tx.QueryRow(ctx, `SELECT zasp_agent_ownership_write_v1.catalog_ready($1)`, pin).Scan(&ready); err != nil || ready {
			t.Fatal("catalog accepted canonical annotation security guard body drift")
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal("canonical guard rollback unconfirmed")
		}
		if err := install(ctx); err != nil || counts() != before || !bytes.Equal(parentBefore, parentCatalog()) {
			t.Fatal("selected replay/parent guard changed canonical effects")
		}
	})
}
