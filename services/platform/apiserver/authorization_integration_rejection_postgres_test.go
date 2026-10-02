package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type rejectionAuthorizationDriver struct {
	authorizationConnectionDriver
	fault string
}

func (d *rejectionAuthorizationDriver) BeginReadCommitted(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil || d.fault == "" {
		return tx, err
	}
	return &rejectionNativeFaultTx{Tx: tx, mode: d.fault}, nil
}

type rejectionNativeFaultTx struct {
	pgx.Tx
	mode string
}

func (tx *rejectionNativeFaultTx) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	tag, err := tx.Tx.Exec(ctx, q, args...)
	if err == nil && q == postgresCurrentIntegrationRejectionSQL {
		if tx.mode == "panic-after-append" {
			panic("owned post-append fault")
		}
		if tx.mode == "error-after-append" {
			return tag, errors.New("owned post-append fault")
		}
	}
	return tag, err
}
func (tx *rejectionNativeFaultTx) Commit(ctx context.Context) error {
	if tx.mode == "before-commit" {
		return errors.New("owned pre-commit fault")
	}
	return tx.Tx.Commit(ctx)
}

// The mounted current handler must reach a safe audit through checked replay
// and update preparation. A generic closed-query503 is not product rejection.
func TestP7IntegrationRejectionPostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires retained local OpenFGA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const integrationID = "pid_78100001-0000-4000-8000-000000000001"
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Rejection','rejection.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Selected')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Selected','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-rejection80','member-rejection80','security_engineer',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','[]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('rejection80-session','sha256'),'session-rejection80',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp()-interval '10 minutes',clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('rejection80-pat','sha256'),'pid_78100004-0000-4000-8000-000000000004','Rejection PAT',$1,$2,$3,$4,'["manage_workflows"]',clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration) VALUES($1,$2,$3,$4,'github','v1','Existing','{}')`, o, w, e, integrationID)
	exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Existing','connector_key','github','configuration','{}'::jsonb,'status','pending_authorization'))`, o, w, e, integrationID)
	const foreignWorkspace = "pid_78100011-0000-4000-8000-000000000011"
	const foreignEnvironment = "pid_78100012-0000-4000-8000-000000000012"
	const foreignIntegration = "pid_78100013-0000-4000-8000-000000000013"
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Foreign')`, o, foreignWorkspace)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Foreign','production')`, o, foreignWorkspace, foreignEnvironment)
	exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration) VALUES($1,$2,$3,$4,'github','v1','Foreign','{}')`, o, foreignWorkspace, foreignEnvironment, foreignIntegration)
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	client, pins := newAuthorizationProjectionFGA(t)
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID)
	reconcile := func() {
		t.Helper()
		if result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
			t.Fatalf("projection=%+v %v", result, err)
		}
	}
	reconcile()
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	var caller bool
	if err := api.QueryRow(ctx, `SELECT session_user='auth80_api' AND current_user=session_user AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&caller); err != nil || !caller {
		t.Fatalf("registered nonsuper API=%v %v", caller, err)
	}
	driver := &rejectionAuthorizationDriver{authorizationConnectionDriver: authorizationConnectionDriver{conn: api}}
	db, _ := NewPostgresJSONDatabase(driver)
	if err := db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, _ := NewPostgresRepository(db)
	i, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "rejection80-session"})
	if err != nil || len(i.Permissions) != 0 {
		t.Fatalf("current identity=%v", err)
	}
	pat, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: "rejection80-pat"})
	if err != nil || len(pat.Permissions) != 0 || !reflect.DeepEqual(pat.credentialBinding.PATCeiling, []string{"manage_workflows"}) {
		t.Fatalf("current PAT identity/ceiling rejected: %v", err)
	}
	resolver, _ := NewPostgresAuthorizationResolver(db)
	a := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	handler, err := newWorkflowHTTPHandler(repo, []byte(strings.Repeat("k", 32)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var operations []Operation
	for _, id := range []string{"createIntegration", "updateIntegration"} {
		policy, _ := authorization.LookupOperation(id)
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: id, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken}, RequireCSRF: true, Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal(err)
	}
	barrier := &sensorCheckBarrier{inner: a}
	router.(*operationRouter).authorizer = barrier
	var providerCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { providerCalls.Add(1); w.WriteHeader(418) }))
	defer provider.Close()
	defer func() {
		if n := providerCalls.Load(); n != 0 {
			t.Errorf("forbidden provider URL received %d requests", n)
		}
	}()
	rejectedBody := fmt.Sprintf(`{"name":"Never persist this","connector_key":"github","configuration":{"authorization_mode":"github_app","provider_url":%q}}`, provider.URL+"/never-persist")
	const correctedBody = `{"name":"Existing","connector_key":"github","configuration":{"authorization_mode":"github_app"}}`
	invoke := func(call context.Context, identity RequestIdentity, operation, target, key, body string, change func(*http.Request)) *httptest.ResponseRecorder {
		method, path := "POST", "/api/v1/integrations"
		if operation == "updateIntegration" {
			method, path = "PATCH", path+"/"+target
		}
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("If-Match", `"1"`)
		request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		request.Header.Set("Origin", "https://console.example")
		request.Header.Set("X-CSRF-Token", identity.CSRFToken)
		if identity.CredentialKind == CredentialBearerToken {
			request.Header.Set("Authorization", "Bearer rejection80-pat")
		} else {
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "rejection80-session"})
		}
		c := context.WithValue(call, identityContextKey{}, identity)
		c = context.WithValue(c, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
		c = context.WithValue(c, correlationContextKey{}, testCorrelationID)
		response := httptest.NewRecorder()
		if change != nil {
			change(request)
		}
		router.ServeHTTP(response, request.WithContext(c))
		return response
	}
	count := func() int {
		t.Helper()
		var n int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit WHERE action='integration.setup.rejected'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	pristine := func() string {
		t.Helper()
		var s string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(i) ORDER BY i.organization_id,i.workspace_id,i.environment_id,i.id) FROM zasp_integrations i),(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id) FROM zasp_workflow_records r),(SELECT count(*) FROM zasp_workflow_idempotency),(SELECT count(*) FROM zasp_workflow_receipts),(SELECT count(*) FROM zasp_workflow_audit))::text`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, identity := range []RequestIdentity{i, pat} {
		for _, operation := range []string{"createIntegration", "updateIntegration"} {
			t.Run(fmt.Sprintf("mounted_%s_%d_repeated_safe_rejection", operation, identity.CredentialKind), func(t *testing.T) {
				before, audits := pristine(), count()
				key := fmt.Sprintf("rejection-mounted-%s-%d", operation, identity.CredentialKind)
				for attempt := 0; attempt < 2; attempt++ {
					r := invoke(ctx, identity, operation, integrationID, key, rejectedBody, nil)
					if r.Code != 400 || count() != audits+attempt+1 {
						t.Fatalf("mounted %s/%d status=%d audit delta=%d body=%s", operation, identity.CredentialKind, r.Code, count()-audits, r.Body)
					}
				}
				if pristine() != before {
					t.Fatal("rejection changed product/idempotency/receipt state")
				}
				var safe bool
				if err := owner.QueryRow(ctx, `SELECT bool_and(a.outcome='rejected' AND a.actor_id=$1 AND a.organization_id=$2 AND a.workspace_id=$3 AND a.environment_id=$4 AND a.metadata=jsonb_build_object('operation',a.metadata->>'operation','resource_kind','integration','reason','invalid_configuration','correlation_id',$5::text) AND a.target_id=CASE a.metadata->>'operation' WHEN 'createIntegration' THEN $4 ELSE $6 END) FROM zasp_admin_audit a WHERE action='integration.setup.rejected'`, p, o, w, e, testCorrelationID, integrationID).Scan(&safe); err != nil || !safe {
					t.Fatalf("safe exact audit=%v %v", safe, err)
				}
				// Corrected reuse is a replay miss, not a claim that valid mutation
				// execution has been implemented by this rejection-only slice.
				route := RoutedOperation{OperationID: operation, PathParameters: map[string]string{}}
				if operation == "updateIntegration" {
					route.PathParameters["id"] = integrationID
				}
				g, err := a.Authorize(ctx, identity, identity.credentialBinding, route)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest("POST", "/", strings.NewReader(correctedBody))
				request.Header.Set("If-Match", `"1"`)
				intent, _, err := canonicalWorkflowIntent(request, route)
				if err != nil {
					t.Fatal(err)
				}
				if _, found, err := repo.ReplayWorkflow(context.WithValue(ctx, requestAuthorizationContextKey{}, g), identity, operation, key, intent); err != nil || found {
					t.Fatalf("corrected key wasn't reusable: found=%v %v", found, err)
				}
			})
		}
	}
	t.Run("existing_success_key_conflict_and_identical_replay", func(t *testing.T) {
		for _, identity := range []RequestIdentity{i, pat} {
			for _, operation := range []string{"createIntegration", "updateIntegration"} {
				key := fmt.Sprintf("rejection-existing-%s-%d", operation, identity.CredentialKind)
				route := RoutedOperation{OperationID: operation, PathParameters: map[string]string{}}
				if operation == "updateIntegration" {
					route.PathParameters["id"] = integrationID
				}
				request := httptest.NewRequest("POST", "/", strings.NewReader(correctedBody))
				request.Header.Set("If-Match", `"1"`)
				intent, _, err := canonicalWorkflowIntent(request, route)
				if err != nil {
					t.Fatal(err)
				}
				result := WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: json.RawMessage(`{"id":"` + integrationID + `","name":"Existing","connector_key":"github","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization"}`), Version: 1}, AuditID: "pid_78100005-0000-4000-8000-000000000005", CorrelationID: testCorrelationID}
				if identity.CredentialKind == CredentialBrowserSession {
					result.ReceiptID = "pid_78100006-0000-4000-8000-000000000006"
				}
				response, _ := json.Marshal(result)
				exec(`INSERT INTO zasp_workflow_idempotency(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,response) VALUES($1,$2,$3,$4,$5,$6,digest(convert_to($7::jsonb::text,'UTF8'),'sha256'),$8::jsonb)`, o, w, e, p, operation, key, intent, response)
				before, audits := pristine(), count()
				if r := invoke(ctx, identity, operation, integrationID, key, rejectedBody, nil); r.Code != 409 || count() != audits+1 {
					t.Fatalf("successful key conflict status=%d audit delta=%d body=%s", r.Code, count()-audits, r.Body)
				}
				want := 200
				if operation == "createIntegration" {
					want = 201
				}
				if r := invoke(ctx, identity, operation, integrationID, key, correctedBody, nil); r.Code != want || r.Header().Get("X-Audit-ID") != result.AuditID || count() != audits+1 {
					t.Fatalf("identical prior replay status=%d body=%s", r.Code, r.Body)
				}
				if pristine() != before {
					t.Fatal("replay/conflict modified existing result")
				}
			}
		}
	})
	t.Run("current_admission_and_original_target_refusals", func(t *testing.T) {
		before, audits := pristine(), count()
		for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }, func(r *http.Request) { r.Header.Set(expectedScopeHeader, "wrong") }} {
			if r := invoke(ctx, i, "createIntegration", integrationID, "rejection-boundary-key", rejectedBody, change); r.Code < 400 || r.Code >= 500 {
				t.Fatalf("browser boundary=%d", r.Code)
			}
		}
		if r := invoke(ctx, i, "updateIntegration", "pid_78100009-0000-4000-8000-000000000009", "rejection-missing-target", rejectedBody, nil); r.Code != 403 {
			t.Fatalf("missing current target=%d", r.Code)
		}
		for _, identity := range []RequestIdentity{i, pat} {
			if r := invoke(ctx, identity, "updateIntegration", foreignIntegration, "rejection-foreign-target", rejectedBody, nil); r.Code != 403 {
				t.Fatalf("foreign target=%d", r.Code)
			}
		}
		t.Cleanup(func() {
			exec(`UPDATE zasp_workflow_records SET deleted_at=NULL WHERE id=$1`, integrationID)
			reconcile()
		})
		exec(`UPDATE zasp_workflow_records SET deleted_at=clock_timestamp() WHERE id=$1`, integrationID)
		reconcile()
		if r := invoke(ctx, i, "updateIntegration", integrationID, "rejection-deleted-record", rejectedBody, nil); r.Code != 404 {
			t.Fatalf("deleted workflow target=%d body=%s", r.Code, r.Body)
		}
		exec(`UPDATE zasp_workflow_records SET deleted_at=NULL WHERE id=$1`, integrationID)
		reconcile()
		if count() != audits || pristine() != before {
			t.Fatal("rejected boundary wrote effects")
		}
	})
	t.Run("deleted_authoritative_target_refusal", func(t *testing.T) {
		before, audits := pristine(), count()
		t.Cleanup(func() {
			exec(`UPDATE zasp_integrations SET state='pending',deleted_at=NULL WHERE id=$1`, integrationID)
			reconcile()
		})
		exec(`UPDATE zasp_integrations SET state='deleted',deleted_at=clock_timestamp() WHERE id=$1`, integrationID)
		reconcile()
		for _, identity := range []RequestIdentity{i, pat} {
			if r := invoke(ctx, identity, "updateIntegration", integrationID, "rejection-deleted-source", rejectedBody, nil); r.Code != 403 {
				t.Fatalf("deleted authoritative target=%d body=%s", r.Code, r.Body)
			}
		}
		exec(`UPDATE zasp_integrations SET state='pending',deleted_at=NULL WHERE id=$1`, integrationID)
		reconcile()
		if count() != audits || pristine() != before {
			t.Fatal("deleted target refusal wrote effects")
		}
	})
	t.Run("compact_body_limit_does_not_limit_jsonb_spacing", func(t *testing.T) {
		body := `{"name":"Never persist padding","connector_key":"github","configuration":{"provider_url":"https://private.invalid"},"padding":[` + strings.Repeat("0,", 5999) + `0]}`
		request := httptest.NewRequest("POST", "/", strings.NewReader(body))
		intent, _, err := canonicalWorkflowIntent(request, RoutedOperation{OperationID: "createIntegration"})
		if err != nil || len(intent) > 16384 {
			t.Fatalf("compact input contract: size=%d %v", len(intent), err)
		}
		var canonicalSize int
		if err := owner.QueryRow(ctx, `SELECT octet_length($1::jsonb::text)`, intent).Scan(&canonicalSize); err != nil || canonicalSize <= 16384 {
			t.Fatalf("JSONB expansion=%d %v", canonicalSize, err)
		}
		before, audits := pristine(), count()
		r := invoke(ctx, i, "createIntegration", integrationID, "rejection-canonical-spacing", body, nil)
		if r.Code != 400 || count() != audits+1 || pristine() != before {
			t.Fatalf("expanded replay status=%d audit delta=%d body=%s", r.Code, count()-audits, r.Body)
		}
	})
	t.Run("post_check_credential_authority_and_revision", func(t *testing.T) {
		for _, tc := range []struct {
			name, change, restore string
			identity              RequestIdentity
			status                int
		}{
			{"revoked_browser", `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp()`, `UPDATE zasp_product_sessions SET revoked_at=NULL`, i, 401},
			{"expired_browser", `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()-interval '1 second'`, `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '1 hour'`, i, 401},
			{"revoked_pat", `UPDATE zasp_product_api_tokens SET revoked_at=clock_timestamp()`, `UPDATE zasp_product_api_tokens SET revoked_at=NULL`, pat, 401},
			{"pat_ceiling_loss", `UPDATE zasp_product_api_tokens SET permissions='[]'`, `UPDATE zasp_product_api_tokens SET permissions='["manage_workflows"]'`, pat, 403},
			{"csrf_change", `UPDATE zasp_product_sessions SET csrf_token=repeat('y',32)`, `UPDATE zasp_product_sessions SET csrf_token=repeat('x',32)`, i, 403},
			{"membership_loss", `UPDATE zasp_identity_memberships SET active=false`, `UPDATE zasp_identity_memberships SET active=true`, i, 403},
			{"role_revision", `UPDATE zasp_identity_memberships SET role='read_only_viewer'`, `UPDATE zasp_identity_memberships SET role='security_engineer'`, i, 409},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before, audits := pristine(), count()
				t.Cleanup(func() { barrier.after = nil; exec(tc.restore); reconcile() })
				barrier.after = func() { exec(tc.change) }
				r := invoke(ctx, tc.identity, "updateIntegration", integrationID, "rejection-stale-"+tc.name, rejectedBody, nil)
				barrier.after = nil
				exec(tc.restore)
				reconcile()
				if r.Code != tc.status || count() != audits || pristine() != before {
					t.Fatalf("stale current authority status=%d want=%d audit delta=%d body=%s", r.Code, tc.status, count()-audits, r.Body)
				}
			})
		}
	})
	// Removing either post-lock classification or the post-INSERT check would
	// turn these expired requests into a committed rejection audit or a409.
	t.Run("wall_clock_expiry_at_native_waits", func(t *testing.T) {
		for _, identity := range []RequestIdentity{i, pat} {
			for _, stage := range []string{"audit", "target", "credential"} {
				t.Run(fmt.Sprintf("%s_%d", stage, identity.CredentialKind), func(t *testing.T) {
					table, predicate := "zasp_product_sessions", "session_id='session-rejection80'"
					if identity.CredentialKind == CredentialBearerToken {
						table, predicate = "zasp_product_api_tokens", "id='pid_78100004-0000-4000-8000-000000000004'"
					}
					t.Cleanup(func() {
						exec(`UPDATE ` + table + ` SET expires_at=clock_timestamp()+interval '1 hour' WHERE ` + predicate)
					})
					exec(`UPDATE ` + table + ` SET expires_at=clock_timestamp()+interval '2 seconds' WHERE ` + predicate)
					lockSQL, args := `LOCK TABLE zasp_admin_audit IN SHARE MODE`, []any(nil)
					if stage == "target" {
						lockSQL, args = `SELECT id FROM zasp_integrations WHERE id=$1 FOR UPDATE`, []any{integrationID}
					} else if stage == "credential" {
						lockSQL = `SELECT token_digest FROM ` + table + ` WHERE ` + predicate + ` FOR UPDATE`
					}
					before, audits := pristine(), count()
					r := connectorRejectionBlockedHTTP(t, ctx, owner, api, lockSQL, args, func(call context.Context) *httptest.ResponseRecorder {
						return invoke(call, identity, "updateIntegration", integrationID, "rejection-wait-"+stage, rejectedBody, nil)
					}, func(wait context.Context) {
						ticker := time.NewTicker(10 * time.Millisecond)
						defer ticker.Stop()
						for {
							var expired bool
							if err := owner.QueryRow(wait, `SELECT expires_at<=clock_timestamp() FROM `+table+` WHERE `+predicate).Scan(&expired); err != nil {
								t.Fatal(err)
							}
							if expired {
								return
							}
							select {
							case <-wait.Done():
								t.Fatal("credential expiry wait timed out")
							case <-ticker.C:
							}
						}
					}, false)
					if r.Code != 401 || count() != audits || pristine() != before {
						t.Fatalf("expired %s status=%d audit delta=%d body=%s", stage, r.Code, count()-audits, r.Body)
					}
				})
			}
		}
	})
	t.Run("blocked_insert_cancellation_rolls_back", func(t *testing.T) {
		before, audits := pristine(), count()
		r := connectorRejectionBlockedHTTP(t, ctx, owner, api, `LOCK TABLE zasp_admin_audit IN SHARE MODE`, nil, func(call context.Context) *httptest.ResponseRecorder {
			return invoke(call, i, "createIntegration", integrationID, "rejection-cancel-audit", rejectedBody, nil)
		}, nil, true)
		if r.Code != 503 || count() != audits || pristine() != before {
			t.Fatalf("cancelled audit status=%d audit delta=%d", r.Code, count()-audits)
		}
	})
	t.Run("actual_insert_rollback_on_application_fault", func(t *testing.T) {
		for _, mode := range []string{"error-after-append", "panic-after-append", "before-commit"} {
			t.Run(mode, func(t *testing.T) {
				g, err := a.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: "createIntegration"})
				if err != nil {
					t.Fatal(err)
				}
				command := IntegrationRejection{CredentialDigest: g.Credential.Digest[:], Operation: g.OperationID, TargetID: e, AuditID: "pid_78100008-0000-4000-8000-000000000008", CorrelationID: testCorrelationID}
				before, audits := pristine(), count()
				t.Cleanup(func() { driver.fault = "" })
				driver.fault = mode
				panicked := false
				func() {
					defer func() {
						if recover() != nil {
							panicked = true
						}
					}()
					err = repo.AuditIntegrationRejection(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, command)
				}()
				driver.fault = ""
				if panicked != (mode == "panic-after-append") || (!panicked && !errors.Is(err, ErrRepositoryUnavailable)) || count() != audits || pristine() != before {
					t.Fatalf("fault=%s panic=%t error=%v audit delta=%d", mode, panicked, err, count()-audits)
				}
			})
		}
	})
	t.Run("native_proof_and_exact_argument_refusals", func(t *testing.T) {
		g, err := a.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: "createIntegration"})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := authorizationProofJSON(g)
		if err != nil {
			t.Fatal(err)
		}
		before, audits := pristine(), count()
		for _, mode := range []string{"proofless", "actor", "digest", "target", "operation", "wrong_read_purpose"} {
			t.Run(mode, func(t *testing.T) {
				tx, err := api.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if mode != "proofless" {
					if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.integration_rejection_fence($1)`, string(proof)); err != nil {
						t.Fatal(err)
					}
				}
				args := []any{o, w, e, p, g.Credential.Digest[:], g.OperationID, e, "pid_78100008-0000-4000-8000-000000000008", testCorrelationID}
				switch mode {
				case "actor":
					args[3] = integrationID
				case "digest":
					args[4] = make([]byte, 32)
				case "target":
					args[6] = integrationID
				case "operation":
					args[5] = "updateIntegration"
				}
				if mode == "wrong_read_purpose" {
					_, err = tx.Exec(ctx, `SELECT zasp_authorization80.integration_update_value($1,$2,$3,$4)`, o, w, e, integrationID)
				} else {
					_, err = tx.Exec(ctx, postgresCurrentIntegrationRejectionSQL, args...)
				}
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != "42501" {
					t.Fatalf("native %s error=%v", mode, err)
				}
			})
		}
		if count() != audits || pristine() != before {
			t.Fatal("native refused append committed effects")
		}
	})
	t.Run("native_rejection_requires_read_committed", func(t *testing.T) {
		g, err := a.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: "updateIntegration", PathParameters: map[string]string{"id": integrationID}})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := authorizationProofJSON(g)
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []pgx.TxIsoLevel{pgx.RepeatableRead, pgx.Serializable} {
			for _, entry := range []string{"fence", "replay", "update_value", "append"} {
				t.Run(string(level)+"/"+entry, func(t *testing.T) {
					tx, err := api.BeginTx(ctx, pgx.TxOptions{IsoLevel: level})
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(context.Background())
					if entry != "fence" {
						if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1)`, string(proof)); err != nil {
							t.Fatalf("shared fence setup: %v", err)
						}
					}
					switch entry {
					case "fence":
						_, err = tx.Exec(ctx, `SELECT zasp_authorization80.integration_rejection_fence($1)`, string(proof))
					case "replay":
						_, err = tx.Exec(ctx, `SELECT zasp_authorization80.integration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`, o, w, e, p, g.OperationID, "rejection-native-isolation", `{"body":{},"resource_id":"`+integrationID+`"}`)
					case "update_value":
						_, err = tx.Exec(ctx, `SELECT zasp_authorization80.integration_update_value($1,$2,$3,$4)`, o, w, e, integrationID)
					case "append":
						_, err = tx.Exec(ctx, postgresCurrentIntegrationRejectionSQL, o, w, e, p, g.Credential.Digest[:], g.OperationID, integrationID, "pid_78100008-0000-4000-8000-000000000008", testCorrelationID)
					}
					var native *pgconn.PgError
					if !errors.As(err, &native) || native.Code != "55000" {
						t.Fatalf("native isolation %s accepted or misclassified: %v", level, err)
					}
				})
			}
		}
	})
}
