package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type recoveryCheckBarrier struct {
	inner RequestAuthorizer
	after func()
}

func (b *recoveryCheckBarrier) Authorize(c context.Context, i RequestIdentity, k CredentialBinding, r RoutedOperation) (RequestAuthorization, error) {
	g, err := b.inner.Authorize(c, i, k, r)
	if err == nil && b.after != nil {
		b.after()
	}
	return g, err
}

func TestP7RecoveryAuthorizationPostgres(t *testing.T) {
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
	identity := fixtureRequestIdentity(t)
	identity.CSRFToken = strings.Repeat("x", 32)
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Recovery authority','recovery-auth.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Recovery')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-recovery80','member-recovery80','read_only_viewer',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('recovery80-credential','sha256'),'session-recovery80',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	patID := "pid_79000008-0000-4000-8000-000000000008"
	exec(`INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('recovery80-pat','sha256'),$5,'Owned recovery fixture',$1,$2,$3,$4,'["view","manage_identity"]',clock_timestamp()+interval '1 hour')`, p, o, w, e, patID)
	seeded := "pid_79000001-0000-4000-8000-000000000001"
	denied := "pid_79000002-0000-4000-8000-000000000002"
	foreign := "pid_79000003-0000-4000-8000-000000000003"
	foreignEnv := "pid_79000004-0000-4000-8000-000000000004"
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Foreign','production')`, o, w, foreignEnv)
	for _, row := range [][2]string{{e, seeded}, {e, denied}, {foreignEnv, foreign}} {
		exec(`INSERT INTO zasp_recovery_backups(organization_id,workspace_id,environment_id,backup_id,retention_days,actor_id,idempotency_key,request_digest) VALUES($1,$2,$3,$4,30,$5,$4,digest($4,'sha256'))`, o, w, row[0], row[1], p)
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
	reconcile := func() {
		t.Helper()
		if _, err := authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	database.currentAuthorization = true
	repository, err := NewRecoveryPublicRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := NewPostgresAuthorizationResolver(database)
	checker := authorizationDecisionFixture{allow: map[string]bool{e: true, seeded: true, testRecoveryBackupID: true, testRecoveryRestoreID: true}, model: model}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	identity.credentialBinding = CredentialBinding{Kind: CredentialBrowserSession, ID: "session-recovery80", Digest: sha256.Sum256([]byte("recovery80-credential"))}
	currentIdentity := identity
	barrier := &recoveryCheckBarrier{inner: authorizer}
	forcedAudit := ""
	handler, err := NewRecoveryPublicHTTPHandler(repository, RecoveryPublicHandlerConfig{NewProductID: func() (string, error) {
		if forcedAudit != "" {
			v := forcedAudit
			forcedAudit = ""
			return v, nil
		}
		return newWorkflowProductID()
	}})
	if err != nil {
		t.Fatal(err)
	}
	var operations []Operation
	for _, name := range []string{"startRecoveryBackup", "getRecoveryBackup", "startRecoveryRestore", "getRecoveryRestore"} {
		policy, err := authorization.LookupOperation(name)
		if err != nil {
			t.Fatal(err)
		}
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: name, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken}, RequireCSRF: policy.Method != "GET", RequireFreshAuth: policy.FreshAuth, Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = barrier
	call := func(method, path, body, key string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(expectedScopeHeader, expectedScopeValue(currentIdentity.Scope))
		request.Header.Set("Origin", "https://console.example")
		request.Header.Set("X-CSRF-Token", currentIdentity.CSRFToken)
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
			request.Header.Set("If-Match", `"0"`)
		}
		c := context.WithValue(ctx, identityContextKey{}, currentIdentity)
		c = context.WithValue(c, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
		c = context.WithValue(c, correlationContextKey{}, testCorrelationID)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request.WithContext(c))
		return response
	}
	counts := func() [4]int {
		t.Helper()
		var v [4]int
		if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_recovery_backups)+(SELECT count(*) FROM zasp_recovery_restores),(SELECT count(*) FROM zasp_recovery_request_receipts),(SELECT count(*) FROM zasp_recovery_audit),(SELECT count(*) FROM zasp_recovery_outbox)`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	t.Run("exact resource proof cannot be reused for another row or kind", func(t *testing.T) {
		grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "getRecoveryBackup", PathParameters: map[string]string{"id": seeded}})
		if err != nil {
			t.Fatal(err)
		}
		c := context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
		if _, err := repository.GetBackup(c, identity, seeded); err != nil {
			t.Fatal(err)
		}
		assertSQLDenial := func(err error) {
			t.Helper()
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
				t.Fatalf("wanted exact current-proof SQL denial, got %v", err)
			}
		}
		if _, err := repository.GetBackup(c, identity, denied); err != nil {
			if !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("pre-SQL sibling denial=%v", err)
			}
		} else {
			t.Fatal("checked backup proof disclosed a denied sibling")
		}
		if _, err := repository.GetRestore(c, identity, seeded); err != nil {
			if !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("pre-SQL kind denial=%v", err)
			}
		} else {
			t.Fatal("backup proof accepted for restore kind")
		}
		proof, err := authorizationProofJSON(grant)
		if err != nil {
			t.Fatal(err)
		}
		for _, native := range []struct{ query, id string }{
			{`SELECT zasp_authorization80.recovery_get_backup($1,$2,$3,$4)`, denied},
			{`SELECT zasp_authorization80.recovery_get_restore($1,$2,$3,$4)`, seeded},
		} {
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, native.query, o, w, e, native.id)
			_ = tx.Rollback(ctx)
			assertSQLDenial(err)
		}
		if _, err := repository.GetBackup(ctx, identity, seeded); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("missing proof error=%v", err)
		}
		malformed := context.WithValue(ctx, requestAuthorizationContextKey{}, RequestAuthorization{})
		if _, err := repository.GetBackup(malformed, identity, seeded); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("malformed proof error=%v", err)
		}
		for _, id := range []string{denied, foreign} {
			if response := call("GET", "/api/v1/recovery/backups/"+id, "", ""); response.Code != 403 {
				t.Fatalf("denied/foreign detail status=%d", response.Code)
			}
		}
	})
	manifest := recoveryManifestFixture(identity)
	manifestJSON, _ := json.Marshal(manifest)
	backupBody := `{"backup_id":"` + testRecoveryBackupID + `","retention_days":30}`
	restoreBody := `{"restore_id":"` + testRecoveryRestoreID + `","target_environment":"owned-recovery-only","manifest":` + string(manifestJSON) + `}`
	t.Run("fresh checked queued effects replay without duplicates", func(t *testing.T) {
		for n, tc := range []struct{ path, body, id, operation string }{{"/api/v1/recovery/backups", backupBody, testRecoveryBackupID, "startRecoveryBackup"}, {"/api/v1/recovery/restores", restoreBody, testRecoveryRestoreID, "startRecoveryRestore"}} {
			key := fmt.Sprintf("recovery-current-proof-%02d", n)
			before := counts()
			checker.allow[e] = false
			if response := call("POST", tc.path, tc.body, key); response.Code != 403 {
				t.Fatalf("%s environment deny status=%d", tc.operation, response.Code)
			}
			checker.allow[e] = true
			currentIdentity.FreshAuthenticated = false
			if response := call("POST", tc.path, tc.body, key); response.Code != 403 || !strings.Contains(response.Body.String(), "fresh_auth_required") {
				t.Fatalf("%s stale browser status=%d", tc.operation, response.Code)
			}
			currentIdentity = identity
			barrier.after = func() {
				exec(`UPDATE zasp_identity_memberships SET role=CASE role WHEN 'read_only_viewer' THEN 'security_admin' ELSE 'read_only_viewer' END WHERE principal_id=$1 AND organization_id=$2`, p, o)
				reconcile()
			}
			stale := call("POST", tc.path, tc.body, key)
			barrier.after = nil
			if stale.Code != 409 || counts() != before {
				t.Fatalf("%s stale mutation status=%d counts=%v", tc.operation, stale.Code, counts())
			}
			barrier.after = func() {
				exec(`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '10 minutes' WHERE session_id='session-recovery80'`)
			}
			stale = call("POST", tc.path, tc.body, key)
			barrier.after = nil
			exec(`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp() WHERE session_id='session-recovery80'`)
			if stale.Code != 409 || counts() != before {
				t.Fatalf("%s expired SQL freshness status=%d", tc.operation, stale.Code)
			}
			fresh := call("POST", tc.path, tc.body, key)
			if fresh.Code != 202 {
				t.Fatalf("%s fresh status=%d", tc.operation, fresh.Code)
			}
			want := before
			for j := range want {
				want[j]++
			}
			if counts() != want {
				t.Fatalf("%s durable effect/receipt/audit/outbox=%v want%v", tc.operation, counts(), want)
			}
			reconcile()
			replay := call("POST", tc.path, tc.body, key)
			if replay.Code != 202 || replay.Header().Get("X-Audit-ID") != fresh.Header().Get("X-Audit-ID") || replay.Header().Get("X-Mutation-Receipt-ID") != fresh.Header().Get("X-Mutation-Receipt-ID") || counts() != want {
				t.Fatalf("%s replay changed durable identity/counts status=%d", tc.operation, replay.Code)
			}
			if got := call("GET", tc.path+"/"+tc.id, "", ""); got.Code != 200 || !strings.Contains(got.Body.String(), `"state":"queued"`) {
				t.Fatalf("%s queued detail status=%d", tc.operation, got.Code)
			}
			checker.allow[tc.id] = false
			denied := call("GET", tc.path+"/"+tc.id, "", "")
			checker.allow[tc.id] = true
			if denied.Code != 403 {
				t.Fatalf("%s resource deny status=%d", tc.operation, denied.Code)
			}
		}
	})
	t.Run("restore scope manifest and target remain closed", func(t *testing.T) {
		before := counts()
		for _, body := range []string{strings.Replace(restoreBody, "owned-recovery-only", "production", 1), strings.Replace(restoreBody, o, "pid_ffffffff-ffff-4fff-8fff-ffffffffffff", 1)} {
			if response := call("POST", "/api/v1/recovery/restores", body, "recovery-invalid-restore"); response.Code != 400 {
				t.Fatalf("invalid restore status=%d", response.Code)
			}
		}
		if counts() != before {
			t.Fatal("invalid restore committed")
		}
	})
	t.Run("PAT ceiling and current credential fence", func(t *testing.T) {
		pat := identity
		pat.CredentialKind = CredentialBearerToken
		pat.CSRFToken = ""
		pat.FreshAuthenticated = false
		pat.credentialBinding = CredentialBinding{Kind: CredentialBearerToken, ID: patID, Digest: sha256.Sum256([]byte("recovery80-pat")), PATCeiling: []string{"view", "manage_identity"}}
		currentIdentity = pat
		defer func() { currentIdentity = identity }()
		if response := call("GET", "/api/v1/recovery/backups/"+seeded, "", ""); response.Code != 200 {
			t.Fatalf("PAT view status=%d", response.Code)
		}
		currentIdentity.credentialBinding.PATCeiling = []string{"view"}
		before := counts()
		if response := call("POST", "/api/v1/recovery/backups", backupBody, "recovery-pat-ceiling"); response.Code != 403 {
			t.Fatalf("PAT ceiling status=%d", response.Code)
		}
		currentIdentity = pat
		barrier.after = func() { exec(`UPDATE zasp_product_api_tokens SET revoked_at=clock_timestamp() WHERE id=$1`, patID) }
		response := call("POST", "/api/v1/recovery/backups", backupBody, "recovery-pat-revoked")
		barrier.after = nil
		exec(`UPDATE zasp_product_api_tokens SET revoked_at=NULL WHERE id=$1`, patID)
		if response.Code != 409 || counts() != before {
			t.Fatalf("revoked PAT status=%d", response.Code)
		}
		response = call("POST", "/api/v1/recovery/backups", backupBody, "recovery-current-proof-00")
		if response.Code != 202 || response.Header().Get("X-Mutation-Receipt-ID") != "" || counts() != before {
			t.Fatalf("authorized PAT replay status=%d", response.Code)
		}
	})
	t.Run("native audit collision rolls back queued effect and outbox", func(t *testing.T) {
		var audit string
		if err := admin.QueryRow(ctx, `SELECT audit_id FROM zasp_recovery_audit ORDER BY audit_id LIMIT 1`).Scan(&audit); err != nil {
			t.Fatal(err)
		}
		forcedAudit = audit
		before := counts()
		body := strings.Replace(backupBody, testRecoveryBackupID, "pid_79000009-0000-4000-8000-000000000009", 1)
		response := call("POST", "/api/v1/recovery/backups", body, "recovery-audit-collision")
		if response.Code != 409 || counts() != before {
			t.Fatalf("rollback status=%d counts=%v", response.Code, counts())
		}
	})
	t.Run("source27 and current61 drift reject", func(t *testing.T) {
		for _, statement := range []string{`UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=27`, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_recovery_fingerprint'`, `GRANT SELECT ON zasp_recovery_backups TO zasp_discovery_api`, `UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`} {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, statement); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			var ready bool
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80.recovery_source_ready()`).Scan(&ready)
			rollback := tx.Rollback(ctx)
			if err != nil || rollback != nil || ready {
				t.Fatalf("source drift ready=%v err=%v rollback=%v", ready, err, rollback)
			}
		}
		var ready bool
		if err := admin.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("canonical61 readiness=%v err=%v", ready, err)
		}
	})
	// This is API enqueue/read evidence only. No outbox worker or provider runs.
	var pending bool
	if err := admin.QueryRow(ctx, `SELECT bool_and(state='pending' AND attempt=0 AND provider_ack IS NULL) FROM zasp_recovery_outbox`).Scan(&pending); err != nil || !pending {
		t.Fatalf("outbox touched by provider: %v %v", pending, err)
	}
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
}
