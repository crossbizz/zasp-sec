package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestP7IdentityVerifiedProviderPostgres(t *testing.T) {
	runIdentityVerifiedProviderFixture(t, nil)
}

// A consuming test can reuse the native installation and controlled provider
// without copying its SQL or running the independent identity protocol matrix.
func runIdentityVerifiedProviderFixture(t *testing.T, consume func(context.Context, string, *pgx.Conn, *pgx.Conn, *PostgresJSONDatabase, *PostgresRepository, *RepositoryIdentityProvider, func() string)) {
	t.Helper()
	t.Setenv("ZASP_P7_AUDIT_TEST", "1")
	t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	var exchanges, sessions atomic.Int32
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var input map[string]any
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			w.WriteHeader(400)
			return
		}
		project, secret, ok := r.BasicAuth()
		if !ok || project != "project-test-identity80" || secret != "secret-fixture-only" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/b2b/oauth/authenticate":
			exchanges.Add(1)
			code, _ := input["oauth_token"].(string)
			if code != "one" && code != "two" {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"status_code":401}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status_code": 200, "session_jwt": "header." + code + ".signature"})
		case "/v1/b2b/sessions/authenticate":
			sessions.Add(1)
			jwt, _ := input["session_jwt"].(string)
			suffix := "one"
			if jwt == "header.two.signature" {
				suffix = "two"
			} else if jwt != "header.one.signature" {
				w.WriteHeader(401)
				return
			}
			member, org := "member-identity80-"+suffix, "organization-identity80-"+suffix
			_ = json.NewEncoder(w).Encode(map[string]any{"status_code": 200, "member_session": map[string]any{"member_session_id": "member-session-identity80-" + suffix, "member_id": member, "organization_id": org, "started_at": now.Format(time.RFC3339), "last_accessed_at": now.Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339)}, "member": map[string]any{"member_id": member, "organization_id": org, "scim_registration": map[string]any{"scim_attributes": map[string]any{"groups": []any{map[string]any{"value": "scim-group-test-identity80-" + suffix}}}}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	deployment := authorization.IdentityDeployment{PublicOrigin: "https://console.example", ProviderBaseURL: server.URL, ProjectID: "project-test-identity80", ConfiguredOrganization: "organization-identity80-one", Mode: "saas"}
	audience, err := deployment.Audience()
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("identity-fixture-seed-01234567890123456789")
	sk, _ := authorization.NewIdentitySessionKey(seed)
	wk, _ := authorization.NewIdentityWebhookKey(seed)
	for _, v := range []struct {
		purpose, version string
		key              []byte
	}{{"session", sk.Version(), sk.Verifier()}, {"webhook", wk.Version(), wk.Verifier()}} {
		var epoch int64
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.register_`+v.purpose+`($1,$2,$3,$4,'auth80_api','')`, v.version, v.key, audience, deployment.ProjectID).Scan(&epoch); err != nil {
			t.Fatal(err)
		}
	}
	for n, suffix := range []string{"one", "two"} {
		id := func(part int) string { return fmt.Sprintf("pid_980000%02d-0000-4000-8000-%012d", n+1, part) }
		o, w, e, p := id(1), id(2), id(3), id(4)
		statements := []struct {
			q string
			a []any
		}{
			{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Identity',$2)`, []any{o, suffix + ".identity.invalid"}},
			{`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Identity')`, []any{o, w}},
			{`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Identity','production')`, []any{o, w, e}},
			{`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,$3,$4,'security_admin',true)`, []any{p, o, "organization-identity80-" + suffix, "member-identity80-" + suffix}},
			{`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Identity','[]',true)`, []any{p, o, w, e}},
		}
		for _, s := range statements {
			if _, err := owner.Exec(ctx, s.q, s.a...); err != nil {
				t.Fatal(err)
			}
		}
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	if err := db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewStytchOAuthAuthenticator(server.URL, deployment.ProjectID, "secret-fixture-only", time.Second, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewRepositoryIdentityProviderWithStart(auth, repo, repo, server.URL+"/v1/b2b/public/oauth/google/start", "public-token-fixture", deployment.ConfiguredOrganization, deployment.PublicOrigin+"/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.RequireNativeIdentity(seed, deployment); err != nil {
		t.Fatal(err)
	}
	if err := provider.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	t.Run("current-repository-readiness", func(t *testing.T) {
		if err := repo.Ready(ctx); err != nil {
			t.Errorf("registered identity repository readiness: %v", err)
		}
	})
	start := func() string {
		t.Helper()
		target, err := provider.Start(ctx, "/discovery/assets")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(target)
		cb, _ := url.Parse(u.Query().Get("login_redirect_url"))
		return cb.Query().Get("state")
	}
	if consume != nil {
		consume(ctx, dsn, owner, api, db, repo, provider, start)
		return
	}
	for n, suffix := range []string{"one", "two"} {
		t.Run(suffix, func(t *testing.T) {
			state := start()
			grant, err := provider.Complete(ctx, suffix, state)
			if err != nil {
				t.Fatalf("verified callback: %v", err)
			}
			if grant.ReturnTo != "/discovery/assets" || grant.nativeAdmission == nil {
				t.Fatal("missing private handoff")
			}
			if grant.Scope.OrganizationID().String() != fmt.Sprintf("pid_980000%02d-0000-4000-8000-000000000001", n+1) {
				t.Fatal("provider organization mapped to wrong tenant")
			}
			var desired, applied int64
			if err := owner.QueryRow(ctx, `SELECT desired,applied FROM zasp_authorization79.organizations WHERE organization_id=$1`, grant.Scope.OrganizationID().String()).Scan(&desired, &applied); err != nil || desired <= applied {
				t.Fatalf("expected own pending projection %d/%d %v", desired, applied, err)
			}
			forged := grant
			forged.nativeAdmission = nil
			if _, err := repo.CreateSession(ctx, forged); err == nil {
				t.Fatal("ordinary grant issued")
			}
			token, err := repo.CreateSession(ctx, grant)
			if err != nil {
				t.Fatalf("native issue: %v", err)
			}
			got, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token})
			if err != nil || got.PrincipalID != grant.PrincipalID || got.Scope != grant.Scope || len(got.Permissions) != 0 {
				t.Fatalf("issued credential authentication: %v", err)
			}
			if strings.Contains(fmt.Sprintf("%+v %#v", grant, grant), token) {
				t.Fatal("prepared credential in formatted grant")
			}
			if _, err := repo.CreateSession(ctx, grant); err == nil {
				t.Fatal("issue replay accepted")
			}
			if _, err := provider.Complete(ctx, suffix, state); err == nil {
				t.Fatal("state replay accepted")
			}
			updated, err := repo.SwitchScope(ctx, got, token, got.Scope)
			if err != nil || updated.Scope != got.Scope || updated.CSRFToken != got.CSRFToken || len(updated.Permissions) != 0 {
				t.Errorf("checked self scope switch: %v", err)
			}
			wrong := got
			wrong.CSRFToken = strings.Repeat("wrong", 9)
			if err := repo.Revoke(ctx, wrong, token); err == nil {
				t.Error("wrong CSRF logout accepted")
			}
			if err := repo.Revoke(ctx, got, token); err != nil {
				t.Errorf("checked logout: %v", err)
			} else if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token}); err == nil {
				t.Error("revoked credential still authenticates")
			}
		})
	}
	failed := start()
	if _, err := provider.Complete(ctx, "invalid", failed); err == nil {
		t.Fatal("invalid provider accepted")
	}
	if _, err := provider.Complete(ctx, "one", failed); err == nil {
		t.Fatal("provider failure revived consumed state")
	}
	if exchanges.Load() != 3 || sessions.Load() != 2 {
		t.Fatalf("provider calls exchange=%d session=%d", exchanges.Load(), sessions.Load())
	}
	t.Run("expiry-after-wait", func(t *testing.T) {
		exerciseIdentityExpiryAfterWait(t, ctx, owner, api, provider, repo, start, sk)
	})
	exerciseIdentityProtocol(t, ctx, owner, api, provider, repo, db, start, sk, wk)
	exerciseIdentityProjectionRelease(t, ctx, owner, api, provider, repo, db, start, wk)
	t.Run("actual-traced-runtime-consumer", func(t *testing.T) {
		config := api.Config()
		dsn, _ := url.Parse(config.ConnString())
		dsn.User = url.UserPassword(config.User, config.Password)
		cmd := exec.CommandContext(ctx, "go", "test", "../agentsec-api", "-run", "^TestP7IdentityTracedNativeRuntime$", "-count=1", "-v")
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "ZASP_") {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "ZASP_P7_IDENTITY_FIXTURE_DSN="+dsn.String(), "ZASP_P7_IDENTITY_FIXTURE_PROVIDER="+server.URL)
		out, err := cmd.CombinedOutput()
		if strings.Contains(string(out), dsn.String()) {
			t.Fatal("child disclosed fixture DSN")
		}
		t.Logf("joined actual runtime child:\n%s", out)
		if err != nil {
			t.Errorf("traced child: %v", err)
		}
	})
	t.Run("verified-webhook-native-and-durable-replay", func(t *testing.T) {
		stale, err := provider.Complete(ctx, "two", start())
		if err != nil {
			t.Fatal(err)
		}
		secret := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
		body := []byte(fmt.Sprintf(`{"action":"DELETE","details":{"organization_id":"organization-identity80-two"},"event_id":"webhook-event-test-identity80-delete-two","id":"member-identity80-two","object_type":"member","project_id":"project-test-identity80","source":"SCIM","timestamp":%q,"vertical":"B2B","workspace_id":"workspace-test-identity80"}`, now.Format(time.RFC3339)))
		for attempt := 0; attempt < 2; attempt++ {
			// A new verifier on each delivery forces the second delivery through
			// the durable database receipt, not its process-local replay cache.
			h, err := NewProductionNativeStytchWebhookHandler(repo, secret, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }, seed, deployment)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, signedStytchWebhookRequest(body, secret, time.Now()))
			want := "{\"processed\":true}\n"
			if attempt == 1 {
				want = "{\"processed\":false}\n"
			}
			if response.Code != http.StatusAccepted || response.Body.String() != want {
				t.Errorf("verified delivery %d: status=%d body=%s", attempt, response.Code, response.Body.String())
			}
		}
		var inactive bool
		var receipts, audits int
		if err := owner.QueryRow(ctx, `SELECT NOT active,(SELECT count(*) FROM zasp_identity_webhook_events WHERE event_id='webhook-event-test-identity80-delete-two'),(SELECT count(*) FROM zasp_admin_audit WHERE action='identity.member.deprovision' AND target_id=m.principal_id) FROM zasp_identity_memberships m WHERE organization_reference='organization-identity80-two'`).Scan(&inactive, &receipts, &audits); err != nil || !inactive || receipts != 1 || audits != 1 {
			t.Errorf("native deprovision effects: inactive=%v receipts=%d audits=%d error=%v", inactive, receipts, audits, err)
		}
		digest := sha256.Sum256(body)
		var raw json.RawMessage
		err = api.QueryRow(ctx, `SELECT public.zasp_identity_admin_reconcile_deprovision($1,$2,$3,$4,$5,$6)`, deployment.ProjectID, "webhook-event-test-identity80-delete-two", "organization-identity80-two", "member-identity80-two", digest[:], "pid_98000002-0000-4000-8000-000000000077").Scan(&raw)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Errorf("unsigned legacy receipt replay: error=%v response=%s", err, raw)
		}
		if _, err := repo.CreateSession(ctx, stale); err == nil {
			t.Error("resolved-before-deprovision proof issued after committed webhook")
		}
	})
	t.Run("PAT-use-validates-before-write", func(t *testing.T) {
		const raw = "identity80-pat-fixture-credential-0123456789"
		const org = "pid_98000001-0000-4000-8000-000000000001"
		const principal = "pid_98000001-0000-4000-8000-000000000004"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest($1,'sha256'),'pid_98000001-0000-4000-8000-000000000099','Identity PAT',$2,$3,'pid_98000001-0000-4000-8000-000000000002','pid_98000001-0000-4000-8000-000000000003','["view"]',clock_timestamp()+interval '1 hour')`, raw, principal, org); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw})
		if err != nil || len(got.Permissions) != 0 || !slices.Equal(got.credentialBinding.PATCeiling, []string{"view"}) {
			t.Fatalf("checked PAT authentication/ceiling: %v", err)
		}
		var before, after time.Time
		if err := owner.QueryRow(ctx, `SELECT last_used_at FROM zasp_product_api_tokens WHERE token_digest=digest($1,'sha256')`, raw).Scan(&before); err != nil {
			t.Fatal(err)
		}
		deprovision, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := deprovision.Exec(ctx, `SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, org); err != nil {
			t.Fatal(err)
		}
		if _, err := deprovision.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, org, principal); err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		go func() {
			_, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw})
			finished <- err
		}()
		early := false
		var concurrentError error
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
	waiting:
		for {
			select {
			case concurrentError = <-finished:
				early = true
				break waiting
			case <-ticker.C:
				var locked bool
				if err := deprovision.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, api.PgConn().PID()).Scan(&locked); err != nil {
					t.Fatal(err)
				}
				if locked {
					break waiting
				}
			case <-deadline.C:
				t.Error("PAT race neither completed nor waited on identity fence")
				break waiting
			}
		}
		if err := deprovision.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if !early {
			concurrentError = <-finished
		}
		if early || concurrentError == nil {
			t.Errorf("PAT crossed uncommitted member change: early=%v accepted=%v", early, concurrentError == nil)
		}
		if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw}); err == nil {
			t.Error("inactive member PAT accepted")
		}
		if err := owner.QueryRow(ctx, `SELECT last_used_at FROM zasp_product_api_tokens WHERE token_digest=digest($1,'sha256')`, raw).Scan(&after); err != nil || !after.Equal(before) {
			t.Errorf("rejected PAT authentication changed last_used_at: before=%s after=%s error=%v", before, after, err)
		}
	})
	t.Log("two accepted provider organizations, pending-projection session issue, actual credential authentication, private provenance, replay and provider-failure consumption")
}
