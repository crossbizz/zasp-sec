package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
)

// Test-only fixture signing deliberately exercises malformed native input. No
// generic signing operation is available from production code or the API role.
func identityFixtureEnvelope(t *testing.T, original []byte, key []byte, mutate func(map[string]any), duplicate bool) string {
	t.Helper()
	var outer struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}
	if json.Unmarshal(original, &outer) != nil {
		t.Fatal("fixture envelope")
	}
	var body map[string]any
	if json.Unmarshal(outer.Body, &body) != nil {
		t.Fatal("fixture body")
	}
	mutate(body)
	outer.Body, _ = json.Marshal(body)
	if duplicate {
		outer.Body = append([]byte(`{"epoch":1,`), outer.Body[1:]...)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("zasp-identity-session-attestation-v1\x00"))
	_, _ = mac.Write(outer.Body)
	outer.MAC = hex.EncodeToString(mac.Sum(nil))
	raw, _ := json.Marshal(outer)
	return string(raw)
}

func exerciseIdentityProtocol(t *testing.T, ctx context.Context, owner, api *pgx.Conn, provider *RepositoryIdentityProvider, repo *PostgresRepository, db *PostgresJSONDatabase, start func() string, sk *authorization.IdentitySessionKey, wk *authorization.IdentityWebhookKey) {
	t.Helper()
	grant := func() SessionGrant {
		t.Helper()
		g, e := provider.Complete(ctx, "one", start())
		if e != nil {
			t.Fatal(e)
		}
		return g
	}
	originalDeployment := provider.identityIssuer.deployment
	registration := func(purpose string, key []byte, version string, d authorization.IdentityDeployment) int64 {
		t.Helper()
		audience, err := d.Audience()
		if err != nil {
			t.Fatal(err)
		}
		var epoch int64
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.register_`+purpose+`($1,$2,$3,$4,'auth80_api',$5)`, version, key, audience, d.ProjectID, d.OrganizationPin()).Scan(&epoch); err != nil {
			t.Fatal(err)
		}
		return epoch
	}
	t.Run("key-rotation-and-config-fail-closed", func(t *testing.T) {
		stale := grant()
		a := stale.nativeAdmission
		next, _ := authorization.NewIdentitySessionKey([]byte("identity-next-fixture-seed-01234567890123456789"))
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var body []byte
		if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, string(a.envelope)).Scan(&body); err != nil {
			t.Fatal(err)
		}
		rotating, err := pgx.Connect(ctx, owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rotating.Exec(ctx, `SET lock_timeout='150ms'`); err != nil {
			t.Fatal(err)
		}
		audience, _ := originalDeployment.Audience()
		var epoch int64
		err = rotating.QueryRow(ctx, `SELECT zasp_authorization80_identity.register_session($1,$2,$3,$4,'auth80_api','')`, next.Version(), next.Verifier(), audience, originalDeployment.ProjectID).Scan(&epoch)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
			t.Errorf("registration bypassed live proof lock: %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		_ = rotating.Close(context.Background())
		if epoch := registration("session", next.Verifier(), next.Version(), originalDeployment); epoch != 2 {
			t.Errorf("rotation epoch=%d", epoch)
		}
		if provider.Ready(ctx) == nil {
			t.Error("old configured session key reported ready")
		}
		if _, err := provider.Start(ctx, "/"); err == nil {
			t.Error("start wrote state with wrong configured session key")
		}
		if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.issue_login($1,$2,$3)`, string(a.envelope), a.token, a.csrf).Scan(&body); err == nil {
			t.Error("old native epoch issued")
		}
		if epoch := registration("session", sk.Verifier(), sk.Version(), originalDeployment); epoch != 3 {
			t.Errorf("restored key epoch=%d", epoch)
		}
		nextWebhook, _ := authorization.NewIdentityWebhookKey([]byte("identity-next-fixture-seed-01234567890123456789"))
		registration("webhook", nextWebhook.Verifier(), nextWebhook.Version(), originalDeployment)
		if provider.Ready(ctx) == nil {
			t.Error("wrong configured webhook key reported ready")
		}
		if _, err := provider.Start(ctx, "/"); err == nil {
			t.Error("start wrote state with wrong configured webhook key")
		}
		registration("webhook", wk.Verifier(), wk.Version(), originalDeployment)
	})
	t.Run("dedicated-local-pin-before-resolve-commit", func(t *testing.T) {
		dedicated := originalDeployment
		dedicated.Mode = "single_tenant"
		dedicated.OrganizationID = "pid_98000002-0000-4000-8000-000000000001"
		registration("session", sk.Verifier(), sk.Version(), dedicated)
		registration("webhook", wk.Verifier(), wk.Version(), dedicated)
		provider.identityIssuer.deployment = dedicated
		if _, err := provider.Complete(ctx, "one", start()); err == nil {
			t.Error("dedicated local tenant mismatch resolved")
		}
		if _, err := provider.Complete(ctx, "two", start()); err == nil {
			t.Error("dedicated external tenant mismatch resolved")
		}
		registration("session", sk.Verifier(), sk.Version(), originalDeployment)
		registration("webhook", wk.Verifier(), wk.Version(), originalDeployment)
		provider.identityIssuer.deployment = originalDeployment
	})
	g := grant()
	t.Run("native-proof-rejections", func(t *testing.T) {
		cases := []struct {
			name      string
			edit      func(map[string]any)
			key       []byte
			duplicate bool
		}{
			{"wrong-domain", func(b map[string]any) { b["domain"] = "zasp-authorization-attestation-v1" }, sk.Verifier(), false},
			{"wrong-purpose-key", func(map[string]any) {}, wk.Verifier(), false},
			{"expired", func(b map[string]any) {
				b["issued_at"] = time.Now().Add(-2 * time.Minute).UnixMilli()
				b["expires_at"] = time.Now().Add(-time.Minute).UnixMilli()
			}, sk.Verifier(), false},
			{"future", func(b map[string]any) {
				b["issued_at"] = time.Now().Add(time.Hour).UnixMilli()
				b["expires_at"] = time.Now().Add(time.Hour + time.Minute).UnixMilli()
			}, sk.Verifier(), false},
			{"wrong-audience", func(b map[string]any) { b["audience"] = strings.Repeat("0", 64) }, sk.Verifier(), false},
			{"wrong-project", func(b map[string]any) { b["project"] = "project-test-other" }, sk.Verifier(), false},
			{"wrong-profile", func(b map[string]any) { b["profile"] = strings.Repeat("0", 64) }, sk.Verifier(), false},
			{"wrong-epoch", func(b map[string]any) { b["epoch"] = 0 }, sk.Verifier(), false},
			{"cross-tenant-substitution", func(b map[string]any) {
				b["organization"] = "organization-identity80-two"
				b["member"] = "member-identity80-two"
			}, sk.Verifier(), false},
			{"duplicate-key", func(map[string]any) {}, sk.Verifier(), true},
			{"duplicate-groups", func(b map[string]any) { b["groups"] = []string{"scim-group-test-a", "scim-group-test-a"} }, sk.Verifier(), false},
			{"unknown-field", func(b map[string]any) { b["permission"] = "manage_identity" }, sk.Verifier(), false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				original := g.nativeAdmission.envelope
				if c.name != "cross-tenant-substitution" {
					original = freshIdentityPrepared(t, ctx, provider, start).envelope
				}
				envelope := identityFixtureEnvelope(t, original, c.key, c.edit, c.duplicate)
				var raw []byte
				err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, envelope).Scan(&raw)
				var p *pgconn.PgError
				if !errors.As(err, &p) || p.Code != "42501" {
					t.Errorf("native malformed proof refusal: %v", err)
				}
				if c.name != "cross-tenant-substitution" {
					if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, string(original)).Scan(&raw); err != nil {
						t.Fatalf("unchanged fresh proof no longer resolves: %v", err)
					}
				}
			})
		}
		// Each independently resolved fixture can advance the retained BEFORE
		// capture even for INSERT ON CONFLICT. Use a current snapshot for replay.
		g = grant()
		var raw []byte
		if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, string(g.nativeAdmission.envelope)).Scan(&raw); err != nil {
			t.Fatalf("exact resolution replay: %v", err)
		}
	})
	t.Run("issue-output-rejection-rolls-back", func(t *testing.T) {
		a := g.nativeAdmission
		var before, after int64
		if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, g.Scope.OrganizationID().String()).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := db.identityTransaction(ctx, identityIssue, []any{string(a.envelope), a.token, a.csrf}, func(json.RawMessage) error { return ErrRepositoryAuthentication }); err == nil {
			t.Fatal("invalid consumer output committed")
		}
		var exists bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_product_sessions WHERE token_digest=digest($1,'sha256'))`, a.token).Scan(&exists); err != nil || exists {
			t.Errorf("rejected output persisted session: %v %v", exists, err)
		}
		if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, g.Scope.OrganizationID().String()).Scan(&after); err != nil || before != after {
			t.Errorf("rejected output persisted revision: %d/%d %v", before, after, err)
		}
		if _, err := repo.CreateSession(ctx, g); err != nil {
			t.Errorf("rollback consumed issuance attempt: %v", err)
		}
	})
	t.Run("member-change-between-resolve-and-issue", func(t *testing.T) {
		stale := grant()
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET version=version+1 WHERE organization_id=$1 AND principal_id=$2`, stale.Scope.OrganizationID().String(), stale.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateSession(ctx, stale); err == nil {
			t.Fatal("changed snapshot issued")
		}
	})
	t.Run("group-and-scope-change-between-resolve-and-issue", func(t *testing.T) {
		for _, q := range []string{`INSERT INTO zasp_identity_member_groups(organization_id,principal_id,group_reference) VALUES($1,$2,'scim-group-test-intervening')`, `UPDATE zasp_authorized_scopes SET permissions='["view"]' WHERE organization_id=$1 AND principal_id=$2`} {
			stale := grant()
			if _, err := owner.Exec(ctx, q, stale.Scope.OrganizationID().String(), stale.PrincipalID.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.CreateSession(ctx, stale); err == nil {
				t.Error("intervening group/scope change issued")
			}
		}
	})
	t.Run("applied-only-progress-preserves-issue", func(t *testing.T) {
		fresh := grant()
		if _, err := owner.Exec(ctx, `UPDATE zasp_authorization79.organizations SET applied=desired WHERE organization_id=$1`, fresh.Scope.OrganizationID().String()); err != nil {
			t.Fatal(err)
		}
		// Controlled revision progress tests snapshot admission only. It is not
		// an OpenFGA projection or permission assertion.
		if _, err := repo.CreateSession(ctx, fresh); err != nil {
			t.Errorf("applied-only progress rejected: %v", err)
		}
	})
	t.Run("simultaneous-native-issue-single-winner", func(t *testing.T) {
		fresh := grant()
		a := fresh.nativeAdmission
		other := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "auth80_api")
		defer other.Close(context.Background())
		begin := make(chan struct{})
		results := make(chan error, 2)
		for _, conn := range []*pgx.Conn{api, other} {
			go func(c *pgx.Conn) {
				<-begin
				var b []byte
				results <- c.QueryRow(ctx, `SELECT zasp_authorization80_identity.issue_login($1,$2,$3)`, string(a.envelope), a.token, a.csrf).Scan(&b)
			}(conn)
		}
		close(begin)
		accepted := 0
		for range 2 {
			err := <-results
			if err == nil {
				accepted++
			} else {
				var p *pgconn.PgError
				if !errors.As(err, &p) || p.Code != "42501" {
					t.Errorf("concurrent issue failure: %v", err)
				}
			}
		}
		if accepted != 1 {
			t.Errorf("simultaneous issue winners=%d", accepted)
		}
	})
	t.Run("mounted-callback-cookie-and-replay", func(t *testing.T) {
		dependencies := auditExportCompositionDependencies()
		dependencies.Session = &sessionHTTPHandler{repository: repo, provider: provider, cookie: CookiePolicy{Secure: true}, deploymentMode: "saas"}
		mounted, err := NewComposition(dependencies)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		mounted.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://console.example/api/v1/session/start?return_to=%2Fdiscovery%2Fassets", nil))
		target, err := url.Parse(response.Header().Get("Location"))
		if err != nil || target.Host == "" {
			t.Fatalf("mounted start status=%d", response.Code)
		}
		callback, _ := url.Parse(target.Query().Get("login_redirect_url"))
		state := callback.Query().Get("state")
		body, _ := json.Marshal(map[string]string{"provider_token": "one", "state": state})
		for attempt := 0; attempt < 2; attempt++ {
			req := httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/session/callback", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			response = httptest.NewRecorder()
			mounted.ServeHTTP(response, req)
			cookies := response.Result().Cookies()
			if attempt == 1 {
				if response.Code == http.StatusOK || len(cookies) != 0 {
					t.Errorf("callback replay set cookie: status=%d count=%d", response.Code, len(cookies))
				}
				continue
			}
			if response.Code != http.StatusOK || len(cookies) != 1 {
				t.Fatalf("mounted callback status=%d cookies=%d", response.Code, len(cookies))
			}
			c := cookies[0]
			if c.Name != browserSessionCookie || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
				t.Error("cookie policy changed")
			}
			if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: c.Value}); err != nil {
				t.Errorf("cookie credential not committed: %v", err)
			}
		}
	})
	exerciseIdentityReleaseNegatives(t, ctx, owner, api, provider, repo, start, sk)
}
