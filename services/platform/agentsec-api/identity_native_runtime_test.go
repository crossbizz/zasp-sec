package main

import (
	"context"
	"io"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type unsupportedIdentityRuntimeDatabase struct {
	*apiserver.PostgresJSONDatabase
}
type nilIdentityRuntimeDatabase struct {
	*apiserver.PostgresJSONDatabase
}

func (*nilIdentityRuntimeDatabase) NativeIdentityDatabase() *apiserver.PostgresJSONDatabase {
	return nil
}

// The apiserver parent owns this PostgreSQL/HTTP fixture and joins this child
// before stopping either. Never use a deployment DSN or provider here.
func TestP7IdentityTracedNativeRuntime(t *testing.T) {
	dsn, base := os.Getenv("ZASP_P7_IDENTITY_FIXTURE_DSN"), os.Getenv("ZASP_P7_IDENTITY_FIXTURE_PROVIDER")
	if dsn == "" || base == "" {
		t.Skip("requires owned parent fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("fixture pool")
	}
	defer pool.Close()
	db, err := apiserver.NewPostgresJSONDatabase(&pgxProductionDriver{pool: pool})
	if err != nil || db.RequireCurrentAuthorization() != nil {
		t.Fatal("native database")
	}
	raw, err := apiserver.NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	config := RuntimeConfig{PublicOrigin: "https://console.example", StytchBaseURL: base, StytchProjectID: "project-test-identity80", StytchOrganizationID: "organization-identity80-one", DeploymentMode: "saas", WorkflowSigningKey: "identity-fixture-seed-01234567890123456789"}
	auth, err := apiserver.NewStytchOAuthAuthenticator(base, config.StytchProjectID, "secret-fixture-only", time.Second, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		t.Fatal(err)
	}
	provider, err := apiserver.NewRepositoryIdentityProviderWithStart(auth, raw, raw, base+"/v1/b2b/public/oauth/google/start", "public-token-fixture", config.StytchOrganizationID, config.PublicOrigin+"/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.RequireNativeIdentity([]byte(config.WorkflowSigningKey), runtimeIdentityDeployment(config)); err != nil {
		t.Fatal(err)
	}
	traced := &tracedJSONDatabase{next: db, metrics: newOperationalMetrics(), exporter: newStructuredSpanExporter(io.Discard)}
	mounted, err := apiserver.NewPostgresRepository(traced)
	if err != nil {
		t.Fatal(err)
	}
	if err := mounted.Ready(ctx); err != nil {
		t.Errorf("actual traced repository readiness: %v", err)
	}
	target, err := provider.Start(ctx, "/")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(target)
	cb, _ := url.Parse(u.Query().Get("login_redirect_url"))
	grant, err := provider.Complete(ctx, "one", cb.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	forged := apiserver.SessionGrant{PrincipalID: grant.PrincipalID, Scope: grant.Scope, Permissions: grant.Permissions, ExpiresAt: grant.ExpiresAt}
	for _, wrapper := range []apiserver.JSONDatabase{&unsupportedIdentityRuntimeDatabase{db}, &nilIdentityRuntimeDatabase{db}} {
		r, err := apiserver.NewPostgresRepository(wrapper)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateSession(ctx, grant); err == nil {
			t.Error("unsupported/nil native wrapper accepted handoff")
		}
	}
	if _, err := mounted.CreateSession(ctx, forged); err == nil {
		t.Error("ordinary grant accepted by traced repository")
	}
	changed := grant
	changed.PrincipalID, _ = domain.ParseProductID("pid_98000002-0000-4000-8000-000000000004")
	if _, err := mounted.CreateSession(ctx, changed); err == nil {
		t.Error("changed grant accepted by traced repository")
	}
	otherDB, _ := apiserver.NewPostgresJSONDatabase(&pgxProductionDriver{pool: pool})
	_ = otherDB.RequireCurrentAuthorization()
	other, err := apiserver.NewPostgresRepository(otherDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.CreateSession(ctx, grant); err == nil {
		t.Error("different native database accepted handoff")
	}
	token, err := mounted.CreateSession(ctx, grant)
	if err != nil {
		t.Fatalf("raw provider to actual traced consumer: %v", err)
	}
	got, err := mounted.Authenticate(ctx, apiserver.Credential{Kind: apiserver.CredentialBrowserSession, Value: token})
	if err != nil {
		t.Fatal(err)
	}
	if err := mounted.Revoke(ctx, got, token); err != nil {
		t.Errorf("actual traced self revoke: %v", err)
	}
	t.Log("actual tracedJSONDatabase consumed shared raw native database; forged/changed/different-database handoffs refused")
}
