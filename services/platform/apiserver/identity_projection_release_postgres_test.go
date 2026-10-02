package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func exerciseIdentityProjectionRelease(t *testing.T, ctx context.Context, owner, api *pgx.Conn, provider *RepositoryIdentityProvider, repo *PostgresRepository, db *PostgresJSONDatabase, start func() string, wk *authorization.IdentityWebhookKey) {
	t.Helper()
	t.Run("issued-credential-requires-real-FGA-and-purpose-separation", func(t *testing.T) {
		if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
			t.Skip("requires owned local OpenFGA store")
		}
		const org = "pid_98000001-0000-4000-8000-000000000001"
		config, err := pgxpool.ParseConfig(owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.User = "auth80_outbox"
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		projection, err := authorization.NewPostgresProjectionRepository(pool)
		if err != nil {
			t.Fatal(err)
		}
		client, pins := newAuthorizationProjectionFGA(t)
		writer, err := authorization.NewOpenFGATupleWriter(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		checker, err := authorization.NewOpenFGA(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, org, pins.StoreID, pins.ModelID); err != nil {
			t.Fatal(err)
		}
		grant, err := provider.Complete(ctx, "one", start())
		if err != nil {
			t.Fatal(err)
		}
		sessionProof := append([]byte(nil), grant.nativeAdmission.envelope...)
		token, err := repo.CreateSession(ctx, grant)
		if err != nil {
			t.Fatal(err)
		}
		i, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token})
		if err != nil {
			t.Fatal(err)
		}
		resolver, err := NewPostgresAuthorizationResolver(db)
		if err != nil {
			t.Fatal(err)
		}
		authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
		route := RoutedOperation{OperationID: "listAPITokens"}
		var desired, applied int64
		if err := owner.QueryRow(ctx, `SELECT desired,applied FROM zasp_authorization79.organizations WHERE organization_id=$1`, org).Scan(&desired, &applied); err != nil || desired <= applied {
			t.Fatalf("identity issue not pending %d/%d %v", desired, applied, err)
		}
		if _, err := authorizer.Authorize(ctx, i, i.credentialBinding, route); err == nil {
			t.Fatal("identity-issued credential gained product access before projection")
		}
		if _, err := repo.ReadAdministration(ctx, i, route.OperationID, nil); err == nil {
			t.Fatal("identity credential bypassed product proof")
		}
		r, err := authorization.Reconcile(ctx, projection, writer, org, pins.StoreID, pins.ModelID)
		if err != nil || !r.Applied {
			t.Fatalf("actual FGA reconcile=%+v error=%v", r, err)
		}
		checked, err := authorizer.Authorize(ctx, i, i.credentialBinding, route)
		if err != nil {
			t.Fatal(err)
		}
		if len(checked.Decisions) == 0 || len(checked.Allowed) == 0 {
			t.Fatal("missing actual allowed FGA decision")
		}
		if _, err := repo.ReadAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, checked), i, route.OperationID, nil); err != nil {
			t.Fatalf("checked native PAT list after real projection: %v", err)
		}
		fgaProof, err := authorizationProofJSON(checked)
		if err != nil {
			t.Fatal(err)
		}

		// Obtain a real verifier-accepted webhook event before creating its
		// typed purpose admission; none of these substitution attempts applies it.
		now := time.Now().UTC().Truncate(time.Millisecond)
		secret := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x65}, 32))
		body := []byte(fmt.Sprintf(`{"action":"DELETE","details":{"organization_id":"organization-identity80-one"},"event_id":"webhook-event-test-identity-purpose-separation","id":"member-identity80-one","object_type":"member","project_id":"project-test-identity80","source":"SCIM","timestamp":%q,"vertical":"B2B","workspace_id":"workspace-test-identity80"}`, now.Format(time.RFC3339Nano)))
		request := signedStytchWebhookRequest(body, secret, now)
		verifier, err := platformidentity.NewWebhookVerifier("project-test-identity80", secret, func() time.Time { return now }, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		event, replay, err := verifier.Verify(body, platformidentity.WebhookHeaders{MessageID: request.Header.Get("Svix-Id"), Timestamp: request.Header.Get("Svix-Timestamp"), Signature: request.Header.Get("Svix-Signature")})
		if err != nil || replay {
			t.Fatalf("verified fixture event: %v", err)
		}
		metadata, err := repo.identityMetadata(ctx)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		webhookProof, err := wk.SignDeprovision(event, authorization.IdentityWebhookAdmission{Registration: metadata.Webhook, Profile: migrations.AuthorizationIdentityProfileChecksum(), BodyDigest: hex.EncodeToString(digest[:]), AuditID: "pid_98000001-0000-4000-8000-000000000088", VerifiedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name, query string
			proof       []byte
		}{
			{"FGA-to-session", `SELECT zasp_authorization80_identity.resolve_login($1)`, fgaProof},
			{"FGA-to-webhook", `SELECT zasp_authorization80_identity.apply_verified_deprovision($1)`, fgaProof},
			{"session-to-webhook", `SELECT zasp_authorization80_identity.apply_verified_deprovision($1)`, sessionProof},
			{"webhook-to-session", `SELECT zasp_authorization80_identity.resolve_login($1)`, webhookProof},
			{"session-to-product", `SELECT zasp_authorization80.fence($1)`, sessionProof},
			{"webhook-to-product", `SELECT zasp_authorization80.fence($1)`, webhookProof},
		} {
			t.Run(c.name, func(t *testing.T) { _, err := api.Exec(ctx, c.query, string(c.proof)); requireIdentityRefusal(t, err) })
		}
		var active bool
		var receipts int
		if err := owner.QueryRow(ctx, `SELECT active,(SELECT count(*) FROM zasp_identity_webhook_events WHERE event_id=$2) FROM zasp_identity_memberships WHERE organization_id=$1`, org, event.EventID).Scan(&active, &receipts); err != nil || !active || receipts != 0 {
			t.Fatalf("purpose substitution changed identity: %v/%d %v", active, receipts, err)
		}
		if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token}); err != nil {
			t.Fatalf("purpose substitution changed session: %v", err)
		}

		const rawPAT = "identity-release-view-only-PAT-01234567890123456789"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest($1,'sha256'),'pid_98000001-0000-4000-8000-000000000087','Ceiling',$2,$3,$4,$5,'["view"]',clock_timestamp()+interval '1 hour')`, rawPAT, i.PrincipalID.String(), org, i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()); err != nil {
			t.Fatal(err)
		}
		pat, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: rawPAT})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authorizer.Authorize(ctx, pat, pat.credentialBinding, route); err == nil {
			t.Error("view-only PAT gained manage_api_tokens")
		}
		var parsed map[string]any
		if json.Unmarshal(fgaProof, &parsed) != nil {
			t.Fatal("missing actual FGA envelope")
		}
		t.Log("identity-issued empty-permission browser credential denied while pending, then actual owned OpenFGA projection/Check and native read passed; six purpose substitutions refused")
	})
}
