package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestP7IdentityStructuralBootstrapPostgres(t *testing.T) {
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
	runner := migrateP7Authorization(t, ctx, owner)
	if err := runner.UpProductionAuthorizationIdentityProfile(ctx); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	var ready bool
	if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.structural_ready($1)`, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || !ready {
		t.Fatalf("empty-key structure: %t %v", ready, err)
	}
	var body []byte
	if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.metadata()`).Scan(&body); err == nil {
		t.Fatal("missing keys allowed runtime")
	}
	for _, purpose := range []string{"session", "webhook"} {
		key := sha256.Sum256([]byte("fixture-purpose-" + purpose))
		version := sha256.Sum256(key[:])
		v := hex.EncodeToString(version[:])
		var epoch int64
		q := `SELECT zasp_authorization80_identity.register_` + purpose + `($1,$2,$3,$4,$5,$6)`
		if err := owner.QueryRow(ctx, q, v, key[:], strings.Repeat("a", 64), "project-test-identity80", "auth80_api", "").Scan(&epoch); err != nil || epoch != 1 {
			t.Fatalf("register %s: %d %v", purpose, epoch, err)
		}
		if err := owner.QueryRow(ctx, q, v, key[:], strings.Repeat("a", 64), "project-test-identity80", "auth80_api", "").Scan(&epoch); err != nil || epoch != 1 {
			t.Fatalf("repeat %s: %d %v", purpose, epoch, err)
		}
		if err := api.QueryRow(ctx, q, v, key[:], strings.Repeat("a", 64), "project-test-identity80", "auth80_api", "").Scan(&epoch); err == nil {
			t.Fatal("API registered verifier")
		}
	}
	if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.metadata()`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var metadata map[string]map[string]any
	if json.Unmarshal(body, &metadata) != nil || len(metadata) != 2 {
		t.Fatal("invalid public metadata")
	}
	state := strings.Repeat("x", 43)
	if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.begin_login($1,'/discovery/assets')`, state).Scan(&ready); err != nil || !ready {
		t.Fatalf("begin: %t %v", ready, err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.consume_login($1)`, state).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var attempt struct {
		AttemptID   string `json:"attempt_id"`
		StateDigest string `json:"state_digest"`
		ReturnPath  string `json:"return_path"`
	}
	if json.Unmarshal(body, &attempt) != nil || len(attempt.AttemptID) != 64 || attempt.ReturnPath != "/discovery/assets" {
		t.Fatal("consumption output")
	}
	expected := sha256.Sum256([]byte(state))
	if attempt.StateDigest != hex.EncodeToString(expected[:]) {
		t.Fatal("consumption digest")
	}
	if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.consume_login($1)`, state).Scan(&body); err == nil {
		t.Fatal("state replay accepted")
	}
	if _, err := api.Exec(ctx, `SELECT key FROM zasp_authorization80_identity.verifiers`); err == nil {
		t.Fatal("API read verifier")
	}
	if _, err := api.Exec(ctx, `SELECT * FROM zasp_authorization80_identity.attempts`); err == nil {
		t.Fatal("API read attempt")
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `CREATE OR REPLACE FUNCTION public.zasp_identity_admin_authorized(organization_value text,principal_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $$ SELECT false $$`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_identity.structural_ready($1)`, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || ready {
		t.Errorf("unprojected source19 helper drift accepted: ready=%v error=%v", ready, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	t.Run("reveal-dependency-catalog-drift", func(t *testing.T) {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `CREATE INDEX identity_fixture_reveal_drift ON public.zasp_api_token_reveal_grants(expires_at)`); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_identity.structural_ready($1)`, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || ready {
			t.Errorf("consumed reveal catalog drift accepted: ready=%v error=%v", ready, err)
		}
	})
	t.Log("structural empty-key install/replay; explicit fixture registrations; API key/attempt isolation; begin/consume single use")
}
