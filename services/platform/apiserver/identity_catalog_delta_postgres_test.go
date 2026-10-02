package apiserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Probe catalog membership with transactional DDL only. This does not implement
// admission: the stand-in trigger refuses every write and is rolled back.
func TestP7IdentityCatalogDeltaPostgres(t *testing.T) {
	t.Setenv("ZASP_P7_AUDIT_TEST", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	sources := []string{"public.zasp_identity_administration_live_fingerprint()", "public.zasp_sa_attack_lab_live_fingerprint()", "public.zasp_sa_multistep_registered_live_fingerprint()", "zasp_authorization79.fingerprint()", "zasp_authorization80.fingerprint()", "zasp_authorization80_audit.fingerprint()"}
	read := func() []string {
		t.Helper()
		v := make([]string, len(sources))
		for i, f := range sources {
			if err := tx.QueryRow(ctx, "SELECT "+f).Scan(&v[i]); err != nil {
				t.Fatal(err)
			}
		}
		return v
	}
	initial := read()
	exec := func(q string) {
		t.Helper()
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	compare := func(stage string) {
		t.Helper()
		now := read()
		for i, f := range sources {
			t.Logf("catalog delta %s %s before=%s after=%s equal=%t", stage, f, initial[i], now[i], initial[i] == now[i])
			if initial[i] != now[i] {
				t.Errorf("unmeasured ancestry change at %s in %s", stage, f)
			}
		}
	}
	exec(`CREATE SCHEMA zasp_identity_catalog_probe AUTHORIZATION zasp_discovery_authority; CREATE FUNCTION zasp_identity_catalog_probe.write_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='probe only'; END $$; ALTER FUNCTION zasp_identity_catalog_probe.write_guard() OWNER TO zasp_discovery_authority; REVOKE ALL ON FUNCTION zasp_identity_catalog_probe.write_guard() FROM PUBLIC`)
	for _, table := range []string{"zasp_identity_states", "zasp_identity_memberships", "zasp_identity_member_groups", "zasp_product_sessions", "zasp_product_api_tokens", "zasp_group_mappings"} {
		exec(fmt.Sprintf(`CREATE TRIGGER zasp_identity_catalog_probe BEFORE INSERT OR UPDATE OR DELETE ON public.%s FOR EACH ROW EXECUTE FUNCTION zasp_identity_catalog_probe.write_guard()`, table))
	}
	compare("six-private-row-guards")
	exec(`GRANT SELECT(state_digest,return_path,expires_at,consumed_at),INSERT(state_digest,return_path,expires_at),UPDATE(consumed_at) ON public.zasp_identity_states TO zasp_discovery_authority; GRANT INSERT(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at) ON public.zasp_product_sessions TO zasp_discovery_authority`)
	compare("exact-state-session-column-grants")
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}
