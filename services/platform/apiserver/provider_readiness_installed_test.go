package apiserver

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Temporarily perturb live authorizations, never publishing changes to the
// shared installation. Each test rolls back its transaction before the next.
func TestClaudeEnterpriseHookReadinessOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	const ready = "zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd')"
	const canonical = "zasp_authorization80.release_readiness_predicates_match()"
	transaction := func(label string, run func(*testing.T, pgx.Tx)) {
		t.Run(label, func(t *testing.T) {
			tx, err := b.admin.Begin(b.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(b.ctx)
			run(t, tx)
		})
	}
	exec := func(t *testing.T, tx pgx.Tx, sql string) {
		t.Helper()
		if _, err := tx.Exec(b.ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	assert := func(t *testing.T, tx pgx.Tx, check string) {
		t.Helper()
		var ok bool
		if err := tx.QueryRow(b.ctx, "SELECT "+check).Scan(&ok); err != nil || !ok {
			t.Fatalf("readiness assertion failed: %s (%v)", check, err)
		}
	}
	denyResolver := func(t *testing.T, tx pgx.Tx) {
		t.Helper()
		exec(t, tx, "SET LOCAL SESSION AUTHORIZATION zasp_svc_api")
		var raw []byte
		err := tx.QueryRow(b.ctx, "SELECT zasp_authorization80.resolve($1,$2,$3,'environment',$3,'')", b.o, b.w, b.e).Scan(&raw)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("changed reader could resolve the environment: %v", err)
		}
	}
	transaction("seal_and_exact_predicates", func(t *testing.T, tx pgx.Tx) { assert(t, tx, canonical+" AND zasp_baseline.intact() AND "+ready) })
	transaction("mutable_registration_is_live", func(t *testing.T, tx pgx.Tx) {
		exec(t, tx, "DELETE FROM zasp_authorization79.registration WHERE checksum='8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987'")
		assert(t, tx, canonical+" AND zasp_baseline.intact() AND NOT "+ready)
	})
	transaction("acl_drift", func(t *testing.T, tx pgx.Tx) {
		exec(t, tx, "GRANT EXECUTE ON FUNCTION zasp_authorization80.release_readiness_predicates_match() TO PUBLIC")
		assert(t, tx, "NOT zasp_baseline.intact() AND NOT "+ready)
	})
	transaction("unbound_login", func(t *testing.T, tx pgx.Tx) {
		exec(t, tx, "DELETE FROM public.zasp_discovery_principal_bindings WHERE principal_name='zasp_svc_api' AND authority_role='zasp_discovery_api'")
		assert(t, tx, "zasp_baseline.intact() AND "+ready)
		denyResolver(t, tx)
	})
	transaction("changed_resealed_predicate_uses_original_reader", func(t *testing.T, tx pgx.Tx) {
		// Simulate a future reviewed predicate with a stricter reader. The guarded
		// path must automatically defer to this changed definition.
		exec(t, tx, `CREATE OR REPLACE FUNCTION zasp_authorization79.reader() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT false'`)
		exec(t, tx, `UPDATE zasp_baseline.seal SET content=zasp_baseline.content(),marker=zasp_baseline.marker()`)
		assert(t, tx, "zasp_baseline.intact() AND NOT "+canonical+" AND "+ready)
		denyResolver(t, tx)
	})
	transaction("reverted_catalog_and_binding", func(t *testing.T, tx pgx.Tx) { assert(t, tx, canonical+" AND zasp_baseline.intact() AND "+ready) })
}
