package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A wrong expansion, stale copied leaf, or privileged-frame leak must fail
// against the independently captured pre-optimization recipe. No expected
// fingerprint is computed by the graph generator under test.
func assertWorkerReadinessGraphEquivalence(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	path := os.Getenv("ZASP_ORDERED_READINESS_REFERENCE")
	higher := os.Getenv("ZASP_ORDERED_HIGHER_READINESS")
	if higher != "" && (higher != "1" || path == "") {
		t.Fatal("higher readiness controls require explicit mode 1 and the original reference")
	}
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "720683fb7646085a2ecc226746cb3a71d9dd24d296a6ab2103cbf0d36573bb7c" {
		t.Fatal("readiness reference is not the reviewed original capture")
	}
	if higher == "1" {
		assertWorkerHigherReadinessEquivalence(t, ctx, owner, raw)
		return
	}
	var capture struct {
		Functions []struct{ Signature, Source string }
	}
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, f := range capture.Functions {
		sources[f.Signature] = strings.TrimSuffix(strings.TrimSpace(f.Source), ";")
	}
	const root = "zasp_temporal77.base67_fingerprint()"
	original := sources[root]
	if original == "" {
		t.Fatal("original readiness root absent")
	}
	module, err := os.ReadFile("../migrations/sql/0080_authorization_worker_readiness_graph.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(module), "$readiness_records$")
	var records []struct{ Signature string }
	if len(parts) != 3 || json.Unmarshal([]byte(parts[1]), &records) != nil || len(records) != 52 {
		t.Fatal("candidate expanded identity records malformed")
	}
	var signatures []string
	for _, r := range records {
		if sources[r.Signature] == "" {
			t.Fatal("expanded original missing from independent capture", r.Signature)
		}
		signatures = append(signatures, r.Signature)
	}
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=52 AND bool_and(
 p.oid IS NOT NULL AND (n.nspname='zasp_authorization80_worker' OR EXISTS(
 SELECT 1 FROM zasp_authorization80_worker.predecessor_functions s WHERE s.signature=p.oid::regprocedure::text)))
 FROM unnest($1::text[]) x(signature) LEFT JOIN pg_proc p ON p.oid=to_regprocedure(x.signature)
 LEFT JOIN pg_namespace n ON n.oid=p.pronamespace`, signatures).Scan(&bound); err != nil || !bound {
		t.Fatal("expanded originals are not independently bound by worker catalog", err)
	}
	transaction := func(t *testing.T, body func(pgx.Tx)) {
		t.Helper()
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := tx.Rollback(cleanup); err != nil {
				t.Error("readiness control rollback", err)
			}
		}()
		body(tx)
	}
	compare := func(t *testing.T, tx pgx.Tx, clean bool) {
		t.Helper()
		var equal, nonempty bool
		if err := tx.QueryRow(ctx, "SELECT "+root+" IS NOT DISTINCT FROM ("+original+"), COALESCE(length("+root+")=64,false)").Scan(&equal, &nonempty); err != nil || !equal || clean && !nonempty {
			t.Fatal("fused/original fingerprint mismatch", err, equal, nonempty)
		}
	}
	ready := func(t *testing.T, want bool) {
		t.Helper()
		var actual bool
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready()`).Scan(&actual); err != nil || actual != want {
			t.Fatal("worker catalog restoration", err, actual)
		}
	}
	ready(t, true)
	for _, role := range []string{owner.Config().User, "zasp_discovery_authority"} {
		t.Run("readiness-equivalence-"+role, func(t *testing.T) {
			transaction(t, func(tx pgx.Tx) {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				compare(t, tx, true)
			})
		})
	}
	// This retained invoker leaf has no owner-switch semantics. Changing its
	// owner while preserving authority EXECUTE tests the pin, not an unrelated
	// permission error that would prevent comparison of the actual recipes.
	const leaf = "public.zasp_discovery_schedule_replay_function_identity(oid)"
	for _, mutation := range []string{"same-result-body", "acl", "owner", "config", "saved-row"} {
		t.Run("readiness-drift-"+mutation, func(t *testing.T) {
			transaction(t, func(tx pgx.Tx) {
				statement := ""
				switch mutation {
				case "same-result-body":
					var definition string
					if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, leaf).Scan(&definition); err != nil || strings.Count(definition, "AS $function$") != 1 {
						t.Fatal("drift definition anchor", err)
					}
					statement = strings.Replace(definition, "AS $function$", "AS $function$\n-- same-result readiness control\n", 1)
				case "acl":
					statement = "GRANT EXECUTE ON FUNCTION " + leaf + " TO PUBLIC"
				case "owner":
					statement = "ALTER FUNCTION " + leaf + " OWNER TO " + pgx.Identifier{owner.Config().User}.Sanitize()
				case "config":
					statement = "ALTER FUNCTION " + leaf + " SET search_path=pg_catalog,public,pg_temp"
				case "saved-row":
					// Exercise the independent saved-byte pin as the fixture owner.
					// Restore the exact immutable trigger before checking readiness;
					// otherwise a disabled trigger could explain the refusal itself.
					var immutable bool
					if err := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(tgenabled='O' AND tgfoid='zasp_temporal67.immutable()'::regprocedure)
 FROM pg_trigger WHERE tgrelid='zasp_authorization80_worker.predecessor_functions'::regclass AND tgname='immutable' AND NOT tgisinternal`).Scan(&immutable); err != nil || !immutable {
						t.Fatal("saved catalog immutable guard identity", err)
					}
					if _, err := tx.Exec(ctx, `ALTER TABLE zasp_authorization80_worker.predecessor_functions DISABLE TRIGGER immutable`); err != nil {
						t.Fatal(err)
					}
					tag, err := tx.Exec(ctx, `UPDATE zasp_authorization80_worker.predecessor_functions SET definition=definition||E'\n-- saved readiness control' WHERE signature=$1::regprocedure::text`, leaf)
					if err != nil || tag.RowsAffected() != 1 {
						t.Fatal("saved original mutation", err)
					}
					if _, err := tx.Exec(ctx, `ALTER TABLE zasp_authorization80_worker.predecessor_functions ENABLE TRIGGER immutable`); err != nil {
						t.Fatal(err)
					}
				}
				if statement != "" {
					if _, err := tx.Exec(ctx, statement); err != nil {
						t.Fatal(err)
					}
				}
				if mutation == "owner" {
					if _, err := tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+leaf+" TO zasp_discovery_authority"); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE zasp_discovery_authority"); err != nil {
					t.Fatal(err)
				}
				var allowed bool
				if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready()`).Scan(&allowed); err != nil || allowed {
					t.Fatal("expanded original drift escaped live catalog", err)
				}
				compare(t, tx, false)
			})
			ready(t, true)
		})
	}
	for _, spec := range []struct{ signature, name, kind, value string }{
		{"zasp_authorization79.ready(text)", "c", "text", "'8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987'"},
		{"zasp_security_agent_budgets_function_identity(oid)", "function_value", "oid", "'public.zasp_security_agent_live_fingerprint()'::regprocedure::oid"},
		{"zasp_discovery_schedule_replay_function_identity(oid)", "value", "oid", "'public.zasp_execution_live_fingerprint()'::regprocedure::oid"},
	} {
		t.Run("readiness-argument-"+spec.name, func(t *testing.T) {
			transaction(t, func(tx pgx.Tx) {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE zasp_discovery_authority"); err != nil {
					t.Fatal(err)
				}
				name := strings.Split(spec.signature, "(")[0]
				if sources[spec.signature] == "" {
					t.Fatal("parameter reference absent")
				}
				for _, argument := range []string{"NULL::" + spec.kind, spec.value} {
					call := name + "(" + argument + ")"
					inline := "(" + sources[spec.signature] + " FROM (SELECT (" + argument + ")::" + spec.kind + " AS " + pgx.Identifier{spec.name}.Sanitize() + ") AS readiness_argument)"
					var equal bool
					if err := tx.QueryRow(ctx, "SELECT "+call+" IS NOT DISTINCT FROM "+inline).Scan(&equal); err != nil || !equal {
						t.Fatal("argument binding changes native scalar behavior", err)
					}
					var count int
					if err := tx.QueryRow(ctx, "SELECT count(*) FROM (SELECT "+inline+" FROM (SELECT 1 WHERE false) empty_input) q").Scan(&count); err != nil || count != 0 {
						t.Fatal("scalar expansion created a row for empty outer input", err)
					}
				}
			})
		})
	}
	if t.Failed() {
		t.Fatal("readiness equivalence controls failed before forward flow")
	}
	t.Log("native readiness original/fused role, drift and argument controls passed; no cross-call cache used")
}
