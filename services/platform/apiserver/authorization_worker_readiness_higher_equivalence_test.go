package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This group consumes the installed roots, not a second implementation of the
// generator. Expected recipes come only from the independently hashed capture.
// Every mutation and temporary reference is rolled back before the real flow.
func assertWorkerHigherReadinessEquivalence(t *testing.T, ctx context.Context, owner *pgx.Conn, raw []byte) {
	t.Helper()
	var captured struct {
		Functions []struct{ Signature, Source, Definition string }
	}
	if err := json.Unmarshal(raw, &captured); err != nil {
		t.Fatal(err)
	}
	sources, definitions := map[string]string{}, map[string]string{}
	for _, f := range captured.Functions {
		sources[f.Signature], definitions[f.Signature] = f.Source, f.Definition
	}
	type rootSpec struct{ name, checksum, fingerprint string }
	roots := []rootSpec{
		{"zasp_temporal68.predecessor_ready", "b0ce6cf26b4b5f7e909f2e8e8ba5fdc987318efb21878c503117b4583b1544a8", "3559e54be45e44575699fb6fad8f23edffe3e98a5b8228f2b2b96ae42057ae92"},
		{"zasp_temporal68.ready", "bf5f2b8a2578c8d3c43b8edd0590c55a5eb7c48b178cca310e0ebadfc90e8eed", "437c678da9969a5935fe7efaa27f593fc58eaeac4e74ff434a5ed44eab2b75eb"},
		{"zasp_temporal78.ready", "29f2a16ea6d9021f159196106a9a57547cca797beaf87cc1fe15a937ae9b6021", "11b999b767465c01389f4482f9196852905866873e585574888281220538d1d4"},
	}
	module, err := os.ReadFile("../migrations/sql/0080_authorization_worker_readiness_graph.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(module), "$higher_records$")
	var manifest struct {
		Records []struct{ Signature string }
		Regions []struct{ Signature, Prefix, OriginalExpression, Suffix, Query string }
	}
	if len(parts) != 3 || json.Unmarshal([]byte(parts[1]), &manifest) != nil || len(manifest.Regions) != 3 || len(manifest.Records) == 0 {
		t.Fatal("higher records missing or malformed")
	}
	var identities []string
	for _, record := range manifest.Records {
		if definitions[record.Signature] == "" {
			t.Fatal("expanded identity missing independent reference", record.Signature)
		}
		identities = append(identities, record.Signature)
	}
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=$2 AND bool_and(p.oid IS NOT NULL AND
 (n.nspname='zasp_authorization80_worker' OR EXISTS(SELECT 1 FROM zasp_authorization80_worker.predecessor_functions s WHERE s.signature=p.oid::regprocedure::text)))
 FROM unnest($1::text[]) x(signature) LEFT JOIN pg_proc p ON p.oid=to_regprocedure(x.signature)
 LEFT JOIN pg_namespace n ON n.oid=p.pronamespace`, identities, len(identities)).Scan(&bound); err != nil || !bound {
		t.Fatal("higher expanded originals not live-pinned", err)
	}
	for _, root := range roots {
		if definitions[root.name+"(text,text)"] == "" {
			t.Fatal("original root missing", root.name)
		}
	}
	var workerChecksum, catalogBodyDigest string
	if err := owner.QueryRow(ctx, `SELECT (SELECT checksum FROM zasp_authorization80_worker.registration),
 encode(digest(convert_to(prosrc,'UTF8'),'sha256'),'hex') FROM pg_proc WHERE oid='zasp_authorization80_worker.catalog_ready()'::regprocedure`).Scan(&workerChecksum, &catalogBodyDigest); err != nil || len(workerChecksum) != 64 || len(catalogBodyDigest) != 64 {
		t.Fatal("compiled graph substitution metadata", err)
	}
	for _, region := range manifest.Regions {
		if strings.TrimSpace(region.Prefix+region.OriginalExpression+region.Suffix) != strings.TrimSpace(sources[region.Signature]) {
			t.Fatal("generated region does not reconstruct independent original", region.Signature)
		}
		want := region.Query
		if region.Prefix != "" || region.Suffix != "" {
			want = region.Prefix + "(" + region.Query + ")" + region.Suffix
		}
		want = strings.ReplaceAll(strings.ReplaceAll(want, "-- worker profile checksum", workerChecksum), "-- worker catalog body digest", catalogBodyDigest)
		var got string
		if err := owner.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid=$1::regprocedure`, region.Signature).Scan(&got); err != nil || strings.TrimSpace(got) != strings.TrimSpace(want) {
			t.Fatal("native candidate is not the emitted higher region", region.Signature, err)
		}
	}
	const tailAnchor = "FOREACH n IN ARRAY"
	originalPred := sources[roots[0].name+"(text,text)"]
	if strings.Count(originalPred, tailAnchor) != 1 {
		t.Fatal("original predecessor tail ambiguous")
	}
	var livePred string
	if err := owner.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid='zasp_temporal68.predecessor_ready(text,text)'::regprocedure`).Scan(&livePred); err != nil || strings.Count(livePred, tailAnchor) != 1 || strings.TrimSpace(strings.SplitN(livePred, tailAnchor, 2)[1]) != strings.TrimSpace(strings.SplitN(originalPred, tailAnchor, 2)[1]) {
		t.Fatal("dynamic predecessor tail changed", err)
	}
	static := strings.SplitN(strings.SplitN(originalPred, "\n IF ", 2)[1], " THEN RETURN false;END IF;", 2)[0]
	exec := func(t *testing.T, tx pgx.Tx, sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	checkCatalog := func(t *testing.T, q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, want bool) {
		t.Helper()
		var got bool
		if err := q.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready()`).Scan(&got); err != nil || got != want {
			t.Fatal("catalog state", err, got, want)
		}
	}
	// Preserve SQL NULL and SQLSTATE. Savepoints let an expected poisoned leaf
	// fail without aborting the subsequent original/candidate comparison.
	type outcome struct {
		value *bool
		state string
	}
	observe := func(t *testing.T, tx pgx.Tx, query string, args ...any) outcome {
		t.Helper()
		sub, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out outcome
		err = sub.QueryRow(ctx, query, args...).Scan(&out.value)
		if err != nil {
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) {
				t.Fatal("non-native comparison failure", err)
			}
			out.state = pgerr.Code
			if out.state != "PZ001" {
				t.Fatal("unexpected SQLSTATE is not equivalence evidence", out.state)
			}
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := sub.Rollback(cleanup); err != nil {
			t.Fatal("comparison savepoint rollback", err)
		}
		return out
	}
	compare := func(t *testing.T, tx pgx.Tx, index int, c, f any, clean bool) {
		t.Helper()
		a := observe(t, tx, "SELECT "+roots[index].name+"($1,$2)", c, f)
		b := observe(t, tx, fmt.Sprintf("SELECT pg_temp.higher_original_%d($1,$2)", index), c, f)
		equal := a.state == b.state && (a.value == nil && b.value == nil || a.value != nil && b.value != nil && *a.value == *b.value)
		if !equal || clean && (a.state != "" || a.value == nil || !*a.value) {
			t.Fatalf("root %s original/candidate differ: native states %q/%q, values %v/%v", roots[index].name, a.state, b.state, a.value, b.value)
		}
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
				t.Error("higher control rollback", err)
			}
		}()
		for i, root := range roots {
			def := definitions[root.name+"(text,text)"]
			anchor := "FUNCTION " + root.name + "("
			if strings.Count(def, anchor) != 1 {
				t.Fatal("reference definition anchor", root.name)
			}
			name := fmt.Sprintf("pg_temp.higher_original_%d", i)
			exec(t, tx, strings.Replace(def, anchor, "FUNCTION "+name+"(", 1))
			exec(t, tx, "ALTER FUNCTION "+name+"(text,text) OWNER TO zasp_discovery_authority")
			exec(t, tx, "REVOKE ALL ON FUNCTION "+name+"(text,text) FROM PUBLIC")
		}
		var temporarySchema string
		if err := tx.QueryRow(ctx, `SELECT nspname FROM pg_namespace WHERE oid=pg_my_temp_schema()`).Scan(&temporarySchema); err != nil {
			t.Fatal(err)
		}
		exec(t, tx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{temporarySchema}.Sanitize()+" TO zasp_discovery_authority")
		checkCatalog(t, tx, true) // Temporary recipes must not contaminate the pin.
		body(tx)
	}
	checkCatalog(t, owner, true)
	t.Run("higher-clean-arguments-and-digests", func(t *testing.T) {
		transaction(t, func(tx pgx.Tx) {
			for _, role := range []string{owner.Config().User, "zasp_discovery_authority"} {
				exec(t, tx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize())
				for i, r := range roots {
					compare(t, tx, i, r.checksum, r.fingerprint, true)
					for _, args := range [][2]any{{"wrong", r.fingerprint}, {nil, r.fingerprint}, {r.checksum, "wrong"}, {r.checksum, nil}, {nil, nil}} {
						compare(t, tx, i, args[0], args[1], false)
					}
				}
				var equal bool
				original := strings.TrimSuffix(strings.TrimSpace(sources["zasp_temporal77.base67_fingerprint()"]), ";")
				if err := tx.QueryRow(ctx, "SELECT zasp_temporal77.base67_fingerprint() IS NOT DISTINCT FROM ("+original+")").Scan(&equal); err != nil || !equal {
					t.Fatal("retained digest changed", err)
				}
				if err := tx.QueryRow(ctx, `SELECT zasp_temporal68.fingerprint()=$1 AND
 zasp_temporal67.fingerprint()='499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf' AND
 zasp_temporal78.fingerprint()=$2 AND zasp_authorization80_worker.projected_temporal_profile()=
 (SELECT fingerprint FROM zasp_authorization80_temporal.registration)`, roots[1].fingerprint, roots[2].fingerprint).Scan(&equal); err != nil || !equal {
					t.Fatal("retained domain/temporal digest bundle changed", err)
				}
			}
		})
	})
	const leaf = "public.zasp_discovery_schedule_replay_function_identity(oid)"
	for _, mutation := range []string{"body", "acl", "owner", "config", "saved-row", "root-body", "root-owner"} {
		t.Run("higher-fallback-"+mutation, func(t *testing.T) {
			transaction(t, func(tx pgx.Tx) {
				switch mutation {
				case "body":
					var def string
					if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, leaf).Scan(&def); err != nil || strings.Count(def, "AS $function$") != 1 {
						t.Fatal("leaf anchor", err)
					}
					exec(t, tx, strings.Replace(def, "AS $function$", "AS $function$\n-- same-result higher control\n", 1))
				case "acl":
					exec(t, tx, "GRANT EXECUTE ON FUNCTION "+leaf+" TO PUBLIC")
				case "owner":
					exec(t, tx, "ALTER FUNCTION "+leaf+" OWNER TO "+pgx.Identifier{owner.Config().User}.Sanitize())
					exec(t, tx, "GRANT EXECUTE ON FUNCTION "+leaf+" TO zasp_discovery_authority")
				case "config":
					exec(t, tx, "ALTER FUNCTION "+leaf+" SET search_path=pg_catalog,public,pg_temp")
				case "saved-row":
					var guarded bool
					if err := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(tgenabled='O' AND tgfoid='zasp_temporal67.immutable()'::regprocedure) FROM pg_trigger WHERE tgrelid='zasp_authorization80_worker.predecessor_functions'::regclass AND tgname='immutable' AND NOT tgisinternal`).Scan(&guarded); err != nil || !guarded {
						t.Fatal("saved-row guard", err)
					}
					exec(t, tx, `ALTER TABLE zasp_authorization80_worker.predecessor_functions DISABLE TRIGGER immutable`)
					tag, err := tx.Exec(ctx, `UPDATE zasp_authorization80_worker.predecessor_functions SET definition=definition||E'\n-- higher saved control' WHERE signature=$1::regprocedure::text`, roots[0].name+"(text,text)")
					if err != nil || tag.RowsAffected() != 1 {
						t.Fatal("saved-row mutation", err)
					}
					exec(t, tx, `ALTER TABLE zasp_authorization80_worker.predecessor_functions ENABLE TRIGGER immutable`)
				case "root-owner":
					// Change the actual definer frame, not merely the session caller.
					for i, r := range roots {
						for _, name := range []string{r.name, fmt.Sprintf("pg_temp.higher_original_%d", i)} {
							exec(t, tx, "ALTER FUNCTION "+name+"(text,text) OWNER TO "+pgx.Identifier{owner.Config().User}.Sanitize())
							exec(t, tx, "GRANT EXECUTE ON FUNCTION "+name+"(text,text) TO zasp_discovery_authority")
						}
					}
				case "root-body":
					for _, r := range roots {
						var def string
						if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, r.name+"(text,text)").Scan(&def); err != nil || strings.Count(def, "AS $function$") != 1 {
							t.Fatal("root body mutation anchor", err)
						}
						exec(t, tx, strings.Replace(def, "AS $function$", "AS $function$\n-- same-result higher root control\n", 1))
					}
				}
				exec(t, tx, "SET LOCAL ROLE zasp_discovery_authority")
				checkCatalog(t, tx, false)
				for i, r := range roots {
					compare(t, tx, i, r.checksum, r.fingerprint, false)
				}
				original := strings.TrimSuffix(strings.TrimSpace(sources["zasp_temporal77.base67_fingerprint()"]), ";")
				got := observe(t, tx, "SELECT zasp_temporal77.base67_fingerprint() IS NOT DISTINCT FROM ("+original+")")
				if got.state != "" || got.value == nil || !*got.value {
					t.Fatal("catalog-false retained digest mismatch")
				}
			})
			checkCatalog(t, owner, true)
		})
	}
	t.Run("higher-poison-short-circuit", func(t *testing.T) {
		transaction(t, func(tx pgx.Tx) {
			exec(t, tx, `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.catalog_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $poison$ BEGIN RAISE EXCEPTION 'fixed readiness poison' USING ERRCODE='PZ001'; END $poison$`)
			exec(t, tx, "SET LOCAL ROLE zasp_discovery_authority")
			if got := observe(t, tx, `SELECT zasp_authorization80_worker.catalog_ready()`); got.state != "PZ001" {
				t.Fatal("poison control did not raise its fixed SQLSTATE")
			}
			for i, r := range roots {
				compare(t, tx, i, r.checksum, r.fingerprint, false)
				for _, c := range []any{"wrong", nil} {
					compare(t, tx, i, c, r.fingerprint, false)
					if i == 0 {
						got := observe(t, tx, "SELECT "+r.name+"($1,$2)", c, r.fingerprint)
						if got.state != "" || got.value == nil || *got.value {
							t.Fatal("predecessor cheap rejection evaluated poison")
						}
					}
				}
			}
		})
		checkCatalog(t, owner, true)
	})
	for _, schema := range []string{"zasp_ordered_worker63", "zasp_ordered_scheduler64"} {
		t.Run("higher-orphan-"+schema, func(t *testing.T) {
			transaction(t, func(tx pgx.Tx) {
				var absent bool
				if err := tx.QueryRow(ctx, `SELECT to_regnamespace($1) IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal66.retired_authorities WHERE schema_name=$1)`, schema).Scan(&absent); err != nil || !absent {
					t.Fatal("orphan control requires absent baseline", err)
				}
				exec(t, tx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()+" AUTHORIZATION zasp_discovery_authority")
				exec(t, tx, "SET LOCAL ROLE zasp_discovery_authority")
				checkCatalog(t, tx, true)
				var bad *bool
				if err := tx.QueryRow(ctx, "SELECT ("+static+") FROM (SELECT $1::text c,$2::text f) original_arguments", roots[0].checksum, roots[0].fingerprint).Scan(&bad); err != nil || bad != nil && *bad {
					t.Fatal("orphan changed static guard; tail control confounded", err)
				}
				compare(t, tx, 0, roots[0].checksum, roots[0].fingerprint, false)
				got := observe(t, tx, "SELECT zasp_temporal68.predecessor_ready($1,$2)", roots[0].checksum, roots[0].fingerprint)
				if got.state != "" || got.value == nil || *got.value {
					t.Fatal("orphan namespace escaped native dynamic tail")
				}
			})
			checkCatalog(t, owner, true)
		})
	}
	if t.Failed() {
		t.Fatal("higher readiness controls failed before actual producer")
	}
	t.Log("higher readiness original/candidate truth, digest, drift, frame, poison and absent/orphan tail controls passed; no present-retired authority claim")
}
