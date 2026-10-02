package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type precisionResolverProgram struct {
	SQL, Collector, Legacy, Expression, Admission, PrivateQuery, ResolverSQL string
	Facts                                                                    []json.RawMessage
}

// Break caught: the emitted successor loses the original signature-resolution
// frame, scalar/lazy/error semantics, or invokes a forged text->oid resolver.
// Root alone executes opt-in PG; absent mode is a compile/skip, not native proof.
func TestP7PrecisionResolverSuccessor(t *testing.T) {
	mode := os.Getenv("ZASP_ORDERED_CURRENT_PRECISION_RESOLVER")
	if mode == "" {
		t.Skip("explicit owned precision resolver acceptance required")
	}
	if mode != "1" && mode != "red" {
		t.Fatal("precision resolver mode refused")
	}
	for _, key := range []string{"ZASP_ORDERED_CURRENT_PRECISION_FRAME_PROBE", "ZASP_ORDERED_CURRENT_NATIVE379", "ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE", "ZASP_ORDERED_MISSING_REFERENCE_NATIVE", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_POLICY_CAPACITY", "ZASP_P7_ORDERED69_RETIREMENT_ACL"} {
		if os.Getenv(key) != "" {
			t.Fatalf("precision resolver overlaps %s", key)
		}
	}
	precisionFrameVerifyPinnedBaseline(t)
	program := precisionResolverLoadProgram(t)
	consumed := false
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, func(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
		consumed = true
		precisionResolverOwned(t, ctx, owner, program, mode == "red")
		return true // No approval, FGA, provider or product-effect fallthrough.
	}, nil)
	if !consumed {
		t.Fatal("precision resolver owned callback not reached")
	}
}

// Execute source compilers only, never the development generator or artifacts.
// Facts come from the complete actual private8 SQL, not observed expected rows.
func precisionResolverLoadProgram(t *testing.T) precisionResolverProgram {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	script := `import fs from 'node:fs';
import {compileOrderedCollector,compileOrderedPrecisionResolverCollectorV1} from './services/platform/migrations/tools/ordered-current-catalog.mjs';
import {withOrderedPrecisionResolverClosureV1,compileOrderedPrecisionPrivateRoutinesV1} from './services/platform/migrations/tools/ordered-current-private.mjs';
import {lowerOrderedTemporal72Catalog} from './services/platform/migrations/tools/ordered-current-temporal72.mjs';
import {precisionResolverAdmissionSQLV1,precisionResolverInstallSQLV1} from './services/platform/migrations/tools/ordered-current-precision-resolver-frame-v1.mjs';
const contract=JSON.parse(fs.readFileSync('./services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json'));
const rules=lowerOrderedTemporal72Catalog(contract).rules.filter(r=>r.id==='temporal72:precision-function');
const collector=compileOrderedPrecisionResolverCollectorV1(rules).sql;
const template=withOrderedPrecisionResolverClosureV1(fs.readFileSync('./services/platform/migrations/sql/0080_authorization_worker_ordered_current_integrity.sql','utf8'));
const begin='  -- ordered-current:direct-collector-begin',end='  -- ordered-current:direct-collector-end';
const sql=template.slice(0,template.indexOf(begin))+begin+'\n'+collector+'\n'+template.slice(template.indexOf(end));
const compiled=compileOrderedPrecisionPrivateRoutinesV1(sql);
const start=collector.indexOf("'precision_definition',")+"'precision_definition',".length;
const stop=collector.indexOf(",'security_definer',",start);
if(start<23||stop<start)throw Error('precision selected field extraction');
console.log(JSON.stringify({sql,collector,legacy:compileOrderedCollector(rules).sql,expression:collector.slice(start,stop),admission:precisionResolverAdmissionSQLV1,privateQuery:compileOrderedCollector(compiled.rules).sql,facts:compiled.facts,resolverSQL:precisionResolverInstallSQLV1}));`
	cmd := exec.CommandContext(ctx, "/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node", "--input-type=module", "-e", script)
	cmd.Dir = orderedCurrentNative379Root()
	raw, err := cmd.Output()
	if err != nil || len(raw) > 1024*1024 {
		t.Fatal("precision source compiler refused", err)
	}
	var program precisionResolverProgram
	if json.Unmarshal(raw, &program) != nil || len(program.Facts) != 8 || program.Expression == "" || program.Admission == "" {
		t.Fatal("precision source program envelope refused")
	}
	return program
}

func precisionResolverOwned(t *testing.T, parent context.Context, owner *pgx.Conn, program precisionResolverProgram, red bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	const frameSQL = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),current_setting('transaction_read_only'),current_setting('transaction_isolation')`
	readFrame := func(q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}) [6]string {
		var frame [6]string
		if err := q.QueryRow(ctx, frameSQL).Scan(&frame[0], &frame[1], &frame[2], &frame[3], &frame[4], &frame[5]); err != nil {
			t.Fatal("precision frame read refused", err)
		}
		return frame
	}
	before := readFrame(owner)
	var version string
	if err := owner.QueryRow(ctx, `SELECT pg_catalog.version()`).Scan(&version); err != nil || version != transformAcceptancePostgres || before[0] != "zasp_test" || before[1] != "zasp_test" {
		t.Fatal("precision exact owned PG18.3/session refused")
	}
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	active := true
	defer func() {
		if active {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer done()
			if err := tx.Rollback(cleanup); err != nil {
				t.Error("precision rollback cleanup failed", err)
			}
		}
	}()
	execSQL := func(sql string) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal("precision bounded setup refused", err)
		}
	}
	var absent bool
	if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='zasp_authorization80_ordered_current')`).Scan(&absent); err != nil || !absent {
		t.Fatal("precision private namespace must be absent")
	}
	execSQL(program.SQL)
	execSQL(`SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog; SET LOCAL TimeZone='UTC'`)
	pristine := readFrame(tx)
	if pristine != [6]string{"zasp_test", "zasp_discovery_authority", "pg_catalog", "UTC", "off", "repeatable read"} {
		t.Fatal("precision pristine frame refused", pristine)
	}
	admitted := func() bool {
		var ok bool
		if err := tx.QueryRow(ctx, program.Admission).Scan(&ok); err != nil {
			t.Fatal("precision resolver admission failed", err)
		}
		return ok
	}
	fullAdmitted := func() bool {
		if !admitted() || readFrame(tx) != pristine {
			return false
		}
		rows, err := tx.Query(ctx, "SELECT pg_catalog.jsonb_build_object('kind',kind,'identity',identity,'fact',fact) FROM ("+program.PrivateQuery+") private_source")
		if err != nil {
			t.Fatal(err)
		}
		var facts []json.RawMessage
		for rows.Next() {
			var raw json.RawMessage
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			facts = append(facts, raw)
		}
		streamErr := rows.Err()
		rows.Close()
		if streamErr != nil {
			t.Fatal(streamErr)
		}
		return orderedCurrentPrivateSuccessorRoutineParity(facts, program.Facts)
	}
	if !fullAdmitted() {
		t.Fatal("precision complete private8 source admission refused")
	}
	collector := program.Collector
	if red {
		collector = program.Legacy
	}
	for _, guard := range precisionFrameGuards {
		identity, _ := json.Marshal([]string{"temporal72:precision-function", "public." + guard.signature})
		var definition *string
		if err := tx.QueryRow(ctx, "SELECT fact->>'precision_definition' FROM ("+collector+") emitted WHERE identity=$1", string(identity)).Scan(&definition); err != nil || definition == nil || supplementSHA([]byte(*definition)) != guard.definitionSHA {
			t.Fatal("precision emitted source-pinned guard mismatch", guard.signature, err, definition == nil)
		}
	}
	if red {
		t.Fatal("precision RED failed to expose lost frame")
	}
	// These are independent source operations. A rollback-only VALUES fixture
	// permits NULL definitions and alias multiplicity without touching saved PKs.
	const sourceScalar = `(SELECT definition FROM (VALUES ($1::text,$2::text),($3::text,$4::text)) saved(signature,definition) WHERE pg_catalog.to_regprocedure(signature)=p.oid)`
	fixture := strings.Replace(program.Expression, "FROM zasp_authorization80_runtime.predecessor_functions", "FROM (VALUES ($1::text,$2::text),($3::text,$4::text)) saved(signature,definition)", 1)
	fixtureSQL := "WITH precision_resolver_admission AS MATERIALIZED (" + program.Admission + ") SELECT " + fixture + " FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure($5)"
	type outcome struct {
		value *string
		state string
	}
	query := func(sql string, args ...any) outcome {
		execSQL("SAVEPOINT precision_case")
		var got outcome
		err := tx.QueryRow(ctx, sql, args...).Scan(&got.value)
		if err != nil {
			var native *pgconn.PgError
			if !errors.As(err, &native) {
				t.Fatal("precision non-native projection error", err)
			}
			got.state = native.Code
			execSQL("ROLLBACK TO SAVEPOINT precision_case")
		}
		execSQL("RELEASE SAVEPOINT precision_case")
		return got
	}
	guard := precisionFrameGuards[0].signature
	// A malformed function-name prefix such as "(" is a soft NULL in PG18.3.
	// Balanced signatures reach two hard-error paths: the type-name grammar and
	// cross-database name validation. These are parser inputs, not connections.
	const malformedType = "to_regprocedure(integer garbage)"
	const crossDatabase = "zasp_missing_precision_database.public.zasp_missing_precision_guard()"
	var firstState, secondState string
	for _, c := range []struct {
		name, key, second string
		definition        *string
		state             string
	}{
		{"unqualified", guard, "zasp_missing_precision_guard()", ptrPrecision("saved-one"), ""},
		{"qualified", "public." + guard, "zasp_missing_precision_guard()", ptrPrecision("saved-one"), ""},
		{"zero", "zasp_missing_precision_guard()", "zasp_another_missing_precision_guard()", ptrPrecision("saved-one"), ""},
		{"null-definition", guard, "zasp_missing_precision_guard()", nil, ""},
		{"multiple-aliases", guard, "public." + guard, ptrPrecision("saved-one"), "21000"},
		{"malformed-soft-null", "(", "zasp_missing_precision_guard()", ptrPrecision("saved-one"), ""},
		{"malformed-selected", malformedType, "zasp_missing_precision_guard()", ptrPrecision("saved-one"), "derive"},
		{"second-error", crossDatabase, "zasp_missing_precision_guard()", ptrPrecision("saved-one"), "derive"},
		{"first-error", malformedType, crossDatabase, ptrPrecision("saved-one"), "derive"},
		{"reverse-first-error", crossDatabase, malformedType, ptrPrecision("saved-one"), "derive"},
	} {
		args := []any{c.key, c.definition, c.second, "saved-two", "public." + guard}
		execSQL("SET LOCAL search_path=pg_catalog,public")
		want := query("SELECT "+sourceScalar+" FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure($5)", args...)
		execSQL("SET LOCAL search_path=pg_catalog")
		got := query(fixtureSQL, args...)
		if !reflect.DeepEqual(got, want) || c.state != "derive" && got.state != c.state || c.state == "derive" && want.state == "" || readFrame(tx) != pristine {
			t.Fatal("precision independent scalar/error/frame mismatch", c.name, got.state, want.state)
		}
		switch c.name {
		case "malformed-soft-null":
			if want.value != nil {
				t.Fatal("precision soft malformed source must be NULL")
			}
		case "malformed-selected":
			firstState = want.state
		case "second-error":
			secondState = want.state
			if firstState == secondState {
				t.Fatal("precision independent error fixtures must be distinguishable", firstState)
			}
		case "first-error", "reverse-first-error":
			expected := firstState
			if c.name == "reverse-first-error" {
				expected = secondState
			}
			if firstState == "" || secondState == "" || want.state != expected {
				t.Fatal("precision saved scalar first error reordered", c.name, want.state, expected)
			}
		}
		t.Log("precision scalar/lazy case", c.name, "SQLSTATE", got.state)
	}
	// These saved keys have independently demanded distinct native errors above.
	// Unselected fingerprint and fallback must not demand either key; fingerprint
	// remains its literal temporal72 scalar unchanged.
	for _, identity := range []string{"public.zasp_production_runtime_precision_live_fingerprint()", "pg_catalog.to_regprocedure(text)"} {
		args := []any{malformedType, "saved", crossDatabase, "saved-two", identity}
		got := query(fixtureSQL, args...)
		if got.state != "" || got.value == nil || readFrame(tx) != pristine {
			t.Fatal("precision unselected guard demanded malformed row", identity, got.state)
		}
	}
	// NULL, absent and soft malformed text retain core resolution NULL, never a
	// prefix rewrite. Exact admitted adapter executes under outer pg_catalog.
	for _, input := range []any{nil, "zasp_missing_precision_guard()", "("} {
		var oid *uint32
		if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_ordered_current.function_resolve_public($1)`, input).Scan(&oid); err != nil || oid != nil || readFrame(tx) != pristine {
			t.Fatal("precision resolver NULL/absent semantics", err)
		}
	}
	// Every drift runs after a successful full admission in this transaction.
	// Poison raises XX000 if invoked: admission and CASE must refuse first.
	poison := `CREATE OR REPLACE FUNCTION zasp_authorization80_ordered_current.function_resolve_public(value text) RETURNS oid LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,public AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='XX000',MESSAGE='precision poison invoked'; END $$;`
	redeclare := func(from, to string) string {
		return `DROP FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text); ` + strings.Replace(program.ResolverSQL, from, to, 1)
	}
	for _, drift := range []struct{ name, sql string }{
		{"body", poison},
		{"path", `ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) SET search_path=pg_catalog`},
		{"extra-config", `ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) SET TimeZone='UTC'`},
		{"definer", `ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) SECURITY DEFINER`},
		{"strict", `ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) STRICT`},
		{"volatile", `ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) VOLATILE`},
		{"parallel", `ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) PARALLEL SAFE`},
		{"cost", `ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) COST 1`},
		{"default", redeclare("value pg_catalog.text)", "value pg_catalog.text DEFAULT NULL)")},
		{"argument-name", redeclare("value pg_catalog.text)", "other pg_catalog.text)")},
		{"return-type", redeclare("RETURNS pg_catalog.oid", "RETURNS pg_catalog.text")},
		{"argument-type", strings.ReplaceAll(redeclare("value pg_catalog.text)", "value pg_catalog.oid)"), "(pg_catalog.text)", "(pg_catalog.oid)")},
		{"owner", `SET LOCAL ROLE zasp_test; ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) OWNER TO zasp_test; SET LOCAL ROLE zasp_discovery_authority`},
		{"schema-owner", `SET LOCAL ROLE zasp_test; ALTER SCHEMA zasp_authorization80_ordered_current OWNER TO zasp_test; SET LOCAL ROLE zasp_discovery_authority`},
		{"leakproof", `SET LOCAL ROLE zasp_test; ALTER FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) LEAKPROOF; SET LOCAL ROLE zasp_discovery_authority`},
		{"routine-acl", `GRANT EXECUTE ON FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text) TO PUBLIC`},
		{"schema-acl", `GRANT USAGE ON SCHEMA zasp_authorization80_ordered_current TO PUBLIC`},
		{"missing", `DROP FUNCTION zasp_authorization80_ordered_current.function_resolve_public(text)`},
		{"overload", `CREATE FUNCTION zasp_authorization80_ordered_current.function_resolve_public(value oid) RETURNS oid LANGUAGE sql AS $$SELECT $1$$`},
		{"extra-private", `CREATE FUNCTION zasp_authorization80_ordered_current.extra_precision() RETURNS oid LANGUAGE sql AS $$SELECT NULL::oid$$`},
		{"forged-catalog", `CREATE OR REPLACE FUNCTION zasp_authorization80_ordered_current.catalog(expected_manifest text) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='XX000'; END $$`},
		{"forged-require", `CREATE OR REPLACE FUNCTION zasp_authorization80_ordered_current.require(expected_manifest text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='XX000'; END $$`},
	} {
		if !fullAdmitted() {
			t.Fatal("precision post-admission drift baseline refused", drift.name)
		}
		execSQL("SAVEPOINT precision_drift")
		execSQL(drift.sql)
		if fullAdmitted() {
			t.Fatal("precision drift independently admitted", drift.name)
		}
		if drift.name == "body" {
			got := query(fixtureSQL, guard, "saved", "zasp_missing_precision_guard()", "other", "public."+guard)
			if got.state != "" || got.value != nil {
				t.Fatal("precision forged resolver demanded or live fallback returned", got.state)
			}
		}
		execSQL("ROLLBACK TO SAVEPOINT precision_drift; RELEASE SAVEPOINT precision_drift")
		if !fullAdmitted() || readFrame(tx) != pristine {
			t.Fatal("precision drift restoration refused", drift.name)
		}
	}
	// Some pg_proc facts have no standalone ALTER form for a non-set PL/pgSQL
	// routine. In this disposable rollback-only fixture, isolate catalog drift
	// and query only the independent admission (never plan/invoke that routine).
	for _, field := range []struct{ name, value string }{
		{"proretset", "true"}, {"prorows", "1"}, {"prokind", "'w'"},
		{"proallargtypes", "ARRAY[25]::oid[]"}, {"proargmodes", `ARRAY['i']::"char"[]`},
		{"provariadic", "25"}, {"prosupport", "'pg_catalog.textlike_support(internal)'::regprocedure::oid"},
		{"protrftypes", "ARRAY[25]::oid[]"}, {"probin", "'precision-poison'"},
		{"prosqlbody", "(SELECT prosqlbody FROM pg_catalog.pg_proc WHERE oid='zasp_authorization80_ordered_current.precision_sqlbody()'::regprocedure)"}, {"prolang", "(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql')"},
	} {
		execSQL("SAVEPOINT precision_catalog_drift; SET LOCAL ROLE zasp_test")
		if field.name == "prosqlbody" {
			execSQL(`CREATE FUNCTION zasp_authorization80_ordered_current.precision_sqlbody() RETURNS oid LANGUAGE SQL BEGIN ATOMIC SELECT NULL::oid; END`)
		}
		execSQL("UPDATE pg_catalog.pg_proc SET " + field.name + "=" + field.value + " WHERE oid='zasp_authorization80_ordered_current.function_resolve_public(text)'::regprocedure")
		execSQL("SET LOCAL ROLE zasp_discovery_authority")
		if admitted() {
			t.Fatal("precision exact catalog fact drift admitted", field.name)
		}
		execSQL("ROLLBACK TO SAVEPOINT precision_catalog_drift; RELEASE SAVEPOINT precision_catalog_drift")
		if !fullAdmitted() || readFrame(tx) != pristine {
			t.Fatal("precision catalog fact restoration refused", field.name)
		}
	}
	for _, wrong := range []string{"SET LOCAL search_path=pg_catalog,public", "SET LOCAL ROLE zasp_test", "SET LOCAL TimeZone='America/Los_Angeles'"} {
		execSQL("SAVEPOINT precision_wrong")
		execSQL(wrong)
		if fullAdmitted() {
			t.Fatal("precision wrong caller/frame admitted", wrong)
		}
		execSQL("ROLLBACK TO SAVEPOINT precision_wrong; RELEASE SAVEPOINT precision_wrong")
	}
	if !fullAdmitted() || readFrame(tx) != pristine {
		t.Fatal("precision final private8/frame restoration refused")
	}
	cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = tx.Rollback(cleanup)
	done()
	active = false
	if err != nil || readFrame(owner) != before {
		t.Fatal("precision rollback/session restoration refused", err)
	}
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='zasp_authorization80_ordered_current')`).Scan(&absent); err != nil || !absent {
		t.Fatal("precision private namespace survived rollback")
	}
	t.Log("precision private8 admission, seven pinned definitions, scalar/lazy/error/refusal and frame rollback verified; full native379 and deployed flows remain pending")
}

func ptrPrecision(value string) *string { return &value }
