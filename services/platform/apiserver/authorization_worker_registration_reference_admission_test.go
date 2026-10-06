package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Only the external QueryRow/Scan boundary is replaced. These controls exercise
// the real harness refusal and JSON admission; they cannot prove native capture.
type registrationReferenceDiagnosticQuery struct {
	raw []byte
	err error
}

func (q registrationReferenceDiagnosticQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	return q
}

func (q registrationReferenceDiagnosticQuery) Scan(dest ...any) error {
	if q.err != nil {
		return q.err
	}
	*dest[0].(*[]byte) = q.raw
	return nil
}

func TestWorkerRegistrationReferenceQueryDiagnosticsMainCases(t *testing.T) {
	// Dropping Scan errors loses the failure class; printing or wrapping the
	// driver error would expose this fixture's hostile catalog and secret data.
	private := "private-function-name password=seeded-secret " + strings.Repeat("x", 8192)
	statement := "SELECT private_schema.private_function($1) /* " + private + " */"
	hostile := &pgconn.PgError{Severity: private, SeverityUnlocalized: private, Code: "42501", Message: private, Detail: private, Hint: private, InternalQuery: private, Where: private, SchemaName: private, TableName: private, ColumnName: private, DataTypeName: private, ConstraintName: private, File: private, Routine: private}
	for _, tc := range []struct {
		name, class, state string
		err                error
	}{
		{"permission", "postgres", "42501", hostile},
		{"wrapped-cast", "postgres", "22P02", fmt.Errorf("%s: %w", private, &pgconn.PgError{Code: "22P02", Message: private})},
		{"no-row", "no_rows", "none", pgx.ErrNoRows},
		{"deadline", "deadline_exceeded", "none", fmt.Errorf("%s: %w", private, context.DeadlineExceeded)},
		{"canceled", "canceled", "none", context.Canceled},
		{"untyped", "untyped", "none", errors.New(private)},
		{"invalid-state", "postgres", "none", &pgconn.PgError{Code: private, Message: private}},
		{"lowercase-state", "postgres", "none", &pgconn.PgError{Code: "22p02", Message: private}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := struct{ Name string }{Name: "unchanged"}
			err := registrationReferenceQueryJSON(context.Background(), registrationReferenceDiagnosticQuery{err: tc.err}, statement, &target, private)
			if err == nil || target.Name != "unchanged" {
				t.Fatal("failed native row was accepted or changed the target")
			}
			message := err.Error()
			classification := map[string]string{"postgres": "class=pg-error", "no_rows": "class=no-rows", "deadline_exceeded": "class=context-deadline", "canceled": "class=context-canceled", "untyped": "class=unknown"}[tc.class]
			if tc.class == "postgres" && tc.state != "none" {
				classification = "sqlstate=" + tc.state
			}
			for _, want := range []string{"original registration reference refused:", "phase=query-row-scan", classification, "statement_sha256=3881a6e5adc60e1245ed1b8a859d05eaceab5a52b0e1334a8f93c1aa32697cc3"} {
				if !strings.Contains(message, want) {
					t.Errorf("bounded query diagnostic lost %q: %s", want, message)
				}
			}
			if len(message) > 256 || strings.ContainsAny(message, "\r\n") || strings.Contains(message, "private") || strings.Contains(message, "seeded-secret") || errors.Unwrap(err) != tc.err {
				t.Fatal("query diagnostic exposed driver/statement/argument data, lost its cause or exceeded its output bound")
			}
		})
	}
}

func TestWorkerRegistrationReferenceQueryJSONAdmission(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   []byte
		valid bool
	}{
		{"success", []byte(`{"Name":"admitted"}`), true},
		{"unknown-field", []byte(`{"Name":"admitted","private":"seeded-secret"}`), false},
		{"trailing-json", []byte(`{"Name":"admitted"} {}`), false},
		{"nil-row", nil, false},
		{"oversized", []byte(strings.Repeat("x", registrationReferenceMaxRowBytes+1)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target struct{ Name string }
			err := registrationReferenceQueryJSON(context.Background(), registrationReferenceDiagnosticQuery{raw: tc.raw}, "SELECT $1", &target, "seeded-secret")
			if (err == nil) != tc.valid || (tc.valid && target.Name != "admitted") {
				t.Fatal("native JSON admission changed", err)
			}
			if err != nil && (len(err.Error()) > 256 || strings.Contains(err.Error(), "seeded-secret")) {
				t.Fatal("JSON admission exposed row data or exceeded its output bound")
			}
		})
	}
}

// A stale compiled pin must refuse the actual current dispatch source. This
// checks the fixed seven-file roster without compiling or executing a fixture.
func TestWorkerRegistrationReferenceCurrentDispatchSources(t *testing.T) {
	paths := []string{
		"migrations/production_authorization_worker_profile.go",
		"migrations/production_authorization_worker_runtime.go",
		"migrations/production_authorization_runtime_profile.go",
		"apiserver/authorization_worker_effect_postgres_test.go",
		"apiserver/postgres_integration_test.go",
		"apiserver/authorization_worker_ordered_policy_postgres_test.go",
		"apiserver/security_agent_temporal_executor_postgres_test.go",
	}
	if len(registrationReferenceDispatchPins) != len(paths) {
		t.Fatal("current dispatch source roster is not closed")
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			file := filepath.Join("..", path)
			info, err := os.Lstat(file)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("current dispatch source is not a regular file")
			}
			digest, err := registrationReferenceHashFile(file)
			if err != nil || digest != registrationReferenceDispatchPins[path] {
				t.Fatal("actual current dispatch source refused by compiled pin", digest, err)
			}
		})
	}
}

// These are unit controls, not a captured catalog or native acceptance claim.
func registrationReferenceTestSource(t *testing.T) string {
	t.Helper()
	w, err := os.ReadFile("../migrations/sql/0080_authorization_worker_profile.sql")
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.ReadFile("../migrations/sql/0080_authorization_runtime_profile.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(r), "$runtime_fingerprint$")
	if len(parts) != 3 {
		t.Fatal("runtime fixture source framing")
	}
	s := strings.Replace(string(w), "-- worker inline runtime fingerprint", parts[1], 1)
	fp := strings.Split(s, "$fingerprint$")
	s = strings.Replace(s, "-- worker inline fingerprint", fp[1], 1)
	return strings.Split(s, "$catalog$")[1]
}

func TestWorkerRegistrationReferenceTrustedCacheCLICompile(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "owned-cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := registrationReferenceAdmitCache(cache); err != nil {
		t.Fatal(err)
	}
	moduleCache := os.Getenv("GOMODCACHE")
	if !filepath.IsAbs(moduleCache) {
		resolveCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		var err error
		moduleCache, err = registrationReferenceUnitModuleCache(resolveCtx, runtime.GOROOT())
		stop()
		if err != nil {
			t.Fatal(err)
		}
	}
	working, _ := os.Getwd()
	b := registrationReferenceBuild{GoRoot: runtime.GOROOT(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CGOEnabled: "0", ModuleCache: moduleCache, BuildCache: cache, ControlledPATH: filepath.Join(runtime.GOROOT(), "bin") + ":/usr/bin:/bin", Platform: filepath.Dir(working)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "original-cli")
	first, err := registrationReferenceCompileOriginalCLI(ctx, b, binary)
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(cache)
	if err != nil || len(files) == 0 {
		t.Fatal("actual admitted Go compiler did not populate trusted cache")
	}
	second, err := registrationReferenceCompileOriginalCLI(ctx, b, binary)
	if err != nil || first != second {
		t.Fatal("cold/warm original CLI bytes differ", err)
	}
	if err := registrationReferenceAdmitCache(cache); err != nil {
		t.Fatal("normal cache writes were refused", err)
	}
	if err := os.Chmod(cache, 0755); err != nil {
		t.Fatal(err)
	}
	if registrationReferenceAdmitCache(cache) == nil {
		t.Fatal("nonprivate cache accepted")
	}
	t.Log("Go1.25.13 CGO0 cold/warm original CLI compilation only; CLI and database not executed", first)
}

func TestWorkerRegistrationReferenceSnapshotRestoration(t *testing.T) {
	for _, captureFails := range []bool{false, true} {
		order := []string{}
		captureErr := error(nil)
		if captureFails {
			captureErr = registrationReferenceRefuse("native cast/permission/partial stream")
		}
		err := registrationReferenceSnapshotControl(context.Background(), func() error { order = append(order, "begin"); return nil }, func() error { order = append(order, "capture"); return captureErr }, func() error { order = append(order, "rollback"); return nil }, func() error { order = append(order, "restored"); return nil })
		if (err != nil) != captureFails || !reflect.DeepEqual(order, []string{"begin", "capture", "rollback", "restored"}) {
			t.Fatal("snapshot success/error restoration", order, err)
		}
	}
	if registrationReferenceSnapshotControl(context.Background(), func() error { return nil }, func() error { return nil }, func() error { return registrationReferenceRefuse("rollback") }, func() error { return nil }) == nil {
		t.Fatal("failed rollback accepted")
	}
	if registrationReferenceSnapshotControl(context.Background(), func() error { return nil }, func() error { return nil }, func() error { return nil }, func() error { return registrationReferenceRefuse("role/path drift") }) == nil {
		t.Fatal("failed frame restoration accepted")
	}
}

func TestWorkerRegistrationReferenceOriginalStatements(t *testing.T) {
	source := registrationReferenceTestSource(t)
	plan, err := registrationReferencePlan(source)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41}
	if len(plan.Sites) != 33 || plan.CatalogSHA256 != "28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016" {
		t.Fatal("original complete source authority")
	}
	for i, site := range plan.Sites {
		if site.Line != want[i] || site.SourceSHA256 != registrationReferenceSHA([]byte(site.Source)) || !strings.Contains(site.Statement, site.Selector) {
			t.Fatalf("source site %d", want[i])
		}
		if len(site.Expressions) != len(site.Types) || strings.Contains(site.Statement, "COLLATE") || strings.Contains(site.Statement, "ORDER BY v") || !strings.HasSuffix(site.Statement, site.Selector+") q(row) LIMIT 5001") {
			t.Fatal("projection changed native selector/order")
		}
	}
	if !strings.Contains(plan.Sites[1].Selector, "signature::regprocedure") || !strings.Contains(plan.Sites[10].Selector, "to_regprocedure(signature)") {
		t.Fatal("distinct original saved-resolution semantics")
	}
	if !strings.Contains(plan.Sites[30].Selector, "OR (t.tgrelid=") || !strings.Contains(plan.Sites[32].Selector, "OR(t.tgrelid='zasp_temporal68.deliveries'") {
		t.Fatal("paired selector source lost")
	}
	for _, mutation := range []string{strings.Replace(source, "count(*)=1", "count(*)>0", 1), strings.Replace(source, "signature::regprocedure", "to_regprocedure(signature)", 1), strings.Replace(source, "UNION ALL", "UNION", 1), source + "\nSELECT true"} {
		if _, err := registrationReferencePlan(mutation); err == nil {
			t.Fatal("source mutation accepted")
		}
	}
}

func TestWorkerRegistrationReferenceNativeFields(t *testing.T) {
	for _, tc := range []struct {
		typ    string
		raw    string
		output *string
		valid  bool
	}{
		{"boolean", "true", registrationReferenceString("t"), true}, {"boolean", "false", registrationReferenceString("f"), true},
		{"boolean", "true", registrationReferenceString("true"), false}, {"text", "\"true\"", registrationReferenceString("true"), true},
		{"text", "null", nil, true}, {"text", "\"\"", registrationReferenceString(""), true}, {"int2", "2", registrationReferenceString("2"), true},
		{"boolean", "null", registrationReferenceString(""), false}, {"text", "\"x\"", nil, false},
	} {
		f := registrationReferenceField{Type: tc.typ, Raw: json.RawMessage(tc.raw), Null: tc.raw == "null", Output: tc.output}
		if (registrationReferenceAdmitField(f, tc.typ) == nil) != tc.valid {
			t.Fatalf("native type/output control %s %s", tc.typ, tc.raw)
		}
	}
	v := registrationReferenceConcat("label", []registrationReferenceField{{Null: true}, {Output: registrationReferenceString("")}, {Output: registrationReferenceString("t")}})
	if v != "label||t" {
		t.Fatal("NULL and empty collapsed")
	}
}

func TestWorkerRegistrationReferenceBagCoverageAndFrames(t *testing.T) {
	plan, err := registrationReferencePlan(registrationReferenceTestSource(t))
	if err != nil {
		t.Fatal(err)
	}
	bags := make([]registrationReferenceBag, 33)
	for i, s := range plan.Sites {
		bags[i] = registrationReferenceBag{Line: s.Line, SiteSHA256: s.SourceSHA256, Complete: true, Rows: []registrationReferenceRow{}}
	}
	if err := registrationReferenceAdmitBags(plan, bags); err != nil {
		t.Fatal(err)
	}
	if err := registrationReferenceAdmitBags(plan, bags[:32]); err == nil {
		t.Fatal("partial bags accepted")
	}
	copyBags := append([]registrationReferenceBag(nil), bags...)
	copyBags[2].Line = 5
	if err := registrationReferenceAdmitBags(plan, copyBags); err == nil {
		t.Fatal("duplicate/missing site accepted")
	}
	copyBags = append([]registrationReferenceBag(nil), bags...)
	copyBags[0].Complete = false
	if err := registrationReferenceAdmitBags(plan, copyBags); err == nil {
		t.Fatal("partial stream accepted")
	}
	row := registrationReferenceRow{Ordinal: 1, Key: json.RawMessage(`["schema","zasp_authorization80_worker"]`), Fields: []registrationReferenceField{
		{Type: "text", Raw: json.RawMessage(`"owner"`), Output: registrationReferenceString("owner")},
		{Type: "text", Raw: json.RawMessage(`null`), Null: true}}, V: registrationReferenceString("schema|owner")}
	copyBags = append([]registrationReferenceBag(nil), bags...)
	copyBags[0].Rows = []registrationReferenceRow{row, row}
	copyBags[0].Rows[1].Ordinal = 2
	if err := registrationReferenceAdmitBags(plan, copyBags); err != nil {
		t.Fatal("native duplicate lost", err)
	}
	copyBags[0].Rows[1].Ordinal = 1
	if err := registrationReferenceAdmitBags(plan, copyBags); err == nil {
		t.Fatal("duplicate ordinal accepted")
	}
	frame := registrationReferenceFunctionFrame{Schema: "x", Name: "f", Arguments: "", Definition: "CREATE FUNCTION x.f() RETURNS boolean LANGUAGE sql AS 'SELECT true'", Owner: "owner", ACL: registrationReferenceString(""), Language: "sql", Result: "boolean", Volatility: "s", Parallel: "u"}
	if err := registrationReferenceAdmitFunction(frame); err != nil {
		t.Fatal(err)
	}
	frame.Definition = ""
	if err := registrationReferenceAdmitFunction(frame); err == nil {
		t.Fatal("TF body-only frame accepted")
	}
}

func TestWorkerRegistrationReferenceOrderingAuthorityAndBounds(t *testing.T) {
	f := registrationReferenceExecutionFrame{Session: "zasp_test", Effective: "zasp_discovery_authority", Role: "zasp_discovery_authority", Path: "pg_catalog, public", Schemas: []string{"pg_catalog", "public"}, RowSecurity: "on", Isolation: "repeatable read", ReadOnly: "on", Encoding: "UTF8", ServerVersion: "180003", AuthorityMember: true, RLSClosed: true, Contaminated: false, StatementTimeout: "10s", LockTimeout: "2s"}
	c := registrationReferenceCollation{Name: "pg_catalog.default", Provider: "d", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	if err := registrationReferenceAdmitExecution(f, c, c); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*registrationReferenceExecutionFrame){func(f *registrationReferenceExecutionFrame) { f.Effective = "zasp_test" }, func(f *registrationReferenceExecutionFrame) { f.Superuser = true }, func(f *registrationReferenceExecutionFrame) { f.BypassRLS = true }, func(f *registrationReferenceExecutionFrame) { f.RLSClosed = false }, func(f *registrationReferenceExecutionFrame) { f.Path = "public" }, func(f *registrationReferenceExecutionFrame) { f.Contaminated = true }} {
		bad := f
		change(&bad)
		if registrationReferenceAdmitExecution(bad, c, c) == nil {
			t.Fatal("authority/contamination accepted")
		}
	}
	bad := c
	bad.Deterministic = false
	if registrationReferenceAdmitExecution(f, bad, bad) == nil {
		t.Fatal("unclosed ordering")
	}
	bad = c
	bad.RecordedVersion = registrationReferenceString("old")
	bad.ActualVersion = registrationReferenceString("new")
	if registrationReferenceAdmitExecution(f, bad, bad) == nil {
		t.Fatal("collation version drift")
	}
	if registrationReferenceCheckBudget(1, 1, registrationReferenceMaxRows+1, 2) == nil || registrationReferenceCheckBudget(1, registrationReferenceMaxRowBytes+1, 1, 2) == nil || registrationReferenceCheckBudget(1, 1, 1, registrationReferenceMaxBytes+1) == nil {
		t.Fatal("unbounded capture")
	}
}

// This checks our generated witness against a real catalog, not PostgreSQL's
// internals. A nonexistent catalog column must fail even for an empty sort bag.
func TestWorkerRegistrationReferenceCollationWitnessPostgres(t *testing.T) {
	if os.Getenv("ZASP_WORKER_REGISTRATION_COLLATION_WITNESS_POSTGRES") != "1" {
		t.Skip("explicit local PostgreSQL collation-witness opt-in required")
	}
	t.Setenv("LC_ALL", "C")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := conn.Close(closeCtx); err != nil {
			t.Error("witness connection cleanup failed")
		}
	})
	var defaultName, version string
	if err := conn.QueryRow(ctx, "SELECT 'pg_catalog.default'::regcollation::text, current_setting('server_version_num')").Scan(&defaultName, &version); err != nil || version != "180003" {
		t.Fatal("the admitted PostgreSQL18.3 witness runtime is required", err)
	}
	want := registrationReferenceCollation{Name: defaultName, Provider: "d", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	query := registrationReferenceCollationSQL("SELECT v FROM unnest($1::text[]) AS facts(v) LIMIT 0")
	for _, values := range []struct {
		name string
		bag  []*string
	}{{"empty", []*string{}}, {"null-array", nil}, {"mixed", []*string{registrationReferenceString("a"), nil, registrationReferenceString("z")}}} {
		t.Run(values.name, func(t *testing.T) {
			var frame registrationReferenceCollation
			if err := registrationReferenceQueryJSON(ctx, conn, query, &frame, values.bag); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(frame, want) {
				t.Fatal("typed sort expression lost the complete default collation frame")
			}
		})
	}
}

func TestWorkerRegistrationReferenceDefaultCollationMapping(t *testing.T) {
	s := registrationReferenceCollationSQL("SELECT NULL::text")
	if !strings.Contains(s, "CASE WHEN c.collprovider='d' THEN d.datcollversion") || !strings.Contains(s, "CASE WHEN c.collprovider='d' THEN pg_database_collation_actual_version(d.oid)") {
		t.Fatal("effective database-default version mapping missing")
	}
	if strings.Contains(s, "COLLATE") || strings.Contains(s, "ORDER BY") {
		t.Fatal("mapping overrode source ordering")
	}
}

// The replay must retain the native source's ordering identity, not merely
// produce a coincidentally equal digest in a C-locale fixture database.
func TestWorkerRegistrationReferenceParameterReplayPostgres(t *testing.T) {
	if os.Getenv("ZASP_WORKER_REGISTRATION_COLLATION_WITNESS_POSTGRES") != "1" {
		t.Skip("explicit local PostgreSQL collation-witness opt-in required")
	}
	t.Setenv("LC_ALL", "C")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	observation := &disposablePostgresCleanupObservation{}
	t.Cleanup(func() {
		if err := registrationReferenceAdmitPublication(true, true, observation.snapshot()); err != nil {
			t.Error("replay fixture cleanup incomplete", err)
		}
	})
	registerDisposablePostgresCleanupObservation(t, observation)
	conn, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if err := conn.Close(closeCtx); err != nil {
			t.Error("replay connection cleanup failed")
		}
	})
	if _, err := conn.Exec(ctx, "CREATE EXTENSION pgcrypto"); err != nil {
		t.Fatal("owned replay extension setup failed")
	}
	var version, extension string
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num'), extversion FROM pg_extension WHERE extname='pgcrypto'").Scan(&version, &extension); err != nil || version != "180003" || extension != "1.4" {
		t.Fatal("admitted replay runtime required", err)
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		rollbackCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if err := tx.Rollback(rollbackCtx); err != nil {
			t.Error("replay snapshot rollback failed")
		}
	})
	if _, err := tx.Exec(ctx, "SET LOCAL search_path=pg_catalog,public; SET LOCAL row_security=on; SET LOCAL statement_timeout='10000ms'; SET LOCAL lock_timeout='2000ms'"); err != nil {
		t.Fatal("bounded replay snapshot failed")
	}
	var builtinC, builtinDefault registrationReferenceCollation
	if err := registrationReferenceQueryJSON(ctx, tx, registrationReferenceBuiltinCSQL, &builtinC); err != nil {
		t.Fatal(err)
	}
	if err := registrationReferenceQueryJSON(ctx, tx, registrationReferenceBuiltinDefaultSQL, &builtinDefault); err != nil {
		t.Fatal(err)
	}
	// Independent fixed source fixtures, not the full original UNION/capture.
	for _, source := range []struct {
		name, relation string
		frame          registrationReferenceCollation
	}{
		{"default", "(SELECT v FROM unnest($1::text[]) AS input(v)) AS facts", builtinDefault},
		{"C_name", "(SELECT nspname::text AS v FROM unnest($1::name[]) AS input(nspname)) AS facts", builtinC},
	} {
		t.Run(source.name, func(t *testing.T) {
			aggregate, witness, err := registrationReferenceParameterReplayQueries(source.frame, source.frame, builtinC, builtinDefault)
			if err != nil {
				t.Fatal(err)
			}
			sourceWitness := registrationReferenceCollationSQL("SELECT v FROM " + source.relation + " LIMIT 0")
			// Literal native oracle: never derive its aggregate from our builder.
			sourceAggregate := `SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM ` + source.relation
			for _, values := range []struct {
				name string
				bag  []*string
				null bool
			}{
				{"empty", []*string{}, true}, {"null_array", nil, true},
				{"null_only", []*string{nil}, true}, {"all_null", []*string{nil, nil}, true},
				{"empty_string", []*string{registrationReferenceString("")}, false},
				{"unicode_duplicates_newline", []*string{registrationReferenceString("z"), nil, registrationReferenceString("a"), registrationReferenceString("é"), registrationReferenceString("e\u0301"), registrationReferenceString("Ω"), registrationReferenceString("😀"), registrationReferenceString("a"), registrationReferenceString(""), registrationReferenceString("line\nvalue")}, false},
				{"reordered_duplicates", []*string{registrationReferenceString("b"), registrationReferenceString("a"), registrationReferenceString("a")}, false},
			} {
				t.Run(values.name, func(t *testing.T) {
					var nativeFrame, replayFrame registrationReferenceCollation
					if err := registrationReferenceQueryJSON(ctx, tx, sourceWitness, &nativeFrame, values.bag); err != nil {
						t.Fatal(err)
					}
					if err := registrationReferenceQueryJSON(ctx, tx, witness, &replayFrame, values.bag); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(nativeFrame, source.frame) || registrationReferenceAdmitSortKeyCollations(nativeFrame, nativeFrame, replayFrame, replayFrame) != nil {
						t.Fatal("complete native/replay ordering identity differs")
					}
					var nativeDigest, replayDigest *string
					if err := tx.QueryRow(ctx, sourceAggregate, values.bag).Scan(&nativeDigest); err != nil {
						t.Fatal("native oracle failed")
					}
					if err := tx.QueryRow(ctx, aggregate, values.bag).Scan(&replayDigest); err != nil {
						t.Fatal("actual replay failed")
					}
					if (nativeDigest == nil) != values.null || (replayDigest == nil) != values.null || !reflect.DeepEqual(nativeDigest, replayDigest) {
						t.Fatal("nullable native/replay digest differs")
					}
					if values.name == "reordered_duplicates" {
						var literalDigest string
						if err := tx.QueryRow(ctx, `SELECT encode(digest(convert_to($1::text,'UTF8'),'sha256'),'hex')`, "a\na\nb").Scan(&literalDigest); err != nil || replayDigest == nil || *replayDigest != literalDigest {
							t.Fatal("duplicate preservation/delimiter/order differs", err)
						}
					}
				})
			}
		})
	}
}

func TestWorkerRegistrationReferenceParameterReplayAuthority(t *testing.T) {
	c := registrationReferenceCollation{Name: `"C"`, Provider: "c", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	d := registrationReferenceCollation{Name: `"default"`, Provider: "d", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	for _, source := range []registrationReferenceCollation{c, d} {
		if aggregate, witness, err := registrationReferenceParameterReplayQueries(source, source, c, d); err != nil || aggregate == "" || witness == "" {
			t.Fatal("complete finite source refused")
		}
		for index := 0; index < reflect.TypeOf(source).NumField(); index++ {
			field := reflect.TypeOf(source).Field(index).Name
			t.Run(source.Provider+"/"+field, func(t *testing.T) {
				bad := source
				value := reflect.ValueOf(&bad).Elem().Field(index)
				switch value.Kind() {
				case reflect.String:
					value.SetString("unadmitted")
				case reflect.Bool:
					value.SetBool(false)
				case reflect.Pointer:
					value.Set(reflect.ValueOf(registrationReferenceString("unadmitted")))
				default:
					t.Fatal("new frame field needs a refusal mutation")
				}
				for _, frames := range [][4]registrationReferenceCollation{{bad, bad, c, d}, {source, bad, c, d}, {source, source, bad, d}, {source, source, c, bad}} {
					if aggregate, witness, err := registrationReferenceParameterReplayQueries(frames[0], frames[1], frames[2], frames[3]); err == nil || aggregate != "" || witness != "" {
						t.Fatal("altered source/builtin emitted usable replay")
					}
				}
			})
		}
	}
	if aggregate, witness, err := registrationReferenceParameterReplayQueries(c, d, c, d); err == nil || aggregate != "" || witness != "" {
		t.Fatal("different original source frames accepted")
	}
}

// These controls catch accepting the wrong original default install, omitting
// consumed upgrade bytes, or observing the digest result rather than ORDER BY v.
func TestWorkerRegistrationReferencePGCryptoInstallChain(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{}
	for name, raw := range map[string]string{
		"pgcrypto.control":       "default_version = '1.4'\nmodule_pathname = '$libdir/pgcrypto'\n",
		"pgcrypto--1.3.sql":      "original base script",
		"pgcrypto--1.3--1.4.sql": "original upgrade script",
		"pgcrypto.so":            "original native library",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		files[path] = registrationReferenceSHA([]byte(raw))
	}
	version, err := registrationReferencePGCryptoVersion(files)
	if err != nil || version != "1.4" {
		t.Fatal("original default install chain refused", version, err)
	}
	upgrade := filepath.Join(dir, "pgcrypto--1.3--1.4.sql")
	want := files[upgrade]
	delete(files, upgrade)
	if _, err := registrationReferencePGCryptoVersion(files); err == nil {
		t.Fatal("missing consumed upgrade accepted")
	}
	files[upgrade] = want
	if err := os.WriteFile(upgrade, []byte("changed upgrade"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := registrationReferencePGCryptoVersion(files); err == nil {
		t.Fatal("changed upgrade bytes accepted")
	}
	if err := os.WriteFile(upgrade, []byte("original upgrade script"), 0600); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(dir, "pgcrypto.control")
	wrong := "default_version = '1.3'\nmodule_pathname = '$libdir/pgcrypto'\n"
	if err := os.WriteFile(control, []byte(wrong), 0600); err != nil {
		t.Fatal(err)
	}
	files[control] = registrationReferenceSHA([]byte(wrong))
	if _, err := registrationReferencePGCryptoVersion(files); err == nil {
		t.Fatal("original installer downgraded to1.3")
	}
	frame := registrationReferenceDigestFrame{Extension: "pgcrypto", Version: "1.4", Schema: "public", Owner: "zasp_test", Source: "pg_digest", Library: "$libdir/pgcrypto", Resolved: true, Function: registrationReferenceFunctionFrame{Language: "c", Strict: true, Volatility: "i", Parallel: "s", Result: "bytea"}}
	if registrationReferenceAdmitDigest(frame, "1.4") != nil {
		t.Fatal("source-selected1.4 digest refused")
	}
	frame.Version = "1.3"
	if registrationReferenceAdmitDigest(frame, "1.4") == nil {
		t.Fatal("digest frame version unrelated to admitted install")
	}
}

func TestWorkerRegistrationReferenceActualSortKeyCollation(t *testing.T) {
	plan, err := registrationReferencePlan(registrationReferenceTestSource(t))
	if err != nil {
		t.Fatal(err)
	}
	outer, nested, err := registrationReferenceSortKeyCollationQueries(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{outer, nested} {
		if !strings.Contains(query, " ) SELECT v FROM facts LIMIT 0\n))) AS oid") {
			t.Fatal("witness is not actual upstream ORDER BY v, including empty bag")
		}
		if strings.Contains(query, "NULL::text") || strings.Contains(query, "COLLATE") {
			t.Fatal("default surrogate/forced collation")
		}
	}
	for _, site := range plan.Sites {
		if !strings.Contains(outer, site.Selector) {
			t.Fatal("outer source selector lost", site.Line)
		}
		if site.Line >= 15 && site.Line <= 27 && !strings.Contains(nested, site.Selector) {
			t.Fatal("nested source selector lost", site.Line)
		}
	}
	c := registrationReferenceCollation{Name: "pg_catalog.default", Provider: "d", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	if registrationReferenceAdmitSortKeyCollations(c, c, c, c) != nil {
		t.Fatal("identical admitted sort keys refused")
	}
	other := c
	other.Name = "pg_catalog.\"C\""
	for _, frames := range [][4]registrationReferenceCollation{{c, c, other, c}, {c, c, c, other}, {c, other, c, c}} {
		if registrationReferenceAdmitSortKeyCollations(frames[0], frames[1], frames[2], frames[3]) == nil {
			t.Fatal("source/parameter sort identity mismatch accepted")
		}
	}
}

func TestWorkerRegistrationReferenceCleanupAndComparison(t *testing.T) {
	c := disposablePostgresCleanupObservation{Available: true, PGCtlStopped: true, CommandWaitJoined: true, NormalExit: true, EndpointChecked: true, EndpointSHA256: strings.Repeat("a", 64), SurvivingResourcesChecked: true}
	if registrationReferenceAdmitPublication(true, true, c) == nil { /* positive complete publication control */
	} else {
		t.Fatal("closed cleanup refused")
	}
	if registrationReferenceAdmitPublication(false, true, c) == nil {
		t.Fatal("partial publish")
	}
	if registrationReferenceAdmitPublication(true, false, c) == nil {
		t.Fatal("unrestored frame publish")
	}
	c.NormalExit = false
	if registrationReferenceAdmitPublication(true, true, c) == nil {
		t.Fatal("abnormal cleanup publish")
	}
	reference := []registrationReferenceBag{{Line: 4, Rows: []registrationReferenceRow{{Ordinal: 1, Key: json.RawMessage(`["schema","x"]`), V: registrationReferenceString("schema|x")}}}}
	before, _ := json.Marshal(reference)
	target := []registrationReferenceBag{{Line: 4, Rows: []registrationReferenceRow{{Ordinal: 1, Key: json.RawMessage(`["schema","y"]`), V: registrationReferenceString("schema|x")}}}}
	if registrationReferenceCompare(reference, target) == nil {
		t.Fatal("equal v hid member drift")
	}
	after, _ := json.Marshal(reference)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("target rewrote reference")
	}
}

func TestWorkerRegistrationReferenceInputClosure(t *testing.T) {
	inputs := []registrationReferenceInput{{Path: "compiler.go", SHA256: strings.Repeat("a", 64), Kind: "go", Package: "original/compiler"}, {Path: "source.sql", SHA256: strings.Repeat("b", 64), Kind: "embed", Package: "original/compiler"}}
	if registrationReferenceAdmitInputs(inputs, inputs) == nil { /* complete unit closure */
	} else {
		t.Fatal("complete input roster refused")
	}
	if registrationReferenceAdmitInputs(inputs, inputs[:1]) == nil {
		t.Fatal("missing transitive embed accepted")
	}
	bad := append([]registrationReferenceInput(nil), inputs...)
	bad[1].SHA256 = strings.Repeat("c", 64)
	if registrationReferenceAdmitInputs(inputs, bad) == nil {
		t.Fatal("changed input accepted")
	}
	bad = append(bad, inputs[0])
	if registrationReferenceAdmitInputs(inputs, bad) == nil {
		t.Fatal("duplicate input accepted")
	}
	merged, err := registrationReferenceMergeInput(inputs[0], registrationReferenceInput{Path: "compiler.go", SHA256: strings.Repeat("a", 64), Kind: "embed", Package: "original/compiler"})
	if err != nil || merged.Kind != "embed+go" {
		t.Fatal("one admitted source consumed as Go AND embed must retain both roles", err)
	}
	if _, err := registrationReferenceMergeInput(inputs[0], registrationReferenceInput{Path: "compiler.go", SHA256: strings.Repeat("c", 64), Kind: "embed", Package: "original/compiler"}); err == nil {
		t.Fatal("same path with split input bytes accepted")
	}
}

func TestWorkerRegistrationReferenceAssemblerHeaderClosure(t *testing.T) {
	paths, err := registrationReferenceToolInputPaths(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
	}
	for _, p := range []string{"VERSION", "go.env", "pkg/include/textflag.h", "pkg/include/funcdata.h"} {
		if !seen[p] {
			t.Fatal("implicit Go assembler/configuration input missing", p)
		}
	}
}

func TestWorkerRegistrationReferenceRuntimePATHBinding(t *testing.T) {
	if registrationReferenceAdmitPATH("/admitted/go", "/admitted/go/bin:/admitted/pg/bin:/usr/bin", "/admitted/go/bin:/admitted/pg/bin:/usr/bin") != nil {
		t.Fatal("controlled root runtime PATH")
	}
	if registrationReferenceAdmitPATH("/admitted/go", "/admitted/go/bin:/admitted/pg/bin:/usr/bin", "/other/pg/bin:/usr/bin") == nil {
		t.Fatal("PG checked under a different path than later fixture")
	}
	if registrationReferenceAdmitPATH("/admitted/go", "/other/go/bin:/admitted/pg/bin", "/other/go/bin:/admitted/pg/bin") == nil {
		t.Fatal("CLI go path not confined")
	}
}

func TestWorkerRegistrationReferenceAllBooleanOrdinalsAndTFJoin(t *testing.T) {
	plan, err := registrationReferencePlan(registrationReferenceTestSource(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[int][]int{6: {5, 6}, 17: {5, 6}, 24: {5, 6}, 7: {5}, 18: {5}, 8: {4}, 19: {4}, 20: {3, 4, 5}, 9: {3}, 21: {3}, 26: {2}, 31: {1}}
	seen := map[int][]int{}
	for _, site := range plan.Sites {
		for i, typ := range site.Types {
			if typ == "boolean" {
				seen[site.Line] = append(seen[site.Line], i+1)
				for _, v := range []bool{true, false} {
					raw, _ := json.Marshal(v)
					out := "f"
					if v {
						out = "t"
					}
					if registrationReferenceAdmitField(registrationReferenceField{Type: typ, Raw: raw, Output: &out}, typ) != nil {
						t.Fatal("boolean source ordinal", site.Line, i+1)
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatal("literal full bare-boolean ordinal roster")
	}
	bags := make([]registrationReferenceBag, 33)
	for i, s := range plan.Sites {
		bags[i] = registrationReferenceBag{Line: s.Line, SiteSHA256: s.SourceSHA256, Complete: true, Rows: []registrationReferenceRow{}}
	}
	f := registrationReferenceFunctionFrame{Schema: "zasp_authorization80_runtime", Name: "stage_insert", Definition: "CREATE FUNCTION zasp_authorization80_runtime.stage_insert() RETURNS trigger LANGUAGE sql AS 'SELECT NULL'", Owner: "zasp_discovery_authority", ACL: registrationReferenceString(""), Language: "sql", Result: "trigger", Volatility: "v", Parallel: "u"}
	fields := []registrationReferenceField{}
	for i, value := range []string{"public.zasp_runtime_stage_work", "zasp_authorization80_runtime_stage_insert", "O", "CREATE TRIGGER native", f.Definition, f.Owner, ""} {
		raw, _ := json.Marshal(value)
		fields = append(fields, registrationReferenceField{Type: plan.Sites[17].Types[i], Raw: raw, Output: registrationReferenceString(value)})
	}
	r := registrationReferenceRow{Ordinal: 1, Key: json.RawMessage(`["trigger",["public","zasp_runtime_stage_work"],"zasp_authorization80_runtime_stage_insert",["zasp_authorization80_runtime","stage_insert",""]]`), Fields: fields, Function: &f}
	r.V = registrationReferenceString(registrationReferenceConcat("stage-insert-trigger", fields))
	bags[17].Rows = []registrationReferenceRow{r}
	r.V = registrationReferenceString(registrationReferenceConcat("runtime-stage-insert-trigger", fields))
	bags[23].Rows = []registrationReferenceRow{r}
	if err := registrationReferenceAdmitBags(plan, bags); err != nil {
		t.Fatal("independent repeated TF contributions", err)
	}
	broken := f
	broken.Owner = "other"
	bags[23].Rows[0].Function = &broken
	if registrationReferenceAdmitBags(plan, bags) == nil {
		t.Fatal("TF joined owner mismatch accepted")
	}
}

func TestWorkerRegistrationReferenceLine2AndRuntimeProvenance(t *testing.T) {
	for _, tc := range []struct {
		count                int64
		fingerprint, derived *string
		want                 bool
	}{
		{0, nil, nil, false}, {1, registrationReferenceString("x"), registrationReferenceString("x"), true}, {2, registrationReferenceString("x"), registrationReferenceString("x"), false}, {1, nil, registrationReferenceString("x"), false}, {1, registrationReferenceString("x"), nil, false}, {1, registrationReferenceString("old"), registrationReferenceString("new"), false},
	} {
		if registrationReferenceGuard(tc.count, tc.fingerprint, tc.derived) != tc.want {
			t.Fatal("line2 NULL/count/equality semantics")
		}
	}
	if registrationReferenceAdmitRuntimeRow([]byte(`{"singleton":true,"checksum":"current","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), "current") != nil {
		t.Fatal("source inserted runtime row provenance")
	}
	if registrationReferenceAdmitRuntimeRow([]byte(`{"singleton":true,"checksum":"old","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), "current") == nil {
		t.Fatal("wrong runtime insertion checksum")
	}
	if registrationReferenceAdmitRuntimeRow([]byte(`{"singleton":false,"checksum":"current","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), "current") == nil {
		t.Fatal("wrong runtime singleton")
	}
}

// These fakes exercise the real query/decode/refusal boundary without a
// database. QueryRow records its inputs; only Scan returns controlled data.
type registrationDiagnosticRow struct {
	raw []byte
	err error
}

func (r registrationDiagnosticRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		panic("unexpected scan destination count")
	}
	*dest[0].(*[]byte) = r.raw
	return nil
}

type registrationDiagnosticQuery struct {
	row       pgx.Row
	statement string
	args      []any
}

func (q *registrationDiagnosticQuery) QueryRow(_ context.Context, statement string, args ...any) pgx.Row {
	q.statement = statement
	q.args = args
	return q.row
}

// Break caught: catalog scan failures must preserve their original cause but
// diagnostics must never render driver messages, SQL, arguments or secrets.
func TestWorkerRegistrationReferenceQueryDiagnostics(t *testing.T) {
	const canary = "postgres://diagnostic-secret:password@private-host/database"
	statement := "SELECT '" + canary + "' /* untrusted phase=secret */"
	sum := sha256.Sum256([]byte(statement))
	digest := hex.EncodeToString(sum[:])
	contaminated := func(code string) *pgconn.PgError {
		return &pgconn.PgError{Code: code, Message: canary, Detail: canary, Hint: canary, Where: canary, SchemaName: canary, TableName: canary, ColumnName: canary, DataTypeName: canary, ConstraintName: canary, File: canary, Routine: canary}
	}
	for _, tc := range []struct {
		name           string
		cause          error
		classification string
	}{
		{"native state", contaminated("42501"), "sqlstate=42501"},
		{"wrapped native state", fmt.Errorf("%s: %w", canary, contaminated("XX000")), "sqlstate=XX000"},
		{"invalid state", contaminated(canary), "class=pg-error"},
		{"lowercase state", contaminated("42p01"), "class=pg-error"},
		{"empty state", contaminated(""), "class=pg-error"},
		{"short state", contaminated("42P0"), "class=pg-error"},
		{"long state", contaminated("42P010"), "class=pg-error"},
		{"nonascii state", contaminated("42Pé"), "class=pg-error"},
		{"state newline", contaminated("42P01\n"), "class=pg-error"},
		{"canceled", fmt.Errorf("%s: %w", canary, context.Canceled), "class=context-canceled"},
		{"deadline", fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), "class=context-deadline"},
		{"no rows", fmt.Errorf("%s: %w", canary, pgx.ErrNoRows), "class=no-rows"},
		{"unknown", errors.New(canary), "class=unknown"},
		{"typed nil native error", (*pgconn.PgError)(nil), "class=unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := &registrationDiagnosticQuery{row: registrationDiagnosticRow{err: tc.cause}}
			var target map[string]any
			err := registrationReferenceQueryJSON(context.Background(), query, statement, &target, canary)
			if err == nil {
				t.Fatal("native failure accepted")
			}
			want := "original registration reference refused: phase=query-row-scan statement_sha256=" + digest + " " + tc.classification
			if err.Error() != want {
				t.Fatalf("safe diagnostic mismatch: %q", err.Error())
			}
			if errors.Unwrap(err) != tc.cause || !errors.Is(err, tc.cause) {
				t.Fatal("original cause discarded")
			}
			for _, format := range []string{"%v", "%+v", "%#v", "%+#v", "%s", "%q"} {
				rendered := fmt.Sprintf(format, err)
				if strings.Contains(rendered, canary) || strings.Contains(rendered, statement) || len(rendered) > 220 {
					t.Fatal("unbounded or contaminated diagnostic rendering")
				}
			}
			if query.statement != statement || !reflect.DeepEqual(query.args, []any{canary}) {
				t.Fatal("diagnostic changed query execution inputs")
			}
		})
	}
}

// Break caught: row limits and strict JSON refusals retain the same caps and
// do not expose payloads while identifying their closed operation phase.
func TestWorkerRegistrationReferenceQueryDiagnosticDecodeAndBounds(t *testing.T) {
	const statement = "SELECT $1::jsonb"
	sum := sha256.Sum256([]byte(statement))
	digest := hex.EncodeToString(sum[:])
	for _, tc := range []struct {
		name         string
		raw          []byte
		phase, class string
	}{
		{"row byte limit", bytes.Repeat([]byte{'x'}, registrationReferenceMaxRowBytes+1), "row-byte-limit", "row-byte-limit"},
		{"malformed JSON", []byte(`{"secret":"diagnostic-secret"`), "json-decode", "json-decode"},
		{"unknown JSON field", []byte(`{"secret":"diagnostic-secret"}`), "json-decode", "json-decode"},
		{"trailing JSON", []byte(`{"value":1} {"secret":"diagnostic-secret"}`), "json-decode", "json-decode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := &registrationDiagnosticQuery{row: registrationDiagnosticRow{raw: tc.raw}}
			var target struct {
				Value int `json:"value"`
			}
			err := registrationReferenceQueryJSON(context.Background(), query, statement, &target)
			if err == nil {
				t.Fatal("malformed/over-limit native row accepted")
			}
			want := "original registration reference refused: phase=" + tc.phase + " statement_sha256=" + digest + " class=" + tc.class
			if err.Error() != want {
				t.Fatalf("safe refusal mismatch: %q", err.Error())
			}
			if errors.Unwrap(err) == nil {
				t.Fatal("refusal cause discarded")
			}
			if tc.name == "malformed JSON" && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal("original JSON decoder cause discarded")
			}
			if strings.Contains(fmt.Sprintf("%+v %#v", err, err), "diagnostic-secret") {
				t.Fatal("JSON payload leaked")
			}
		})
	}
	for _, raw := range [][]byte{[]byte(`{"value":1}`), append([]byte(`{"value":1}`), bytes.Repeat([]byte{' '}, registrationReferenceMaxRowBytes-len(`{"value":1}`))...)} {
		query := &registrationDiagnosticQuery{row: registrationDiagnosticRow{raw: raw}}
		var target struct {
			Value int `json:"value"`
		}
		if err := registrationReferenceQueryJSON(context.Background(), query, statement, &target); err != nil || target.Value != 1 {
			t.Fatal("valid JSON row at or below existing byte cap refused")
		}
	}
}

// Break caught: a reviewed live source successor cannot retain a historical
// dispatch pin. This binds all seven actual regular files, without execution.
func TestWorkerRegistrationReferenceDispatchSourceConsistency(t *testing.T) {
	expected := []string{
		"apiserver/authorization_worker_effect_postgres_test.go",
		"apiserver/authorization_worker_ordered_policy_postgres_test.go",
		"apiserver/postgres_integration_test.go",
		"apiserver/security_agent_temporal_executor_postgres_test.go",
		"migrations/production_authorization_runtime_profile.go",
		"migrations/production_authorization_worker_profile.go",
		"migrations/production_authorization_worker_runtime.go",
	}
	paths := make([]string, 0, len(registrationReferenceDispatchPins))
	for relative := range registrationReferenceDispatchPins {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	if !reflect.DeepEqual(paths, expected) {
		t.Fatal("closed seven-file dispatch roster differs")
	}
	for _, relative := range expected {
		filename := filepath.Join("..", relative)
		info, err := os.Lstat(filename)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("dispatch source is not a regular file: %s", relative)
		}
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		got := hex.EncodeToString(digest[:])
		if want := registrationReferenceDispatchPins[relative]; got != want {
			t.Errorf("dispatch source pin mismatch: %s got=%s want=%s", relative, got, want)
		}
	}
}

// Break caught: updating a reviewed live digest must not bypass the actual
// binder's exact source checks for any of the seven dispatch inputs.
func TestWorkerRegistrationReferenceDispatchInputRefusal(t *testing.T) {
	directory := t.TempDir()
	pins := make(map[string]string, len(registrationReferenceDispatchPins))
	for relative, digest := range registrationReferenceDispatchPins {
		raw, err := os.ReadFile(filepath.Join("..", relative))
		if err != nil {
			t.Fatal(err)
		}
		filename := filepath.Join(directory, relative)
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, raw, 0600); err != nil {
			t.Fatal(err)
		}
		pins[relative] = digest
	}
	build := registrationReferenceBuild{Platform: directory, DispatchPins: pins}
	if err := registrationReferenceCheckDispatchInputs(build); err != nil {
		t.Fatal("complete reviewed dispatch inputs refused", err)
	}
	paths := make([]string, 0, len(pins))
	for relative := range pins {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		for _, mode := range []string{"missing", "changed"} {
			t.Run(relative+"/"+mode, func(t *testing.T) {
				filename := filepath.Join(directory, relative)
				raw, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.WriteFile(filename, raw, 0600); err != nil {
						t.Error(err)
					}
				}()
				if mode == "missing" {
					if err := os.Remove(filename); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(filename, append(append([]byte(nil), raw...), '\n'), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := registrationReferenceCheckDispatchInputs(build); err == nil || !strings.Contains(err.Error(), "dispatch source input differs") {
					t.Fatal("unreviewed dispatch bytes accepted", err)
				}
			})
		}
	}
	for _, relative := range []string{filepath.Join(directory, "outside.go"), "../outside.go", "apiserver/../outside.go"} {
		t.Run("closed path/"+relative, func(t *testing.T) {
			pins[relative] = strings.Repeat("0", 64)
			defer delete(pins, relative)
			if err := registrationReferenceCheckDispatchInputs(build); err == nil || !strings.Contains(err.Error(), "dispatch source path") {
				t.Fatal("unclosed dispatch path accepted", err)
			}
		})
	}
	t.Run("missing declared pin", func(t *testing.T) {
		relative := paths[0]
		digest := pins[relative]
		delete(pins, relative)
		defer func() { pins[relative] = digest }()
		if err := registrationReferenceCheckDispatchInputs(build); err == nil || !strings.Contains(err.Error(), "source-bound dispatch pins absent") {
			t.Fatal("incomplete dispatch authority accepted", err)
		}
	})
	t.Run("caller changed declared pin", func(t *testing.T) {
		relative := paths[0]
		digest := pins[relative]
		pins[relative] = strings.Repeat("0", 64)
		defer func() { pins[relative] = digest }()
		if err := registrationReferenceCheckDispatchInputs(build); err == nil || !strings.Contains(err.Error(), "original compiler dispatch changed") {
			t.Fatal("caller dispatch authority accepted", err)
		}
	})
	if err := registrationReferenceCheckDispatchInputs(build); err != nil {
		t.Fatal("restored dispatch inputs refused", err)
	}
}

// Break caught: a control witness must select real PG18 catalog columns while
// preserving its nullable rules key and exact original fingerprint scalar.
// These independent field rosters come from the byte-reviewed PG18.3 bootstrap
// catalog (SHA256 ba43fc265c5e477644ac7c28b1771e42d020ee76520cb80bf9a82074a9e90756).
func TestWorkerRegistrationReferencePG18CollationColumnBindings(t *testing.T) {
	schema := map[string]string{
		"c": "oid collname collnamespace collowner collprovider collisdeterministic collencoding collcollate collctype colllocale collicurules collversion",
		"d": "oid datname datdba encoding datlocprovider datistemplate datallowconn dathasloginevt datconnlimit datfrozenxid datminmxid dattablespace datcollate datctype datlocale daticurules datcollversion datacl",
	}
	columns := map[string]map[string]bool{}
	for alias, roster := range schema {
		columns[alias] = map[string]bool{}
		for _, name := range strings.Fields(roster) {
			columns[alias][name] = true
		}
	}
	plan, err := registrationReferencePlan(registrationReferenceTestSource(t))
	if err != nil {
		t.Fatal(err)
	}
	if plan.CatalogSHA256 != "28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016" {
		t.Fatal("original source authority changed")
	}
	outer, nested, err := registrationReferenceSortKeyCollationQueries(plan)
	if err != nil {
		t.Fatal(err)
	}
	c := registrationReferenceCollation{Name: `"C"`, Provider: "c", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	d := c
	d.Name, d.Provider = `"default"`, "d"
	_, parameterC, err := registrationReferenceParameterReplayQueries(c, c, c, d)
	if err != nil {
		t.Fatal(err)
	}
	_, parameterDefault, err := registrationReferenceParameterReplayQueries(d, d, c, d)
	if err != nil {
		t.Fatal(err)
	}
	references := regexp.MustCompile(`\b([cd])\.([a-z][a-z0-9_]*)`)
	rulesBinding := regexp.MustCompile(`'rules',c\.([a-z][a-z0-9_]*)`)
	for _, witness := range []struct{ name, query string }{{"outer", outer}, {"nested", nested}, {"parameter_C", parameterC}, {"parameter_default", parameterDefault}} {
		t.Run(witness.name, func(t *testing.T) {
			// Only the outer witness projection uses aliases c/d for these catalogs;
			// the original scalar has its own unrelated aliases and remains unmodified.
			const boundary = ") AS oid) SELECT jsonb_build_object("
			index := strings.LastIndex(witness.query, boundary)
			if index < 0 {
				t.Fatal("catalog witness projection framing")
			}
			projection := witness.query[index+len(boundary):]
			valid := true
			for _, reference := range references.FindAllStringSubmatch(projection, -1) {
				if !columns[reference[1]][reference[2]] {
					t.Errorf("unresolved PG18 control-witness column: alias=%s column=%s", reference[1], reference[2])
					valid = false
				}
			}
			if !valid {
				return
			}
			binding := rulesBinding.FindStringSubmatch(projection)
			if len(binding) != 2 || binding[1] != "collicurules" {
				t.Fatal("rules key is not bound to nullable ICU rules catalog field")
			}
		})
	}
	for _, fixture := range []struct {
		raw  string
		want *string
	}{{`{"rules":null}`, nil}, {`{"rules":"reviewed-icu-rules"}`, registrationReferenceString("reviewed-icu-rules")}} {
		var frame registrationReferenceCollation
		if err := registrationReferenceJSON([]byte(fixture.raw), &frame); err != nil {
			t.Fatal("rules result schema refused", err)
		}
		if !reflect.DeepEqual(frame.Rules, fixture.want) {
			t.Fatal("rules null/text result semantics changed")
		}
	}
}

// Break caught: a collation refusal loses its observed-frame identity or leaks
// native frame values through diagnostic formatting.
func TestWorkerRegistrationReferenceCollationDiagnostic(t *testing.T) {
	canary := "collation-diagnostic-secret-value"
	base := registrationReferenceCollation{Name: "pg_catalog.default", Provider: "d", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	statement := "collation-diagnostic-statement-secret"
	for _, tc := range []struct {
		name    string
		witness registrationReferenceCollationWitness
	}{{"nested", registrationReferenceNestedCollationWitness}, {"outer", registrationReferenceOuterCollationWitness}} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			changed.Name = canary
			changed.Locale = &canary
			var err error
			if tc.name == "nested" {
				err = registrationReferenceAdmitParameterCollations(tc.witness, statement, base, base, changed, changed)
			} else {
				err = registrationReferenceAdmitParameterCollations(tc.witness, statement, base, base, base, changed)
			}
			if err == nil {
				t.Fatal("collation inequality accepted")
			}
			sourceRaw, _ := json.Marshal(base)
			parameterRaw, _ := json.Marshal(changed)
			want := "original registration reference refused: witness=" + tc.name + "-parameter-collation statement_sha256=" + registrationReferenceSHA([]byte(statement)) + " source_frame_sha256=" + registrationReferenceSHA(sourceRaw) + " parameter_frame_sha256=" + registrationReferenceSHA(parameterRaw) + " differing_fields=name,locale"
			if err.Error() != want {
				t.Fatal("closed witness/hash/field diagnostic differs")
			}
			for _, format := range []string{"%v", "%+v", "%#v", "%+#v", "%s", "%q"} {
				rendered := fmt.Sprintf(format, err)
				if strings.Contains(rendered, canary) || strings.Contains(rendered, statement) || len(rendered) > 650 {
					t.Fatal("unsafe or unbounded diagnostic formatting")
				}
			}
			if errors.Unwrap(err) == nil || !strings.Contains(errors.Unwrap(err).Error(), "source/parameter expression collation differs") {
				t.Fatal("original equality refusal lost")
			}
		})
	}
	if registrationReferenceAdmitParameterCollations(registrationReferenceNestedCollationWitness, statement, base, base, base, base) != nil {
		t.Fatal("equal frames refused")
	}
	if registrationReferenceAdmitParameterCollations(registrationReferenceCollationWitness(99), statement, base, base, base, base) == nil {
		t.Fatal("unknown witness accepted")
	}
}

func TestWorkerRegistrationReferenceCollationDiagnosticFieldRoster(t *testing.T) {
	fields := []string{"name", "provider", "deterministic", "locale", "rules", "recorded_version", "actual_version", "database_provider", "database_collate", "database_ctype", "database_locale", "database_recorded_version", "database_actual_version"}
	base := registrationReferenceCollation{Name: "admitted", Deterministic: true}
	value := "private-frame-value"
	mutations := []func(*registrationReferenceCollation){func(x *registrationReferenceCollation) { x.Name = value }, func(x *registrationReferenceCollation) { x.Provider = value }, func(x *registrationReferenceCollation) { x.Deterministic = false }, func(x *registrationReferenceCollation) { x.Locale = &value }, func(x *registrationReferenceCollation) { x.Rules = &value }, func(x *registrationReferenceCollation) { x.RecordedVersion = &value }, func(x *registrationReferenceCollation) { x.ActualVersion = &value }, func(x *registrationReferenceCollation) { x.DatabaseProvider = value }, func(x *registrationReferenceCollation) { x.DatabaseCollate = value }, func(x *registrationReferenceCollation) { x.DatabaseCType = value }, func(x *registrationReferenceCollation) { x.DatabaseLocale = &value }, func(x *registrationReferenceCollation) { x.DatabaseRecordedVersion = &value }, func(x *registrationReferenceCollation) { x.DatabaseActualVersion = &value }}
	for i, mutate := range mutations {
		t.Run(fields[i], func(t *testing.T) {
			changed := base
			mutate(&changed)
			err := registrationReferenceAdmitParameterCollations(registrationReferenceNestedCollationWitness, "fixed-witness", base, base, changed, changed)
			if err == nil || !strings.HasSuffix(err.Error(), "differing_fields="+fields[i]) {
				t.Fatal("closed differing-field roster incorrect")
			}
		})
	}
	all := base
	for _, mutate := range mutations {
		mutate(&all)
	}
	combined := registrationReferenceAdmitParameterCollations(registrationReferenceNestedCollationWitness, "fixed-witness", base, base, all, all)
	if combined == nil || !strings.HasSuffix(combined.Error(), "differing_fields="+strings.Join(fields, ",")) || len(fmt.Sprintf("%+#v", combined)) > 650 {
		t.Fatal("combined closed field ordering or diagnostic bound differs")
	}
	oversized := base
	oversized.Name = strings.Repeat("private-oversized-frame", registrationReferenceMaxRowBytes/10)
	bounded := registrationReferenceAdmitParameterCollations(registrationReferenceNestedCollationWitness, "fixed-witness", base, base, oversized, oversized)
	if bounded == nil || bounded.Error() != "original registration reference refused: collation diagnostic frame byte limit" {
		t.Fatal("diagnostic frame cap not enforced")
	}
	for _, format := range []string{"%#v", "%+#v"} {
		if strings.Contains(fmt.Sprintf(format, bounded), "private-oversized-frame") {
			t.Fatal("over-limit diagnostic frame leaked")
		}
	}

	empty := ""
	changed := base
	changed.Locale = &empty
	err := registrationReferenceAdmitParameterCollations(registrationReferenceNestedCollationWitness, "fixed-witness", base, base, changed, changed)
	if err == nil || !strings.HasSuffix(err.Error(), "differing_fields=locale") {
		t.Fatal("null versus empty field lost")
	}
}

// Break caught: aggregate and witness must consume the SAME admitted source
// replay expression, without rewriting any original source selector.
func TestWorkerRegistrationReferenceParameterSortKeyBinding(t *testing.T) {
	source := registrationReferenceTestSource(t)
	if registrationReferenceSHA([]byte(source)) != registrationReferenceCatalogSHA {
		t.Fatal("original catalog authority changed")
	}
	plan, err := registrationReferencePlan(source)
	if err != nil {
		t.Fatal(err)
	}
	outer, nested, err := registrationReferenceSortKeyCollationQueries(plan)
	if err != nil {
		t.Fatal(err)
	}
	c := registrationReferenceCollation{Name: `"C"`, Provider: "c", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	d := c
	d.Name, d.Provider = `"default"`, "d"
	for _, tc := range []struct {
		frame    registrationReferenceCollation
		relation string
	}{
		{c, `(SELECT v COLLATE pg_catalog."C" AS v FROM unnest($1::text[]) AS input(v)) AS facts`},
		{d, `unnest($1::text[]) AS facts(v)`},
	} {
		aggregate, witness, err := registrationReferenceParameterReplayQueries(tc.frame, tc.frame, c, d)
		if err != nil {
			t.Fatal(err)
		}
		expected := `SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM ` + tc.relation
		if aggregate != expected || witness != registrationReferenceCollationSQL("SELECT v FROM "+tc.relation+" LIMIT 0") {
			t.Fatal("aggregate/witness admitted sort key binding differs")
		}
	}
	if strings.Contains(outer, "COLLATE") || strings.Contains(nested, "COLLATE") {
		t.Fatal("original source ordering expression was rewritten")
	}
	for _, site := range plan.Sites {
		if !strings.Contains(outer, site.Selector) {
			t.Fatal("original source selector changed")
		}
	}
}

func TestWorkerRegistrationReferenceParameterSortKeyIdentityAndTypedBags(t *testing.T) {
	c := registrationReferenceCollation{Name: `"C"`, Provider: "c", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	originalDefault := c
	originalDefault.Name = `"default"`
	originalDefault.Provider = "d"
	raw, _ := json.Marshal(c)
	defaultRaw, _ := json.Marshal(originalDefault)
	if registrationReferenceSHA(raw) != "9dafbce30531cc09feaab043595aecc725933d7535afdebe59bd593ca6771b86" || registrationReferenceSHA(defaultRaw) != "d1ef14544a5a577cb089d365166b4c49a684cef38a4b828838505d8d862d7923" {
		t.Fatal("reviewed bootstrap frame identities changed")
	}
	if registrationReferenceAdmitSortKeyCollations(c, c, c, c) != nil {
		t.Fatal("exact C replay source frame refused")
	}
	if registrationReferenceAdmitSortKeyCollations(originalDefault, originalDefault, c, c) == nil {
		t.Fatal("nonmatching original default source admitted by fixed C replay")
	}

	for _, change := range []func(*registrationReferenceCollation){func(x *registrationReferenceCollation) { *x = originalDefault }, func(x *registrationReferenceCollation) { x.Name = "arbitrary-collation" }, func(x *registrationReferenceCollation) { x.Deterministic = false }, func(x *registrationReferenceCollation) { v := "changed-version"; x.RecordedVersion = &v }} {
		q := c
		change(&q)
		if registrationReferenceAdmitSortKeyCollations(c, c, q, q) == nil {
			t.Fatal("different/default/nondeterministic/version replay admitted")
		}
	}
	_, witness, err := registrationReferenceParameterReplayQueries(c, c, c, originalDefault)
	if err != nil {
		t.Fatal(err)
	}
	value := "typed-value"
	for _, bag := range [][]*string{nil, {}, {nil, &value, &value}} {
		query := &registrationDiagnosticQuery{row: registrationDiagnosticRow{raw: raw}}
		var observed registrationReferenceCollation
		if registrationReferenceQueryJSON(context.Background(), query, witness, &observed, bag) != nil || !reflect.DeepEqual(query.args, []any{bag}) || !reflect.DeepEqual(observed, c) {
			t.Fatal("typed null/empty/duplicate bag witness context changed")
		}
	}
}
