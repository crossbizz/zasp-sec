package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

func TestWorkerRegistrationReferenceQueryDiagnostics(t *testing.T) {
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
			for _, want := range []string{"original registration reference refused:", "error_class=" + tc.class, "sqlstate=" + tc.state, "statement_sha256=3881a6e5adc60e1245ed1b8a859d05eaceab5a52b0e1334a8f93c1aa32697cc3"} {
				if !strings.Contains(message, want) {
					t.Errorf("bounded query diagnostic lost %q: %s", want, message)
				}
			}
			if len(message) > 256 || strings.ContainsAny(message, "\r\n") || strings.Contains(message, "private") || strings.Contains(message, "seeded-secret") || errors.Unwrap(err) != nil {
				t.Fatal("query diagnostic exposed driver/statement/argument data or exceeded its output bound")
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

func TestWorkerRegistrationReferenceDefaultCollationMapping(t *testing.T) {
	s := registrationReferenceCollationSQL("SELECT NULL::text")
	if !strings.Contains(s, "CASE WHEN c.collprovider='d' THEN d.datcollversion") || !strings.Contains(s, "CASE WHEN c.collprovider='d' THEN pg_database_collation_actual_version(d.oid)") {
		t.Fatal("effective database-default version mapping missing")
	}
	if strings.Contains(s, "COLLATE") || strings.Contains(s, "ORDER BY") {
		t.Fatal("mapping overrode source ordering")
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
	outer, nested, parameter, err := registrationReferenceSortKeyCollationQueries(plan)
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
	if !strings.Contains(parameter, "SELECT v FROM unnest($1::text[]) AS facts(v) LIMIT 0))) AS oid") || strings.Contains(parameter, "ARRAY[") {
		t.Fatal("parameter witness did not use exact actual parameter expression")
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
