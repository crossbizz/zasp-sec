package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// These assertions fail if a refusal loses its fixed location or prints a
// compared value. The interface keeps this RED executable on the old boundary.
func TestTransformAcceptanceSpecificPrivateDiagnostics(t *testing.T) {
	r := transformAcceptanceRule{ID: "public:sa_multistep:function", Cap: 1, Fields: []string{"owner", "strict"}, FieldTypes: map[string]string{"owner": "string", "strict": "boolean"}}
	original := []transformAcceptanceRow{{OID: "42", Line: "fixed-line", Fact: json.RawMessage(`{"owner":"private-sentinel","strict":false}`)}}
	for _, tc := range []struct{ name, fact, line, stage, field string }{
		{"value", `{"owner":"secret-different","strict":false}`, "fixed-line", "value", "owner"},
		{"type", `{"owner":"private-sentinel","strict":"secret-different"}`, "fixed-line", "type", "strict"},
		{"line", `{"owner":"private-sentinel","strict":false}`, "secret-different", "line", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := []transformAcceptanceRow{{Identity: `["public:sa_multistep:function","public.f()"]`, Line: tc.line, Fact: json.RawMessage(tc.fact)}}
			_, err := compareTransformAcceptanceRows(r, original, candidate, map[string]string{"public.f()": "42"})
			var diagnostic interface{ Diagnostic() map[string]string }
			if err == nil || !errors.As(err, &diagnostic) {
				t.Fatal("refusal lost typed diagnostic")
			}
			labels := diagnostic.Diagnostic()
			if labels["rule"] != r.ID || labels["field"] != tc.field || labels["stage"] != tc.stage {
				t.Fatalf("wrong safe location: %v", labels)
			}
			b, _ := json.Marshal(labels)
			if strings.Contains(string(b)+err.Error(), "secret-different") || strings.Contains(string(b)+err.Error(), "private-sentinel") {
				t.Fatal("diagnostic leaked value")
			}
		})
	}
}

func TestTransformAcceptanceObservedInitialRestoredFramesPersist(t *testing.T) {
	io, _, ctx, cancel := transformBoundaryFixture(t, "")
	defer cancel()
	originalExercise, originalValidate := io.Exercise, io.Validate
	original := orderedSupplementFrame{Session: "zasp_test", Role: "zasp_discovery_authority", SearchPath: "pg_catalog, public", TimeZone: "UTC", Postgres: transformAcceptancePostgres, ServerVersionNum: "180003", Pgcrypto: "1.4", ReadOnly: true}
	candidate := original
	candidate.SearchPath = "pg_catalog"
	io.Exercise = func(c context.Context, step transformAcceptanceCase) (json.RawMessage, error) {
		if _, e := originalExercise(c, step); e != nil {
			return nil, e
		}
		if checkTransformExecutionFrame(original, false, "pg_catalog, public") != nil || checkTransformExecutionFrame(candidate, false, "pg_catalog") != nil {
			t.Fatal("controlled checked frames")
		}
		return json.Marshal(map[string]any{"verified": true, "executionFrames": map[string]any{"public:sa_multistep:function": map[string]any{"original": original, "candidate": candidate}}})
	}
	io.Validate = func(c context.Context, raw json.RawMessage) error {
		return originalValidate(c, json.RawMessage(`{"verified":true}`))
	}
	raw, err := runTransformAcceptanceCase(ctx, transformAcceptanceCase{ID: "pristine"}, io)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Frames          struct{ Initial, Restored, PostAdmissionRestored orderedSupplementFrame }
		ExecutionFrames map[string]map[string]orderedSupplementFrame
	}
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("result JSON")
	}
	f := result.Frames.Initial
	if f.SearchPath != `"$user", public` || f.TimeZone != "America/Los_Angeles" || f.Postgres != "exact" || f.Role != "zasp_test" || f.Session != "zasp_test" || f.ServerVersionNum != "180003" || f.Pgcrypto != "1.4" || f.ReadOnly || result.Frames.Restored != f || result.Frames.PostAdmissionRestored != f {
		t.Fatal("actual nondefault frame/build discarded or replaced")
	}
	if result.ExecutionFrames["public:sa_multistep:function"]["original"] != original || result.ExecutionFrames["public:sa_multistep:function"]["candidate"] != candidate {
		t.Fatal("observed query frames discarded")
	}
}

func TestTransformAcceptanceDiagnosticsAggregateConfigAndUnwrapping(t *testing.T) {
	rule := "public:sa_multistep:function"
	a, b := "private-aggregate", "different-private-aggregate"
	err := compareTransformAggregate(rule, &a, &b)
	var d interface{ Diagnostic() map[string]string }
	if !errors.As(err, &d) || d.Diagnostic()["stage"] != "aggregate" || d.Diagnostic()["rule"] != rule {
		t.Fatal("aggregate location lost")
	}
	if compareTransformAggregate(rule, nil, nil) != nil {
		t.Fatal("NULL aggregate changed")
	}
	input, e := loadTransformAcceptance(transformAcceptancePacketDirectory)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bad := json.RawMessage(`{"objectOID":"42","identity":"private-sentinel","config":["application_name=private-sentinel"],"dimensions":1,"lowerBound":1,"upperBound":1,"originalText":"secret-different"}`)
	err = checkTransformConfigWithNode(ctx, input, []json.RawMessage{bad}, false)
	if !errors.As(err, &d) || d.Diagnostic()["stage"] != "config" || d.Diagnostic()["field"] != "config_text_or_empty" {
		t.Fatal("config refusal lost location")
	}
	first := &pgconn.PgError{Code: "42703", Position: 5212, Message: "private-sentinel", Detail: "secret-different", Where: "raw SQL"}
	later := &pgconn.PgError{Code: "25P02", Position: 999, Message: "later-private"}
	wrapped := &transformAcceptanceCaseError{ID: "saved-missing-column", Cause: errors.Join(transformAt(rule, "original", first), later)}
	labels := wrapped.Diagnostic()
	if labels["case"] != "saved-missing-column" || labels["rule"] != rule || labels["stage"] != "sql" || labels["phase"] != "original" || labels["sqlstate"] != "42703" || labels["position"] != "5212" {
		t.Fatalf("earliest cause/location lost: %v", labels)
	}
	var got *pgconn.PgError
	if !errors.As(wrapped, &got) || got != first {
		t.Fatal("cause no longer unwraps")
	}
	for _, failure := range []error{err, wrapped, &transformAcceptanceCaseError{ID: "private-sentinel", Cause: &transformAcceptanceFailure{Rule: "secret-different", Field: "raw SQL", Stage: "later-private", Phase: "private-sentinel", Cause: &pgconn.PgError{Code: "bad\n!", Position: 1048577, Message: "private-sentinel"}}}} {
		if !errors.As(failure, &d) {
			t.Fatal("typed diagnostic absent")
		}
		raw, _ := json.Marshal(d.Diagnostic())
		if len(raw) > 2048 {
			t.Fatal("unbounded diagnostic")
		}
		for _, secret := range []string{"private-sentinel", "secret-different", "raw SQL", "later-private", "1048577", "bad\\n!"} {
			if strings.Contains(string(raw)+failure.Error(), secret) {
				t.Fatal("diagnostic leaked untrusted field")
			}
		}
	}
}

func transformBoundaryFixture(t *testing.T, fail string) (transformAcceptanceIO, *[]string, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	calls := []string{}
	active := false
	readOnly := false
	frames := 0
	evidence := 0
	frame := orderedSupplementFrame{Session: "zasp_test", Role: "zasp_test", SearchPath: "\"$user\", public", TimeZone: "America/Los_Angeles", Postgres: "exact", ServerVersionNum: "180003", Pgcrypto: "1.4"}
	check := func(c context.Context, stage string) error {
		calls = append(calls, stage)
		if stage == "rollback" || stage == "dispose" {
			if c.Err() != nil {
				t.Fatal("cleanup inherited cancellation")
			}
			d, ok := c.Deadline()
			if !ok || time.Until(d) > 3*time.Second {
				t.Fatal("cleanup unbounded")
			}
		} else if stage != "frame" {
			d, ok := c.Deadline()
			if !ok || time.Until(d) > 30*time.Second {
				t.Fatal("observer unbounded")
			}
		}
		if fail == stage {
			return errors.New("injected " + stage)
		}
		return nil
	}
	io := transformAcceptanceIO{
		Frame: func(c context.Context) (orderedSupplementFrame, error) {
			if e := check(c, "frame"); e != nil {
				return frame, e
			}
			frames++
			f := frame
			if active {
				f.ReadOnly = readOnly
			}
			if fail == "restored-frame" && frames > 1 {
				f.Role = "wrong"
			}
			return f, nil
		},
		Begin: func(c context.Context, write bool) error {
			if e := check(c, "begin"); e != nil {
				return e
			}
			active = true
			readOnly = !write
			return nil
		},
		Configure: func(c context.Context) error { return check(c, "configure") },
		Admission: func(c context.Context) error { return check(c, "admission") },
		Evidence: func(c context.Context) (string, error) {
			if e := check(c, "evidence"); e != nil {
				return "", e
			}
			evidence++
			if fail == "restored-evidence" && evidence > 1 {
				return "changed", nil
			}
			return "frozen", nil
		},
		Exercise: func(c context.Context, _ transformAcceptanceCase) (json.RawMessage, error) {
			if e := check(c, "exercise"); e != nil {
				return nil, e
			}
			if fail == "cancel" {
				cancel()
			}
			return json.RawMessage(`{"verified":true}`), nil
		},
		Rollback: func(c context.Context) error { e := check(c, "rollback"); active = false; return e },
		Validate: func(c context.Context, raw json.RawMessage) error {
			if active || frames%3 != 0 || evidence%2 != 0 || string(raw) != `{"verified":true}` {
				t.Fatal("local validation preceded full restoration")
			}
			if fail == "validate-cancel" {
				cancel()
			}
			return check(c, "validate")
		},
		Dispose: func(c context.Context) error { return check(c, "dispose") },
	}
	return io, &calls, ctx, cancel
}
func TestTransformAcceptanceRestorationBeforeResult(t *testing.T) {
	for _, write := range []bool{false, true} {
		io, calls, ctx, cancel := transformBoundaryFixture(t, "")
		defer cancel()
		result, e := runTransformAcceptanceCase(ctx, transformAcceptanceCase{ID: "pristine", Write: write}, io)
		var observed map[string]json.RawMessage
		if e != nil || json.Unmarshal(result, &observed) != nil || string(observed["verified"]) != `true` || observed["frames"] == nil {
			t.Fatal("case did not return actual comparison", e)
		}
		want := []string{"frame", "begin", "configure", "admission", "evidence", "exercise", "rollback", "frame", "begin", "configure", "admission", "evidence", "rollback", "frame", "validate"}
		if !reflect.DeepEqual(*calls, want) {
			t.Fatalf("missing admission/restoration: %v", *calls)
		}
	}
}
func TestTransformAcceptanceRefusalAndIndependentCleanup(t *testing.T) {
	for _, stage := range []string{"begin", "configure", "admission", "evidence", "exercise", "rollback", "restored-frame", "restored-evidence", "cancel", "validate", "validate-cancel"} {
		t.Run(stage, func(t *testing.T) {
			io, calls, ctx, cancel := transformBoundaryFixture(t, stage)
			defer cancel()
			result, e := runTransformAcceptanceCase(ctx, transformAcceptanceCase{ID: "pristine", Write: true}, io)
			if e == nil || result != nil {
				t.Fatal("failure exposed result")
			}
			found := false
			for _, call := range *calls {
				if call == "dispose" {
					found = true
				}
			}
			if !found {
				t.Fatal("failed case did not dispose")
			}
		})
	}
}
func TestTransformAcceptanceDependencyRefusals(t *testing.T) {
	if _, e := runTransformAcceptanceCase(context.Background(), transformAcceptanceCase{ID: "pristine"}, transformAcceptanceIO{}); e == nil {
		t.Fatal("empty dependencies admitted")
	}
	io, _, ctx, cancel := transformBoundaryFixture(t, "")
	cancel()
	if _, e := runTransformAcceptanceCase(ctx, transformAcceptanceCase{ID: "pristine"}, io); e == nil {
		t.Fatal("cancelled start admitted")
	}
}
func TestTransformAcceptanceTypedComparison(t *testing.T) {
	r := transformAcceptanceRule{ID: "public:sa_multistep:function", Cap: 1, Fields: []string{"owner", "strict", "acl"}, FieldTypes: map[string]string{"owner": "string", "strict": "boolean", "acl": "string"}}
	original := []transformAcceptanceRow{{OID: "42", Line: "function|owner|f|", Fact: json.RawMessage(`{"owner":"owner","strict":false,"acl":null}`)}}
	candidate := []transformAcceptanceRow{{Identity: `["public:sa_multistep:function","public.f()"]`, Line: original[0].Line, Fact: json.RawMessage(`{"strict":false,"acl":null,"owner":"owner"}`)}}
	roster := map[string]string{"public.f()": "42"}
	if digest, e := compareTransformAcceptanceRows(r, original, candidate, roster); e != nil || len(digest) != 64 {
		t.Fatal("actual typed comparison missing", e)
	}
	for _, mode := range []string{"boolean-string", "null-empty", "field-missing", "field-extra", "duplicate-key", "line", "foreign", "duplicate-row", "empty"} {
		t.Run(mode, func(t *testing.T) {
			o := append([]transformAcceptanceRow{}, original...)
			c := append([]transformAcceptanceRow{}, candidate...)
			switch mode {
			case "boolean-string":
				c[0].Fact = json.RawMessage(`{"owner":"owner","strict":"false","acl":null}`)
			case "null-empty":
				c[0].Fact = json.RawMessage(`{"owner":"owner","strict":false,"acl":""}`)
			case "field-missing":
				c[0].Fact = json.RawMessage(`{"owner":"owner","acl":null}`)
			case "field-extra":
				c[0].Fact = json.RawMessage(`{"owner":"owner","strict":false,"acl":null,"extra":0}`)
			case "duplicate-key":
				c[0].Fact = json.RawMessage(`{"owner":"owner","owner":"owner","strict":false,"acl":null}`)
			case "line":
				c[0].Line = "different"
			case "foreign":
				c[0].Identity = `["public:sa_multistep:function","other.f()"]`
			case "duplicate-row":
				c = append(c, c[0])
			case "empty":
				c = nil
				o = nil
			}
			if _, e := compareTransformAcceptanceRows(r, o, c, roster); e == nil {
				t.Fatal("invalid comparison accepted")
			}
		})
	}
}

func TestTransformAcceptanceRawObservationsMatchExactTypedUniverse(t *testing.T) {
	p := transformAcceptancePacket{MaxRows: 2, MaxBytes: 1024, Rules: []transformAcceptanceRule{{ID: "public:sa_multistep:function", Cap: 2}}, RawRules: []json.RawMessage{json.RawMessage(`{"id":"raw-transform:public:sa_multistep","kind":"routine","fields":["owner","strict"]}`)}}
	row := json.RawMessage(`{"kind":"routine","identity":"[\"raw-transform:public:sa_multistep\",\"public.f()\"]","fact":{"owner":"owner","strict":false}}`)
	counts := map[string]int{"public:sa_multistep:function": 1}
	if err := checkTransformRawObservations(p, []json.RawMessage{row}, counts); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []json.RawMessage{
		json.RawMessage(`{"kind":"routine","identity":"[\"raw-transform:public:sa_multistep\",\"public.f()\"]","fact":{"owner":"owner","strict":"false"}}`),
		json.RawMessage(`{"kind":"routine","identity":"[\"raw-transform:public:sa_multistep\",\"public.f()\"]","fact":{"owner":"owner","extra":false}}`),
		json.RawMessage(`{"kind":"routine","identity":"[\"raw-transform:public:foreign\",\"public.f()\"]","fact":{"owner":"owner","strict":false}}`),
	} {
		if checkTransformRawObservations(p, []json.RawMessage{bad}, counts) == nil {
			t.Fatal("malformed intermediate input admitted")
		}
	}
	for _, rows := range [][]json.RawMessage{{}, {row, row}} {
		if checkTransformRawObservations(p, rows, counts) == nil {
			t.Fatal("partial/duplicate intermediate universe admitted")
		}
	}
}

func TestTransformAcceptanceConfigWitnessUsesActualRoster(t *testing.T) {
	raw := json.RawMessage(`{"objectOID":"42","identity":"public.f()","config":null,"dimensions":null,"lowerBound":null,"upperBound":null,"originalText":""}`)
	roster := map[string]string{"public.f()": "42"}
	if e := checkTransformWitnessRoster([]json.RawMessage{raw}, roster); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []map[string]string{{"public.f()": "43"}, {"public.g()": "42"}, {}, {"public.f()": "42", "public.g()": "43"}} {
		if checkTransformWitnessRoster([]json.RawMessage{raw}, bad) == nil {
			t.Fatal("foreign/incomplete witness association")
		}
	}
	if checkTransformWitnessRoster([]json.RawMessage{raw, raw}, roster) == nil {
		t.Fatal("duplicate witness")
	}
}

func TestTransformAcceptanceFullPacketAndLocalFormatter(t *testing.T) {
	input, e := loadTransformAcceptance(transformAcceptancePacketDirectory)
	if e != nil {
		t.Fatal(e)
	}
	if len(input.Paths) != 16 || len(input.Packet.Rules) != 13 || len(input.Packet.Cases) != 19 || input.Packet.CompiledSHA256 != "981a36a06bdb553b32f88243e4f8fdc5e55df2d2d2c70739cb8221c7cf7bea1e" {
		t.Fatal("incomplete actual packet")
	}
	w := json.RawMessage(`{"objectOID":"42","identity":"public.f()","config":["search_path=pg_catalog, public"],"dimensions":1,"lowerBound":1,"upperBound":1,"originalText":"{\"search_path=pg_catalog, public\"}"}`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if checkTransformConfigWithNode(ctx, input, []json.RawMessage{w}, false) != nil {
		t.Fatal("frozen actual formatter not consumed")
	}
	for _, name := range []string{"snapshot-manifest.json", "transform-acceptance.json", transformAcceptanceBuilder, "services/platform/migrations/tools/ordered-current-transform-compiler.mjs"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, source := range input.Paths {
				rel, e := filepath.Rel(input.Directory, source)
				if e != nil {
					t.Fatal(e)
				}
				b, e := os.ReadFile(source)
				if e != nil {
					t.Fatal(e)
				}
				target := filepath.Join(dir, rel)
				if os.MkdirAll(filepath.Dir(target), 0700) != nil || os.WriteFile(target, b, 0600) != nil {
					t.Fatal("copy packet")
				}
			}
			file, e := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_WRONLY, 0600)
			if e != nil {
				t.Fatal(e)
			}
			_, e = file.WriteString("\n")
			closeErr := file.Close()
			if e != nil || closeErr != nil {
				t.Fatal("tamper fixture")
			}
			if _, e = loadTransformAcceptance(dir); e == nil {
				t.Fatal("tampered actual input admitted")
			}
		})
	}
}

func TestTransformAcceptanceClosedMode(t *testing.T) {
	if on, e := transformAcceptanceMode("", nil); on || e != nil {
		t.Fatal("default does not delegate")
	}
	if on, e := transformAcceptanceMode("1", nil); !on || e != nil {
		t.Fatal("explicit mode refused")
	}
	for _, value := range []string{"true", "catalog", "2"} {
		if _, e := transformAcceptanceMode(value, nil); e == nil {
			t.Fatal("invalid mode admitted")
		}
	}
	for _, key := range transformAcceptanceOverlaps {
		if _, e := transformAcceptanceMode("1", map[string]string{key: "1"}); e == nil {
			t.Fatal("overlap admitted", key)
		}
	}
}

func TestTransformAcceptanceCompleteGroupPublication(t *testing.T) {
	input, e := loadTransformAcceptance(transformAcceptancePacketDirectory)
	if e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"", "exercise", "validate-cancel", "encode", "short", "reordered", "collision"} {
		t.Run(fault, func(t *testing.T) {
			io, calls, ctx, cancel := transformBoundaryFixture(t, fault)
			defer cancel()
			destination := filepath.Join(t.TempDir(), "result.json")
			if fault == "collision" && os.WriteFile(destination, []byte("retained"), 0600) != nil {
				t.Fatal("collision setup")
			}
			cases := append([]transformAcceptanceCase{}, input.Packet.Cases...)
			if fault == "short" {
				cases = cases[:18]
			}
			if fault == "reordered" {
				cases[0], cases[1] = cases[1], cases[0]
			}
			encoded := false
			pub, e := runTransformAcceptanceGroup(ctx, cases, io, input.Paths, destination, func(results []json.RawMessage) ([]byte, error) {
				encoded = true
				if len(results) != 19 {
					t.Fatal("partial group encoded")
				}
				if fault == "encode" {
					return nil, errors.New("fixed encode refusal")
				}
				return json.Marshal(map[string]any{"completedCases": len(results)})
			})
			if fault != "" {
				if e == nil {
					t.Fatal("failed group published")
				}
				raw, readErr := os.ReadFile(destination)
				if fault == "collision" {
					if readErr != nil || string(raw) != "retained" {
						t.Fatal("collision changed")
					}
				} else if !os.IsNotExist(readErr) {
					t.Fatal("failure exposed output")
				}
				if (fault == "exercise" || fault == "validate-cancel" || fault == "short" || fault == "reordered") && encoded {
					t.Fatal("incomplete boundary reached encoder")
				}
				if len(*calls) > 0 && (*calls)[len(*calls)-1] != "dispose" {
					t.Fatal("failure not disposed")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			raw, e := os.ReadFile(destination)
			if e != nil || string(raw) != "{\"completedCases\":19}\n" || pub.FileSHA256 != supplementSHA(raw) || pub.PayloadSHA256 != supplementSHA(raw[:len(raw)-1]) {
				t.Fatal("publication bytes")
			}
			info, e := os.Stat(destination)
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("publication mode")
			}
		})
	}
}

func TestTransformAcceptanceExecutionFrameAndCombinedProjection(t *testing.T) {
	f := orderedSupplementFrame{Session: "zasp_test", Role: "zasp_discovery_authority", SearchPath: "pg_catalog", TimeZone: "UTC", Postgres: transformAcceptancePostgres, ServerVersionNum: "180003", Pgcrypto: "1.4", ReadOnly: true}
	if checkTransformExecutionFrame(f, false, "pg_catalog") != nil {
		t.Fatal("exact frame refused")
	}
	for _, field := range []string{"role", "path", "timezone", "readonly", "version", "build", "extension", "session"} {
		bad := f
		switch field {
		case "role":
			bad.Role = "zasp_test"
		case "path":
			bad.SearchPath = "public"
		case "timezone":
			bad.TimeZone = "Etc/UTC"
		case "readonly":
			bad.ReadOnly = false
		case "version":
			bad.ServerVersionNum = "180004"
		case "build":
			bad.Postgres = "another"
		case "extension":
			bad.Pgcrypto = "1.3"
		case "session":
			bad.Session = "foreign"
		}
		if checkTransformExecutionFrame(bad, false, "pg_catalog") == nil {
			t.Error("foreign frame accepted", field)
		}
	}
	a := json.RawMessage(`{"kind":"routine","identity":"[\"public:sa_multistep:function\",\"public.f()\"]","fact":{"strict":false,"acl":null}}`)
	b := json.RawMessage(`{"identity":"[\"public:sa_multistep:function\",\"public.f()\"]","kind":"routine","fact":{"acl":null,"strict":false}}`)
	if compareTransformCombinedRows([]json.RawMessage{a}, []json.RawMessage{b}) != nil {
		t.Fatal("same typed combined result refused")
	}
	for _, bad := range [][]json.RawMessage{{}, {b, b}, {json.RawMessage(`{"kind":"routine","identity":"[\"public:sa_multistep:function\",\"public.f()\"]","fact":{"strict":"false","acl":null}}`)}} {
		if compareTransformCombinedRows([]json.RawMessage{a}, bad) == nil {
			t.Fatal("different combined SQL result admitted")
		}
	}
	changed := json.RawMessage(`{"kind":"routine","identity":"[\"public:sa_multistep:function\",\"public.f()\"]","fact":{"strict":true,"acl":null}}`)
	var d interface{ Diagnostic() map[string]string }
	if e := compareTransformCombinedRows([]json.RawMessage{a}, []json.RawMessage{changed}); !errors.As(e, &d) || d.Diagnostic()["rule"] != "public:sa_multistep:function" || d.Diagnostic()["field"] != "strict" || d.Diagnostic()["stage"] != "combined" {
		t.Fatal("combined projection lost safe rule/field")
	}
}
