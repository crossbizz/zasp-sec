package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func supplementControlShape() orderedSupplementShape {
	return orderedSupplementShape{Rules: []orderedSupplementRule{{ID: "runtime:session_reads:policy", Kind: "policy_view", Fields: []string{"roles_text", "using"}}}, Fields: map[string]map[string]string{"policy_view": {"roles_text": "string", "using": "string"}}, CategoryMaxRows: map[string]int{"policy_view": 2}, RuleMaxRows: map[string]int{"runtime:session_reads:policy": 2}, MaxRows: 2, MaxBytes: 1024}
}
func supplementControlRow() json.RawMessage {
	return json.RawMessage(`{"kind":"policy_view","identity":"[\"runtime:session_reads:policy\",\"public.fixed.policy\"]","fact":{"roles_text":"{public}","using":null}}`)
}

func TestOrderedSupplementRows(t *testing.T) {
	good := supplementControlRow()
	cases := []struct {
		name    string
		rows    []json.RawMessage
		change  func(*orderedSupplementShape)
		invalid bool
	}{
		{name: "raw-null", rows: []json.RawMessage{good}},
		{name: "empty-selected-universe", rows: []json.RawMessage{}},
		{name: "extra-field", rows: []json.RawMessage{json.RawMessage(strings.Replace(string(good), `"using":null`, `"using":null,"secret":"value"`, 1))}, invalid: true},
		{name: "missing-field", rows: []json.RawMessage{json.RawMessage(strings.Replace(string(good), `,"using":null`, "", 1))}, invalid: true},
		{name: "wrong-type", rows: []json.RawMessage{json.RawMessage(strings.Replace(string(good), `"using":null`, `"using":42`, 1))}, invalid: true},
		{name: "unknown-kind", rows: []json.RawMessage{json.RawMessage(strings.Replace(string(good), "policy_view", "unknown", 1))}, invalid: true},
		{name: "unknown-rule", rows: []json.RawMessage{json.RawMessage(strings.Replace(string(good), "runtime:session_reads:policy", "other", 1))}, invalid: true},
		{name: "duplicate-key", rows: []json.RawMessage{json.RawMessage(strings.Replace(string(good), `"using":null`, `"using":null,"using":"other"`, 1))}, invalid: true},
		{name: "duplicate-row", rows: []json.RawMessage{good, good}, invalid: true},
		{name: "category-cap", rows: []json.RawMessage{good}, change: func(s *orderedSupplementShape) { s.CategoryMaxRows["policy_view"] = 0 }, invalid: true},
		{name: "byte-cap", rows: []json.RawMessage{good}, change: func(s *orderedSupplementShape) { s.MaxBytes = 1 }, invalid: true},
		{name: "missing-caps", rows: []json.RawMessage{good}, change: func(s *orderedSupplementShape) { s.CategoryMaxRows = nil }, invalid: true},
		{name: "rule-cap", rows: []json.RawMessage{good}, change: func(s *orderedSupplementShape) { s.RuleMaxRows["runtime:session_reads:policy"] = 0 }, invalid: true},
		{name: "missing-rule-caps", rows: []json.RawMessage{good}, change: func(s *orderedSupplementShape) { s.RuleMaxRows = nil }, invalid: true},
		{name: "empty-zero-cap", rows: []json.RawMessage{}, change: func(s *orderedSupplementShape) {
			s.RuleMaxRows["runtime:session_reads:policy"] = 0
			s.CategoryMaxRows["policy_view"] = 0
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := supplementControlShape()
			if tc.change != nil {
				tc.change(&s)
			}
			err := checkOrderedSupplementRows(s, tc.rows)
			if (err != nil) != tc.invalid {
				t.Fatal("row boundary admission mismatch")
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("private error leak")
			}
		})
	}
}

func TestOrderedSupplementBoundary(t *testing.T) {
	for _, failure := range []string{"", "begin", "configure", "admission-before", "role", "collector-frame", "collect", "ignored-emit-error", "reset-role", "admission-after", "rollback", "restored-frame", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := []string{}
			execs, frames, admissions := 0, 0, 0
			rollbackIndependent := false
			disposed := false
			rolledBack := false
			owner := orderedSupplementFrame{Session: "zasp_test", Role: "zasp_test", SearchPath: "\"$user\", public", TimeZone: "Etc/UTC", Postgres: "PostgreSQL fixture", ServerVersionNum: "180000", Pgcrypto: "1.3"}
			io := orderedSupplementIO{
				Begin: func(context.Context) error {
					calls = append(calls, "begin")
					if failure == "begin" {
						return errors.New("private DSN")
					}
					return nil
				},
				Exec: func(_ context.Context, sql string) error {
					execs++
					name := []string{"configure", "role", "reset-role"}[execs-1]
					calls = append(calls, name)
					if failure == name {
						return errors.New("private SQL")
					}
					if name == "configure" && !strings.Contains(sql, "pg_advisory_xact_lock_shared") {
						t.Fatal("missing schema shared lock")
					}
					return nil
				},
				Frame: func(context.Context) (orderedSupplementFrame, error) {
					frames++
					name := "original-frame"
					got := owner
					if frames == 2 && !rolledBack {
						name = "collector-frame"
						got.Role = "zasp_discovery_authority"
						got.SearchPath = "pg_catalog"
						got.TimeZone = "UTC"
						got.ReadOnly = true
					}
					if rolledBack {
						name = "restored-frame"
					}
					calls = append(calls, name)
					if failure == name {
						got.Role = "foreign"
					}
					return got, nil
				},
				Admission: func(context.Context) error {
					admissions++
					name := "admission-before"
					if admissions == 2 {
						name = "admission-after"
					}
					calls = append(calls, name)
					if failure == name {
						return errors.New("private detail")
					}
					return nil
				},
				Collect: func(_ context.Context, emit func(json.RawMessage) error) error {
					calls = append(calls, "collect")
					if failure == "ignored-emit-error" {
						_ = emit(json.RawMessage(`{"private":"invalid"}`))
						return nil
					}
					if failure == "collect" {
						return errors.New("private row")
					}
					if failure == "cancel" {
						cancel()
						return ctx.Err()
					}
					return emit(supplementControlRow())
				},
				Rollback: func(clean context.Context) error {
					rolledBack = true
					calls = append(calls, "rollback")
					deadline, ok := clean.Deadline()
					rollbackIndependent = clean.Err() == nil && ok && time.Until(deadline) <= 3*time.Second
					if failure == "rollback" {
						return errors.New("private rollback")
					}
					return nil
				},
				Dispose: func(clean context.Context) error {
					deadline, ok := clean.Deadline()
					if clean.Err() != nil || !ok || time.Until(deadline) > 3*time.Second {
						t.Fatal("unbounded ambiguous close")
					}
					disposed = true
					return nil
				},
			}
			rows, frame, err := runOrderedSupplementBoundary(ctx, "zasp_test", supplementControlShape(), io)
			if (err != nil) != (failure != "") {
				t.Fatal("capture refusal mismatch", failure)
			}
			if failure == "" {
				if len(rows) != 1 || string(rows[0]) != string(supplementControlRow()) || frame.Role != "zasp_discovery_authority" {
					t.Fatal("raw output/frame lost")
				}
				want := []string{"original-frame", "begin", "configure", "admission-before", "role", "collector-frame", "collect", "reset-role", "admission-after", "rollback", "restored-frame"}
				if !reflect.DeepEqual(calls, want) {
					t.Fatal("fresh check/frame order changed", calls)
				}
			} else if rows != nil {
				t.Fatal("failed capture returned usable rows")
			}
			if failure != "begin" && !rollbackIndependent {
				t.Fatal("cleanup context not independently bounded")
			}
			if disposed != (failure == "begin" || failure == "rollback" || failure == "restored-frame") {
				t.Fatal("ambiguous connection not disposed or healthy connection disposed")
			}
			if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("capture error exposed backend detail")
			}
		})
	}
}

func TestOrderedSupplementAtomTypes(t *testing.T) {
	for _, tc := range []struct {
		kind, raw string
		valid     bool
	}{
		{"string", `null`, true}, {"string", `"raw\\ntext"`, true}, {"number", `-0.25`, true},
		{"number", `-0`, false}, {"number", `1e2`, false}, {"integer", `1.25`, false},
		{"array", `["one","two"]`, true}, {"array", `[1]`, false}, {"acl", `"{owner=X/owner}"`, true},
		{"boolean", `false`, true}, {"boolean", `"false"`, false}, {"unknown", `42`, false},
	} {
		if supplementAtom(json.RawMessage(tc.raw), tc.kind) != tc.valid {
			t.Fatalf("typed atom admission changed: %s", tc.kind)
		}
	}
}

func supplementPinnedInputs(t *testing.T) orderedSupplementInputs {
	t.Helper()
	base := "../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement"
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			t.Fatal("pinned supplementary fixture missing")
		}
		return raw
	}
	return orderedSupplementInputs{Contract: read("ordered-current-supplementary-query-contract2.json"), SQL: read("ordered-current-supplementary-select2.sql"), Rules: read("ordered-current-supplementary-rules2.json"), Sites: read("ordered-current-supplementary-sites2.json"), Compiler: read("ordered-current-inventory-compiled.json"), Catalog: read("ordered-current-effective-catalog1.json"), SourceContract: read("ordered-current-effective-contract3.json")}
}

func TestOrderedSupplementArtifactPins(t *testing.T) {
	input := supplementPinnedInputs(t)
	t.Run("pinned", func(t *testing.T) {
		shape, err := verifyOrderedSupplementInputs(input)
		if err != nil || len(shape.Rules) != 57 || shape.MaxRows != 520 || shape.MaxBytes != 16777216 {
			t.Fatal("exact source-bound query refused or bounds lost")
		}
	})
	for _, name := range []string{"query", "contract", "rules", "sites", "compiler", "catalog", "source-contract", "empty", "self-repin", "role", "source-pin"} {
		t.Run(name, func(t *testing.T) {
			copy := input
			switch name {
			case "query":
				copy.SQL = append(append([]byte{}, input.SQL...), []byte(" SELECT 'private'")...)
			case "contract":
				copy.Contract = append(append([]byte{}, input.Contract...), ' ')
			case "rules":
				copy.Rules = []byte(`[]`)
			case "sites":
				copy.Sites = []byte(`[]`)
			case "compiler":
				copy.Compiler = []byte(`{"checksum":"e12"}`)
			case "catalog":
				copy.Catalog = []byte(`{}`)
			case "source-contract":
				copy.SourceContract = []byte(`{}`)
			case "empty":
				copy = orderedSupplementInputs{}
			case "self-repin":
				copy.SQL = []byte("SELECT 'private'")
				sum := sha256.Sum256(copy.SQL)
				copy.Contract = []byte(strings.Replace(string(input.Contract), "2b2adb28c2537de544ee7a5e543972ef25e771ac73b28313d78c1d20fedc28cd", hex.EncodeToString(sum[:]), 1))
			case "role":
				copy.Contract = []byte(strings.Replace(string(input.Contract), `"requiredRole": "zasp_discovery_authority"`, `"requiredRole": "foreign"`, 1))
			case "source-pin":
				copy.Contract = []byte(strings.Replace(string(input.Contract), "d431ecc57e280c8fc6174f0a47c8d4706c8515d0ac2cc17d4494f4acaa5edc9b", strings.Repeat("0", 64), 1))
			}
			if _, err := verifyOrderedSupplementInputs(copy); err == nil {
				t.Fatal("changed/unfinalized artifact accepted")
			}
		})
	}
}

func TestOrderedSupplementSuccessorCaps(t *testing.T) {
	input := supplementPinnedInputs(t)
	shape, err := verifyOrderedSupplementInputs(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"role-profile:current-profile", "role-profile:native-roles"} {
		t.Run(id, func(t *testing.T) {
			var rule orderedSupplementRule
			for _, candidate := range shape.Rules {
				if candidate.ID == id {
					rule = candidate
				}
			}
			want := 1
			if id == "role-profile:native-roles" {
				want = 3
			}
			if rule.ID == "" || shape.RuleMaxRows[id] != want {
				t.Fatal("successor cap missing")
			}
			var rows []json.RawMessage
			for i := 0; i <= want; i++ {
				fact := map[string]any{}
				for _, field := range rule.Fields {
					fact[field] = nil
				}
				key, _ := json.Marshal([]string{id, strings.Repeat("x", i+1)})
				row, _ := json.Marshal(map[string]any{"kind": rule.Kind, "identity": string(key), "fact": fact})
				rows = append(rows, row)
			}
			if checkOrderedSupplementRows(shape, rows[:want]) != nil || checkOrderedSupplementRows(shape, rows) == nil {
				t.Fatal("successor cap not enforced")
			}
		})
	}
	old, err := os.ReadFile("../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-supplementary-query-contract.json")
	if err != nil {
		t.Fatal("old immutable contract missing")
	}
	input.Contract = old
	if _, err := verifyOrderedSupplementInputs(input); err == nil {
		t.Fatal("old 55-rule contract accepted")
	}
}

func TestOrderedSupplementInputFiles(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "input")
	if os.WriteFile(regular, []byte("fixed"), 0600) != nil {
		t.Fatal("fixture")
	}
	t.Run("regular", func(t *testing.T) {
		raw, e := readOrderedSupplementFile(regular, 5)
		if e != nil || string(raw) != "fixed" {
			t.Fatal("regular input refused")
		}
	})
	for _, mode := range []string{"cap", "directory", "symlink", "fifo", "absent"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(dir, mode)
			limit := 5
			switch mode {
			case "cap":
				path = regular
				limit = 4
			case "directory":
				path = dir
			case "symlink":
				if os.Symlink(regular, path) != nil {
					t.Fatal("fixture")
				}
			case "fifo":
				if syscall.Mkfifo(path, 0600) != nil {
					t.Fatal("fixture")
				}
			}
			start := time.Now()
			if _, e := readOrderedSupplementFile(path, limit); e == nil {
				t.Fatal("invalid input admitted")
			}
			if time.Since(start) > time.Second {
				t.Fatal("nonregular input blocked")
			}
		})
	}
}

func TestOrderedSupplementPublication(t *testing.T) {
	for _, mode := range []string{"ok", "exists", "input-collision", "symlink", "oversized", "relative"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "reference.json")
			payload := []byte(`{"rows":[]}`)
			limit := 1024
			var inputs []string
			switch mode {
			case "exists":
				if os.WriteFile(path, []byte("untouched"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "input-collision":
				inputs = []string{path}
			case "symlink":
				if os.Symlink(filepath.Join(dir, "target"), path) != nil {
					t.Fatal("fixture")
				}
			case "oversized":
				limit = 1
			case "relative":
				path = "relative.json"
			}
			got, err := publishOrderedSupplement(path, inputs, payload, limit)
			if (err == nil) != (mode == "ok") {
				t.Fatal("publication boundary mismatch")
			}
			if mode == "ok" {
				raw, e := os.ReadFile(path)
				info, s := os.Stat(path)
				if e != nil || s != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || string(raw) != string(payload)+"\n" {
					t.Fatal("private atomic file incorrect")
				}
				p, f := sha256.Sum256(payload), sha256.Sum256(raw)
				if got.PayloadSHA256 != hex.EncodeToString(p[:]) || got.FileSHA256 != hex.EncodeToString(f[:]) || got.Bytes != len(raw) {
					t.Fatal("payload/file hashes conflated")
				}
			} else if mode == "exists" {
				raw, _ := os.ReadFile(path)
				if string(raw) != "untouched" {
					t.Fatal("existing output overwritten")
				}
			}
			entries, _ := os.ReadDir(dir)
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".ordered-supplement-") {
					t.Fatal("temporary publication residue")
				}
			}
		})
	}
}
