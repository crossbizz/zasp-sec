package apiserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Literal closed metadata shape, independent of the exporter's field map and
// SQL. No fixture rows represent real captured installation evidence.
func workerUpgradeCompleteFixture(t *testing.T) []byte {
	t.Helper()
	document := map[string]any{
		"format": "zasp-worker-effective-catalog-v2", "compiled_checksum": ordered69PredecessorCompiledChecksum,
		"functions":     []any{map[string]any{"identity": "public.zasp_example()", "definition": "CREATE FUNCTION public.zasp_example() RETURNS boolean LANGUAGE sql AS 'SELECT true'", "owner": "authority", "acl": nil, "language": "sql", "volatility": "s", "security_definer": true, "strict": false, "parallel": "u", "config": []string{"search_path=pg_catalog"}, "arguments": "", "result": "boolean", "leakproof": false, "cost": 100, "rows": 0}},
		"registrations": []any{map[string]any{"schema": "zasp_authorization80_worker", "checksum": ordered69PredecessorCompiledChecksum, "fingerprint": strings.Repeat("a", 64), "singleton": true, "predecessor": nil, "outbox_predecessor": nil, "profile_name": nil}},
	}
	for _, category := range strings.Fields("schemas relations columns constraints indexes triggers policies roles memberships saved_functions saved_views saved_constraints saved_triggers static_sources types enum_values domain_constraints ranges default_acls rewrite_rules dependencies shared_dependencies extensions role_settings") {
		document[category] = []any{}
	}
	document["saved_functions"] = []any{map[string]any{"schema": "zasp_sa_multistep_prior", "signature": "public.zasp_old()", "definition": "CREATE FUNCTION public.zasp_old() RETURNS boolean LANGUAGE sql AS 'SELECT false'", "owner": "authority", "acl": "[]"}}
	document["saved_constraints"] = []any{map[string]any{"schema": "zasp_temporal76", "signature": "public.zasp_jobs.limit", "definition": "CHECK (true)"}}
	document["saved_triggers"] = []any{map[string]any{"schema": "zasp_existing_tests_predecessor", "relation": "zasp_security_agent_audit", "name": "recovery_hold", "definition": "CREATE TRIGGER recovery_hold BEFORE INSERT ON public.zasp_security_agent_audit EXECUTE FUNCTION public.zasp_guard()", "enabled": "O"}}
	document["types"] = []any{map[string]any{"identity": "public.zasp_test_domain", "owner": "authority", "acl": nil, "kind": "d", "category": "S", "relation": nil, "element": nil, "array": nil, "base": "text", "not_null": true, "default": nil, "collation": "pg_catalog.default", "input": "domain_in(cstring,oid,integer)", "output": "textout(text)", "receive": nil, "send": nil, "analyze": nil, "subscript": nil, "length": -1, "by_value": false, "alignment": "i", "storage": "x", "delimiter": ",", "preferred": false, "defined": true, "type_modifier": -1, "dimensions": 0}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Native81363 measured 20,943 managed dependency records. These synthetic
// records reproduce cardinality and closed shape, not captured catalog data.
func TestWorkerUpgradeCatalogDependencyBound(t *testing.T) {
	for _, tc := range []struct {
		name, category, code string
		count                int
		private              bool
	}{
		{name: "measured-cardinality", category: "dependencies", count: 20943},
		{name: "dependency-edge", category: "dependencies", count: 32768},
		{name: "dependency-overflow", category: "dependencies", count: 32769, code: "category-limit"},
		{name: "other-category-unchanged", category: "shared_dependencies", count: 20001, code: "category-limit"},
		{name: "dependency-private-field", category: "dependencies", count: 20943, code: "record-width", private: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var document map[string]json.RawMessage
			if json.Unmarshal(workerUpgradeCompleteFixture(t), &document) != nil {
				t.Fatal("fixture")
			}
			records := make([]map[string]any, tc.count)
			for i := range records {
				records[i] = map[string]any{"object": fmt.Sprintf("table public.zasp_fixture_%d", i), "referenced": "schema public", "kind": "n"}
			}
			if tc.private {
				records[len(records)-1]["private-key"] = "must-not-appear"
			}
			rows, err := json.Marshal(records)
			if err != nil {
				t.Fatal("fixture")
			}
			document[tc.category] = rows
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal("fixture")
			}
			destination := filepath.Join(t.TempDir(), "catalog.json")
			err = writeWorkerUpgradeCatalog(destination, raw)
			if tc.code != "" {
				count := tc.count
				if tc.private {
					count = 4
				}
				want := fmt.Sprintf("catalog refusal code=%s category=%s count=%d bytes=%d", tc.code, tc.category, count, len(raw))
				if err == nil || err.Error() != want {
					t.Fatal("bounded private refusal changed")
				}
				if _, err := os.Lstat(destination); !os.IsNotExist(err) {
					t.Fatal("refused artifact emitted")
				}
				return
			}
			if err != nil {
				t.Fatal("bounded managed dependency capture refused", err)
			}
			written, err := os.ReadFile(destination)
			if err != nil || string(written) != string(raw)+"\n" {
				t.Fatal("dependency capture dropped or changed records")
			}
			info, err := os.Stat(destination)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("catalog output privacy changed")
			}
		})
	}
}

// Refusal must identify its validation boundary without exposing definitions,
// values, unknown field names, filesystem paths, or underlying error text.
func TestWorkerUpgradeCatalogRefusalDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, category, code string
		count                int
		mutate               func(map[string]json.RawMessage)
	}{
		{"missing-category", "types", "category-shape", 0, func(d map[string]json.RawMessage) {
			delete(d, "types")
			d["unknown-private-field"] = json.RawMessage(`[]`)
		}},
		{"record-width", "roles", "record-width", 1, func(d map[string]json.RawMessage) {
			d["roles"] = json.RawMessage(`[{"unknown-private-field":"secret"}]`)
		}},
		{"nested-value", "functions", "value-type", 15, func(d map[string]json.RawMessage) {
			d["functions"] = json.RawMessage(strings.Replace(string(d["functions"]), `"owner":"authority"`, `"owner":{"secret":"private"}`, 1))
		}},
		{"array-value", "functions", "array-value", 15, func(d map[string]json.RawMessage) {
			d["functions"] = json.RawMessage(strings.Replace(string(d["functions"]), `"search_path=pg_catalog"`, `{"secret":"private"}`, 1))
		}},
		{"registration-hash", "registrations", "registration-hash", 1, func(d map[string]json.RawMessage) {
			d["registrations"] = json.RawMessage(strings.Replace(string(d["registrations"]), strings.Repeat("a", 64), "private", 1))
		}},
		{"category-limit", "roles", "category-limit", 20001, func(d map[string]json.RawMessage) {
			d["roles"] = json.RawMessage("[" + strings.Repeat("{},", 20000) + "{}]")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d map[string]json.RawMessage
			if json.Unmarshal(workerUpgradeCompleteFixture(t), &d) != nil {
				t.Fatal("fixture")
			}
			tc.mutate(d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(t.TempDir(), "private-output.json")
			err = writeWorkerUpgradeCatalog(destination, raw)
			want := fmt.Sprintf("catalog refusal code=%s category=%s count=%d bytes=%d", tc.code, tc.category, tc.count, len(raw))
			if err == nil || err.Error() != want {
				t.Fatalf("safe refusal boundary absent: expected %q", want)
			}
			if _, err = os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("invalid catalog emitted")
			}
		})
	}
	t.Run("filesystem", func(t *testing.T) {
		raw := workerUpgradeCompleteFixture(t)
		err := writeWorkerUpgradeCatalog(filepath.Join(t.TempDir(), "private-missing-directory", "private-output.json"), raw)
		want := fmt.Sprintf("catalog refusal code=output-open category=none count=0 bytes=%d", len(raw))
		if err == nil || err.Error() != want {
			t.Fatal("filesystem refusal lost safe class or exposed path")
		}
	})
}

func TestWorkerUpgradeCatalogStructuralClosure(t *testing.T) {
	raw := workerUpgradeCompleteFixture(t)
	output := filepath.Join(t.TempDir(), "catalog.json")
	if err := writeWorkerUpgradeCatalog(output, raw); err != nil {
		t.Fatal("complete static closure refused", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != string(raw)+"\n" {
		t.Fatal("static bytes changed", err)
	}
	for _, category := range strings.Fields("saved_constraints saved_triggers static_sources types enum_values domain_constraints ranges default_acls rewrite_rules dependencies shared_dependencies extensions role_settings") {
		t.Run("missing-"+category, func(t *testing.T) {
			var changed map[string]json.RawMessage
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture")
			}
			delete(changed, category)
			value, _ := json.Marshal(changed)
			destination := filepath.Join(t.TempDir(), "refused.json")
			if writeWorkerUpgradeCatalog(destination, value) == nil {
				t.Fatal("incomplete catalog emitted")
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("refused artifact exists")
			}
		})
	}
	for _, category := range []string{"saved_functions", "types", "dependencies", "role_settings"} {
		t.Run("private-injection-"+category, func(t *testing.T) {
			var changed map[string]json.RawMessage
			_ = json.Unmarshal(raw, &changed)
			changed[category] = json.RawMessage(`[{"key":"private-key","product_row":{"secret":"private"}}]`)
			value, _ := json.Marshal(changed)
			destination := filepath.Join(t.TempDir(), "refused.json")
			if writeWorkerUpgradeCatalog(destination, value) == nil {
				t.Fatal("private fields accepted")
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("refused artifact exists")
			}
		})
	}
}
