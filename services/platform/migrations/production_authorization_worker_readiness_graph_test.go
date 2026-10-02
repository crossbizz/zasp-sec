package migrations

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkerReadinessGraphAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	const graph = "DO $readiness_graph$"
	if strings.Count(source, graph) != 1 {
		t.Fatal("missing one shared readiness computation")
	}
	if strings.Index(source, graph) < strings.Index(source, "END $owners$;") {
		t.Fatal("readiness source/frame verification must follow final ownership")
	}
	if strings.Count(source, "DO $higher_readiness$") != 1 || strings.Count(source, "END $higher_readiness$;") != 1 ||
		strings.Index(source, "DO $higher_readiness$") < strings.Index(source, "END $owners$;") ||
		strings.Index(source, "END $higher_readiness$;") > strings.Index(source, graph) {
		t.Fatal("higher regions must verify final ownership before the base graph changes its precursor")
	}
	parts := strings.Split(source, "$higher_records$")
	if len(parts) != 3 {
		t.Fatal("higher region record delimiter changed")
	}
	var higher struct {
		Regions []struct {
			Signature string `json:"signature"`
			Prefix    string `json:"prefix"`
			Suffix    string `json:"suffix"`
			Query     string `json:"query"`
		} `json:"regions"`
	}
	if err := json.Unmarshal([]byte(parts[1]), &higher); err != nil || len(higher.Regions) != 3 {
		t.Fatal("invalid higher expression manifest", err)
	}
	for i, signature := range []string{"zasp_temporal68.predecessor_ready(text,text)", "zasp_temporal68.ready(text,text)", "zasp_temporal78.ready(text,text)"} {
		if higher.Regions[i].Signature != signature || !strings.Contains(higher.Regions[i].Query, "pg_get_functiondef(p.oid)") {
			t.Fatal("higher expression identity or guarded live leaf changed")
		}
	}
	if !strings.Contains(higher.Regions[0].Prefix, "c IS DISTINCT FROM") || !strings.Contains(higher.Regions[0].Suffix, "EXECUTE format('SELECT %I.fingerprint()',n)") || !strings.Contains(higher.Regions[2].Prefix, "SELECT c=") {
		t.Fatal("higher graph lost native cheap guards or opaque dynamic tail")
	}
	if strings.Count(source, "END $readiness_graph$;") != 1 || strings.Count(source, "regexp_replace(btrim(original_value),';[[:space:]]*$','')") != 2 {
		t.Fatal("shared readiness generator duplicated or truncated installer")
	}
	for _, required := range []string{
		"readiness_0(value) AS MATERIALIZED (SELECT zasp_authorization80_worker.catalog_ready())",
		"current_user=''zasp_discovery_authority''",
		"SELECT CASE WHEN (SELECT value FROM readiness_0) THEN",
		"readiness graph exact source or frame changed",
		"readiness graph call anchor changed",
		"ON CONFLICT(signature) DO NOTHING",
	} {
		if !strings.Contains(source, required) {
			t.Error("missing shared readiness contract", required)
		}
	}
}
