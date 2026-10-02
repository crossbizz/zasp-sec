package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadinessAttributionSanitizesPlan(t *testing.T) {
	raw := []byte(`[{"Planning Time":1.25,"Execution Time":2.5,"Plan":{"Node Type":"Aggregate","Actual Total Time":2,"Actual Rows":1,"Actual Loops":1,"Output":["secret"],"Filter":"secret","Plans":[{"Node Type":"secret-node","Actual Total Time":1,"Actual Rows":2,"Actual Loops":1,"Relation Name":"secret"}]}}]`)
	got, err := readinessAttributionPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("untrusted plan text escaped sanitization")
	}
	if got.PlanningMS != 1.25 || got.ExecutionMS != 2.5 || len(got.Nodes) != 2 || got.Nodes[0].Kind != "Aggregate" || got.Nodes[1].Kind != "other" {
		t.Fatal("safe numeric plan evidence missing")
	}
	for _, bad := range []string{`[]`, `[{},{}]`, `[{"Plan":{"Node Type":"Result","Actual Rows":-1}}]`, `[{"Plan":{"Node Type":"Result","Actual Total Time":1e999}}]`} {
		if _, err := readinessAttributionPlan([]byte(bad)); err == nil {
			t.Fatal("invalid plan accepted")
		}
	}
}

// Losing the parent links makes inclusive subplans impossible to attribute:
// this consumes the real existing plan parser, not a synthetic tree builder.
func TestReadinessAttributionPreservesParentLinks(t *testing.T) {
	raw := []byte(`[{"Plan":{"Node Type":"Result","Plans":[{"Node Type":"Aggregate"},{"Node Type":"Append","Plans":[{"Node Type":"Seq Scan"}]}]}}]`)
	got, err := readinessAttributionPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got.Nodes)
	var nodes []map[string]any
	if json.Unmarshal(encoded, &nodes) != nil || len(nodes) != 4 {
		t.Fatal("sanitized tree cardinality lost")
	}
	for i, want := range []struct {
		parent any
		depth  float64
	}{{nil, 0}, {float64(0), 1}, {float64(0), 1}, {float64(2), 2}} {
		id, hasID := nodes[i]["id"]
		parent, hasParent := nodes[i]["parent_id"]
		if !hasID || !hasParent || id != float64(i) || parent != want.parent || nodes[i]["depth"] != want.depth {
			t.Fatal("source plan parent linkage lost")
		}
	}
}

func TestReadinessAttributionSourceMapAndPrivacy(t *testing.T) {
	module, err := os.ReadFile("../migrations/sql/0080_authorization_worker_readiness_graph.sql")
	if err != nil {
		t.Fatal("candidate module unavailable")
	}
	sum := sha256.Sum256(module)
	manifest, _ := json.Marshal(map[string]any{"files": []map[string]string{{"path": "services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql", "sha256": hex.EncodeToString(sum[:])}}})
	manifestSum := sha256.Sum256(manifest)
	sources, err := readinessAttributionSourceMap(module, manifest, hex.EncodeToString(manifestSum[:]))
	if err != nil || len(sources) < 3 || sources["higher_catalog"] != "zasp_authorization80_worker.catalog_ready()" || sources["higher_0"] != "zasp_temporal78.fingerprint()" || sources["higher_1"] != "zasp_temporal78.catalog_ready()" {
		t.Fatal("candidate source map unavailable")
	}
	raw := []byte(`[{"Plan":{"Node Type":"Result","Subplan Name":"CTE higher_0","source":"secret","Plans":[{"Node Type":"CTE Scan","CTE Name":"higher_catalog","Relation Name":"secret"},{"Node Type":"Result","Subplan Name":"CTE secret","CTE Name":"secret","Alias":"secret"}]}}]`)
	got, err := readinessAttributionPlan(raw, sources)
	if err != nil || got.Nodes[0].Source != "zasp_temporal78.fingerprint()" || got.Nodes[1].Source != "zasp_authorization80_worker.catalog_ready()" || got.Nodes[2].Source != "" {
		t.Fatal("fixed source identity lost or unknown identity accepted")
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "CTE Name") || strings.Contains(string(encoded), "Subplan Name") {
		t.Fatal("server labels escaped sanitizer")
	}
	again, _ := readinessAttributionPlan(raw, sources)
	encodedAgain, _ := json.Marshal(again)
	if string(encoded) != string(encodedAgain) {
		t.Fatal("sanitized tree is nondeterministic")
	}
	if _, err := readinessAttributionSourceMap(module, manifest, strings.Repeat("0", 64)); err == nil {
		t.Fatal("foreign manifest accepted")
	}
	if _, err := readinessAttributionSourceMap(append(append([]byte(nil), module...), ' '), manifest, hex.EncodeToString(manifestSum[:])); err == nil {
		t.Fatal("module outside manifest accepted")
	}
	// Even a freshly hashed manifest cannot authorize an inconsistent ordinal map.
	for _, anchor := range []string{"higher_0(value) AS MATERIALIZED (", "higher_catalog(value) AS MATERIALIZED ("} {
		bad := []byte(strings.ReplaceAll(string(module), anchor, "unmapped(value) AS MATERIALIZED ("))
		badSum := sha256.Sum256(bad)
		badManifest, _ := json.Marshal(map[string]any{"files": []map[string]string{{"path": "services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql", "sha256": hex.EncodeToString(badSum[:])}}})
		badManifestSum := sha256.Sum256(badManifest)
		if _, err := readinessAttributionSourceMap(bad, badManifest, hex.EncodeToString(badManifestSum[:])); err == nil {
			t.Fatal("source ordinal mismatch accepted")
		}
	}
}

func TestReadinessAttributionExclusiveArtifactAndDefaultOff(t *testing.T) {
	t.Setenv("ZASP_ORDERED_READINESS_PLAN_OUTPUT", "")
	t.Setenv("ZASP_ORDERED_READINESS_PLAN_MANIFEST", "/does-not-exist")
	if captureReadinessSourceAttribution(t, nil, nil) {
		t.Fatal("absent output consumed observer")
	}
	path := filepath.Join(t.TempDir(), "sanitized.json")
	doc := readinessAttributionArtifact{Version: 1, Plans: []readinessAttributionObservedPlan{{Root: "catalog", Metrics: readinessAttributionMetrics{Nodes: []readinessAttributionNode{{Kind: "Result"}}}}}}
	hash, err := writeReadinessAttributionArtifact(path, doc)
	if err != nil {
		t.Fatal("sanitized artifact write failed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("sanitized artifact unavailable")
	}
	info, err := os.Stat(path)
	sum := sha256.Sum256(raw)
	if err != nil || info.Mode().Perm() != 0600 || hash != hex.EncodeToString(sum[:]) {
		t.Fatal("artifact mode or digest invalid")
	}
	if _, err := writeReadinessAttributionArtifact(path, doc); err == nil {
		t.Fatal("artifact overwritten")
	}
	link := filepath.Join(t.TempDir(), "link")
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink fixture unavailable")
	}
	if _, err := writeReadinessAttributionArtifact(link, doc); err == nil {
		t.Fatal("artifact symlink followed")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("existing evidence changed")
	}
	if _, err := writeReadinessAttributionArtifact("relative.json", doc); err == nil {
		t.Fatal("relative evidence path accepted")
	}
	doc.ModuleSHA256 = strings.Repeat("x", 8*1024*1024)
	if _, err := writeReadinessAttributionArtifact(filepath.Join(t.TempDir(), "oversize"), doc); err == nil {
		t.Fatal("oversized evidence accepted")
	}
}

func TestReadinessAttributionTreeBounds(t *testing.T) {
	leaf := `{"Node Type":"Result"}`
	deep := leaf
	for i := 0; i < 65; i++ {
		deep = `{"Node Type":"Result","Plans":[` + deep + `]}`
	}
	wide := `{"Node Type":"Append","Plans":[` + strings.TrimSuffix(strings.Repeat(leaf+",", 4096), ",") + `]}`
	for _, tree := range []string{deep, wide} {
		if _, err := readinessAttributionPlan([]byte(`[{"Plan":` + tree + `}]`)); err == nil {
			t.Fatal("unbounded source plan accepted")
		}
	}
}

func TestReadinessAttributionPinnedCaptureSelectors(t *testing.T) {
	path := os.Getenv("ZASP_ORDERED_READINESS_REFERENCE")
	if path == "" {
		t.Skip("explicit retained capture required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("retained capture unavailable")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "720683fb7646085a2ecc226746cb3a71d9dd24d296a6ab2103cbf0d36573bb7c" {
		t.Fatal("retained capture identity changed")
	}
	var captured struct {
		Functions []struct{ Signature, Source string }
	}
	if json.Unmarshal(raw, &captured) != nil {
		t.Fatal("retained capture malformed")
	}
	for _, f := range captured.Functions {
		if f.Signature != "zasp_authorization80_worker.catalog_ready()" {
			continue
		}
		got, err := readinessAttributionSelectors(f.Source)
		if err != nil {
			t.Fatal("actual pinned catalog selectors rejected")
		}
		if strings.Count(got, " UNION ALL ") != 8 || strings.Count(got, "t.tgname='zasp_authorization80_runtime_stage_insert'") != 2 || !strings.Contains(got, "WHERE(t.tgrelid='public.zasp_security_agent_runs'") || !strings.Contains(got, "WHERE(t.tgrelid IN('public.zasp_gateway_devices'") {
			t.Fatal("actual selector scope or duplicate demand lost")
		}
		if _, err := readinessAttributionSelectors(strings.Replace(f.Source, "WHERE(t.tgrelid", "WHERE/**/(t.tgrelid", 1)); err == nil {
			t.Fatal("unreviewed selector syntax accepted")
		}
		return
	}
	t.Fatal("actual catalog recipe absent")
}

func TestReadinessAttributionAbsentDoesNotUseDatabase(t *testing.T) {
	t.Setenv("ZASP_ORDERED_READINESS_ATTRIBUTION", "")
	if runReadinessAttribution(t, context.Background(), nil) {
		t.Fatal("default path consumed diagnostic")
	}
}

func TestReadinessAttributionSelectorsRetainRepeatedDemand(t *testing.T) {
	var lines []string
	for _, digit := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "0"} {
		lines = append(lines, "UNION ALL SELECT pg_get_functiondef(p.oid) FROM pg_proc p WHERE p.oid="+digit)
	}
	source := strings.Join(lines, "\n")
	got, err := readinessAttributionSelectors(source)
	if err != nil || strings.Count(got, " UNION ALL ") != 8 || strings.Count(got, "p.oid=0") != 2 {
		t.Fatal("repeated selector demand lost")
	}
	for _, bad := range []string{strings.Join(lines[:8], "\n"), source + ";", strings.Replace(source, " FROM pg_proc p WHERE ", " FROM arbitrary p WHERE ", 1)} {
		if _, err := readinessAttributionSelectors(bad); err == nil {
			t.Fatal("unsupported selector shape accepted")
		}
	}
}
