package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func securityAgentExportSnapshotFixture(t *testing.T, l complianceExportLease) (json.RawMessage, securityAgentExportBinding) {
	t.Helper()
	b := securityAgentExportBinding{RunID: "pid_20000001-0000-4000-8000-000000000001", StepID: "pid_20000002-0000-4000-8000-000000000002", Selection: []securityAgentExportSelection{{Kind: "finding", ID: "pid_20000003-0000-4000-8000-000000000003", Version: 7, AssociationDigest: "sha256:" + strings.Repeat("a", 64)}}}
	return securityAgentExportTestSnapshot(t, l, b, []string{`{"summary":"=1+1 <script>"}`}), b
}

func securityAgentExportTestSnapshot(t *testing.T, l complianceExportLease, b securityAgentExportBinding, contents []string) json.RawMessage {
	t.Helper()
	records := make([]map[string]any, len(b.Selection))
	for i, s := range b.Selection {
		h := sha256.Sum256([]byte(contents[i]))
		records[i] = map[string]any{"source_kind": s.Kind, "source_id": s.ID, "source_version": s.Version, "association_digest": s.AssociationDigest, "content_sha256": hex.EncodeToString(h[:]), "content_json": contents[i]}
	}
	v := map[string]any{"mapping_revision": "security-agent-run-evidence-v1", "snapshot_at": "2026-09-19T01:02:03.123456789Z", "organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(), "run_id": b.RunID, "step_id": b.StepID, "records": records}
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(buf.Bytes())
}

func securityAgentExportTestReject(t *testing.T, ctx context.Context, l complianceExportLease, b securityAgentExportBinding, raw []byte) {
	t.Helper()
	p, err := renderSecurityAgentEvidenceExportPackage(ctx, l, b, raw)
	if err != errWorkerExecution || !reflect.DeepEqual(p, compliancePreparedArtifact{}) {
		t.Fatalf("rejection leaked artifact: size=%d err=%v", len(p.Bytes), err)
	}
}

// Missing binding checks would allow a different run, source or source order.
func TestSecurityAgentExportRenderBindsScopeAndSelection(t *testing.T) {
	l := complianceRuntimeLease(t)
	raw, b := securityAgentExportSnapshotFixture(t, l)
	for _, field := range []string{"run", "step", "empty", "kind", "id", "version", "digest"} {
		t.Run(field, func(t *testing.T) {
			bad := b
			bad.Selection = append([]securityAgentExportSelection(nil), b.Selection...)
			switch field {
			case "run":
				bad.RunID = l.ExportID
			case "step":
				bad.StepID = l.ExportID
			case "empty":
				bad.Selection = nil
			case "kind":
				bad.Selection[0].Kind = "run_audit"
			case "id":
				bad.Selection[0].ID = l.ExportID
			case "version":
				bad.Selection[0].Version++
			case "digest":
				bad.Selection[0].AssociationDigest = "sha256:" + strings.Repeat("b", 64)
			}
			securityAgentExportTestReject(t, context.Background(), l, bad, raw)
		})
	}
	for _, field := range []string{"organization_id", "workspace_id", "environment_id"} {
		t.Run(field, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(raw, &v)
			v[field] = l.ExportID
			bad, _ := json.Marshal(v)
			securityAgentExportTestReject(t, context.Background(), l, b, bad)
		})
	}
	b.Selection = append(b.Selection, b.Selection[0])
	b.Selection[1].ID = l.ExportID
	raw = securityAgentExportTestSnapshot(t, l, b, []string{`{}`, `{"second":true}`})
	b.Selection[0], b.Selection[1] = b.Selection[1], b.Selection[0]
	securityAgentExportTestReject(t, context.Background(), l, b, raw)
}

// Dropping escaping, exact bytes, identities or checksums breaks this consumer check.
func TestSecurityAgentExportRenderFrozenFormats(t *testing.T) {
	l := complianceRuntimeLease(t)
	raw, b := securityAgentExportSnapshotFixture(t, l)
	before := bytes.Clone(raw)
	bindingBefore := append([]securityAgentExportSelection(nil), b.Selection...)
	p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, raw)
	if err != nil {
		t.Fatal(err)
	}
	q, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, raw)
	if err != nil || !bytes.Equal(p.Bytes, q.Bytes) {
		t.Fatal("render is not deterministic")
	}
	if !bytes.Equal(raw, before) || !reflect.DeepEqual(b.Selection, bindingBefore) {
		t.Fatal("input mutated")
	}
	var env struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		JSON    json.RawMessage `json:"json"`
		CSV     string          `json:"csv"`
		Human   string          `json:"human"`
	}
	if json.Unmarshal(p.Bytes, &env) != nil || env.Version != 1 || env.ID != l.ExportID {
		t.Fatal("invalid envelope")
	}
	var manifest map[string]any
	if json.Unmarshal(env.JSON, &manifest) != nil {
		t.Fatal("invalid manifest")
	}
	for k, want := range map[string]any{"mapping_revision": "security-agent-run-evidence-v1", "renderer_revision": "security-agent-evidence-envelope-v1", "snapshot_at": "2026-09-19T01:02:03.123456789Z", "organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(), "run_id": b.RunID, "step_id": b.StepID} {
		if manifest[k] != want {
			t.Fatalf("manifest %s=%v", k, manifest[k])
		}
	}
	r := manifest["records"].([]any)[0].(map[string]any)
	content := `{"summary":"=1+1 <script>"}`
	h := sha256.Sum256([]byte(content))
	if r["content_json"] != content || r["content_sha256"] != hex.EncodeToString(h[:]) || r["association_digest"] != "sha256:"+strings.Repeat("a", 64) {
		t.Fatal("content or distinct association digest lost")
	}
	rows, err := csv.NewReader(strings.NewReader(env.CSV)).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("csv rows %v %v", rows, err)
	}
	if len(rows[0]) != 13 || len(rows[1]) != 13 {
		t.Fatal("CSV missing fields")
	}
	for i, key := range rows[0] {
		want, ok := manifest[key]
		if !ok {
			want = r[key]
		}
		if key == "source_version" {
			want = "7"
		}
		if rows[1][i] != fmt.Sprint(want) {
			t.Fatalf("CSV %s=%q want %v", key, rows[1][i], want)
		}
	}
	if strings.Contains(env.Human, "<script>") || !strings.Contains(env.Human, html.EscapeString(content)) || !strings.Contains(env.Human, "<pre>") || !strings.Contains(env.Human, "does not establish remediation") {
		t.Fatal("unsafe or misleading readable format")
	}
	h = sha256.Sum256(p.Bytes)
	if p.SHA256 != hex.EncodeToString(h[:]) || p.Size != int64(len(p.Bytes)) || p.Reference != l.ExportID || p.RendererRevision != "security-agent-evidence-envelope-v1" {
		t.Fatal("artifact identity/hash mismatch")
	}
	if !reflect.DeepEqual(p.FormatSizes, map[string]int64{"json": int64(len(env.JSON)), "csv": int64(len(env.CSV)), "readable": int64(len(env.Human))}) {
		t.Fatal("format byte sizes wrong")
	}
}

// Omitting a wire validation must expose an accepted malformed snapshot here.
func TestSecurityAgentExportRenderRejectsInvalidWire(t *testing.T) {
	l := complianceRuntimeLease(t)
	raw, b := securityAgentExportSnapshotFixture(t, l)
	mutations := map[string]func(map[string]any, map[string]any){
		"revision":           func(v, r map[string]any) { v["mapping_revision"] = "other" },
		"unknown outer":      func(v, r map[string]any) { v["extra"] = true },
		"unknown record":     func(v, r map[string]any) { r["extra"] = true },
		"null record":        func(v, r map[string]any) { v["records"] = []any{nil} },
		"null records":       func(v, r map[string]any) { v["records"] = nil },
		"empty records":      func(v, r map[string]any) { v["records"] = []any{} },
		"null content":       func(v, r map[string]any) { r["content_json"] = nil },
		"zero hash":          func(v, r map[string]any) { r["content_sha256"] = strings.Repeat("0", 64) },
		"uppercase hash":     func(v, r map[string]any) { r["content_sha256"] = strings.Repeat("A", 64) },
		"missing hash":       func(v, r map[string]any) { delete(r, "content_sha256") },
		"invalid time":       func(v, r map[string]any) { v["snapshot_at"] = "yesterday" },
		"non UTC":            func(v, r map[string]any) { v["snapshot_at"] = "2026-09-19T01:02:03+00:00" },
		"non canonical time": func(v, r map[string]any) { v["snapshot_at"] = "2026-09-19T01:02:03.000Z" },
		"duplicate record":   func(v, r map[string]any) { v["records"] = []any{r, r} },
		"wrong version":      func(v, r map[string]any) { r["source_version"] = 8 },
		"wrong kind":         func(v, r map[string]any) { r["source_kind"] = "attack_path" },
		"wrong ID":           func(v, r map[string]any) { r["source_id"] = l.ExportID },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(raw, &v)
			r := v["records"].([]any)[0].(map[string]any)
			mutate(v, r)
			bad, _ := json.Marshal(v)
			securityAgentExportTestReject(t, context.Background(), l, b, bad)
		})
	}
	for name, bad := range map[string][]byte{"empty": nil, "malformed": []byte(`{"`), "trailing": append(bytes.Clone(raw), []byte(` {}`)...), "invalid UTF8": append(bytes.Clone(raw[:len(raw)-1]), 0xff, '}'), "duplicate outer": []byte(strings.Replace(string(raw), `"run_id":`, `"run_id":"ignored","run_id":`, 1)), "duplicate record key": []byte(strings.Replace(string(raw), `"source_kind":`, `"source_kind":"ignored","source_kind":`, 1)), "case alias": []byte(strings.Replace(string(raw), `"run_id"`, `"RUN_ID"`, 1))} {
		t.Run(name, func(t *testing.T) { securityAgentExportTestReject(t, context.Background(), l, b, bad) })
	}
	for _, content := range []string{"", `null`, `[]`, `"text"`, `{"x":1,"x":2}`, `{"outer":{"x":1,"x":2}}`, `{} {}`, "{\"x\":\"\xff\"}", `{"x":` + strings.Repeat(`[`, 32) + `0` + strings.Repeat(`]`, 32) + `}`} {
		t.Run(fmt.Sprintf("content %d", len(content)), func(t *testing.T) {
			bad := securityAgentExportTestSnapshot(t, l, b, []string{content})
			securityAgentExportTestReject(t, context.Background(), l, b, bad)
		})
	}
	for _, field := range []string{"mapping_revision", "snapshot_at", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "records"} {
		t.Run("missing "+field, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(raw, &v)
			delete(v, field)
			bad, _ := json.Marshal(v)
			securityAgentExportTestReject(t, context.Background(), l, b, bad)
		})
	}
	securityAgentExportTestReject(t, nil, l, b, raw)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	securityAgentExportTestReject(t, ctx, l, b, raw)
	badLease := l
	badLease.ExportID = "invalid"
	securityAgentExportTestReject(t, context.Background(), badLease, b, raw)
	badLease = l
	badLease.Scope = domain.Scope{}
	securityAgentExportTestReject(t, context.Background(), badLease, b, raw)
}

func TestSecurityAgentExportRenderRejectsInvalidSelection(t *testing.T) {
	l := complianceRuntimeLease(t)
	_, base := securityAgentExportSnapshotFixture(t, l)
	for _, s := range []securityAgentExportSelection{{"finding", "invalid", 7, "sha256:" + strings.Repeat("a", 64)}, {"unknown", l.ExportID, 7, "sha256:" + strings.Repeat("a", 64)}, {"finding", l.ExportID, 0, "sha256:" + strings.Repeat("a", 64)}, {"finding", l.ExportID, 9007199254740992, "sha256:" + strings.Repeat("a", 64)}, {"finding", l.ExportID, 7, strings.Repeat("a", 64)}, {"finding", l.ExportID, 7, "sha256:" + strings.Repeat("A", 64)}, {"manual", l.ExportID, 7, "sha256:" + strings.Repeat("a", 64)}, {"finding", strings.Repeat("a", 64), 7, "sha256:" + strings.Repeat("a", 64)}} {
		b := base
		b.Selection = []securityAgentExportSelection{s}
		raw := securityAgentExportTestSnapshot(t, l, b, []string{`{}`})
		securityAgentExportTestReject(t, context.Background(), l, b, raw)
	}
	for _, version := range []int64{7, 8} {
		b := base
		b.Selection = append(append([]securityAgentExportSelection(nil), base.Selection...), base.Selection[0])
		b.Selection[1].Version = version
		raw := securityAgentExportTestSnapshot(t, l, b, []string{`{}`, `{}`})
		securityAgentExportTestReject(t, context.Background(), l, b, raw)
	}
}

// Filtering a source kind or rewriting source state must fail this preservation test.
func TestSecurityAgentExportRenderAllKindsAndStates(t *testing.T) {
	l := complianceRuntimeLease(t)
	_, b := securityAgentExportSnapshotFixture(t, l)
	b.Selection = nil
	contents := []string{}
	for i, kind := range []string{"finding", "attack_path", "runtime_decision", "run_audit", "existing_test", "attack_lab", "manual"} {
		id := fmt.Sprintf("pid_30000000-0000-4000-8000-%012d", i+1)
		if kind == "manual" {
			id = strings.Repeat("c", 64)
		}
		b.Selection = append(b.Selection, securityAgentExportSelection{kind, id, 9007199254740991, "sha256:" + strings.Repeat("a", 64)})
		contents = append(contents, `{"pending":true,"failed":true,"cleanup_pending":true,"formula":" =1+1","text":"<script>&\"'"}`)
	}
	raw := securityAgentExportTestSnapshot(t, l, b, contents)
	p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, raw)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		JSON struct {
			Records []struct {
				Kind    string `json:"source_kind"`
				ID      string `json:"source_id"`
				Content string `json:"content_json"`
			} `json:"records"`
		} `json:"json"`
		CSV   string `json:"csv"`
		Human string `json:"human"`
	}
	if json.Unmarshal(p.Bytes, &env) != nil || len(env.JSON.Records) != 7 {
		t.Fatal("sources omitted")
	}
	rows, err := csv.NewReader(strings.NewReader(env.CSV)).ReadAll()
	if err != nil || len(rows) != 8 {
		t.Fatal("CSV sources omitted")
	}
	ci := -1
	for i, k := range rows[0] {
		if k == "content_json" {
			ci = i
		}
	}
	if ci < 0 {
		t.Fatal("content header missing")
	}
	for i, s := range b.Selection {
		if env.JSON.Records[i].Kind != s.Kind || env.JSON.Records[i].ID != s.ID || env.JSON.Records[i].Content != contents[i] || rows[i+1][ci] != contents[i] {
			t.Fatal("source changed or order lost")
		}
	}
	for _, state := range []string{"pending", "failed", "cleanup_pending"} {
		if !strings.Contains(env.Human, state) {
			t.Fatal("state omitted")
		}
	}
}

func TestSecurityAgentExportRenderCSVFormulaEscaping(t *testing.T) {
	for _, prefix := range []string{"=", "+", "-", "@", "\t", "\r", "\n"} {
		for _, spaces := range []string{"", " ", "   "} {
			value := spaces + prefix + "payload"
			if got := securityAgentExportCSVCell(value); got != "'"+value {
				t.Fatalf("unsafe CSV cell %q -> %q", value, got)
			}
		}
	}
	for _, safe := range []string{"", "  ", "value", "{\"formula\":\"=1+1\"}", "'=1+1", "x\t=1"} {
		if securityAgentExportCSVCell(safe) != safe {
			t.Fatalf("safe cell changed: %q", safe)
		}
	}
}

// Valid JSON may start with TAB/CR/LF. The CSV still needs a formula guard,
// while the manifest and readable form must retain the original bytes.
func TestSecurityAgentExportRenderCSVLeadingWhitespace(t *testing.T) {
	l := complianceRuntimeLease(t)
	_, b := securityAgentExportSnapshotFixture(t, l)
	for _, prefix := range []string{"\t", "\r", "\n", "  \t", "  \r", "  \n"} {
		content := prefix + `{"formula":"=1+1"}`
		raw := securityAgentExportTestSnapshot(t, l, b, []string{content})
		p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, raw)
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			CSV   string `json:"csv"`
			Human string `json:"human"`
			JSON  struct {
				Records []struct {
					Content string `json:"content_json"`
				} `json:"records"`
			} `json:"json"`
		}
		if json.Unmarshal(p.Bytes, &env) != nil {
			t.Fatal("invalid package")
		}
		rows, err := csv.NewReader(strings.NewReader(env.CSV)).ReadAll()
		if err != nil || len(rows) != 2 {
			t.Fatal("invalid CSV", err)
		}
		if rows[1][12] != "'"+content || env.JSON.Records[0].Content != content || !strings.Contains(env.Human, "<pre>"+html.EscapeString(content)+"</pre>") {
			t.Fatalf("CSV guard or exact content lost for %q", prefix)
		}
	}
}

type securityAgentExportCancelAtReturn struct {
	context.Context
	checks int
}

func (c *securityAgentExportCancelAtReturn) Err() error {
	c.checks++
	if c.checks > 1 {
		return context.Canceled
	}
	return nil
}

func TestSecurityAgentExportRenderChecksContextBeforeReturningBytes(t *testing.T) {
	l := complianceRuntimeLease(t)
	raw, b := securityAgentExportSnapshotFixture(t, l)
	ctx := &securityAgentExportCancelAtReturn{Context: context.Background()}
	securityAgentExportTestReject(t, ctx, l, b, raw)
}

// The bounded writer must accept the exact byte budget and refuse the next byte
// without a partial write. This checks the common CSV/readable allocation cap.
func TestSecurityAgentExportRenderFormatBufferBoundary(t *testing.T) {
	b := &securityAgentExportBuffer{limit: 4 << 20}
	if n, err := b.Write(bytes.Repeat([]byte("x"), 4<<20)); err != nil || n != 4<<20 {
		t.Fatal("exact format budget rejected")
	}
	if n, err := b.Write([]byte("x")); err != errWorkerExecution || n != 0 || b.Len() != 4<<20 {
		t.Fatal("format overflow was written")
	}
}

func TestSecurityAgentExportRenderBoundaries(t *testing.T) {
	l := complianceRuntimeLease(t)
	_, base := securityAgentExportSnapshotFixture(t, l)
	makeN := func(n int, content string) (json.RawMessage, securityAgentExportBinding) {
		b := base
		b.Selection = nil
		contents := []string{}
		for i := 0; i < n; i++ {
			s := base.Selection[0]
			s.ID = fmt.Sprintf("pid_30000000-0000-4000-8000-%012d", i+1)
			b.Selection = append(b.Selection, s)
			contents = append(contents, content)
		}
		return securityAgentExportTestSnapshot(t, l, b, contents), b
	}
	for _, n := range []int{0, 100, 101} {
		raw, b := makeN(n, `{}`)
		p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, raw)
		if n == 100 {
			if err != nil || len(p.Bytes) == 0 {
				t.Fatal("100 records rejected", err)
			}
		} else {
			securityAgentExportTestReject(t, context.Background(), l, b, raw)
		}
	}
	for _, size := range []int{65536, 65537} {
		content := `{"x":"` + strings.Repeat("x", size-8) + `"}`
		if len(content) != size {
			t.Fatal("bad fixture")
		}
		raw, b := makeN(1, content)
		p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, raw)
		if size == 65536 {
			if err != nil || len(p.Bytes) == 0 {
				t.Fatal("exact content limit rejected", err)
			}
		} else {
			securityAgentExportTestReject(t, context.Background(), l, b, raw)
		}
	}
	content := `{"x":` + strings.Repeat(`[`, 31) + `0` + strings.Repeat(`]`, 31) + `}`
	raw, b := makeN(1, content)
	if _, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, raw); err != nil {
		t.Fatal("depth32 rejected", err)
	}
	raw, b = makeN(1, `{}`)
	exact := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), (4<<20)-len(raw))...)
	if _, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, b, exact); err != nil {
		t.Fatal("exact snapshot limit rejected", err)
	}
	securityAgentExportTestReject(t, context.Background(), l, b, append(exact, ' '))
	// HTML/JSON escaping expands a sub-4MiB snapshot beyond the per-format limit.
	raw, b = makeN(20, `{"x":"`+strings.Repeat("<", 50000)+`"}`)
	if len(raw) >= 4<<20 {
		t.Fatal("fixture already oversized")
	}
	securityAgentExportTestReject(t, context.Background(), l, b, raw)
	// Each format can fit while their combined envelope exceeds 8MiB.
	raw, b = makeN(50, `{"x":"`+strings.Repeat("x", 60000)+`"}`)
	if len(raw) >= 4<<20 {
		t.Fatal("fixture already oversized")
	}
	securityAgentExportTestReject(t, context.Background(), l, b, raw)
}
