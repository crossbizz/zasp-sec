package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
)

// Continue the real CLI exact-version receipt through the production browser
// session, request-bound source authorization, and immutable export capture.
// The installed worker tests separately render and deliver this capture.
func exerciseSharedAddonCoverage(t *testing.T, b *installedBaseline, reviewer installedPrincipal, version, digest string, refs []addonevidence.Reference) {
	t.Helper()
	index := slices.IndexFunc(refs, func(r addonevidence.Reference) bool {
		return r.Framework == "owasp_agentic_top10" && r.Edition == "2026" && r.UpstreamID == "ASI04" && r.EvidenceKind == "static_scan" && r.RuleID == "dependency.unpinned"
	})
	if index < 0 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatal("offline version is missing its exact ASI04 finding")
	}
	ref := refs[index]
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewComplianceRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	handler := &complianceHTTPHandler{source: source, exports: &ComplianceExportsRepository{source: source}, signingKey: bytes.Repeat([]byte{0xa3}, 32)}
	var operations []Operation
	for _, d := range complianceOperations {
		operations = append(operations, Operation{Method: d.Method, Pattern: d.Pattern, OperationID: d.OperationID, Permission: "view_compliance", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: d.Method == http.MethodPost, RequireFreshAuth: d.OperationID == "createComplianceExport", Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = b.authorizer
	const origin = "https://app.zasp.test"
	server, err := NewProductMiddleware(ProductSecurity{PublicOrigin: origin, MaximumBodyBytes: 32 * 1024, Authenticate: repo.Authenticate, GenerateCorrelationID: b.id}, router)
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string, body []byte, scope string, want int) []byte {
		t.Helper()
		method := http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, origin+path, bytes.NewReader(body)).WithContext(b.ctx)
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session-secret-" + reviewer.identity.PrincipalID.String()})
		req.Header.Set(expectedScopeHeader, scope)
		if body != nil {
			req.Header.Set("Origin", origin)
			req.Header.Set("X-CSRF-Token", reviewer.identity.CSRFToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "framework-cli-"+b.id())
		}
		out := httptest.NewRecorder()
		server.ServeHTTP(out, req)
		if out.Code != want || out.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: status %d, expected %d: %s", method, req.URL.Path, out.Code, want, out.Body.String())
		}
		if bytes.Contains(out.Body.Bytes(), []byte("private-example")) {
			t.Fatal("local dependency name escaped the findings-only boundary")
		}
		return out.Body.Bytes()
	}
	scope := expectedScopeValue(reviewer.identity.Scope)
	filter := url.Values{"framework": {ref.Framework}, "edition": {ref.Edition}, "upstream_id": {ref.UpstreamID}, "evidence_kind": {ref.EvidenceKind}}
	const prefix = "/api/v1/compliance/"
	var coverage compliancemap.ReportPage
	if json.Unmarshal(call(prefix+"coverage?"+filter.Encode(), nil, scope, 200), &coverage) != nil ||
		coverage.Total != 10 || coverage.Matched != 1 || len(coverage.Items) != 1 || coverage.Items[0].Control.UpstreamID != ref.UpstreamID || coverage.Items[0].Counts["static_scan"] < 1 || coverage.Items[0].Verified != nil {
		t.Fatalf("catalog did not present the offline static finding: %+v", coverage)
	}
	exact := func(rows []compliancemap.ReportEvidence) bool {
		return slices.ContainsFunc(rows, func(e compliancemap.ReportEvidence) bool {
			return e.Source == "addon_version" && e.ID == version && e.ManifestDigest == digest && e.Rule == ref.RuleID && e.Version == ref.RuleVersion && e.Kind == ref.EvidenceKind && e.Framework == ref.Framework && e.Edition == ref.Edition && e.Upstream == ref.UpstreamID
		})
	}
	for _, q := range []url.Values{filter, {"source_kind": {"addon_version"}, "source_id": {version}}} {
		var evidence struct {
			Items []compliancemap.ReportEvidence `json:"items"`
		}
		if json.Unmarshal(call(prefix+"coverage/evidence?"+q.Encode(), nil, scope, 200), &evidence) != nil || !exact(evidence.Items) {
			t.Fatal("source and edition drilldown do not resolve the exact CLI version")
		}
	}
	call(prefix+"coverage/evidence?"+filter.Encode(), nil, b.o+"/"+b.w+"/"+b.id(), 409)
	selector := compliancemap.ReportSelector{Framework: ref.Framework, Edition: ref.Edition, Upstream: ref.UpstreamID, EvidenceKind: ref.EvidenceKind}
	body, err := json.Marshal(selector)
	if err != nil {
		t.Fatal(err)
	}
	var job struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	queued := call(prefix+"exports", body, scope, 201)
	if json.Unmarshal(queued, &job) != nil || !validProductID(job.ID) || job.Status != "pending" {
		t.Fatalf("export did not queue: %s", queued)
	}
	frozen := b.text("SELECT snapshot::text FROM public.zasp_framework_export_snapshots WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND export_id=$4", b.o, b.w, b.e, job.ID)
	var pack compliancemap.FrozenReport
	if json.Unmarshal([]byte(frozen), &pack) != nil || pack.Environment != b.e || pack.Organization != b.o || pack.Workspace != b.w || pack.Selector != selector || pack.Schema != "framework-coverage.v1" || pack.Coverage.Digest != coverage.Digest || !exact(pack.Evidence) || strings.Contains(frozen, "private-example") {
		t.Fatal("export did not freeze the requested edition, scope and redacted source reference")
	}
}
