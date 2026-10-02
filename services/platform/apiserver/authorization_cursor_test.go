package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func p7CursorRequest(t *testing.T, identity RequestIdentity, operation, path string, params map[string]string, revision int64) *http.Request {
	t.Helper()
	r := workflowRequest(t, identity, testCorrelationID, operation, params, http.MethodGet, path, "")
	r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
	grant := RequestAuthorization{Identity: identity, OperationID: operation, Credential: CredentialBinding{Kind: identity.CredentialKind, ID: "cursor-session"}, Revision: authorization.Revision{Desired: revision, Applied: revision, Generation: 1}}
	return r.WithContext(context.WithValue(r.Context(), requestAuthorizationContextKey{}, grant))
}

type p7CursorAdministration struct{ administrationRecorder }

func (s *p7CursorAdministration) ReadAdministration(_ context.Context, _ RequestIdentity, operation string, _ map[string]string) (json.RawMessage, error) {
	s.reads++
	if operation != "listEnvironments" {
		return nil, ErrRepositoryOperation
	}
	return json.RawMessage(`{"items":[{"id":"pid_86000001-0000-4000-8000-000000000001"},{"id":"pid_86000002-0000-4000-8000-000000000002"}]}`), nil
}

func TestP7AdministrationCursorRejectsChangedAuthorization(t *testing.T) {
	i := fixtureRequestIdentity(t)
	s := &p7CursorAdministration{}
	h := &identityHTTPHandler{administration: s, signingKey: []byte(strings.Repeat("k", 32)), now: time.Now}
	path := "/api/v1/environments?limit=1&workspace_id=" + i.Scope.WorkspaceID().String()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, p7CursorRequest(t, i, "listEnvironments", path, nil, 1))
	var page struct {
		PageInfo struct {
			Next string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.PageInfo.Next == "" {
		t.Fatalf("first page %d %s", w.Code, w.Body.String())
	}
	for _, revision := range []int64{1, 2} {
		before := s.reads
		w = httptest.NewRecorder()
		h.ServeHTTP(w, p7CursorRequest(t, i, "listEnvironments", path+"&cursor="+page.PageInfo.Next, nil, revision))
		if revision == 1 && w.Code != 200 {
			t.Fatalf("same authorization rejected %d %s", w.Code, w.Body.String())
		}
		if revision == 2 && (w.Code != 404 || s.reads != before) {
			t.Fatalf("changed authorization reused cursor: status=%d reads=%d before=%d", w.Code, s.reads, before)
		}
	}
}

func TestP7AuditExportCursorRejectsChangedAuthorization(t *testing.T) {
	store, first, last := auditExportTwoChunkContentsFixture(t)
	second := first
	authority := *first.authority
	authority.Chunk = last
	second.authority = &authority
	s := &auditExportHTTPStub{pages: map[int64]auditExportReadResult{1: first, 2: second}}
	_, _, i, _ := auditExportRepositoryFixture(t)
	h, err := newAuditExportHTTPHandler(s, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), newWorkflowProductID)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/audit-exports/" + first.export.ID
	params := map[string]string{"id": first.export.ID}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, p7CursorRequest(t, i, "getAuditExport", path, params, 1))
	var page struct {
		Contents struct {
			PageInfo struct {
				Next string `json:"next_cursor"`
			} `json:"page_info"`
		} `json:"contents"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Contents.PageInfo.Next == "" {
		t.Fatalf("first page %d %s", w.Code, w.Body.String())
	}
	for _, revision := range []int64{1, 2} {
		before := s.reads
		w = httptest.NewRecorder()
		h.ServeHTTP(w, p7CursorRequest(t, i, "getAuditExport", path+"?cursor="+page.Contents.PageInfo.Next, params, revision))
		if revision == 1 && w.Code != 200 {
			t.Fatalf("same authorization rejected %d %s", w.Code, w.Body.String())
		}
		if revision == 2 && (w.Code != 404 || s.reads != before) {
			t.Fatalf("changed authorization reused export cursor: status=%d reads=%d before=%d", w.Code, s.reads, before)
		}
	}
}

func TestP7ComplianceRejectsUnsignedCurrentCursor(t *testing.T) {
	i := fixtureRequestIdentity(t)
	raw := `{"organization_id":"` + i.Scope.OrganizationID().String() + `","workspace_id":"` + i.Scope.WorkspaceID().String() + `","environment_id":"` + i.Scope.EnvironmentID().String() + `","operation":"listEvidence","framework":"","control_id":"","source_kind":"policy","source_id":"policy-001"}`
	r := p7CursorRequest(t, i, "listComplianceEvidence", "/api/v1/compliance/evidence?cursor="+base64.RawURLEncoding.EncodeToString([]byte(raw)), nil, 1)
	if _, err := complianceHTTPListOptions(r, i, "listComplianceEvidence"); err == nil {
		t.Fatal("current authorization accepted unsigned compliance cursor without a server key")
	}
}

type p7ComplianceCursorDatabase struct{ *discoveryCallDatabase }

func (d *p7ComplianceCursorDatabase) QueryJSON(ctx context.Context, q string, a ...any) (json.RawMessage, error) {
	if len(a) == 9 && a[5] == "listControls" {
		return json.RawMessage(`{"mapping_revision":"product-evidence-v1","collected_at":"2026-09-18T00:00:00Z","items":[{"framework":"soc2_security","control_id":"soc2_security-policies","label":"Policy definitions","required_sources":["policy"],"maximum_age_seconds":86400,"freshness":"stale","fresh_until":"2026-01-03T00:00:00Z"}],"next_cursor":null}`), nil
	}
	return d.discoveryCallDatabase.QueryJSON(ctx, q, a...)
}

func TestP7ComplianceCursorBindsCurrentAuthorization(t *testing.T) {
	i := fixtureRequestIdentity(t)
	next := `{"organization_id":"` + i.Scope.OrganizationID().String() + `","workspace_id":"` + i.Scope.WorkspaceID().String() + `","environment_id":"` + i.Scope.EnvironmentID().String() + `","operation":"listEvidence","framework":"","control_id":"","source_kind":"policy","source_id":"policy-001"}`
	db := &discoveryCallDatabase{schema: ProductionRecoverySchemaVersion, responses: map[string]json.RawMessage{
		postgresComplianceReadySQL: json.RawMessage(`true`),
		`SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`: json.RawMessage(`{"mapping_revision":"product-evidence-v1","collected_at":"2026-09-18T00:00:00Z","items":[` + compliancePolicyJSON + `],"next_cursor":` + next + `}`),
	}}
	source, err := NewComplianceRepository(&p7ComplianceCursorDatabase{db})
	if err != nil {
		t.Fatal(err)
	}
	h := &complianceHTTPHandler{source: source, signingKey: []byte(strings.Repeat("k", 32))}
	path := "/api/v1/compliance/evidence?limit=1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, p7CursorRequest(t, i, "listComplianceEvidence", path, nil, 1))
	var page struct {
		PageInfo struct {
			Next string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.PageInfo.Next == "" {
		t.Fatalf("first page %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		name   string
		change func(*RequestAuthorization)
	}{
		{"same", func(*RequestAuthorization) {}},
		{"revision", func(g *RequestAuthorization) { g.Revision.Desired++; g.Revision.Applied++ }},
		{"generation", func(g *RequestAuthorization) { g.Revision.Generation++ }},
		{"credential", func(g *RequestAuthorization) { g.Credential.ID = "other-session" }},
		{"ceiling", func(g *RequestAuthorization) { g.Credential.PATCeiling = []string{"view"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := p7CursorRequest(t, i, "listComplianceEvidence", path+"&cursor="+page.PageInfo.Next, nil, 1)
			g, _ := requestAuthorizationFromContext(r.Context())
			tc.change(&g)
			r = r.WithContext(context.WithValue(r.Context(), requestAuthorizationContextKey{}, g))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 400
			if tc.name == "same" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("cursor status %d want %d: %s", w.Code, want, w.Body.String())
			}
		})
	}
	// Enforcing handlers never derive a public key from absent configuration.
	h.signingKey = nil
	w = httptest.NewRecorder()
	h.ServeHTTP(w, p7CursorRequest(t, i, "listComplianceEvidence", path, nil, 1))
	if w.Code != 503 {
		t.Fatalf("missing server key status=%d", w.Code)
	}
}
