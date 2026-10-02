package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Provider transport is controlled, but the driver, Store, mounted session
// middleware, read lease, terminal grant operation and audit commit are real.
func TestComplianceHTTPPostgresReadClassification(t *testing.T) {
	withComplianceFixFixture(t, func(f *complianceFixFixture) {
		api := f.connect("security_agent_v33_discovery_api_login")
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		sessions, err := NewPostgresRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		source, err := NewComplianceRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := sessions.Authenticate(f.ctx, Credential{Kind: CredentialBrowserSession, Value: "compliance-fix-session"})
		if err != nil {
			t.Fatal(err)
		}
		handler := &complianceHTTPHandler{source: source, exports: &ComplianceExportsRepository{source: source}}
		router, err := NewCompositionWithCompliance(auditExportCompositionDependencies(), nil, handler)
		if err != nil {
			t.Fatal(err)
		}
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, Authenticate: sessions.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
		if err != nil {
			t.Fatal(err)
		}
		invoke := func(ctx context.Context, path, body string) *httptest.ResponseRecorder {
			return complianceHTTPRequest(t, mounted, identity, "POST", path, body, func(r *http.Request) {
				r.Header.Set("Cookie", browserSessionCookie+"=compliance-fix-session")
				*r = *r.WithContext(ctx)
			})
		}
		for _, mode := range classificationModes {
			t.Run(mode, func(t *testing.T) {
				job := f.job(api, "read-classification-"+mode)
				ref, _ := domain.ParseEvidenceRef(job)
				body := []byte(`{"version":1,"id":"` + job + `","json":[],"csv":"header\n","human":"Frozen historical report"}`)
				if mode == "envelope" {
					body = []byte(strings.Replace(string(body), `"version":1`, `"version":2`, 1))
				}
				sum := sha256.Sum256(body)
				artifact := artifactstore.Artifact{Locator: artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: "frozen-v1"}, MediaType: "application/json", Body: body, Size: int64(len(body)), SHA256: sum}
				f.exec(`UPDATE zasp_compliance_export_jobs SET state='completed',phase='terminal',storage_state='verified',receipt_version='frozen-v1',artifact_reference=$1,artifact_size=$2,artifact_digest=$3,renderer_revision='compliance-envelope-v1',package=$4,format_sizes='{"json":2,"csv":7,"readable":24}' WHERE export_id=$1`, job, len(body), sum[:], body)
				path := "/api/v1/compliance/exports/" + job
				grant := invoke(f.ctx, path+"/download-grants", `{"format":"human"}`)
				var issued struct {
					Token string `json:"token"`
				}
				if grant.Code != 201 || json.Unmarshal(grant.Body.Bytes(), &issued) != nil || len(issued.Token) != 64 {
					t.Fatalf("grant: %d %s", grant.Code, grant.Body)
				}
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				store, _, provider := classificationStore(t, artifact, mode, cancel)
				handler.reader = store
				var originalLease time.Time
				provider.headHook = func() {
					if err := f.owner.QueryRow(f.ctx, `SELECT read_expires_at FROM zasp_compliance_export_grants WHERE grant_digest=digest($1,'sha256')`, issued.Token).Scan(&originalLease); err != nil || !originalLease.After(time.Now()) {
						t.Fatalf("durable lease absent before provider: %v", err)
					}
				}
				downloadBody := `{"format":"human","token":"` + issued.Token + `"}`
				w := invoke(ctx, path+"/download", downloadBody)
				if classificationValid(mode) {
					if w.Code != 200 || w.Body.String() != "Frozen historical report" || w.Header().Get("Content-Disposition") == "" {
						t.Fatalf("valid download %d %s", w.Code, w.Body)
					}
				} else if w.Code != 503 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), classificationSecret) || strings.Contains(w.Body.String(), "Frozen") {
					t.Fatalf("failure disclosed %d %s", w.Code, w.Body)
				}
				checkState := func() {
					t.Helper()
					var used, lease *time.Time
					if err := f.owner.QueryRow(f.ctx, `SELECT used_at,read_expires_at FROM zasp_compliance_export_grants WHERE grant_digest=digest($1,'sha256')`, issued.Token).Scan(&used, &lease); err != nil {
						t.Fatal(err)
					}
					terminal := classificationValid(mode) || classificationIntegrity(mode)
					if (used != nil) != terminal {
						t.Fatalf("terminal grant state: used=%v mode=%s", used != nil, mode)
					}
					if terminal {
						if lease != nil {
							t.Fatal("terminal read lease retained")
						}
					} else if lease == nil || !lease.Equal(originalLease) {
						t.Fatal("provider failure changed or extended read lease")
					}
					var count int
					var safe bool
					if err := f.owner.QueryRow(f.ctx, `SELECT count(*),coalesce(bool_and(metadata=jsonb_build_object('export_id',$1::text,'format','readable','reason','artifact_integrity')),true) FROM zasp_admin_audit WHERE action='compliance.export.integrity_failed' AND target_id=$1`, job).Scan(&count, &safe); err != nil {
						t.Fatal(err)
					}
					expected := 0
					if classificationIntegrity(mode) {
						expected = 1
					}
					if count != expected || !safe {
						t.Fatalf("durable safe integrity audit count=%d want=%d safe=%v", count, expected, safe)
					}
				}
				checkState()
				replay := invoke(f.ctx, path+"/download", downloadBody)
				if replay.Code == 200 || replay.Header().Get("Content-Disposition") != "" {
					t.Fatal("failed/single-use read replay disclosed")
				}
				checkState()
			})
		}
	})
}
