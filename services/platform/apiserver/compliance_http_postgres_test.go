package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type compliancePGReader struct {
	artifact  artifactstore.Artifact
	afterRead func()
}

func TestComplianceHTTPPostgresControlFreshness(t *testing.T) {
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
		router, err := NewCompositionWithCompliance(auditExportCompositionDependencies(), nil, &complianceHTTPHandler{source: source})
		if err != nil {
			t.Fatal(err)
		}
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, Authenticate: sessions.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
		if err != nil {
			t.Fatal(err)
		}
		var fresh time.Time
		if err := f.owner.QueryRow(f.ctx, `SELECT date_trunc('second',clock_timestamp())`).Scan(&fresh); err != nil {
			t.Fatal(err)
		}
		f.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body,created_at,updated_at) SELECT $1,$2,$3,'policy','policy-'||lpad(n::text,3,'0'),1,'{}','2020-01-01T00:00:00Z',CASE WHEN n=101 THEN $4::timestamptz ELSE '2020-01-01T00:00:00Z'::timestamptz END FROM generate_series(1,101) n;`, complianceOrg, complianceWorkspace, complianceEnvironment, fresh)
		check := func(t *testing.T, control, freshness string, deadline time.Time, preview int) {
			t.Helper()
			w := complianceHTTPRequest(t, mounted, identity, "GET", "/api/v1/compliance/controls?control_id="+control, "", func(r *http.Request) { r.Header.Set("Cookie", browserSessionCookie+"=compliance-fix-session") })
			var page struct {
				Items []struct {
					ID          string    `json:"id"`
					Freshness   string    `json:"freshness"`
					FreshUntil  time.Time `json:"fresh_until"`
					EvidenceIDs []string  `json:"evidence_ids"`
				} `json:"items"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
				t.Fatalf("control response %d %s", w.Code, w.Body)
			}
			got := page.Items[0]
			if got.ID != control || got.Freshness != freshness || !got.FreshUntil.Equal(deadline) || len(got.EvidenceIDs) != preview {
				t.Fatalf("authoritative %s control: %+v want freshness=%s deadline=%s preview=%d", control, got, freshness, deadline, preview)
			}
		}
		t.Run("fresh_101st_source", func(t *testing.T) { check(t, "soc2_security-policies", "fresh", fresh.Add(24*time.Hour), 100) })
		f.exec(`UPDATE zasp_workflow_records SET updated_at='2020-01-01T00:00:00Z' WHERE (organization_id,workspace_id,environment_id,kind)=($1,$2,$3,'policy')`, complianceOrg, complianceWorkspace, complianceEnvironment)
		t.Run("all_stale", func(t *testing.T) {
			check(t, "soc2_security-policies", "stale", time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC), 100)
		})
		f.exec(`DELETE FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind)=($1,$2,$3,'policy')`, complianceOrg, complianceWorkspace, complianceEnvironment)
		t.Run("missing", func(t *testing.T) { check(t, "soc2_security-policies", "missing", time.Unix(0, 0), 0) })
		f.exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,migration_seeded) VALUES($1,$2,$3,'staging','metadata_only',30,true,true)`, complianceOrg, complianceWorkspace, complianceEnvironment)
		t.Run("migration_seeded_only", func(t *testing.T) { check(t, "soc2_security-configuration", "missing", time.Unix(0, 0), 1) })
	})
}

func (r *compliancePGReader) Get(ctx context.Context, l artifactstore.Locator) (artifactstore.Artifact, error) {
	if r.afterRead != nil {
		r.afterRead()
	}
	return r.artifact, nil
}

// Uses mounted browser middleware, actual session authentication and registered
// SQL grant authority. Only immutable object storage is replaced.
func TestComplianceHTTPPostgresGrantLifecycle(t *testing.T) {
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
		reader := &compliancePGReader{}
		handler := &complianceHTTPHandler{source: source, exports: &ComplianceExportsRepository{source: source}, reader: reader}
		router, err := NewCompositionWithCompliance(auditExportCompositionDependencies(), nil, handler)
		if err != nil {
			t.Fatal(err)
		}
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, Authenticate: sessions.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
		if err != nil {
			t.Fatal(err)
		}
		invoke := func(path, body string) *httptest.ResponseRecorder {
			return complianceHTTPRequest(t, mounted, identity, "POST", path, body, func(r *http.Request) { r.Header.Set("Cookie", browserSessionCookie+"=compliance-fix-session") })
		}
		created := invoke("/api/v1/compliance/exports", `{}`)
		if created.Code != 201 {
			t.Fatalf("create %d %s", created.Code, created.Body)
		}
		var job struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(created.Body.Bytes(), &job) != nil || job.ID == "" {
			t.Fatal("missing job")
		}
		ref, _ := domain.ParseEvidenceRef(job.ID)
		body := []byte(`{"version":1,"id":"` + job.ID + `","json":[],"csv":"header\n","human":"Frozen historical report"}`)
		sum := sha256.Sum256(body)
		reader.artifact = artifactstore.Artifact{Locator: artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: "frozen-v1"}, MediaType: "application/json", Body: body, Size: int64(len(body)), SHA256: sum}
		f.exec(`UPDATE zasp_compliance_export_jobs SET state='completed',phase='terminal',storage_state='verified',receipt_version='frozen-v1',artifact_reference=$1,artifact_size=$2,artifact_digest=$3,renderer_revision='compliance-envelope-v1',package=$4,format_sizes='{"json":2,"csv":7,"readable":24}' WHERE export_id=$1`, job.ID, len(body), sum[:], body)
		path := "/api/v1/compliance/exports/" + job.ID
		grant := func() string {
			t.Helper()
			w := invoke(path+"/download-grants", `{"format":"human"}`)
			var v struct {
				Token string `json:"token"`
			}
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &v) != nil || len(v.Token) != 64 {
				t.Fatalf("grant %d %s", w.Code, w.Body)
			}
			return v.Token
		}
		download := func(token string) *httptest.ResponseRecorder {
			return invoke(path+"/download", `{"format":"human","token":"`+token+`"}`)
		}
		token := grant()
		w := download(token)
		if w.Code != 200 || w.Body.String() != "Frozen historical report" {
			t.Fatalf("download %d %s", w.Code, w.Body)
		}
		if w = download(token); w.Code == 200 {
			t.Fatal("grant replay disclosed")
		}
		token = grant()
		reader.artifact.Body = []byte("tampered")
		w = download(token)
		if w.Code != 503 {
			t.Fatalf("integrity response %d %s", w.Code, w.Body)
		}
		var count int
		var metadata json.RawMessage
		if err := f.owner.QueryRow(f.ctx, `SELECT count(*),min(metadata::text)::jsonb FROM zasp_admin_audit WHERE action='compliance.export.integrity_failed' AND target_id=$1`, job.ID).Scan(&count, &metadata); err != nil || count != 1 {
			var raw json.RawMessage
			diagnostic := api.QueryRow(f.ctx, postgresComplianceExportGrantSQL, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, f.digest[:], job.ID, token, "readable", "integrity_failure", source.checksum, source.fingerprint).Scan(&raw)
			t.Fatalf("denied download audit did not persist count=%d error=%v direct=%v", count, err, diagnostic)
		}
		if strings.Contains(string(metadata), token) || strings.Contains(string(metadata), "frozen-v1") || strings.Contains(string(metadata), "reference") {
			t.Fatal("private grant/storage coordinates in audit")
		}
		_ = download(token)
		if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_admin_audit WHERE action='compliance.export.integrity_failed' AND target_id=$1`, job.ID).Scan(&count); err != nil || count != 1 {
			t.Fatal("replay duplicated integrity audit")
		}
		reader.artifact.Body = body
		// Observe and cancel the actual audit INSERT while its relation lock is
		// blocked. No catalog changes bypass registered readiness or authority.
		token = grant()
		reader.artifact.Body = []byte("tampered")
		httpDone := make(chan struct{})
		_, _ = f.blocked(api, `LOCK TABLE zasp_admin_audit IN SHARE MODE`, nil, func(ctx context.Context) (json.RawMessage, error) {
			defer close(httpDone)
			w = complianceHTTPRequest(t, mounted, identity, "POST", path+"/download", `{"format":"human","token":"`+token+`"}`, func(r *http.Request) {
				r.Header.Set("Cookie", browserSessionCookie+"=compliance-fix-session")
				*r = *r.WithContext(ctx)
			})
			return w.Body.Bytes(), nil
		}, func(ctx context.Context) {
			var inserting bool
			if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_admin_audit'::regclass AND mode='RowExclusiveLock' AND NOT granted)`, api.PgConn().PID()).Scan(&inserting); err != nil || !inserting {
				t.Fatalf("did not reach audit INSERT: %v", err)
			}
			if _, err := f.owner.Exec(ctx, `SELECT pg_cancel_backend($1)`, api.PgConn().PID()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-httpDone:
			case <-ctx.Done():
				t.Fatal("cancelled audit HTTP did not join")
			}
		})
		if w.Code != 503 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), "Frozen") || strings.Contains(w.Body.String(), "diagnostic") {
			t.Fatalf("audit commit failure disclosed: %d %s", w.Code, w.Body)
		}
		var unconsumed bool
		if err := f.owner.QueryRow(f.ctx, `SELECT used_at IS NULL AND read_expires_at IS NOT NULL FROM zasp_compliance_export_grants WHERE grant_digest=digest($1,'sha256')`, token).Scan(&unconsumed); err != nil || !unconsumed {
			t.Fatalf("audit commit failure consumed grant: %v", err)
		}
		if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_admin_audit WHERE action='compliance.export.integrity_failed' AND target_id=$1`, job.ID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("audit commit failure persisted a row: %d %v", count, err)
		}
		reader.artifact.Body = body
		token = grant()
		reader.afterRead = func() {
			f.exec(`UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, job.ID)
		}
		w = download(token)
		if w.Code == 200 || strings.Contains(w.Body.String(), "Frozen") {
			t.Fatal("grant extended export expiry")
		}
		reader.afterRead = nil
		f.exec(`UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=clock_timestamp()+interval '1 hour' WHERE export_id=$1`, job.ID)
		token = grant()
		reader.afterRead = func() { f.exec(`DELETE FROM zasp_authorized_scopes WHERE principal_id=$1`, compliancePrincipal) }
		w = download(token)
		if w.Code == 200 {
			t.Fatal("revoked source authority disclosed")
		}
	})
}
