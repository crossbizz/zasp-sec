package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const complianceHTTPJobID = "pid_10000004-0000-4000-8000-000000000004"
const complianceHTTPToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type complianceHTTPDatabase struct {
	t              *testing.T
	identity       RequestIdentity
	operations     []string
	failure        error
	consumeFailure error
	grantFormat    string
	artifact       artifactstore.Artifact
	readDeadline   time.Time
	createBody     string
}

func (d *complianceHTTPDatabase) SchemaVersion(context.Context) (string, error) {
	return ProductionRecoverySchemaVersion, nil
}
func (d *complianceHTTPDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected exec")
}
func (d *complianceHTTPDatabase) QueryJSON(ctx context.Context, q string, a ...any) (json.RawMessage, error) {
	if q == postgresComplianceReadySQL {
		return json.RawMessage(`true`), nil
	}
	if len(a) < 5 || a[0] != d.identity.Scope.OrganizationID().String() || a[1] != d.identity.Scope.WorkspaceID().String() || a[2] != d.identity.Scope.EnvironmentID().String() || a[3] != d.identity.PrincipalID.String() {
		d.t.Fatal("request authority lost")
	}
	sum := sha256.Sum256([]byte("compliance-cookie"))
	if !bytes.Equal(a[4].([]byte), sum[:]) {
		d.t.Fatal("credential digest lost")
	}
	if d.failure != nil {
		return nil, d.failure
	}
	switch q {
	case postgresComplianceExportCreateSQL, postgresComplianceExportGetSQL:
		if q == postgresComplianceExportCreateSQL {
			d.createBody = string(a[6].(json.RawMessage))
		}
		d.operations = append(d.operations, "job")
		return json.Marshal(ComplianceExportJob{ExportID: complianceHTTPJobID, OrganizationID: d.identity.Scope.OrganizationID().String(), WorkspaceID: d.identity.Scope.WorkspaceID().String(), EnvironmentID: d.identity.Scope.EnvironmentID().String(), State: "completed", Phase: "terminal", CreatedAt: time.Now().Add(-time.Hour).UTC(), RetrievalExpiresAt: time.Now().Add(time.Hour).UTC(), MappingRevision: "product-evidence-v1"})
	case postgresComplianceExportGrantSQL:
		op := a[8].(string)
		d.operations = append(d.operations, op)
		d.grantFormat = a[7].(string)
		if a[5] != complianceHTTPJobID || len(a[6].(string)) != 64 {
			d.t.Fatal("grant binding lost")
		}
		if op == "consume" && d.consumeFailure != nil {
			return nil, d.consumeFailure
		}
		if op == "read" {
			return json.Marshal(map[string]any{"reference": d.artifact.Reference.String(), "version": d.artifact.VersionID, "size": d.artifact.Size, "sha256": hex.EncodeToString(d.artifact.SHA256[:]), "renderer_revision": "compliance-envelope-v1", "read_expires_at": d.readDeadline})
		}
		return json.Marshal(map[string]any{"expires_at": time.Now().Add(time.Minute).UTC(), "consumed": op == "consume" || op == "integrity_failure"})
	case postgresComplianceReadSQL:
		op := a[5].(string)
		d.operations = append(d.operations, op)
		if op == "getEvidence" {
			return json.RawMessage(compliancePolicyJSON), nil
		}
		if op == "listControls" {
			return json.RawMessage(`{"mapping_revision":"product-evidence-v1","collected_at":"2026-09-18T00:00:00Z","items":[{"framework":"soc2_security","control_id":"soc2_security-policies","label":"Policy definitions","required_sources":["policy"],"maximum_age_seconds":86400,"freshness":"stale","fresh_until":"2026-01-03T00:00:00Z"}],"next_cursor":null}`), nil
		}
		return json.RawMessage(`{"mapping_revision":"product-evidence-v1","collected_at":"2026-09-18T00:00:00Z","items":[` + compliancePolicyJSON + `],"next_cursor":null}`), nil
	}
	return nil, errors.New("unexpected database operation")
}

type complianceHTTPReader struct {
	db          *complianceHTTPDatabase
	tamper      string
	gotDeadline bool
}

func (r *complianceHTTPReader) Get(ctx context.Context, l artifactstore.Locator) (artifactstore.Artifact, error) {
	r.db.operations = append(r.db.operations, "storage")
	deadline, ok := ctx.Deadline()
	r.gotDeadline = ok && !deadline.After(r.db.readDeadline)
	if l != r.db.artifact.Locator {
		return artifactstore.Artifact{}, errors.New("locator drift")
	}
	a := r.db.artifact
	switch r.tamper {
	case "bytes":
		a.Body = []byte(`{}`)
	case "version":
		a.VersionID = "other"
	case "scope":
		a.Scope = domain.Scope{}
	case "digest":
		a.SHA256 = [32]byte{}
	case "size":
		a.Size++
	case "error":
		return a, errors.New("s3://private-bucket diagnostic")
	}
	return a, nil
}
func complianceHTTPFixture(t *testing.T) (http.Handler, *complianceHTTPDatabase, *complianceHTTPReader, *RequestIdentity) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "view_compliance"}
	identity.FreshAuthenticated = true
	body := []byte(`{"version":1,"id":"` + complianceHTTPJobID + `","json":[{"control":{"id":"old-control","framework":"SOC 2","name":"Old renderer","evidence_ids":[],"fresh_until":"2025-01-01T00:00:00Z"},"evidence":[],"freshness":"missing"}],"csv":"old,csv\n","human":"Persisted report from an older renderer."}`)
	ref, _ := domain.ParseEvidenceRef(complianceHTTPJobID)
	db := &complianceHTTPDatabase{t: t, identity: identity, artifact: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: "version-1"}, MediaType: "application/json", Body: body, Size: int64(len(body)), SHA256: sha256.Sum256(body)}, readDeadline: time.Now().Add(20 * time.Second).UTC()}
	source, err := NewComplianceRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	reader := &complianceHTTPReader{db: db}
	h := &complianceHTTPHandler{source: source, exports: &ComplianceExportsRepository{source: source}, reader: reader}
	router, err := NewCompositionWithCompliance(auditExportCompositionDependencies(), nil, h)
	if err != nil {
		t.Fatal(err)
	}
	mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(context.Context, Credential) (RequestIdentity, error) { return identity, nil }}, router)
	if err != nil {
		t.Fatal(err)
	}
	return mounted, db, reader, &identity
}
func complianceHTTPRequest(t *testing.T, h http.Handler, identity RequestIdentity, method, path, body string, change func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "compliance-cookie"})
	r.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
	r.Header.Set("Origin", "https://console.example.test")
	r.Header.Set("X-CSRF-Token", identity.CSRFToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "compliance-request")
	if change != nil {
		change(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestComplianceHTTPMountedPublicLifecycle(t *testing.T) {
	for _, tc := range []struct {
		method, path, body, want string
		status                   int
	}{
		{"GET", "/api/v1/compliance/controls", "", `"id":"soc2_security-policies"`, 200},
		{"GET", "/api/v1/compliance/evidence?framework=soc2_security", "", `"asset_id":"policy-001"`, 200},
		{"GET", "/api/v1/compliance/evidence/policy/policy-001?source_version=7", "", `"source_version":7`, 200},
		{"POST", "/api/v1/compliance/exports", `{"framework":"soc2_security"}`, `"status":"completed"`, 201},
		{"GET", "/api/v1/compliance/exports/`ID`", "", `"status":"completed"`, 200},
		{"POST", "/api/v1/compliance/exports/`ID`/download-grants", `{"format":"human"}`, `"token":`, 201},
		{"POST", "/api/v1/compliance/exports/`ID`/download", `{"format":"human","token":"` + complianceHTTPToken + `"}`, "Persisted report from an older renderer.", 200},
	} {
		t.Run(tc.path, func(t *testing.T) {
			h, db, reader, id := complianceHTTPFixture(t)
			w := complianceHTTPRequest(t, h, *id, tc.method, strings.ReplaceAll(tc.path, "`ID`", complianceHTTPJobID), tc.body, nil)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if strings.Contains(tc.path, "/download") && db.grantFormat != "readable" {
				t.Fatal("human SQL format drift")
			}
			if strings.HasSuffix(tc.path, "/download") && (!reader.gotDeadline || strings.Join(db.operations, ",") != "read,storage,consume" || !strings.Contains(w.Header().Get("Content-Disposition"), ".txt")) {
				t.Fatalf("download lifecycle %v", db.operations)
			}
			if tc.path == "/api/v1/compliance/controls" && strings.Contains(w.Body.String(), `"control":`) {
				t.Fatal("live controls became export wrapper")
			}
		})
	}
}
func TestComplianceHTTPMountedDenials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*http.Request)
		identity func(*RequestIdentity)
		status   int
	}{
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.test") }, nil, 403},
		{"csrf", func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }, nil, 403},
		{"scope", func(r *http.Request) { r.Header.Set(expectedScopeHeader, "foreign") }, nil, 409},
		{"duplicate-cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "other"}) }, nil, 401},
		{"fresh", nil, func(i *RequestIdentity) { i.FreshAuthenticated = false; i.FreshAuthExpiresAt = time.Time{} }, 403},
		{"audit-permission", nil, func(i *RequestIdentity) { i.Permissions = []string{"view", "view_compliance"} }, 403},
		{"view-permission", nil, func(i *RequestIdentity) { i.Permissions = []string{"view_audit", "view_compliance"} }, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _, id := complianceHTTPFixture(t)
			if tc.identity != nil {
				tc.identity(id)
			}
			w := complianceHTTPRequest(t, h, *id, "POST", "/api/v1/compliance/exports", `{}`, tc.change)
			if w.Code != tc.status || len(db.operations) != 0 {
				t.Fatalf("status=%d ops=%v body=%s", w.Code, db.operations, w.Body)
			}
		})
	}
}
func TestComplianceHTTPDownloadNoDisclosureBeforeConsume(t *testing.T) {
	for _, mode := range []string{"bytes", "version", "scope", "digest", "size", "error", "revoked", "expired", "replay"} {
		t.Run(mode, func(t *testing.T) {
			h, db, reader, id := complianceHTTPFixture(t)
			reader.tamper = mode
			if mode == "revoked" {
				db.consumeFailure = ErrComplianceForbidden
			}
			if mode == "expired" || mode == "replay" {
				db.consumeFailure = ErrRepositoryAuthentication
			}
			w := complianceHTTPRequest(t, h, *id, "POST", "/api/v1/compliance/exports/"+complianceHTTPJobID+"/download", `{"format":"human","token":"`+complianceHTTPToken+`"}`, nil)
			if w.Code == 200 || strings.Contains(w.Body.String(), "Persisted report") || strings.Contains(w.Body.String(), "private-bucket") || w.Header().Get("Content-Disposition") != "" {
				t.Fatalf("disclosed %d %s", w.Code, w.Body)
			}
			if mode != "revoked" && mode != "expired" && mode != "replay" && strings.Contains(strings.Join(db.operations, ","), "consume") {
				t.Fatal("invalid artifact consumed")
			}
		})
	}
}
func TestComplianceHTTPStrictInputs(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/compliance/evidence/policy/policy-001?source_version=7&source_version=8", ""},
		{"GET", "/api/v1/compliance/evidence/policy/policy-001?organization_id=foreign", ""},
		{"GET", "/api/v1/compliance/controls?limit=01", ""},
		{"POST", "/api/v1/compliance/exports", `{"framework":"hipaa","framework":"soc2_security"}`},
		{"POST", "/api/v1/compliance/exports", `{"id":"` + complianceHTTPJobID + `"}`},
		{"POST", "/api/v1/compliance/exports/`ID`/download-grants", `{"format":"readable"}`},
		{"POST", "/api/v1/compliance/exports/`ID`/download?token=secret", `{"format":"json","token":"` + complianceHTTPToken + `"}`},
	} {
		h, db, _, id := complianceHTTPFixture(t)
		w := complianceHTTPRequest(t, h, *id, tc.method, strings.ReplaceAll(tc.path, "`ID`", complianceHTTPJobID), tc.body, nil)
		if w.Code < 400 || len(db.operations) != 0 {
			t.Errorf("accepted %s %s: %d %v", tc.path, tc.body, w.Code, db.operations)
		}
	}
}
