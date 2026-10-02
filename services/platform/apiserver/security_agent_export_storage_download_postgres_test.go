package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This matrix connects registered release58 SQL, the mounted production HTTP
// handler and artifactstore.Store. Only provider I/O and authentication are
// controlled. Plans and packages are fixtures, not public planner/renderer or
// separate worker-process proof (those have their own tests).
type exportStorageMatrixDriver struct {
	mu            sync.Mutex
	objects       map[artifactstore.DriverLocator]artifactstore.DriverObject
	gets, deletes int
	barrier       func(context.Context) error
	mutate        func(artifactstore.DriverObject) artifactstore.DriverObject
}

func (d *exportStorageMatrixDriver) Put(_ context.Context, o artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	o.VersionID = "matrix-immutable-" + o.Reference.String()
	o.Body = bytes.Clone(o.Body)
	d.objects[o.DriverLocator] = o
	return o, nil
}
func (d *exportStorageMatrixDriver) Get(ctx context.Context, l artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	d.mu.Lock()
	d.gets++
	o, ok := d.objects[l]
	barrier, mutate := d.barrier, d.mutate
	d.mu.Unlock()
	if barrier != nil {
		if err := barrier(ctx); err != nil {
			return artifactstore.DriverObject{}, err
		}
	}
	if !ok {
		return artifactstore.DriverObject{}, errors.New("private matrix object absent")
	}
	o.Body = bytes.Clone(o.Body)
	if mutate != nil {
		o = mutate(o)
	}
	return o, nil
}
func (d *exportStorageMatrixDriver) Delete(_ context.Context, l artifactstore.DriverLocator) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deletes++
	delete(d.objects, l)
	return nil
}

// The real SDK decodes these HTTP responses into the typed error consumed by
// ExportCleanup. A generic HTTP 404 deliberately carries no NoSuchVersion code.
type exportStorageCleanupHTTP struct {
	t       *testing.T
	driver  *exportStorageMatrixDriver
	locator artifactstore.DriverLocator
	mode    string
	methods []string
}

func (h *exportStorageCleanupHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	h.methods = append(h.methods, r.Method)
	if r.URL.Path != "/matrix-export-bucket/"+h.locator.Key || r.URL.Query().Get("versionId") != h.locator.VersionID || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || r.Header.Get("X-Amz-Bypass-Governance-Retention") != "" {
		h.t.Errorf("cleanup request escaped exact scoped key/version/owner: %s %v", r.URL, r.Header)
		return nil, errors.New("unexpected cleanup locator")
	}
	status, body := http.StatusNoContent, ""
	header := http.Header{}
	if h.mode == "denied" {
		status, body = http.StatusForbidden, `<Error><Code>AccessDenied</Code></Error>`
	}
	h.driver.mu.Lock()
	defer h.driver.mu.Unlock()
	switch r.Method {
	case http.MethodDelete:
		if h.mode != "denied" {
			if _, exists := h.driver.objects[h.locator]; exists {
				delete(h.driver.objects, h.locator)
				h.driver.deletes++
			}
			header.Set("X-Amz-Version-Id", h.locator.VersionID)
		}
	case http.MethodGet:
		if r.Header.Get("Range") != "bytes=0-0" {
			h.t.Error("cleanup absence GET is not bounded")
		}
		if h.mode != "denied" {
			status = http.StatusNotFound
			if _, exists := h.driver.objects[h.locator]; exists {
				h.t.Error("cleanup absence response would hide existing object")
			}
			if h.mode == "typed_absent" {
				body = `<Error><Code>NoSuchVersion</Code><Message>Missing exact version</Message></Error>`
			}
		}
	default:
		h.t.Errorf("unexpected cleanup method %s", r.Method)
		return nil, errors.New("unexpected cleanup method")
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

type exportStorageMatrixArtifact struct {
	run, step, environment, id string
	artifact                   artifactstore.Artifact
	manifest                   []byte
	csv, human                 string
}
type exportStorageMatrix struct {
	f        *exportDBFixture
	driver   *exportStorageMatrixDriver
	store    *artifactstore.Store
	identity RequestIdentity
	items    []exportStorageMatrixArtifact
}

func newExportStorageMatrix(t *testing.T, f *exportDBFixture) *exportStorageMatrix {
	t.Helper()
	d := &exportStorageMatrixDriver{objects: make(map[artifactstore.DriverLocator]artifactstore.DriverObject)}
	store, err := artifactstore.NewExport(d, artifactstore.Config{OperationTimeout: 10 * time.Second, MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	m := &exportStorageMatrix{f: f, driver: d, store: store}
	for n, spec := range []struct{ run, step, environment string }{
		{exportFixtureRun, exportFixtureStep, f.e},
		{"pid_8e190001-0000-4000-8000-000000000001", "pid_8e190002-0000-4000-8000-000000000002", f.e},
		{"pid_8e190003-0000-4000-8000-000000000003", "pid_8e190004-0000-4000-8000-000000000004", "pid_8e190005-0000-4000-8000-000000000005"},
	} {
		if n > 0 {
			seedSecondExportRun(t, f, spec.run, spec.step, spec.environment, n+1)
		}
		var raw json.RawMessage
		err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.o, f.w, spec.environment, spec.run, exportFixtureWorker, exportFixtureLease, fmt.Sprintf("pid_8e191001-0000-4000-8000-%012d", n+1), fmt.Sprintf("pid_8e191002-0000-4000-8000-%012d", n+1), migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
		if err != nil {
			t.Fatal(err)
		}
		var admitted struct {
			ExportID string `json:"export_id"`
		}
		if err := json.Unmarshal(raw, &admitted); err != nil || !validProductID(admitted.ExportID) {
			t.Fatalf("dispatch=%s %v", raw, err)
		}
		// capture uses the real registered executor; adapt only its scoped fixture.
		scoped := *f
		scoped.e = spec.environment
		captured := scoped.capture(t, admitted.ExportID)
		var capture struct {
			Snapshot map[string]any `json:"snapshot"`
		}
		if err := json.Unmarshal(captured, &capture); err != nil || capture.Snapshot == nil {
			t.Fatalf("capture=%s %v", captured, err)
		}
		capture.Snapshot["renderer_revision"] = "security-agent-evidence-envelope-v1"
		manifest, err := json.Marshal(capture.Snapshot)
		if err != nil {
			t.Fatal(err)
		}
		csv, human := fmt.Sprintf("matrix,original-%d\r\n", n), fmt.Sprintf("Matrix original report %d", n)
		body, err := json.Marshal(map[string]any{"version": 1, "id": admitted.ExportID, "json": json.RawMessage(manifest), "csv": csv, "human": human})
		if err != nil {
			t.Fatal(err)
		}
		executor := m.connect(t, "export_source_executor")
		var generation int64
		if err := f.owner.QueryRow(f.ctx, `SELECT generation FROM zasp_compliance_export_jobs WHERE export_id=$1`, admitted.ExportID).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		intent := map[string]any{"renderer_revision": "security-agent-evidence-envelope-v1", "reference": admitted.ExportID, "bytes_hex": hex.EncodeToString(body), "sha256": hex.EncodeToString(sum[:]), "size": len(body), "format_sizes": map[string]int{"json": len(manifest), "csv": len(csv), "readable": len(human)}}
		mutate := func(fn string, payload any) {
			t.Helper()
			var receipt json.RawMessage
			if err := executor.QueryRow(f.ctx, `SELECT `+fn+`($1,$2,$3,$4,'export-source-worker',$5,$6,$7,$8,$9)`, f.o, f.w, spec.environment, admitted.ExportID, strings.Repeat("b", 64), generation, payload, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&receipt); err != nil {
				t.Fatalf("%s: %v", fn, err)
			}
		}
		mutate("zasp_compliance_export_prepare_artifact", intent)
		o, _ := domain.ParseProductID(f.o)
		w, _ := domain.ParseProductID(f.w)
		e, _ := domain.ParseProductID(spec.environment)
		scope, err := domain.NewScope(o, w, e)
		if err != nil {
			t.Fatal(err)
		}
		ref, _ := domain.ParseEvidenceRef(admitted.ExportID)
		a, err := store.Put(f.ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: body})
		if err != nil {
			t.Fatal(err)
		}
		mutate("zasp_compliance_export_finish", map[string]any{"reference": admitted.ExportID, "version": a.VersionID, "size": a.Size, "sha256": hex.EncodeToString(a.SHA256[:])})
		m.items = append(m.items, exportStorageMatrixArtifact{spec.run, spec.step, spec.environment, admitted.ExportID, a, manifest, csv, human})
	}
	const reader = "pid_8e190040-0000-4000-8000-000000000040"
	digest := sha256.Sum256([]byte("compliance-cookie"))
	csrf := strings.Repeat("c", 32)
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'storage-matrix','storage-matrix-reader','read_only_viewer',true);
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Storage matrix reader','["view"]');
INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view"]',$6,clock_timestamp()+interval '1 hour',clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, reader, digest[:], csrf); err != nil {
		t.Fatal(err)
	}
	p, _ := domain.ParseProductID(reader)
	m.identity = RequestIdentity{Scope: m.items[0].artifact.Scope, PrincipalID: p, CredentialKind: CredentialBrowserSession, Permissions: []string{"view"}, CSRFToken: csrf}
	t.Logf("release58 checksum=%s fingerprint=%s; registered dispatch/capture/prepare/finish; local storage driver; fixture package renderer", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
	return m
}

func (m *exportStorageMatrix) connect(t *testing.T, role string) *pgx.Conn {
	t.Helper()
	cfg := m.f.owner.Config().Copy()
	cfg.User = role
	c, err := pgx.ConnectConfig(m.f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}
func (m *exportStorageMatrix) handler(t *testing.T, identity RequestIdentity) http.Handler {
	t.Helper()
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: m.connect(t, m.f.api.Config().User)})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewSecurityAgentExportsRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewCompositionWithSecurityAgentExports(auditExportCompositionDependencies(), nil, nil, &securityAgentExportHTTPHandler{exports: repo, reader: m.store})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(context.Context, Credential) (RequestIdentity, error) { return identity, nil }}, router)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func (m *exportStorageMatrix) request(t *testing.T, h http.Handler, item exportStorageMatrixArtifact, suffix, format, token string, change func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"format":%q}`, format)
	if suffix == "download" {
		body = fmt.Sprintf(`{"format":%q,"token":%q}`, format, token)
	}
	return complianceHTTPRequest(t, h, m.identity, http.MethodPost, "/api/v1/security-agent-runs/"+item.run+"/steps/"+item.step+"/export/"+suffix, body, change)
}
func (m *exportStorageMatrix) issue(t *testing.T, h http.Handler, item exportStorageMatrixArtifact, format string) string {
	t.Helper()
	r := m.request(t, h, item, "download-grants", format, "", nil)
	var grant struct {
		Token string `json:"token"`
	}
	if r.Code != http.StatusCreated || json.Unmarshal(r.Body.Bytes(), &grant) != nil || !validExistingTestPublicDigest(grant.Token) {
		t.Fatalf("grant=%d %s", r.Code, r.Body)
	}
	return grant.Token
}
func (m *exportStorageMatrix) refuse(t *testing.T, r *httptest.ResponseRecorder) {
	t.Helper()
	if r.Code < 400 || r.Header().Get("Content-Disposition") != "" || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unsafe refusal: %d %v %s", r.Code, r.Header(), r.Body)
	}
	for _, secret := range []string{"matrix-immutable-", "private matrix", "matrix,original-", "Matrix original report", "content_json", "s3://", "bytes_hex", "receipt_version"} {
		if strings.Contains(r.Body.String(), secret) {
			t.Fatalf("refusal disclosed %q: %s", secret, r.Body)
		}
	}
}
func (m *exportStorageMatrix) grantState(t *testing.T, token string) (used, leased bool, audits int) {
	t.Helper()
	err := m.f.owner.QueryRow(m.f.ctx, `SELECT used_at IS NOT NULL,read_expires_at IS NOT NULL,(SELECT count(*) FROM zasp_admin_audit WHERE target_id=g.export_id AND action='compliance.export.integrity_failed') FROM zasp_compliance_export_grants g WHERE grant_digest=digest($1,'sha256')`, token).Scan(&used, &leased, &audits)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// A missing session/format/run/scope binding would disclose one of three real
// stored packages. Successful JSON/CSV/human responses prove the same fixture.
func TestSecurityAgentExportStorageDownloadRefusalsPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		m := newExportStorageMatrix(t, f)
		h := m.handler(t, m.identity)
		item := m.items[0]
		for _, format := range []string{"json", "csv", "human"} {
			token := m.issue(t, h, item, format)
			r := m.request(t, h, item, "download", format, token, nil)
			want := map[string]string{"json": string(item.manifest), "csv": item.csv, "human": item.human}[format]
			media := map[string]string{"json": "application/json", "csv": "text/csv; charset=utf-8", "human": "text/plain; charset=utf-8"}[format]
			if r.Code != 200 || r.Body.String() != want || r.Header().Get("Content-Type") != media || r.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(r.Header().Get("Content-Disposition"), "attachment;") || r.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s stored bytes/headers=%d %v %s", format, r.Code, r.Header(), r.Body)
			}
		}
		token := m.issue(t, h, item, "json")
		otherDigest := sha256.Sum256([]byte("other-session"))
		if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($1,$2,$3,$4,$5,'["view"]',$6,clock_timestamp()+interval '1 hour',clock_timestamp())`, otherDigest[:], m.identity.PrincipalID.String(), f.o, f.w, f.e, m.identity.CSRFToken); err != nil {
			t.Fatal(err)
		}
		otherSession := func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "other-session"})
		}
		otherIssue := m.request(t, h, item, "download-grants", "json", "", otherSession)
		var otherGrant struct {
			Token string `json:"token"`
		}
		if otherIssue.Code != http.StatusCreated || json.Unmarshal(otherIssue.Body.Bytes(), &otherGrant) != nil || !validExistingTestPublicDigest(otherGrant.Token) {
			t.Fatalf("second valid session cannot issue its own grant: %d %s", otherIssue.Code, otherIssue.Body)
		}
		otherDownload := m.request(t, h, item, "download", "json", otherGrant.Token, otherSession)
		if otherDownload.Code != http.StatusOK || !bytes.Equal(otherDownload.Body.Bytes(), item.manifest) {
			t.Fatalf("second valid session cannot use its own grant: %d %s", otherDownload.Code, otherDownload.Body)
		}
		t.Log("second persisted session issued and consumed its own grant for the same principal and scope")
		for _, mode := range []string{"wrong_format", "sibling_run", "foreign_scope", "wrong_session", "wrong_csrf", "expired"} {
			t.Run(mode, func(t *testing.T) {
				target, format, change := item, "json", (func(*http.Request))(nil)
				switch mode {
				case "wrong_format":
					format = "csv"
				case "sibling_run":
					target = m.items[1]
				case "foreign_scope":
					target = m.items[2]
				case "wrong_session":
					change = otherSession
				case "wrong_csrf":
					change = func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }
				case "expired":
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_grants SET expires_at=clock_timestamp() WHERE grant_digest=digest($1,'sha256')`, token); err != nil {
						t.Fatal(err)
					}
				}
				m.driver.mu.Lock()
				before := m.driver.gets
				m.driver.mu.Unlock()
				m.refuse(t, m.request(t, h, target, "download", format, token, change))
				m.driver.mu.Lock()
				after := m.driver.gets
				m.driver.mu.Unlock()
				if after != before {
					t.Fatal("refusal reached storage")
				}
				used, leased, audits := m.grantState(t, token)
				if used || leased || audits != 0 {
					t.Fatalf("refusal mutated grant: %v %v %d", used, leased, audits)
				}
			})
		}
	})
}

// Removing the single-reader lease or final consume authorization breaks this
// test. The barrier is below the production artifact reader, after SQL read.
func TestSecurityAgentExportStorageDownloadGrantRacesPostgres(t *testing.T) {
	for _, mode := range []string{"same_grant", "membership_revoked", "scope_revoked"} {
		t.Run(mode, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				m := newExportStorageMatrix(t, f)
				h := m.handler(t, m.identity)
				other := m.handler(t, m.identity)
				item := m.items[0]
				token := m.issue(t, h, item, "json")
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				var enteredOnce sync.Once
				m.driver.barrier = func(ctx context.Context) error {
					enteredOnce.Do(func() { close(entered) })
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- m.request(t, h, item, "download", "json", token, nil); close(done) }()
				defer func() {
					once.Do(func() { close(release) })
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("grant race did not join during cleanup")
					}
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("download never reached storage GET")
				}
				used, leased, _ := m.grantState(t, token)
				if used || !leased {
					t.Fatal("GET has no live unconsumed read lease")
				}
				if mode == "same_grant" {
					m.refuse(t, m.request(t, other, item, "download", "json", token, nil))
				} else {
					q := `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`
					if mode == "scope_revoked" {
						q = `DELETE FROM zasp_authorized_scopes WHERE principal_id=$1`
					}
					if _, err := f.owner.Exec(f.ctx, q, m.identity.PrincipalID.String()); err != nil {
						t.Fatal(err)
					}
				}
				once.Do(func() { close(release) })
				var r *httptest.ResponseRecorder
				select {
				case r = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("download did not join")
				}
				if mode == "same_grant" {
					if r.Code != 200 || !bytes.Equal(r.Body.Bytes(), item.manifest) {
						t.Fatalf("winner=%d %s", r.Code, r.Body)
					}
				} else {
					m.refuse(t, r)
				}
				m.refuse(t, m.request(t, other, item, "download", "json", token, nil))
				used, leased, audits := m.grantState(t, token)
				if used != (mode == "same_grant") || leased != (mode != "same_grant") || audits != 0 {
					t.Fatalf("consume bookkeeping=%v %v %d", used, leased, audits)
				}
				if m.driver.gets != 1 {
					t.Fatalf("same grant performed %d storage reads", m.driver.gets)
				}
			})
		})
	}
}

// Keep outer hashes valid for semantic attacks: losing package/binding checks
// must fail even when the provider and recorded receipt agree on the bytes.
func TestSecurityAgentExportStorageDownloadCorruptionPostgres(t *testing.T) {
	for _, mode := range []string{"corrupt_bytes", "wrong_version", "swapped_selection", "malformed_package"} {
		t.Run(mode, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				m := newExportStorageMatrix(t, f)
				h := m.handler(t, m.identity)
				item := m.items[0]
				if mode == "corrupt_bytes" {
					m.driver.mutate = func(o artifactstore.DriverObject) artifactstore.DriverObject { o.Body[0] = '['; return o }
				}
				if mode == "wrong_version" {
					m.driver.mutate = func(o artifactstore.DriverObject) artifactstore.DriverObject {
						o.VersionID = "matrix-wrong-immutable-version"
						return o
					}
				}
				if mode == "swapped_selection" || mode == "malformed_package" {
					var envelope map[string]any
					if err := json.Unmarshal(item.artifact.Body, &envelope); err != nil {
						t.Fatal(err)
					}
					if mode == "malformed_package" {
						delete(envelope, "csv")
					} else {
						var sibling map[string]any
						if err := json.Unmarshal(m.items[1].manifest, &sibling); err != nil {
							t.Fatal(err)
						}
						envelope["json"].(map[string]any)["records"] = sibling["records"]
					}
					body, err := json.Marshal(envelope)
					if err != nil {
						t.Fatal(err)
					}
					sum := sha256.Sum256(body)
					m.driver.mu.Lock()
					for k, o := range m.driver.objects {
						if o.Reference == item.artifact.Reference {
							o.Body = body
							o.Size = int64(len(body))
							o.SHA256 = sum
							m.driver.objects[k] = o
						}
					}
					m.driver.mu.Unlock()
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_jobs SET package=$2,artifact_size=$3,artifact_digest=$4 WHERE export_id=$1`, item.id, body, len(body), sum[:]); err != nil {
						t.Fatal(err)
					}
				}
				token := m.issue(t, h, item, "json")
				r := m.request(t, h, item, "download", "json", token, nil)
				m.refuse(t, r)
				if r.Code != 503 {
					t.Fatalf("integrity response=%d", r.Code)
				}
				used, leased, audits := m.grantState(t, token)
				if !used || leased || audits != 1 {
					t.Fatalf("integrity not single-use: %v %v %d", used, leased, audits)
				}
				m.refuse(t, m.request(t, h, item, "download", "json", token, nil))
				_, _, audits = m.grantState(t, token)
				if audits != 1 || m.driver.gets != 1 {
					t.Fatalf("replay performed I/O or audited again: %d %d", m.driver.gets, audits)
				}
			})
		})
	}
}

// Cleanup cannot delete an object while HTTP owns a read lease. Expiry and
// successful consume release it; deletion then uses the exact scoped version.
func TestSecurityAgentExportStorageDownloadReadLeaseCleanupPostgres(t *testing.T) {
	for _, mode := range []string{"exact_expiry", "consumed_release"} {
		t.Run(mode, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				m := newExportStorageMatrix(t, f)
				h := m.handler(t, m.identity)
				item := m.items[0]
				token := m.issue(t, h, item, "json")
				var raw json.RawMessage
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				m.driver.barrier = func(ctx context.Context) error {
					close(entered)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- m.request(t, h, item, "download", "json", token, nil); close(done) }()
				defer func() {
					releaseOnce.Do(func() { close(release) })
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("storage download did not join during cleanup")
					}
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("cleanup download did not reach storage GET")
				}
				cleaner := m.connect(t, "export_source_cleanup")
				claim := func() map[string]any {
					t.Helper()
					if err := cleaner.QueryRow(f.ctx, `SELECT zasp_compliance_export_claim($1,$2,$3,$4,'matrix-cleaner',$5,'cleanup',$6,$7)`, f.o, f.w, f.e, item.id, strings.Repeat("e", 64), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
						t.Fatal(err)
					}
					var out map[string]any
					if err := json.Unmarshal(raw, &out); err != nil {
						t.Fatal(err)
					}
					return out
				}
				var retrieval time.Time
				if err := f.owner.QueryRow(f.ctx, `SELECT retrieval_expires_at FROM zasp_compliance_export_jobs WHERE export_id=$1`, item.id).Scan(&retrieval); err != nil {
					t.Fatal(err)
				}
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=clock_timestamp() WHERE export_id=$1`, item.id); err != nil {
					t.Fatal(err)
				}
				if c := claim(); c != nil {
					t.Fatalf("live read allowed cleanup=%v", c)
				}
				if mode == "consumed_release" {
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=$2 WHERE export_id=$1`, item.id, retrieval); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_grants SET read_expires_at=clock_timestamp() WHERE grant_digest=digest($1,'sha256')`, token); err != nil {
						t.Fatal(err)
					}
				}
				releaseOnce.Do(func() { close(release) })
				select {
				case response := <-done:
					if mode == "consumed_release" {
						if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), item.manifest) {
							t.Fatalf("consume release response=%d %s", response.Code, response.Body)
						}
					} else {
						m.refuse(t, response)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("cleanup download did not join")
				}
				m.driver.mu.Lock()
				m.driver.barrier = nil
				m.driver.mu.Unlock()
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=clock_timestamp() WHERE export_id=$1`, item.id); err != nil {
					t.Fatal(err)
				}
				c := claim()
				if c == nil {
					t.Fatal("released/expired read still blocked cleanup")
				}
				for key, want := range map[string]string{"organization_id": f.o, "workspace_id": f.w, "environment_id": f.e, "export_id": item.id, "reference": item.id, "version": item.artifact.VersionID, "lane": "cleanup"} {
					if c[key] != want {
						t.Fatalf("cleanup claim changed exact scoped locator: %s=%v want %s", key, c[key], want)
					}
				}
				ref, err := domain.ParseEvidenceRef(c["reference"].(string))
				if err != nil {
					t.Fatal(err)
				}
				key, err := bucketlayout.ExportKey(item.artifact.Scope, ref.ArtifactID())
				if err != nil {
					t.Fatal(err)
				}
				locator := artifactstore.DriverLocator{Scope: item.artifact.Scope, Reference: ref, Key: key, VersionID: c["version"].(string)}
				transport := &exportStorageCleanupHTTP{t: t, driver: m.driver, locator: locator}
				client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://cleanup.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
				deletion, err := s3driver.NewExportCleanup(client, s3driver.Config{Bucket: "matrix-export-bucket", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
				if err != nil {
					t.Fatal(err)
				}
				var before string
				var pendingRetention bool
				if err := f.owner.QueryRow(f.ctx, `SELECT to_jsonb(j)::text,storage_state='delete_pending' AND retained_bytes>0 AND package IS NOT NULL FROM zasp_compliance_export_jobs j WHERE export_id=$1`, item.id).Scan(&before, &pendingRetention); err != nil || !pendingRetention {
					t.Fatalf("cleanup has no retained package to protect: %v %v", pendingRetention, err)
				}
				for _, fault := range []string{"denied", "generic404"} {
					transport.mode, transport.methods = fault, nil
					if err := deletion.DeleteExact(f.ctx, locator); !errors.Is(err, s3driver.ErrImmutable) {
						t.Fatalf("%s supplied false absence proof: %v", fault, err)
					}
					if strings.Join(transport.methods, ",") != "DELETE,GET" {
						t.Fatalf("%s cleanup protocol=%v", fault, transport.methods)
					}
					var after string
					if err := f.owner.QueryRow(f.ctx, `SELECT to_jsonb(j)::text FROM zasp_compliance_export_jobs j WHERE export_id=$1`, item.id).Scan(&after); err != nil || after != before {
						t.Fatalf("%s released accounting without typed absence: %v", fault, err)
					}
					var audits int
					if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_admin_audit WHERE target_id=$1 AND action='compliance.export.deleted'`, item.id).Scan(&audits); err != nil || audits != 0 {
						t.Fatalf("%s wrote deletion audit: %d %v", fault, audits, err)
					}
					t.Logf("cleanup %s: production DeleteExact rejected; exact job JSON and deletion audit unchanged; requests=%v", fault, transport.methods)
				}
				transport.mode, transport.methods = "typed_absent", nil
				if err := deletion.DeleteExact(f.ctx, locator); err != nil {
					t.Fatalf("typed exact-version absence refused: %v", err)
				}
				if strings.Join(transport.methods, ",") != "DELETE,GET" {
					t.Fatalf("typed absence cleanup protocol=%v", transport.methods)
				}
				payload := map[string]any{"outcome": "verified_absent", "reference": item.id, "version": item.artifact.VersionID}
				if err := cleaner.QueryRow(f.ctx, `SELECT zasp_compliance_export_cleanup($1,$2,$3,$4,'matrix-cleaner',$5,$6,$7,$8,$9)`, f.o, f.w, f.e, item.id, strings.Repeat("e", 64), int64(c["generation"].(float64)), payload, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var deleted bool
				if err := f.owner.QueryRow(f.ctx, `SELECT storage_state='deleted' AND retained_bytes=0 AND package IS NULL AND (SELECT count(*) FROM zasp_admin_audit WHERE target_id=$1 AND action='compliance.export.deleted')=1 FROM zasp_compliance_export_jobs WHERE export_id=$1`, item.id).Scan(&deleted); err != nil || !deleted {
					t.Fatalf("cleanup bookkeeping=%v %v", deleted, err)
				}
				t.Log("typed NoSuchVersion accepted by production DeleteExact; registered cleanup released retention and wrote one deletion audit")
				for _, survivor := range m.items[1:] {
					a, err := m.store.Get(f.ctx, survivor.artifact.Locator)
					if err != nil || !bytes.Equal(a.Body, survivor.artifact.Body) {
						t.Fatalf("cleanup touched sibling/foreign package: %v", err)
					}
					var retained bool
					if err := f.owner.QueryRow(f.ctx, `SELECT storage_state='verified' AND retained_bytes>0 AND package IS NOT NULL FROM zasp_compliance_export_jobs WHERE export_id=$1`, survivor.id).Scan(&retained); err != nil || !retained {
						t.Fatalf("cleanup touched sibling/foreign bookkeeping: %v %v", retained, err)
					}
				}
				if m.driver.deletes != 1 {
					t.Fatalf("cleanup performed %d deletes", m.driver.deletes)
				}
			})
		})
	}
}
