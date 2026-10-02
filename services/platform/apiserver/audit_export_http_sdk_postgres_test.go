//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// The worker's actual saved bytes/versions cross a private fixture-file boundary
// into a separate read-only provider. This is not one continuous S3 process,
// live AWS, or durable outbox acceptance. All job authority is real PostgreSQL.
func TestAuditExportHTTPPostWorkerSDKPagedGet(t *testing.T) {
	for _, release := range []struct {
		name    string
		version int64
	}{{"schema52", 52}, {"schema53", 53}, {"schema54", 54}} {
		t.Run(release.name, func(t *testing.T) {
			exerciseAuditExportHTTPPostWorker(t, release.version)
		})
	}
}

func exerciseAuditExportHTTPPostWorker(t *testing.T, version int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	if version >= 53 {
		if err := precisionMigrationRunner(t, f.admin).UpProductionSecurityAgentBudgets(ctx); err != nil {
			t.Fatal("upgrade completed export fixture to current schema53", err)
		}
	}
	if version == 54 {
		if err := precisionMigrationRunner(t, f.admin).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal("upgrade completed export fixture to schema54", err)
		}
	}
	var actual int64
	if err := f.admin.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&actual); err != nil || actual != version {
		t.Fatalf("completed export fixture schema=%d want=%d: %v", actual, version, err)
	}
	f.register(t, ctx)
	auditExportWorkerConnections(t, ctx, f)
	provider := newAuditExportHTTPReaderFixture(t, ctx, f.identity.Scope)
	server := auditExportHTTPRealServer(t, ctx, f, provider, time.Second)
	cookie, selected := "owned-audit-export-browser-fixture", f.identity.Scope
	invoke := func(t *testing.T, method, target string, want int) []byte {
		t.Helper()
		body := ""
		if method == http.MethodPost {
			body = "{}"
		}
		request, err := http.NewRequestWithContext(ctx, method, server.URL+target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://audit-export.invalid")
		request.Header.Set("X-CSRF-Token", f.identity.CSRFToken)
		request.Header.Set(expectedScopeHeader, expectedScopeValue(selected))
		request.Header.Set("Idempotency-Key", "audit-http-worker-sdk-key")
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: cookie})
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal("owned HTTP request", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, (audit.ExportMaximumChunkBytes+16384)+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(raw) > audit.ExportMaximumChunkBytes+16384 || response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("HTTP contract status=%d want=%d bytes=%d read=%v close=%v", response.StatusCode, want, len(raw), readErr, closeErr)
		}
		for _, forbidden := range []string{`"authority"`, `"object_reference"`, `"version_id"`, `"artifact_id"`, `"policy_id"`, "s3://", "arn:aws:", "owned-secret-never-exported"} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Fatal("public response exposed private authority or sensitive metadata")
			}
		}
		if want != http.StatusOK && want != http.StatusCreated {
			var failure struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(raw, &failure) != nil || failure.Code == "" || bytes.Contains(raw, []byte(`"contents"`)) {
				t.Fatal("invalid public refusal")
			}
			if want == http.StatusServiceUnavailable && failure.Code != "provider_unavailable" {
				t.Fatal("unstable provider refusal code", failure.Code)
			}
		}
		return raw
	}
	created := invoke(t, http.MethodPost, "/api/v1/audit-exports", http.StatusCreated)
	descriptor, err := audit.DecodeExportDescriptor(created)
	if err != nil || descriptor.Status != "queued" {
		t.Fatal("HTTP did not create durable queued job", err)
	}
	if !bytes.Equal(created, invoke(t, http.MethodPost, "/api/v1/audit-exports", http.StatusCreated)) {
		t.Fatal("HTTP 201 replay changed job")
	}
	args := f.createArgs()
	args[7] = descriptor.ID // Do not execute Create SQL or reuse its fixture IDs.
	basePath := "/api/v1/audit-exports/" + descriptor.ID
	var queued struct {
		Export   audit.ExportDescriptor `json:"export"`
		Contents json.RawMessage        `json:"contents"`
	}
	if json.Unmarshal(invoke(t, http.MethodGet, basePath, http.StatusOK), &queued) != nil || queued.Export.ID != descriptor.ID || string(queued.Contents) != "null" || provider.calls() != 0 {
		t.Fatal("queued HTTP fabricated contents or read S3")
	}
	var one bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_audit_export_jobs) AND (SELECT count(*)=1 FROM zasp_audit_export_idempotency) AND (SELECT count(*)=1 FROM zasp_audit_export_outbox) AND (SELECT count(*)=1 FROM zasp_admin_audit WHERE action='audit_export.request')`).Scan(&one); err != nil || !one {
		t.Fatal("POST/replay durable effects", err)
	}
	expected, fixturePath := auditExportPrepareWorkerSource(t, ctx, f, args)
	auditExportCaptureWorkerChild(t, ctx, f, args, fixturePath, "complete")
	auditExportAssertCompletedSDK(t, ctx, f, args, expected, fixturePath+".objects.json")
	provider.load(auditExportReadWorkerObjects(t, fixturePath+".objects.json"))
	binding := audit.ExportBinding{OrganizationID: descriptor.OrganizationID, WorkspaceID: descriptor.WorkspaceID, EnvironmentID: descriptor.EnvironmentID, ExportID: descriptor.ID}
	if err := f.admin.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&binding.CaptureID); err != nil {
		t.Fatal(err)
	}
	chunks, manifest := auditExportHTTPExpectedBytes(t, binding, expected)
	snapshot := func() string {
		t.Helper()
		var value string
		if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY kind,ordinal) FROM zasp_audit_export_intents i),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY kind,ordinal) FROM zasp_audit_export_receipts r),'completion',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM zasp_admin_audit a WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	assertPage := func(t *testing.T, raw []byte, ordinal int) string {
		t.Helper()
		var page struct {
			Export   json.RawMessage `json:"export"`
			Contents *struct {
				Manifest    json.RawMessage `json:"manifest"`
				Chunk       json.RawMessage `json:"chunk"`
				ChunkSHA256 string          `json:"chunk_sha256"`
				PageInfo    struct {
					Next *string `json:"next_cursor"`
					More bool    `json:"has_more"`
				} `json:"page_info"`
			} `json:"contents"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&page) != nil || decoder.Decode(&struct{}{}) != io.EOF || page.Contents == nil {
			t.Fatal("ready HTTP omitted verified public contents")
		}
		ready, err := audit.DecodeExportDescriptor(page.Export)
		wantManifest, _ := audit.DecodeExportManifest(manifest)
		manifestSum := sha256.Sum256(manifest)
		if err != nil || ready.Status != "ready" || ready.ID != descriptor.ID || ready.OrganizationID != binding.OrganizationID || ready.WorkspaceID != binding.WorkspaceID || ready.EnvironmentID != binding.EnvironmentID || ready.CreatedAt != descriptor.CreatedAt || ready.AuditCorrelationID != descriptor.AuditCorrelationID || ready.EventCount == nil || *ready.EventCount != 1006 || ready.ChunkCount == nil || *ready.ChunkCount != 2 || ready.ChunkBytes == nil || *ready.ChunkBytes != wantManifest.ChunkBytes || ready.ManifestSHA256 != hex.EncodeToString(manifestSum[:]) {
			t.Fatal("public ready descriptor differs from original job and independent bytes", err)
		}
		chunk, err := audit.DecodeExportChunk(page.Contents.Chunk)
		if err != nil || chunk.Ordinal != int64(ordinal) || !bytes.Equal(page.Contents.Chunk, chunks[ordinal-1]) || !bytes.Equal(page.Contents.Manifest, manifest) {
			t.Fatal("HTTP changed exact independent chunk/manifest bytes", ordinal, err)
		}
		sum := sha256.Sum256(chunks[ordinal-1])
		if page.Contents.ChunkSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("HTTP chunk digest changed")
		}
		if ordinal == 1 {
			if !page.Contents.PageInfo.More || page.Contents.PageInfo.Next == nil || *page.Contents.PageInfo.Next == "" {
				t.Fatal("missing bound next cursor")
			}
			return *page.Contents.PageInfo.Next
		}
		if page.Contents.PageInfo.More || page.Contents.PageInfo.Next != nil {
			t.Fatal("terminal HTTP page invented cursor")
		}
		return ""
	}
	cursor := assertPage(t, invoke(t, http.MethodGet, basePath, http.StatusOK), 1)
	nextPath := basePath + "?cursor=" + url.QueryEscape(cursor)
	if provider.calls() != 4 {
		t.Fatal("first page did not read manifest/chunk pinned HEAD and GET", provider.calls())
	}
	// Recreate the actual API composition and SDK client. The signing key and SQL
	// state survive; no private in-memory cursor state crosses this boundary.
	server.Client().CloseIdleConnections()
	server.Close()
	provider.closeIdle()
	server = auditExportHTTPRealServer(t, ctx, f, provider, time.Second)
	exec := func(statement string, values ...any) {
		t.Helper()
		if _, err := f.admin.Exec(ctx, statement, values...); err != nil {
			t.Fatal("owned fixture mutation", err)
		}
	}
	exec(`UPDATE zasp_admin_audit SET target_id='changed after capture' WHERE id='pid_53000000-0000-4000-8000-000000000001'`)
	exec(`DELETE FROM zasp_admin_audit WHERE id='pid_53000000-0000-4000-8000-000000000002'`)
	exec(`INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,'pid_55000001-0000-4000-8000-000000000001',$4,'late.source','excluded late row','succeeded','{}','2020-01-01T00:00:00Z')`, args[0], args[1], args[2], args[3])
	exec(`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '1 hour' WHERE token_digest=$1`, f.digest[:])
	assertPage(t, invoke(t, http.MethodGet, nextPath, http.StatusOK), 2)
	assertPage(t, invoke(t, http.MethodGet, basePath, http.StatusOK), 1)
	noProvider := func(method, target string, status int) {
		t.Helper()
		count := provider.calls()
		invoke(t, method, target, status)
		if provider.calls() != count {
			t.Fatal("refused auth/cursor reached S3")
		}
	}
	noProvider(http.MethodPost, "/api/v1/audit-exports", http.StatusForbidden)
	exec(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
	noProvider(http.MethodGet, nextPath, http.StatusForbidden)
	exec(`UPDATE zasp_identity_memberships SET role='security_admin' WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
	assertPage(t, invoke(t, http.MethodGet, nextPath, http.StatusOK), 2)
	noProvider(http.MethodGet, "/api/v1/audit-exports/pid_55000002-0000-4000-8000-000000000002?cursor="+url.QueryEscape(cursor), http.StatusNotFound)
	workspace, environment := "pid_52000021-0000-4000-8000-000000000021", "pid_52000022-0000-4000-8000-000000000022"
	w, _ := domain.ParseProductID(workspace)
	e, _ := domain.ParseProductID(environment)
	selected, err = domain.NewScope(f.identity.Scope.OrganizationID(), w, e)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO zasp_authorized_scopes(organization_id,principal_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Owned second selected scope','["view_audit"]')`, args[0], args[3], workspace, environment)
	exec(`UPDATE zasp_product_sessions SET workspace_id=$2,environment_id=$3 WHERE token_digest=$1`, f.digest[:], workspace, environment)
	noProvider(http.MethodGet, nextPath, http.StatusNotFound)
	assertPage(t, invoke(t, http.MethodGet, basePath, http.StatusOK), 1)
	exec(`UPDATE zasp_product_sessions SET workspace_id=$2,environment_id=$3 WHERE token_digest=$1`, f.digest[:], args[1], args[2])
	selected = f.identity.Scope
	secondPrincipal := "pid_55000003-0000-4000-8000-000000000003"
	secondCookie := "owned-second-audit-http-browser-fixture"
	secondDigest := sha256.Sum256([]byte(secondCookie))
	exec(`INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role) VALUES($1,$2,'sandbox-org','audit-http-second-member','security_admin')`, args[0], secondPrincipal)
	exec(`INSERT INTO zasp_authorized_scopes(organization_id,principal_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Owned second principal scope','["view_audit"]')`, args[0], secondPrincipal, args[1], args[2])
	exec(`INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($1,$2,$3,$4,$5,'["view_audit"]',$6,clock_timestamp()+interval '1 hour',clock_timestamp())`, secondDigest[:], secondPrincipal, args[0], args[1], args[2], f.identity.CSRFToken)
	cookie = secondCookie
	assertPage(t, invoke(t, http.MethodGet, basePath, http.StatusOK), 1)
	noProvider(http.MethodGet, nextPath, http.StatusNotFound)
	cookie = "owned-audit-export-browser-fixture"
	for _, fault := range []string{"missing version", "returned version", "kms", "scope metadata", "checksum mismatch", "coherent corruption", "coherent manifest", "timeout"} {
		t.Run(fault, func(t *testing.T) {
			done := provider.setFault(fault)
			target, ordinal := nextPath, 2
			if fault == "coherent manifest" {
				target, ordinal = basePath, 1
			}
			invoke(t, http.MethodGet, target, http.StatusServiceUnavailable)
			provider.assertFault(t, fault, chunks[1], manifest)
			if fault == "timeout" {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("owned timeout handler did not join")
				}
			}
			provider.setFault("")
			assertPage(t, invoke(t, http.MethodGet, target, http.StatusOK), ordinal)
			if snapshot() != before {
				t.Fatal("provider refusal/recovery changed ready authority")
			}
		})
	}
	exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:])
	noProvider(http.MethodGet, nextPath, http.StatusUnauthorized)
	if snapshot() != before {
		t.Fatal("HTTP retrieval mutated durable export completion")
	}
	provider.assertClean(t)
	if t.Failed() {
		return
	}
	t.Log("authenticated HTTP export through registered PostgreSQL and owned SDK bytes proven: events=1006 chunks=2; seeded wakeup; no live AWS or durable outbox claim")
}

func auditExportHTTPExpectedBytes(t *testing.T, binding audit.ExportBinding, events []json.RawMessage) ([][]byte, []byte) {
	t.Helper()
	var chunks [][]byte
	previous, total := audit.ExportZeroDigest, int64(0)
	for ordinal := 1; ordinal <= 2; ordinal++ {
		first, last := (ordinal-1)*1000, min(ordinal*1000, len(events))
		chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: int64(ordinal), FirstEvent: int64(first + 1), EventCount: int64(last - first), PreviousDigest: previous}
		for _, raw := range events[first:last] {
			event, err := audit.DecodeExportEvent(raw)
			if err != nil {
				t.Fatal(err)
			}
			chunk.Events = append(chunk.Events, event)
		}
		body, err := audit.EncodeExportChunk(chunk)
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, body)
		total += int64(len(body))
		sum := sha256.Sum256(body)
		previous = hex.EncodeToString(sum[:])
	}
	manifest, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 1006, ChunkCount: 2, ChunkBytes: total, ChainRoot: previous})
	if err != nil {
		t.Fatal(err)
	}
	return chunks, manifest
}

type auditExportHTTPReaderFixture struct {
	mu            sync.Mutex
	objects       map[string]auditExportCapturedObject
	fault         string
	done          chan struct{}
	count         int
	failure       string
	faultReads    []string
	corruptBodies [][]byte
	server        *httptest.Server
	clients       []*http.Client
}

func newAuditExportHTTPReaderFixture(t *testing.T, parent context.Context, scope domain.Scope) *auditExportHTTPReaderFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	fixture := &auditExportHTTPReaderFixture{objects: map[string]auditExportCapturedObject{}}
	policy := auditExportTestPolicy()
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.count++
		fault, done := fixture.fault, fixture.done
		ref := "s3://" + strings.TrimPrefix(r.URL.Path, "/")
		object, ok := fixture.objects[ref]
		query := r.URL.Query()
		queryOK := len(query["versionId"]) == 1 && (r.Method == http.MethodHead && len(query) == 1 || r.Method == http.MethodGet && len(query) == 2 && len(query["x-id"]) == 1 && query.Get("x-id") == "GetObject")
		valid := ok && strings.HasPrefix(r.URL.Path, "/"+policy.Bucket+"/organizations/"+scope.OrganizationID().String()+"/workspaces/"+scope.WorkspaceID().String()+"/environments/"+scope.EnvironmentID().String()+"/exports/") && queryOK && query.Get("versionId") == object.Version && r.Header.Get("X-Amz-Expected-Bucket-Owner") == policy.ExpectedBucketOwner && r.Header.Get("X-Amz-Checksum-Mode") == "ENABLED" && strings.Contains(r.Header.Get("Authorization"), "Credential=OWNEDREADERFIXTURE/")
		if !valid {
			fixture.failure = "unexpected unpinned, unsigned or mutating reader request"
		}
		if fault != "" {
			fixture.faultReads = append(fixture.faultReads, r.Method+" "+object.Version)
		}
		fixture.mu.Unlock()
		if !valid {
			http.Error(w, "owned reader refused", http.StatusBadRequest)
			return
		}
		chunk, chunkErr := audit.DecodeExportChunk(object.Body)
		if (fault == "missing version" || fault == "coherent corruption") && (chunkErr != nil || chunk.Ordinal != 2) {
			fault = "" // The manifest must complete before a selected-chunk fault.
		}
		if fault == "coherent manifest" && chunkErr == nil {
			fault = ""
		}
		if fault == "timeout" {
			defer close(done)
			select {
			case <-r.Context().Done():
			case <-ctx.Done():
			}
			return
		}
		if fault == "missing version" {
			http.Error(w, "owned missing version", http.StatusNotFound)
			return
		}
		body := bytes.Clone(object.Body)
		sum := sha256.Sum256(body)
		if fault == "checksum mismatch" && r.Method == http.MethodGet {
			body[0] = '!'
		}
		if fault == "coherent corruption" {
			chunk.Events[0].TargetID = "OWNED snapshot source"
			body, chunkErr = audit.EncodeExportChunk(chunk)
		}
		if fault == "coherent manifest" {
			var manifest audit.ExportManifest
			manifest, chunkErr = audit.DecodeExportManifest(object.Body)
			if chunkErr == nil {
				last := "0"
				if strings.HasSuffix(manifest.ChainRoot, last) {
					last = "1"
				}
				manifest.ChainRoot = manifest.ChainRoot[:63] + last
				body, chunkErr = audit.EncodeExportManifest(manifest)
			}
		}
		if fault == "coherent corruption" || fault == "coherent manifest" {
			if chunkErr != nil || len(body) != len(object.Body) || bytes.Equal(body, object.Body) {
				fixture.mu.Lock()
				fixture.failure = "coherent fixture must change valid same-length bytes"
				fixture.mu.Unlock()
				http.Error(w, "owned corruption fixture invalid", http.StatusInternalServerError)
				return
			}
			sum = sha256.Sum256(body)
			fixture.mu.Lock()
			fixture.corruptBodies = append(fixture.corruptBodies, bytes.Clone(body))
			fixture.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("X-Amz-Version-Id", object.Version)
		w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
		w.Header().Set("X-Amz-Server-Side-Encryption", "aws:kms")
		w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", policy.KMSKeyARN)
		for key, value := range map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "artifact_id": path.Base(r.URL.Path), "media_type": "application/json", "sha256": hex.EncodeToString(sum[:])} {
			w.Header().Set("X-Amz-Meta-"+key, value)
		}
		switch fault {
		case "returned version":
			w.Header().Set("X-Amz-Version-Id", "wrong-owned-version")
		case "kms":
			w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "wrong-owned-key")
		case "scope metadata":
			w.Header().Set("X-Amz-Meta-Organization_id", "pid_55000009-0000-4000-8000-000000000009")
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(func() { cancel(); fixture.server.Close(); fixture.closeIdle() })
	return fixture
}

func (f *auditExportHTTPReaderFixture) load(objects map[string]auditExportCapturedObject) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, object := range objects {
		f.objects[key] = auditExportCapturedObject{Body: bytes.Clone(object.Body), Version: object.Version}
	}
}
func (f *auditExportHTTPReaderFixture) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return f.count }
func (f *auditExportHTTPReaderFixture) setFault(value string) <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = value
	f.faultReads = nil
	f.corruptBodies = nil
	f.done = make(chan struct{})
	return f.done
}

func (f *auditExportHTTPReaderFixture) assertFault(t *testing.T, fault string, expectedChunk, expectedManifest []byte) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if fault == "coherent corruption" || fault == "coherent manifest" {
		if len(f.corruptBodies) != 2 {
			t.Fatal("coherent corruption did not serve both HEAD and GET")
		}
		for _, body := range f.corruptBodies {
			original := expectedChunk
			if fault == "coherent manifest" {
				original = expectedManifest
				if _, err := audit.DecodeExportManifest(body); err != nil {
					t.Fatal("coherent manifest is not canonical codec output", err)
				}
			} else {
				if chunk, err := audit.DecodeExportChunk(body); err != nil || chunk.Ordinal != 2 {
					t.Fatal("coherent selected chunk is not canonical codec output", err)
				}
			}
			if len(body) != len(original) || bytes.Equal(body, original) {
				t.Fatal("coherent corruption did not change same-length canonical bytes")
			}
		}
	}
	if fault == "missing version" || fault == "coherent corruption" {
		want := []string{"HEAD owned-TLS-version-3", "GET owned-TLS-version-3", "HEAD owned-TLS-version-2"}
		if fault == "coherent corruption" {
			want = append(want, "GET owned-TLS-version-2")
		}
		if !slices.Equal(f.faultReads, want) {
			t.Fatal("selected-chunk fault did not follow successful manifest read", f.faultReads)
		}
	}
}
func (f *auditExportHTTPReaderFixture) closeIdle() {
	f.mu.Lock()
	clients := append([]*http.Client(nil), f.clients...)
	f.mu.Unlock()
	for _, client := range clients {
		client.CloseIdleConnections()
	}
}
func (f *auditExportHTTPReaderFixture) assertClean(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != "" {
		t.Fatal(f.failure)
	}
}

func auditExportHTTPRealServer(t *testing.T, ctx context.Context, f auditExportPG, provider *auditExportHTTPReaderFixture, timeout time.Duration) *httptest.Server {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	identityRepository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: provider.server.Client().Transport.(*http.Transport).Clone(), Timeout: 2 * time.Second}
	provider.mu.Lock()
	provider.clients = append(provider.clients, client)
	provider.mu.Unlock()
	policy := auditExportTestPolicy()
	sdk := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(provider.server.URL), UsePathStyle: true, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "OWNEDREADERFIXTURE", SecretAccessKey: "owned-reader-secret-not-real"}, nil
	}), HTTPClient: client, RetryMaxAttempts: 1})
	handler, err := NewAuditExportProductionHandler(ctx, database, AuditExportHandlerConfiguration{Storage: []AuditExportStorageConfiguration{{Policy: policy, Client: sdk}}, CursorSigningKey: []byte(strings.Repeat("h", 32)), ProviderTimeout: timeout})
	if err != nil {
		t.Fatal("actual HTTP factory", err)
	}
	router, err := NewCompositionWithAuditExports(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")}, handler)
	if err != nil {
		t.Fatal(err)
	}
	secured, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://audit-export.invalid", MaximumBodyBytes: 1024, Authenticate: identityRepository.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(secured)
	server.Client().Timeout = 5 * time.Second
	t.Cleanup(func() { server.Close(); server.Client().CloseIdleConnections() })
	return server
}
