//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

func auditHTTPSizePhase(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < budget+20*time.Second {
		return nil, nil, errors.New("phase cannot fit with cleanup margin")
	}
	c, cancel := context.WithTimeout(ctx, budget)
	return c, cancel, nil
}

func runAuditHTTPSizeWorker(ctx context.Context, binary, dsn, mode, address, ca, token, control string) (auditHTTPSizeChildResult, error) {
	result := auditHTTPSizeChildResult{Mode: mode}
	if control != "" && control != "diagnostics" && (control != "worker-retain" || mode != "audit-export") || mode != "audit-export" && mode != "audit-export-outbox" {
		return result, errors.New("invalid worker control/mode")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 20*time.Second {
		return result, errors.New("worker deadline admission")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer r.Close()
	cmd := exec.Command(binary, "-test.run=^TestAuditHTTPSizeWorkerProcess$", "-test.v", "-test.count=1", "-test.timeout=9m")
	cmd.Env = append(auditHTTPSizeEnvironment(), "ZASP_AUDIT_HTTP_SIZE_DSN="+dsn, "ZASP_AUDIT_HTTP_SIZE_MODE="+mode, "ZASP_AUDIT_HTTP_SIZE_ADDRESS="+address, "ZASP_AUDIT_HTTP_SIZE_CA="+ca, "ZASP_AUDIT_HTTP_SIZE_TOKEN="+token, "ZASP_AUDIT_HTTP_SIZE_CONTROL="+control, "ZASP_AUDIT_HTTP_SIZE_DEADLINE="+deadline.Format(time.RFC3339Nano))
	cmd.ExtraFiles = []*os.File{w}
	output, runErr := testprocess.Run(ctx, cmd)
	closeErr := w.Close()
	result.Output = output
	if runErr != nil {
		return result, errors.Join(runErr, closeErr)
	}
	result.Joined = true
	if cmd.Process != nil {
		result.PID = cmd.Process.Pid
	}
	record, recordErr := auditHTTPSizeReadTerminal(r, mode)
	err = errors.Join(runErr, closeErr, recordErr)
	if record.PID != result.PID || cmd.ProcessState == nil || !cmd.ProcessState.Success() || bytes.Contains(output, []byte("--- SKIP:")) {
		err = errors.Join(err, fmt.Errorf("worker terminal refused: %s", output))
	}
	if err == nil {
		result.PeakRSSBytes, err = auditHTTPSizePeak(cmd.ProcessState)
		result.RetainedBytes, result.SelfRSSBytes = record.RetainedBytes, record.SelfRSSBytes
		if result.SelfRSSBytes > result.PeakRSSBytes {
			err = errors.New("worker self RSS exceeds kernel final peak")
		}
	}
	return result, err
}

func auditHTTPSizeDSN(t *testing.T, f auditExportPG, login string) string {
	t.Helper()
	u, err := url.Parse(f.admin.Config().ConnString())
	if err != nil || u.Scheme != "postgres" {
		t.Fatal("closed fixture DSN")
	}
	u.User = url.User(login)
	return u.String()
}

func TestAuditHTTPSizeProcessCompositionPostgres(t *testing.T) {
	root, binaries, retain := auditHTTPSizeBuildChildren(t, "race")
	for _, empty := range []bool{false, true} {
		name := "small"
		if empty {
			name = "controlled-zero-source"
		}
		t.Run(name, func(t *testing.T) {
			auditHTTPSizeCompositionCase(t, binaries, root, auditHTTPSizeFixture{Rows: 1000, Empty: empty}, retain)
		})
	}
}

func auditHTTPSizeBuildChildren(t *testing.T, mode string) (string, map[string]string, *bool) {
	t.Helper()
	if mode != "" && mode != "race" {
		t.Fatal("invalid parent build mode")
	}
	for _, name := range []string{"initdb", "postgres", "pg_ctl", "pg_isready", "node"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("required owned fixture executable absent", name)
		}
	}
	root, err := os.MkdirTemp("", "zasp-audit-http-composition-")
	if err != nil {
		t.Fatal(err)
	}
	retain := false
	t.Cleanup(func() {
		if retain {
			t.Log("retaining uncertain owned root", root)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	binaries := map[string]string{}
	for _, target := range []string{"apiserver", "agentsec-worker"} {
		started := time.Now()
		binary := filepath.Join(root, target+"."+mode+".test")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		toolchain, err := auditHTTPSizeToolchain(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		flags := []string{"test", "-c", "-o", binary, "../" + target}
		if mode == "race" {
			flags = append([]string{"test", "-race"}, flags[1:]...)
		}
		cmd := exec.Command(toolchain, flags...)
		cmd.Env = auditHTTPSizeBuildEnvironment()
		output, err := testprocess.Run(ctx, cmd)
		cancel()
		if err != nil {
			retain = true
			t.Fatalf("bounded explicit build: %v\n%s", err, output)
		}
		if err := auditHTTPSizeVerifyBinary(binary, mode); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		t.Logf("explicit mode=%q toolchain=%s flags=%q binary=%s sha256=%x build_elapsed=%s GOGC=100 GOMEMLIMIT=off GOMAXPROCS=2", mode, toolchain, flags, binary, sum, time.Since(started))
		binaries[target] = binary
	}
	return root, binaries, &retain
}

type auditHTTPSizeFixture struct {
	Rows           int
	Empty          bool
	Control        string
	Diagnostics    bool
	OrderlyRestart bool
}
type auditHTTPSizeCaseResult struct {
	API, Publisher, Executor auditHTTPSizeChildResult
	APIA, Replay             auditHTTPSizeChildResult
	Summary                  auditHTTPSizeSummary
}

func auditHTTPSizeCompositionCase(t *testing.T, binaries map[string]string, root string, fixture auditHTTPSizeFixture, retain *bool) auditHTTPSizeCaseResult {
	if fixture.Rows != 1000 && fixture.Rows != 100001 || fixture.Control != "" && fixture.Control != "api-retain" && fixture.Control != "worker-retain" || fixture.Diagnostics && fixture.Control != "" || fixture.OrderlyRestart && (fixture.Rows != 100001 || fixture.Empty || fixture.Control != "" || fixture.Diagnostics) {
		t.Fatal("invalid trusted fixture configuration")
	}
	empty := fixture.Empty
	var caseResult auditHTTPSizeCaseResult
	fixtureStarted := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	ctx, owner := newAuditHTTPFixtureOwner(t, ctx, root, func() { *retain = true })
	owner.startPostgres = func(t *testing.T, ctx context.Context, username string) string {
		return auditHTTPSizeStartPostgres(t, ctx, owner, username)
	}
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	args := f.createArgs()
	if !empty {
		if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT $1,'pid_53000001-0000-4000-8000-000000000001','pid_53000002-0000-4000-8000-000000000002','pid_53000000-0000-4000-8000-'||lpad(n::text,12,'0'),$2,'integration.webhook','large-fixture','succeeded',jsonb_build_object('payload',repeat('x',512),'counter',n),'2099-01-01T00:00:00Z'::timestamptz FROM generate_series(1,$3::integer)n`, args[0], args[3], fixture.Rows); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES('pid_54000001-0000-4000-8000-000000000001','pid_54000002-0000-4000-8000-000000000002','pid_54000003-0000-4000-8000-000000000003','pid_54000004-0000-4000-8000-000000000004',$1,'foreign.scope','excluded','succeeded','{}')`, args[3]); err != nil {
		t.Fatal(err)
	}
	bridge := newAuditHTTPSizeBridge(ctx)
	var providerCalls atomic.Int64
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { providerCalls.Add(1); bridge.ServeHTTP(w, r) }))
	var api *auditHTTPSizeAPIChild
	var provider *auditHTTPSizeProvider
	var oracles []*auditHTTPSizeExpected
	var apiResult auditHTTPSizeChildResult
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("HTTP redirect refused") }}
	owner.processes = append(owner.processes, auditHTTPFixtureClose{"API child", func(cleanup context.Context) error {
		client.CloseIdleConnections()
		if api == nil {
			return nil
		}
		if api.stopped {
			return errors.New("active API already stopped; ownership unproven")
		}
		var err error
		apiResult, err = api.Stop(cleanup)
		if !api.joined {
			return errors.Join(err, errors.New("API join unproven"))
		}
		return err
	}})
	owner.handlers = append(owner.handlers, auditHTTPFixtureClose{"continuous provider handlers", func(cleanup context.Context) error {
		_ = front.Listener.Close() // stop admission before cancellation/join
		err := bridge.Close(cleanup)
		if provider != nil {
			err = errors.Join(err, provider.Close(cleanup))
		}
		if err != nil {
			return err
		}
		if err := auditHTTPSizeShutdownServer(cleanup, front.Config); err != nil {
			return err
		}
		front.Close()
		return nil
	}})
	caPath := filepath.Join(owner.root, "provider.ca.pem")
	tokenPath := caPath + ".token"
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(auditExportProcessToken), 0600); err != nil {
		t.Fatal(err)
	}
	auditHTTPSizePartialFactoryCleanup(t, ctx, f, front.Listener.Addr().String(), caPath)
	var err error
	apiStarted := time.Now()
	apiControl := ""
	if fixture.Control == "api-retain" {
		apiControl = fixture.Control
	}
	if fixture.Diagnostics {
		apiControl = "diagnostics"
	}
	api, err = startAuditHTTPSizeAPI(ctx, binaries["apiserver"], auditHTTPSizeDSN(t, f, "invocation_discovery_api"), front.Listener.Addr().String(), caPath, apiControl)
	if err != nil {
		t.Fatal("actual API child unavailable", err)
	}
	t.Logf("API readiness elapsed=%s (PID still unverified until runner joins)", time.Since(apiStarted))
	invoke := func(parent context.Context, method, target string, status int) []byte {
		requestCtx, stop := context.WithTimeout(parent, 10*time.Second)
		defer stop()
		body := ""
		if method == http.MethodPost {
			body = "{}"
		}
		request, err := http.NewRequestWithContext(requestCtx, method, api.URL()+target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://audit-export.invalid")
		request.Header.Set("X-CSRF-Token", f.identity.CSRFToken)
		request.Header.Set(expectedScopeHeader, expectedScopeValue(f.identity.Scope))
		request.Header.Set("Idempotency-Key", "audit-http-size-process-key")
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-export-browser-fixture"})
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, audit.ExportMaximumChunkBytes+16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(raw) > audit.ExportMaximumChunkBytes+16384 || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("HTTP contract status=%d want=%d bytes=%d read=%v close=%v", response.StatusCode, status, len(raw), readErr, closeErr)
		}
		for _, secret := range []string{`"authority"`, `"object_reference"`, `"version_id"`, `"artifact_id"`, `"policy_id"`, "s3://", "arn:aws:", "owned-secret"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("private authority in public response")
			}
		}
		return raw
	}
	created := invoke(ctx, http.MethodPost, "/api/v1/audit-exports", 201)
	descriptor, err := audit.DecodeExportDescriptor(created)
	if err != nil || descriptor.Status != "queued" || descriptor.OrganizationID != args[0] || descriptor.WorkspaceID != args[1] || descriptor.EnvironmentID != args[2] || descriptor.EventCount != nil {
		t.Fatal("queued descriptor mismatch", err)
	}
	if !bytes.Equal(created, invoke(ctx, http.MethodPost, "/api/v1/audit-exports", 201)) {
		t.Fatal("idempotent POST differs")
	}
	var requestedAt time.Time
	var requestAuditID string
	if err := f.admin.QueryRow(ctx, `SELECT requested_at,audit_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], descriptor.ID).Scan(&requestedAt, &requestAuditID); err != nil {
		t.Fatal(err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, descriptor.CreatedAt)
	if err != nil || !createdAt.Equal(requestedAt) || descriptor.AuditCorrelationID != requestAuditID {
		t.Fatal("POST descriptor timestamp/correlation differs from durable job", err)
	}
	args[7] = descriptor.ID
	target := "/api/v1/audit-exports/" + descriptor.ID
	var queued struct {
		Export   json.RawMessage `json:"export"`
		Contents json.RawMessage `json:"contents"`
	}
	if auditHTTPSizeDecode(invoke(ctx, http.MethodGet, target, 200), &queued) != nil || !bytes.Equal(queued.Export, bytes.TrimSpace(created)) || string(queued.Contents) != "null" {
		t.Fatal("queued GET fabricated contents")
	}
	earlyCalls := providerCalls.Load()
	if earlyCalls != 0 {
		t.Fatal("API called uninstalled provider")
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_audit_export_jobs) AND (SELECT count(*)=1 FROM zasp_audit_export_idempotency) AND (SELECT count(*)=1 FROM zasp_audit_export_outbox) AND (SELECT count(*)=1 FROM zasp_admin_audit WHERE action='audit_export.request') AND (SELECT count(*)=0 FROM zasp_audit_export_receipts) AND (SELECT count(*)=0 FROM zasp_admin_audit WHERE action='audit_export.complete')`).Scan(&exact); err != nil || !exact {
		t.Fatal("durable POST/replay effects", err)
	}
	if empty {
		var only bool
		if err := f.admin.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(action='audit_export.request' AND id=$2 AND target_id=$3) FROM zasp_admin_audit WHERE organization_id=$1`, args[0], descriptor.AuditCorrelationID, descriptor.ID).Scan(&only); err != nil || !only {
			t.Fatal("zero control request is not sole source", err)
		}
		tag, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1 AND id=$2 AND action='audit_export.request' AND target_id=$3`, args[0], descriptor.AuditCorrelationID, descriptor.ID)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("owned request-audit deletion", err)
		}
		var count int64
		if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1)+(SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1)+(SELECT count(*) FROM zasp_red_team_audit WHERE organization_id=$1)`, args[0]).Scan(&count); err != nil || count != 0 {
			t.Fatal("source union not zero", err)
		}
		t.Log("controlled zero deletes only owned POST request audit; normal production POST is not naturally empty")
	}
	connect := func() *pgx.Conn {
		conn, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		auditHTTPFixtureOwnConnection(ctx, "oracle/provider observer", conn)
		return conn
	}
	for range 2 {
		e, err := newAuditHTTPSizeExpected(ctx, connect(), args[0].(string))
		if err != nil {
			t.Fatal(err)
		}
		oracles = append(oracles, e)
		owner.resources = append(owner.resources, auditHTTPFixtureClose{"original-source oracle", e.Close})
	}
	provider, err = newAuditHTTPSizeProvider(ctx, connect(), auditExportTestPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Bind(args, oracles[0]); err != nil {
		t.Fatal(err)
	}
	process := newAuditExportProcessProviderWithPolicy(t, ctx, f, worker, args, nil, auditExportTestPolicy(), provider)
	if err := bridge.Install(http.HandlerFunc(process.serve)); err != nil {
		t.Fatal(err)
	}
	pids := map[int]bool{os.Getpid(): true}
	for _, mode := range []string{"audit-export-outbox", "audit-export"} {
		login, budget := "audit_export_outbox_fixture", 90*time.Second
		if mode == "audit-export" {
			login, budget = "audit_export_worker_fixture", 8*time.Minute
		}
		phase, stop, err := auditHTTPSizePhase(ctx, budget)
		if err != nil {
			t.Fatal(err)
		}
		workerStarted := time.Now()
		workerControl := ""
		if fixture.Control == "worker-retain" && mode == "audit-export" {
			workerControl = fixture.Control
		}
		if fixture.Diagnostics {
			workerControl = "diagnostics"
		}
		r, err := runAuditHTTPSizeWorker(phase, binaries["agentsec-worker"], auditHTTPSizeDSN(t, f, login), mode, front.Listener.Addr().String(), caPath, tokenPath, workerControl)
		stop()
		if err != nil {
			if !r.Joined {
				owner.retained = errors.Join(owner.retained, errors.New("worker runner join unproven"))
			}
			t.Logf("failure-only continuous-provider refusal: %v", provider.Check())
			t.Logf("failure-only queue receipt evidence: %s", process.queueReceiptSnapshot())
			t.Fatalf("actual worker path unavailable: %v\n%s", err, r.Output)
		}
		if r.PID == api.ready.PID || pids[r.PID] {
			t.Fatal("child PID not distinct")
		}
		pids[r.PID] = true
		t.Logf("joined child pid=%d mode=%s peakRSS=%d retained=%d selfRSS=%d elapsed=%s budget=%s cleanup_reserve=20s\n%s", r.PID, r.Mode, r.PeakRSSBytes, r.RetainedBytes, r.SelfRSSBytes, time.Since(workerStarted), budget, r.Output)
		if mode == "audit-export-outbox" {
			caseResult.Publisher = r
		} else {
			caseResult.Executor = r
		}
		if mode == "audit-export-outbox" {
			process.mu.Lock()
			sends := process.sends
			messages := len(process.messages)
			messageID := ""
			if messages == 1 {
				messageID = process.messages[0].ID
			}
			failure := process.failure
			process.mu.Unlock()
			if sends != 1 || messages != 1 || failure != "" {
				t.Fatal("canonical actual publication missing", failure)
			}
			auditExportAssertProcessPublication(t, ctx, f, args, messageID, 1)
			if err := f.admin.QueryRow(ctx, `SELECT status='queued' AND attempt=0 AND NOT captured AND completion_audit_id IS NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&exact); err != nil || !exact {
				t.Fatal("publisher captured job", err)
			}
		}
	}
	if err := provider.Check(); err != nil {
		t.Fatal(err)
	}
	process.mu.Lock()
	deletes, failure := process.deletes, process.failure
	authorities := process.assumes["outbox"] == 1 && process.assumes["worker"] == 1 && process.identities["outbox"] >= 1 && process.identities["worker"] >= 1 && process.receives == 1 && process.deleteAttempts == 1 && len(process.messages) == 1 && process.messages[0].Deliveries == 1 && process.messages[0].Deleted
	process.mu.Unlock()
	if deletes != 1 || failure != "" || !authorities {
		t.Fatal("registered ready-before-ACK missing", failure)
	}
	t.Logf("successful first-delivery queue receipt evidence: %s", process.queueReceiptSnapshot())
	binding := audit.ExportBinding{OrganizationID: descriptor.OrganizationID, WorkspaceID: descriptor.WorkspaceID, EnvironmentID: descriptor.EnvironmentID, ExportID: descriptor.ID}
	var capturedAt time.Time
	if err := f.admin.QueryRow(ctx, `SELECT capture_id,captured_at FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&binding.CaptureID, &capturedAt); err != nil {
		t.Fatal(err)
	}
	before := auditHTTPSizeSQLDigest(t, ctx, f, args)
	var inventory auditHTTPOrderlyInventory
	var savedMessage *auditExportProcessMessage
	var savedMessageHash [32]byte
	var savedMessageID string
	var firstACK time.Time
	if fixture.OrderlyRestart {
		inventory = auditHTTPOrderlyInventorySnapshot(t, ctx, provider)
		process.mu.Lock()
		savedMessage = process.messages[0]
		savedMessageHash, savedMessageID, firstACK = sha256.Sum256(savedMessage.Body), savedMessage.ID, savedMessage.AcknowledgedAt
		process.mu.Unlock()
	}
	restarted, membershipChecked := false, false
	traverse := func() auditHTTPSizeSummary {
		started := time.Now()
		defer func() { t.Logf("complete traversal elapsed=%s budget=3m", time.Since(started)) }()
		phase, stop, err := auditHTTPSizePhase(ctx, 3*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		e := oracles[1]
		if err := e.Reset(phase, binding); err != nil {
			t.Fatal(err)
		}
		cursor := ""
		ordinal := int64(1)
		var savedManifest []byte
		var pendingPage []byte
		for {
			path := target
			if cursor != "" {
				path += "?cursor=" + url.QueryEscape(cursor)
			}
			raw := pendingPage
			pendingPage = nil
			if raw == nil {
				raw = invoke(phase, http.MethodGet, path, 200)
			}
			var page struct {
				Export   json.RawMessage `json:"export"`
				Contents *struct {
					Manifest json.RawMessage `json:"manifest"`
					Chunk    json.RawMessage `json:"chunk"`
					SHA      string          `json:"chunk_sha256"`
					Page     struct {
						Next *string `json:"next_cursor"`
						More bool    `json:"has_more"`
					} `json:"page_info"`
				} `json:"contents"`
			}
			if auditHTTPSizeDecode(raw, &page) != nil || page.Contents == nil {
				t.Fatal("closed ready page")
			}
			contents := page.Contents
			ready, err := audit.DecodeExportDescriptor(page.Export)
			manifest, mErr := audit.DecodeExportManifest(contents.Manifest)
			if err != nil || mErr != nil || ready.Status != "ready" || ready.ID != descriptor.ID || ready.OrganizationID != descriptor.OrganizationID || ready.WorkspaceID != descriptor.WorkspaceID || ready.EnvironmentID != descriptor.EnvironmentID || ready.CreatedAt != descriptor.CreatedAt || ready.AuditCorrelationID != descriptor.AuditCorrelationID || manifest.Binding != binding || ready.EventCount == nil || *ready.EventCount != manifest.EventCount || ready.ChunkCount == nil || *ready.ChunkCount != manifest.ChunkCount || ready.ChunkBytes == nil || *ready.ChunkBytes != manifest.ChunkBytes {
				t.Fatal("ready descriptor/binding mismatch", err, mErr)
			}
			captureTime, captureErr := time.Parse(time.RFC3339Nano, ready.CapturedAt)
			if captureErr != nil || !captureTime.Equal(capturedAt) {
				t.Fatal("ready capture timestamp differs from durable job", captureErr)
			}
			sum := sha256.Sum256(contents.Manifest)
			if ready.ManifestSHA256 != hex.EncodeToString(sum[:]) {
				t.Fatal("manifest digest mismatch")
			}
			if savedManifest == nil {
				savedManifest = append([]byte(nil), contents.Manifest...)
			} else if !bytes.Equal(savedManifest, contents.Manifest) {
				t.Fatal("manifest changed between pages")
			}
			expected, nextErr := e.Next(phase)
			if empty {
				if nextErr != io.EOF || string(contents.Chunk) != "null" || contents.SHA != "" || manifest.EventCount != 0 {
					t.Fatal("zero page contains a chunk")
				}
			} else {
				if nextErr != nil || !bytes.Equal(expected, contents.Chunk) {
					t.Fatal("original canonical chunk differs", ordinal, nextErr)
				}
				chunk, err := audit.DecodeExportChunk(contents.Chunk)
				if err != nil || chunk.Ordinal != ordinal {
					t.Fatal("chunk ordinal")
				}
				sum := sha256.Sum256(expected)
				if contents.SHA != hex.EncodeToString(sum[:]) {
					t.Fatal("chunk SHA mismatch")
				}
			}
			if contents.Page.More {
				if contents.Page.Next == nil || *contents.Page.Next == "" || empty {
					t.Fatal("missing next cursor")
				}
				cursor = *contents.Page.Next
				if fixture.OrderlyRestart && !restarted && ordinal == 1 {
					client.CloseIdleConnections()
					// Keep A in the owner slot until its sole runner and complete
					// terminal protocol prove a normal joined exit. Stop is one-shot.
					stoppedAt := time.Now()
					a := api
					caseResult.APIA, err = a.Stop(phase)
					if err != nil || !a.joined {
						owner.retained = errors.Join(err, errors.New("API A orderly join unproven"))
						t.Fatal(owner.retained)
					}
					if pids[caseResult.APIA.PID] {
						t.Fatal("API A PID not distinct")
					}
					pids[caseResult.APIA.PID] = true
					api = nil
					t.Logf("joined API A pid=%d peakRSS=%d stop_elapsed=%s cleanup-complete normal-exit exact protocol EOF; saved first-page cursor", caseResult.APIA.PID, caseResult.APIA.PeakRSSBytes, time.Since(stoppedAt))
					// Assignment includes a nonnil child returned with startup error;
					// the existing owner then classifies that exact B, never A again.
					api, err = startAuditHTTPSizeAPI(ctx, binaries["apiserver"], auditHTTPSizeDSN(t, f, "invocation_discovery_api"), front.Listener.Addr().String(), caPath, "")
					if err != nil {
						t.Fatal("fresh API B unavailable", err)
					}
					if pids[api.ready.PID] {
						t.Fatal("fresh API B reused a prior PID")
					}
					if auditHTTPSizeSQLDigest(t, phase, f, args) != before || auditHTTPOrderlyInventorySnapshot(t, phase, provider) != inventory {
						t.Fatal("orderly API replacement changed durable SQL or continuous inventory")
					}
					restarted = true
				} else if fixture.OrderlyRestart && restarted && !membershipChecked && ordinal == 2 {
					// B has returned exactly one page. Keep authentication for the
					// role-based403 check; full membership removal separately earns401.
					nextPath := target + "?cursor=" + url.QueryEscape(cursor)
					var originalRole string
					if err := f.admin.QueryRow(phase, `SELECT role FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2 AND active`, args[0], args[3]).Scan(&originalRole); err != nil {
						t.Fatal("original active membership role", err)
					}
					setRole := func(role string) {
						tag, err := f.admin.Exec(phase, `UPDATE zasp_identity_memberships SET role=$3 WHERE organization_id=$1 AND principal_id=$2 AND active AND role<>$3`, args[0], args[3], role)
						if err != nil || tag.RowsAffected() != 1 {
							t.Fatal("exact membership role revoke/restore", err)
						}
					}
					setActive := func(active bool) {
						tag, err := f.admin.Exec(phase, `UPDATE zasp_identity_memberships SET active=$3 WHERE organization_id=$1 AND principal_id=$2 AND active<>$3`, args[0], args[3], active)
						if err != nil || tag.RowsAffected() != 1 {
							t.Fatal("exact membership revoke/restore", err)
						}
					}
					refused := func(status int) {
						calls := providerCalls.Load()
						invoke(phase, http.MethodGet, nextPath, status)
						if providerCalls.Load() != calls {
							t.Fatal("revoked B cursor reached provider")
						}
					}
					setRole("read_only_viewer")
					refused(http.StatusForbidden)
					setRole(originalRole)
					first := invoke(phase, http.MethodGet, nextPath, http.StatusOK)
					setActive(false)
					refused(http.StatusUnauthorized)
					setActive(true)
					if !bytes.Equal(first, invoke(phase, http.MethodGet, nextPath, http.StatusOK)) {
						t.Fatal("restored membership same cursor changed canonical response")
					}
					// Consume this exact restored response through the next ordinary
					// independent byte/descriptor/manifest check, with no extra GET.
					pendingPage = first
					membershipChecked = true
					t.Log("API B after its first page: membership role revoked403, membership inactive401, each zero provider calls; original role/activity restored, same cursor bytes agree")
				}
				ordinal++
				continue
			}
			if contents.Page.Next != nil {
				t.Fatal("terminal cursor present")
			}
			if !empty {
				if _, err := e.Next(phase); err != io.EOF {
					t.Fatal("HTTP stopped before source EOF", err)
				}
			}
			manifestBytes, summary, err := e.Manifest()
			if err != nil || !bytes.Equal(manifestBytes, savedManifest) {
				t.Fatal("complete manifest differs from original source", err)
			}
			want := int64(fixture.Rows + 1)
			if empty {
				want = 0
			}
			if summary.Events != want || !empty && (summary.ChunkBytes <= 0 || summary.Chunks <= 0) {
				t.Fatal("complete source totals", summary)
			}
			if !empty && fixture.Rows == 100001 && summary.ChunkBytes <= 64<<20 {
				t.Fatal("full fixture not strictly greater than 64 MiB", summary)
			}
			auditHTTPSizeCompletion(t, phase, f, args, provider, manifestBytes, summary)
			return summary
		}
	}
	summary := traverse()
	if !empty {
		for _, statement := range []string{`UPDATE zasp_admin_audit SET target_id='changed after capture' WHERE id='pid_53000000-0000-4000-8000-000000000001'`, `DELETE FROM zasp_admin_audit WHERE id='pid_53000000-0000-4000-8000-000000000002'`} {
			tag, err := f.admin.Exec(ctx, statement)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatal("source mutation", err)
			}
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,'pid_55000001-0000-4000-8000-000000000001',$4,'late.source','excluded late row','succeeded','{}','2020-01-01T00:00:00Z')`, args[:4]...); err != nil {
			t.Fatal(err)
		}
		if again := traverse(); again != summary {
			t.Fatal("post-mutation snapshot changed")
		}
	}
	if fixture.OrderlyRestart {
		if !restarted || !membershipChecked {
			t.Fatal("orderly restart or post-restart membership barrier not reached")
		}
		if auditHTTPSizeSQLDigest(t, ctx, f, args) != before || auditHTTPOrderlyInventorySnapshot(t, ctx, provider) != inventory {
			t.Fatal("API traversals changed immutable completion or live inventory")
		}
		process.redeliver(t)
		// Preserve the fixture's absolute cleanup reserve. A late ready replay
		// gets less than eight minutes; it never extends this fixture's life.
		deadline, _ := ctx.Deadline()
		replayDeadline := time.Now().Add(8 * time.Minute)
		if last := deadline.Add(-20 * time.Second); last.Before(replayDeadline) {
			replayDeadline = last
		}
		replayCtx, stop := context.WithDeadline(ctx, replayDeadline)
		replayStarted := time.Now()
		t.Logf("ready replay effective_budget=%s maximum=8m fixture_cleanup_reserve=20s", time.Until(replayDeadline))
		caseResult.Replay, err = runAuditHTTPSizeWorker(replayCtx, binaries["agentsec-worker"], auditHTTPSizeDSN(t, f, "audit_export_worker_fixture"), "audit-export", front.Listener.Addr().String(), caPath, tokenPath, "")
		stop()
		if err != nil {
			if !caseResult.Replay.Joined {
				owner.retained = errors.Join(owner.retained, errors.New("ready replay runner join unproven"))
			}
			t.Logf("failed ready replay receipt evidence: %s", process.queueReceiptSnapshot())
			t.Fatalf("fresh ready executor failed: %v\n%s", err, caseResult.Replay.Output)
		}
		if pids[caseResult.Replay.PID] || caseResult.Replay.PID == api.ready.PID {
			t.Fatal("ready replay PID not distinct")
		}
		pids[caseResult.Replay.PID] = true
		process.mu.Lock()
		replayed := len(process.messages) == 1 && process.messages[0] == savedMessage && savedMessage.ID == savedMessageID && sha256.Sum256(savedMessage.Body) == savedMessageHash && savedMessage.Deliveries == 2 && savedMessage.Deleted && savedMessage.ReceivedAt.After(firstACK) && savedMessage.AcknowledgedAt.After(savedMessage.ReceivedAt) && process.sends == 1 && process.receives == 2 && process.deleteAttempts == 2 && process.deletes == 2 && process.assumes["worker"] == 2 && process.identities["worker"] >= 2 && process.failure == ""
		process.mu.Unlock()
		if !replayed || auditHTTPSizeSQLDigest(t, ctx, f, args) != before || auditHTTPOrderlyInventorySnapshot(t, ctx, provider) != inventory {
			t.Fatal("ready replay changed exact message, Terminal ACK, SQL or immutable PUT inventory")
		}
		if err := provider.Check(); err != nil {
			t.Fatal(err)
		}
		t.Logf("joined ready replay executor pid=%d peakRSS=%d elapsed=%s cleanup-complete normal-exit; exact message SHA256=%x; SQL=%s inventory=%s identity=%s PUTs=%d repeats=%d\n%s", caseResult.Replay.PID, caseResult.Replay.PeakRSSBytes, time.Since(replayStarted), savedMessageHash, before, inventory.Digest, inventory.Identity, inventory.Puts, inventory.Repeats, caseResult.Replay.Output)
		t.Logf("second-delivery Terminal-ready-before-ACK receipt evidence: %s", process.queueReceiptSnapshot())
	}
	if auditHTTPSizeSQLDigest(t, ctx, f, args) != before {
		t.Fatal("HTTP reads changed immutable SQL")
	}
	client.CloseIdleConnections()
	cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
	cleanupStarted := time.Now()
	err = owner.Close(cleanup)
	done()
	if err != nil {
		*retain = true
		t.Fatal(err)
	}
	r := apiResult
	t.Logf("aggregate owner cleanup elapsed=%s fixture_elapsed=%s", time.Since(cleanupStarted), time.Since(fixtureStarted))
	if pids[r.PID] {
		t.Fatal("API PID not distinct")
	}
	pids[r.PID] = true
	t.Logf("joined API pid=%d mode=%s peakRSS=%d retained=%d selfRSS=%d cleanup-complete normal-exit exact protocol EOF", r.PID, r.Mode, r.PeakRSSBytes, r.RetainedBytes, r.SelfRSSBytes)
	t.Logf("complete continuous HTTP: parent=%d api=%d events=%d chunks=%d bytes=%d manifest=%s chain=%s control=%q diagnostics=%v; child RSS excludes PostgreSQL and parent inventory/client/oracle", os.Getpid(), r.PID, summary.Events, summary.Chunks, summary.ChunkBytes, summary.ManifestSHA256, summary.ChainRoot, fixture.Control, fixture.Diagnostics)
	caseResult.API, caseResult.Summary = r, summary
	return caseResult
}

func auditHTTPSizeDecode(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func auditHTTPSizeSQLDigest(t *testing.T, ctx context.Context, f auditExportPG, args []any) string {
	t.Helper()
	hash := sha256.New()
	for _, table := range []string{"zasp_audit_export_jobs", "zasp_audit_export_outbox", "zasp_audit_export_chunks", "zasp_audit_export_intents", "zasp_audit_export_receipts", "zasp_audit_export_retries"} {
		// Each row is bounded; the export-event table is deliberately excluded.
		rows, err := f.admin.Query(ctx, "SELECT to_jsonb(r)::text FROM "+table+" r WHERE organization_id=$1 ORDER BY to_jsonb(r)::text", args[0])
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			fmt.Fprintf(hash, "%s:%d:%s\n", table, len(raw), raw)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range []string{
		`SELECT ordinal::text||':'||encode(sha256(canonical_event),'hex') FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2 ORDER BY ordinal`,
		`SELECT to_jsonb(a)::text FROM zasp_admin_audit a WHERE organization_id=$1 AND target_id=$2 AND action='audit_export.complete' ORDER BY id`,
	} {
		rows, err := f.admin.Query(ctx, query, args[0], args[7])
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			fmt.Fprintf(hash, "%d:%s\n", len(row), row)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func auditHTTPSizeCompletion(t *testing.T, ctx context.Context, f auditExportPG, args []any, p *auditHTTPSizeProvider, manifest []byte, s auditHTTPSizeSummary) {
	t.Helper()
	var exact bool
	err := f.admin.QueryRow(ctx, `SELECT status='ready' AND captured AND attempt=1 AND generation=1 AND event_count=$3 AND chunk_count=$4 AND chunk_bytes=$5 AND manifest_bytes=$6 AND reserved_bytes=$5+octet_length($6::bytea) AND lease_worker IS NULL AND lease_token_digest IS NULL AND lease_expires_at IS NULL AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.id=j.completion_audit_id AND a.organization_id=j.organization_id AND a.workspace_id=j.workspace_id AND a.environment_id=j.environment_id AND a.actor_id=j.principal_id AND a.target_id=j.id AND a.action='audit_export.complete' AND a.outcome='succeeded' AND a.occurred_at=j.completed_at AND a.metadata=jsonb_build_object('event_count',$3::bigint,'chunk_count',$4::bigint,'chunk_bytes',$5::bigint,'manifest_sha256',$7::text)) AND (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete')=1 AND (SELECT count(*) FROM zasp_audit_export_retries WHERE organization_id=$1)=0 FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7], s.Events, s.Chunks, s.ChunkBytes, manifest, s.ManifestSHA256).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("registered completion/accounting mismatch", err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT chain_root=decode($3,'hex') AND (SELECT count(*) FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2)=$4 AND (SELECT count(*) FROM zasp_audit_export_chunks WHERE organization_id=$1 AND export_id=$2)=$5 AND (SELECT count(*) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2)=$5+1 AND (SELECT count(*) FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2)=$5+1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7], s.ChainRoot, s.Events, s.Chunks).Scan(&exact); err != nil || !exact {
		t.Fatal("complete frozen/intent/receipt counts and chain", err)
	}
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer func() { <-p.gate }()
	rows, err := f.admin.Query(ctx, `SELECT i.kind,i.ordinal,i.object_reference,i.sha256,i.size_bytes,r.version_id,r.sha256,r.size_bytes FROM zasp_audit_export_intents i JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=$1 AND i.export_id=$2 ORDER BY i.kind,i.ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := int64(0)
	for rows.Next() {
		var kind, reference, version string
		var sha, receiptSHA []byte
		var ordinal, size, receiptSize int64
		if err := rows.Scan(&kind, &ordinal, &reference, &sha, &size, &version, &receiptSHA, &receiptSize); err != nil {
			t.Fatal(err)
		}
		object, ok := p.objects[reference]
		if !ok {
			t.Fatal("receipt lacks inventory object")
		}
		sum := sha256.Sum256(object.Body)
		if !bytes.Equal(sha, sum[:]) || !bytes.Equal(receiptSHA, sha) || receiptSize != size || size != int64(len(object.Body)) || version != object.Version {
			t.Fatal("immutable receipt/object mismatch")
		}
		count++
	}
	if rows.Err() != nil || count != s.Chunks+1 {
		t.Fatal("receipt count mismatch", rows.Err())
	}
	objects := len(p.objects)
	if int64(objects) != count {
		t.Fatal("unreceipted inventory object")
	}
	if int64(p.counts["worker-PUT"]) != count || p.counts["worker-repeat-PUT"] != 0 || !p.manifest || p.chunks != s.Chunks {
		t.Fatal("provider immutable upload accounting")
	}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
}

func auditHTTPSizePartialFactoryCleanup(t *testing.T, ctx context.Context, f auditExportPG, address, ca string) {
	t.Helper()
	count := func() int {
		var n int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename='invocation_discovery_api'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	_, cleanup, err := auditHTTPSizeAPIFactory(ctx, auditHTTPSizeDSN(t, f, "invocation_discovery_api"), address, ca, []byte("invalid-key"))
	if err == nil {
		_ = cleanup()
		t.Fatal("invalid signing key accepted after database acquisition")
	}
	if acquired := count(); acquired != before+1 {
		_ = cleanup()
		t.Fatalf("partial factory did not reach registered connection: before=%d after=%d", before, acquired)
	}
	if err := cleanup(); err != nil {
		t.Fatal("explicit partial factory cleanup", err)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for count() != before {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("partial factory leaked registered database connection")
		}
	}
	t.Log("partial factory key refusal: acquired registered connection, explicit cleanup closed it")
}
