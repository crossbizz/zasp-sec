//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

// Saved-version recovery cannot admit unpinned GET, missing objects or extra query authority.
func TestAuditExportRecoveryDiscoveryContract(t *testing.T) {
	for _, tc := range []struct {
		name, method, query, checksum string
		enabled, exists, want         bool
	}{
		{"saved", "HEAD", "", "ENABLED", true, true, true},
		{"default", "HEAD", "", "ENABLED", false, true, false},
		{"missing", "HEAD", "", "ENABLED", true, false, false},
		{"get", "GET", "", "ENABLED", true, true, false},
		{"query", "HEAD", "?versionId=foreign", "ENABLED", true, true, false},
		{"checksum", "HEAD", "", "", true, true, false},
	} {
		r := httptest.NewRequest(tc.method, "https://bucket.s3.us-east-1.amazonaws.com/exact"+tc.query, nil)
		r.Header.Set("X-Amz-Checksum-Mode", tc.checksum)
		if got := auditExportRecoveryDiscovery(tc.enabled, tc.exists, r); got != tc.want {
			t.Errorf("%s discovery=%t want=%t", tc.name, got, tc.want)
		}
	}
}

type auditRecoveryEvent struct {
	PID                                               int
	Phase, Operation                                  string
	Before, Hold, ContextLive                         bool
	Body                                              json.RawMessage
	SQLState, Worker, TokenDigest, CaptureID, Version string
	Generation                                        int64
	Attempt                                           int
}

func auditRecoveryFrozen(t *testing.T, ctx context.Context, f auditExportPG, args []any) string {
	t.Helper()
	var body string
	err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('header',jsonb_build_array(capture_id,captured,captured_at,event_count,chunk_count,chunk_bytes,chain_root,manifest_bytes,policy_id,storage_policy),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY ordinal) FROM zasp_audit_export_events e WHERE organization_id=$1 AND export_id=$2),'plans',(SELECT jsonb_agg(to_jsonb(c) ORDER BY ordinal) FROM zasp_audit_export_chunks c WHERE organization_id=$1 AND export_id=$2))::text FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func auditRecoveryReceiptSnapshot(t *testing.T, ctx context.Context, f auditExportPG, args []any) string {
	t.Helper()
	var body string
	if err := f.admin.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY kind,ordinal),'[]'::jsonb)::text FROM zasp_audit_export_receipts r WHERE organization_id=$1 AND export_id=$2`, args[0], args[7]).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}
func auditRecoveryFirstReceipt(t *testing.T, ctx context.Context, f auditExportPG, args []any) string {
	t.Helper()
	var body string
	if err := f.admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(r))::text FROM zasp_audit_export_receipts r WHERE organization_id=$1 AND export_id=$2 AND kind='chunk' AND ordinal=1`, args[0], args[7]).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}
func auditRecoveryInventory(p *auditExportProcessProvider) map[string]auditExportProcessObject {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]auditExportProcessObject{}
	for ref, o := range p.objects {
		o.Body = bytes.Clone(o.Body)
		o.Headers = o.Headers.Clone()
		out[ref] = o
	}
	return out
}
func auditRecoveryAge(t *testing.T, ctx context.Context, f auditExportPG, args []any, p *auditExportProcessProvider, ready bool) {
	t.Helper()
	if !ready {
		tag, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2 AND status='processing' AND generation=1 AND attempt=1 AND lease_worker IS NOT NULL`, args[0], args[7])
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("exact fixture lease aging", err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.messages) != 1 || p.messages[0].Deleted || p.messages[0].Deliveries != 1 || p.messages[0].Receipt == "" {
		t.Fatal("exact delivery aging absent")
	}
	p.messages[0].Visible = time.Time{}
}
func auditRecoveryBoundary(t *testing.T, ctx context.Context, f auditExportPG, args []any, p *auditExportProcessProvider, receipts, objects int, ready bool, generation int, e auditRecoveryEvent) {
	t.Helper()
	var exact bool
	status := "processing"
	completion := 0
	if ready {
		status = "ready"
		completion = 1
	}
	err := f.admin.QueryRow(ctx, `SELECT status=$3 AND captured AND event_count=1006 AND chunk_count=2 AND generation=$4 AND attempt=$4 AND (SELECT count(*) FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2)=$5 AND (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete')=$6 AND ((completion_audit_id IS NOT NULL)=$7) FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7], status, generation, receipts, completion, ready).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("independent persisted boundary absent", err)
	}
	var chunks, manifests int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='chunk'),count(*) FILTER (WHERE kind='manifest') FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2`, args[0], args[7]).Scan(&chunks, &manifests); err != nil || chunks != min(receipts, 2) || manifests != completion {
		t.Fatal("boundary chunk-prefix/manifest receipt split", err)
	}
	p.mu.Lock()
	ok := len(p.objects) == objects && p.puts == objects && p.heads == 2*objects && p.gets == 2*objects && p.deletes == 0 && p.deleteAttempts == 0 && p.failure == ""
	p.mu.Unlock()
	if !ok {
		t.Fatal("provider boundary/zero ACK absent", p.problem())
	}
	// The raw lease identity comes from A's actual delegated call, never from B.
	if !ready && generation == 1 {
		if err := f.admin.QueryRow(ctx, `SELECT capture_id=$3 AND generation=$4 AND attempt=$5 AND lease_worker=$6 AND encode(lease_token_digest,'hex')=$7 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7], e.CaptureID, e.Generation, e.Attempt, e.Worker, e.TokenDigest).Scan(&exact); err != nil || !exact {
			t.Fatal("A original SQL lease identity absent", err)
		}
	}
	// Each boundary verifies every saved object against independent source bytes
	// and every committed receipt against that exact physical provider version.
	auditRecoveryObjects(t, ctx, f, args, p, objects, receipts)
	if e.Version != "" {
		kind, ordinal := "chunk", 1
		if e.Operation == "finish" {
			kind, ordinal = "manifest", 0
		}
		var ref string
		if err := f.admin.QueryRow(ctx, `SELECT object_reference FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2 AND kind=$3 AND ordinal=$4`, args[0], args[7], kind, ordinal).Scan(&ref); err != nil {
			t.Fatal(err)
		}
		if auditRecoveryInventory(p)[ref].Version != e.Version {
			t.Fatal("actual delegated receipt version differs from saved object")
		}
	}
}
func auditRecoveryObjects(t *testing.T, ctx context.Context, f auditExportPG, args []any, p *auditExportProcessProvider, objectCount, receiptCount int) {
	t.Helper()
	binding := audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string)}
	if err := f.admin.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&binding.CaptureID); err != nil {
		t.Fatal(err)
	}
	expected, err := auditExportProcessExpected(binding, p.events)
	if err != nil {
		t.Fatal(err)
	}
	inventory := auditRecoveryInventory(p)
	rows, err := f.admin.Query(ctx, `SELECT i.kind,i.ordinal,i.artifact_id,i.object_reference,i.sha256,i.size_bytes,coalesce(r.version_id,''),coalesce(r.sha256,'\x'::bytea),coalesce(r.size_bytes,0) FROM zasp_audit_export_intents i LEFT JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=$1 AND i.export_id=$2 ORDER BY i.kind,i.ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	objects, receipts := 0, 0
	for rows.Next() {
		var kind, id, ref, version string
		var ordinal, size, receiptSize int64
		var digest, receiptDigest []byte
		if err := rows.Scan(&kind, &ordinal, &id, &ref, &digest, &size, &version, &receiptDigest, &receiptSize); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		body, ok := expected[fmt.Sprintf("%s:%d", kind, ordinal)]
		hash := sha256.Sum256(body)
		wantID := auditLocalstackArtifactID(binding, kind, ordinal)
		wantRef := fmt.Sprintf("s3://%s/organizations/%s/workspaces/%s/environments/%s/exports/%s", auditExportTestPolicy().Bucket, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, wantID)
		if !ok || id != wantID || ref != wantRef || size != int64(len(body)) || !bytes.Equal(digest, hash[:]) {
			rows.Close()
			t.Fatal("intent differs from original canonical bytes")
		}
		object, exists := inventory[ref]
		if exists {
			objects++
			policy := auditExportTestPolicy()
			if !bytes.Equal(object.Body, body) || object.Version == "" || object.Headers.Get("X-Amz-Version-Id") != object.Version || object.Headers.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(hash[:]) || object.Headers.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || object.Headers.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != policy.KMSKeyARN || object.Headers.Get("Content-Type") != "application/json" {
				rows.Close()
				t.Fatal("physical version/body/checksum/KMS differs")
			}
			for key, value := range map[string]string{"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID, "environment_id": binding.EnvironmentID, "artifact_id": id, "media_type": "application/json", "sha256": hex.EncodeToString(hash[:])} {
				if object.Headers.Get("X-Amz-Meta-"+key) != value {
					rows.Close()
					t.Fatal("physical scoped metadata differs")
				}
			}
		}
		if version != "" {
			receipts++
			if !exists || version != object.Version || receiptSize != size || !bytes.Equal(receiptDigest, hash[:]) {
				rows.Close()
				t.Fatal("SQL receipt differs from physical version")
			}
		}
	}
	rows.Close()
	if rows.Err() != nil || objects != objectCount || len(inventory) != objects || receipts != receiptCount {
		t.Fatal("saved object/receipt inventory incomplete", rows.Err(), objects, receipts)
	}
}
func auditRecoveryTerminal(t *testing.T, b *auditRecoveryBarrier) {
	t.Helper()
	claims, terminal := 0, false
	for _, e := range b.snapshot() {
		if e.Before {
			continue
		}
		switch e.Operation {
		case "claim":
			if string(e.Body) != "null" {
				t.Fatal("terminal replay acquired another lease")
			}
			claims++
		case "terminal":
			var body struct {
				State string `json:"state"`
			}
			terminal = json.Unmarshal(e.Body, &body) == nil && body.State == "ready" && e.ContextLive && e.SQLState == ""
		case "capture", "record", "finish", "retry":
			t.Fatal("terminal replay performed execution authority")
		}
	}
	if claims != 1 || !terminal {
		t.Fatal("fresh worker omitted actual Terminal ready")
	}
}
func auditRecoveryFinal(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, p *auditExportProcessProvider, generation, acks int) {
	t.Helper()
	auditRecoveryObjects(t, ctx, f, args, p, 3, 3)
	// Reuse the accepted read-only canonical-source/plan oracle. It performs no
	// LocalStack calls and introduces no provider lane or prior-case rerun.
	auditLocalstackAssertCapturedSource(t, ctx, f, args, events)
	binding := audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string)}
	if err := f.admin.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&binding.CaptureID); err != nil {
		t.Fatal(err)
	}
	expected, err := auditExportProcessExpected(binding, events)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := audit.DecodeExportManifest(expected["manifest:0"])
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(expected["manifest:0"])
	var exact bool
	err = f.admin.QueryRow(ctx, `SELECT status='ready' AND captured AND attempt=$3 AND generation=$3 AND event_count=1006 AND chunk_count=2 AND chunk_bytes=$4 AND manifest_bytes=$5 AND chain_root=$6 AND reserved_bytes=$4+octet_length($5::bytea) AND lease_worker IS NULL AND lease_token_digest IS NULL AND lease_expires_at IS NULL AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.id=j.completion_audit_id AND a.organization_id=j.organization_id AND a.workspace_id=j.workspace_id AND a.environment_id=j.environment_id AND a.actor_id=j.principal_id AND a.target_id=j.id AND a.action='audit_export.complete' AND a.outcome='succeeded' AND a.occurred_at=j.completed_at AND a.metadata=jsonb_build_object('event_count',1006::bigint,'chunk_count',2::bigint,'chunk_bytes',$4::bigint,'manifest_sha256',$7::text)) AND (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete')=1 AND (SELECT count(*) FROM zasp_audit_export_retries WHERE organization_id=$1 AND export_id=$2)=0 AND (SELECT array_agg(ordinal ORDER BY ordinal) FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2 AND kind='chunk')=ARRAY[1,2]::bigint[] FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7], generation, manifest.ChunkBytes, expected["manifest:0"], mustAuditRecoveryDigest(t, manifest.ChainRoot), hex.EncodeToString(hash[:])).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("final exact manifest/chain/reservation/completion", err)
	}
	p.mu.Lock()
	ok := p.sends == 1 && len(p.messages) == 1 && p.messages[0].Deleted && p.deletes == acks && p.deleteAttempts == acks && p.receives == acks+1 && p.failure == ""
	p.mu.Unlock()
	if !ok {
		t.Fatal("final queue/Terminal-before-ACK effects", p.queueReceiptSnapshot())
	}
}
func mustAuditRecoveryDigest(t *testing.T, s string) []byte {
	t.Helper()
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type auditRecoveryBarrier struct {
	server  *httptest.Server
	reached chan auditRecoveryEvent
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	events  []auditRecoveryEvent
}

func newAuditRecoveryBarrier(t *testing.T, owner *auditHTTPFixtureOwner) *auditRecoveryBarrier {
	b := &auditRecoveryBarrier{reached: make(chan auditRecoveryEvent, 1), release: make(chan struct{})}
	b.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/observe" || r.URL.RawQuery != "" {
			http.Error(w, "closed observation", 400)
			return
		}
		var event auditRecoveryEvent
		decoder := json.NewDecoder(io.LimitReader(r.Body, 32769))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&event) != nil || decoder.Decode(&struct{}{}) != io.EOF || event.PID <= 0 {
			http.Error(w, "invalid observation", 400)
			return
		}
		b.mu.Lock()
		b.events = append(b.events, event)
		b.mu.Unlock()
		if event.Hold {
			select {
			case b.reached <- event:
			default:
				http.Error(w, "duplicate barrier", 400)
				return
			}
			select {
			case <-b.release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	owner.handlers = append(owner.handlers, auditHTTPFixtureClose{"recovery observation handler", func(ctx context.Context) error {
		b.unblock()
		if err := b.server.Config.Shutdown(ctx); err != nil {
			return err
		}
		b.server.Close()
		return nil
	}})
	return b
}
func (b *auditRecoveryBarrier) unblock() { b.once.Do(func() { close(b.release) }) }
func (b *auditRecoveryBarrier) snapshot() []auditRecoveryEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]auditRecoveryEvent(nil), b.events...)
}

type auditRecoveryResult struct {
	output []byte
	err    error
}
type auditRecoveryChild struct {
	command *exec.Cmd
	force   chan struct{}
	cancel  context.CancelFunc
	done    chan struct{}
	result  auditRecoveryResult
}

func (l *auditExportProcessLauncher) startRecovery(t *testing.T, ctx context.Context, owner *auditHTTPFixtureOwner, f auditExportPG, p *auditExportProcessProvider, ca, token, phase string, b *auditRecoveryBarrier) *auditRecoveryChild {
	target, err := url.Parse(f.admin.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	target.User = url.User("audit_export_worker_fixture")
	child := &auditRecoveryChild{command: exec.Command(l.binary, "-test.run=^TestAuditExportRecoveryProcessWorkerPostgres$", "-test.v", "-test.count=1"), force: make(chan struct{}), done: make(chan struct{})}
	child.command.Env = []string{"PATH=" + os.Getenv("PATH"), "GOTOOLCHAIN=local", "ZASP_AUDIT_EXPORT_PROCESS_DSN=" + target.String(), "ZASP_AUDIT_EXPORT_PROCESS_MODE=audit-export", "ZASP_AUDIT_EXPORT_PROCESS_ADDRESS=" + p.server.Listener.Addr().String(), "ZASP_AUDIT_EXPORT_PROCESS_CA=" + ca, "ZASP_AUDIT_EXPORT_PROCESS_TOKEN=" + token, "ZASP_AUDIT_EXPORT_RECOVERY_PHASE=" + phase, "ZASP_AUDIT_EXPORT_RECOVERY_CONTROL=" + b.server.URL + "/observe"}
	runCtx, cancel := context.WithTimeout(ctx, 100*time.Second)
	child.cancel = cancel
	owner.processes = append(owner.processes, auditHTTPFixtureClose{"recovery child " + phase, func(cleanup context.Context) error {
		cancel()
		select {
		case <-child.done:
			pid := 0
			if child.command.Process != nil {
				pid = child.command.Process.Pid
			}
			t.Logf("owned child cleanup result: phase=%s pid=%d state=%v err=%v", phase, pid, child.command.ProcessState, child.result.err)
			if child.result.err != nil && child.result.err != testprocess.ErrForceKilled {
				return child.result.err
			}
			return nil
		case <-cleanup.Done():
			return errors.New("recovery child join uncertain")
		}
	}})
	go func() {
		defer close(child.done)
		child.result.output, child.result.err = testprocess.RunWithForceKill(runCtx, child.command, child.force)
	}()
	return child
}
func (c *auditRecoveryChild) join(t *testing.T, ctx context.Context, killed bool) int {
	t.Helper()
	select {
	case <-c.done:
	case <-ctx.Done():
		t.Fatal("recovery child join deadline", ctx.Err())
	}
	c.cancel()
	t.Logf("recovery child terminal: killed=%t err=%v\n%s", killed, c.result.err, c.result.output)
	if killed {
		if c.result.err != testprocess.ErrForceKilled || c.command.ProcessState == nil {
			t.Fatal("missing exact force-kill result")
		}
		status, ok := c.command.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || bytes.Contains(c.result.output, []byte("registered recovery joined:")) {
			t.Fatal("missing SIGKILL WaitStatus")
		}
	} else if c.result.err != nil || !bytes.Contains(c.result.output, []byte("registered recovery joined:")) || !bytes.Contains(c.result.output, []byte("PASS")) || bytes.Contains(c.result.output, []byte("SKIP")) {
		t.Fatal("fresh recovery child did not complete")
	}
	return c.command.Process.Pid
}
func (b *auditRecoveryBarrier) wait(t *testing.T, ctx context.Context, c *auditRecoveryChild) auditRecoveryEvent {
	t.Helper()
	bound, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	select {
	case e := <-b.reached:
		if !e.ContextLive || e.SQLState != "" {
			t.Fatal("barrier not reached through live SQL", e)
		}
		t.Logf("parent observed held child: phase=%s pid=%d operation=%s before=%t", e.Phase, e.PID, e.Operation, e.Before)
		return e
	case <-c.done:
		t.Fatalf("recovery barrier absent: %v\n%s", c.result.err, c.result.output)
	case <-bound.Done():
		t.Fatal("recovery barrier deadline", bound.Err())
	}
	return auditRecoveryEvent{}
}

// Missing capture retention, receipt replay, SQL fencing or terminal ACK ordering
// breaks parent-owned SQL/provider assertions, even if a child returns success.
func TestAuditExportWorkerPostgresRecoveryProcessBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	launcher := newAuditExportProcessLauncher(t, ctx)
	for _, phase := range []string{"capture", "receipt", "stale", "manifest", "finish"} {
		t.Run(phase, func(t *testing.T) {
			caseCtx, stop := context.WithTimeout(ctx, 100*time.Second)
			defer stop()
			caseCtx, owner := newAuditHTTPFixtureOwner(t, caseCtx, "", func() { launcher.failed = true })
			owner.startPostgres = func(t *testing.T, ctx context.Context, user string) string {
				return auditHTTPSizeStartPostgres(t, ctx, owner, user)
			}
			f := auditExportPGFixture(t, caseCtx)
			f.register(t, caseCtx)
			worker, _ := auditExportWorkerConnections(t, caseCtx, f)
			args := f.createArgs()
			var created json.RawMessage
			if err := f.api.QueryRow(caseCtx, postgresAuditExportCreateSQL, args...).Scan(&created); err != nil {
				t.Fatal(err)
			}
			events, _ := auditExportPrepareWorkerSource(t, caseCtx, f, args)
			if len(events) != 1006 {
				t.Fatal("source count", len(events))
			}
			p := newAuditExportProcessProvider(t, caseCtx, f, worker, args, events)
			p.mu.Lock()
			p.recoveryDiscoveryEnabled = true
			p.mu.Unlock()
			ca, token := filepath.Join(owner.root, "ca.pem"), filepath.Join(owner.root, "token")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(auditExportProcessToken), 0600); err != nil {
				t.Fatal(err)
			}
			publisher := launcher.run(t, caseCtx, f, p, "audit-export-outbox", ca, token)
			p.mu.Lock()
			messageID := p.messages[0].ID
			p.mu.Unlock()
			auditExportAssertProcessPublication(t, caseCtx, f, args, messageID, 1)
			aBarrier := newAuditRecoveryBarrier(t, owner)
			a := launcher.startRecovery(t, caseCtx, owner, f, p, ca, token, phase, aBarrier)
			event := aBarrier.wait(t, caseCtx, a)
			cutAt := time.Now()
			t.Logf("actual boundary: phase=%s pid=%d operation=%s before=%t generation=%d attempt=%d version=%s", phase, event.PID, event.Operation, event.Before, event.Generation, event.Attempt, event.Version)
			frozen := auditRecoveryFrozen(t, caseCtx, f, args)
			receipts, objects, ready := 0, 0, false
			switch phase {
			case "receipt":
				receipts, objects = 1, 1
			case "stale":
				objects = 1
			case "manifest":
				receipts, objects = 2, 3
			case "finish":
				receipts, objects, ready = 3, 3, true
			}
			auditRecoveryBoundary(t, caseCtx, f, args, p, receipts, objects, ready, 1, event)
			prefix := auditRecoveryReceiptSnapshot(t, caseCtx, f, args)
			saved := auditRecoveryInventory(p)
			var aPID, bPID int
			bBarrier := newAuditRecoveryBarrier(t, owner)
			if phase == "stale" {
				auditRecoveryAge(t, caseCtx, f, args, p, false)
				b := launcher.startRecovery(t, caseCtx, owner, f, p, ca, token, "claim", bBarrier)
				claim := bBarrier.wait(t, caseCtx, b)
				var lease struct {
					Generation int64 `json:"generation"`
					Attempt    int   `json:"attempt"`
				}
				if json.Unmarshal(claim.Body, &lease) != nil || lease.Generation != 2 || lease.Attempt != 2 {
					t.Fatal("B did not claim generation2", string(claim.Body))
				}
				auditRecoveryBoundary(t, caseCtx, f, args, p, 0, 1, false, 2, event)
				before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
				p.mu.Lock()
				initialAttempts, initialRenewals := p.renewalAttempts, p.renewals
				p.mu.Unlock()
				aBarrier.unblock()
				aPID = a.join(t, caseCtx, false)
				if elapsed := time.Since(cutAt); elapsed >= 60*time.Second {
					t.Fatal("missed queue-renewal window", elapsed)
				} else {
					t.Logf("A SQL refusal and normal error-exit joined before renewal: elapsed=%s", elapsed)
				}
				refused := false
				for _, e := range aBarrier.snapshot() {
					if e.Operation == "record" && !e.Before {
						refused = e.SQLState == "42501" && e.ContextLive && e.Generation == 1 && e.Attempt == 1 && e.Worker == event.Worker && e.TokenDigest == event.TokenDigest && e.CaptureID == event.CaptureID && e.Version == event.Version
						t.Logf("A actual SQL refusal: SQLSTATE=%s live=%t worker=%s token_sha256=%s generation=%d", e.SQLState, e.ContextLive, e.Worker, e.TokenDigest, e.Generation)
					}
				}
				if !refused || auditExportProcessSQLSnapshot(t, caseCtx, f, args) != before || !reflect.DeepEqual(saved, auditRecoveryInventory(p)) {
					t.Fatal("stale A fencing or zero durable effects absent")
				}
				p.mu.Lock()
				// Both real dispatchers renew their receipt before their first SQL
				// query. Only activity after the B-held snapshot is stale-A activity.
				clean := p.deleteAttempts == 0 && p.deletes == 0 && p.renewalAttempts == initialAttempts && p.renewals == initialRenewals && p.failure == ""
				t.Logf("A resume queue delta: initial_attempts=%d initial_renewals=%d final_attempts=%d final_renewals=%d delete_attempts=%d deletes=%d refusal=%q", initialAttempts, initialRenewals, p.renewalAttempts, p.renewals, p.deleteAttempts, p.deletes, p.failure)
				p.mu.Unlock()
				if !clean {
					t.Fatal("stale A reached ACK/queue cancellation")
				}
				bBarrier.unblock()
				bPID = b.join(t, caseCtx, false)
			} else {
				close(a.force)
				aPID = a.join(t, caseCtx, true)
				aBarrier.unblock()
				t.Logf("barrier to SIGKILL/join=%s", time.Since(cutAt))
				auditRecoveryAge(t, caseCtx, f, args, p, ready)
				if phase == "capture" {
					tag, err := f.admin.Exec(caseCtx, `UPDATE zasp_admin_audit SET target_id='changed after capture',metadata='{"counter":99}' WHERE organization_id=$1`, args[0])
					if err != nil || tag.RowsAffected() != 1006 {
						t.Fatal("fixture source mutation", err)
					}
				}
				before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
				bPhase := "recovery"
				if ready {
					bPhase = "terminal"
				}
				b := launcher.startRecovery(t, caseCtx, owner, f, p, ca, token, bPhase, bBarrier)
				bPID = b.join(t, caseCtx, false)
				if ready && (auditExportProcessSQLSnapshot(t, caseCtx, f, args) != before || !reflect.DeepEqual(saved, auditRecoveryInventory(p))) {
					t.Fatal("terminal replay rewrote committed state")
				}
				if ready {
					auditRecoveryTerminal(t, bBarrier)
				}
			}
			if aPID == bPID || aPID == publisher || bPID == publisher || aPID != event.PID {
				t.Fatal("process identities not distinct")
			}
			if auditRecoveryFrozen(t, caseCtx, f, args) != frozen {
				t.Fatal("recovery changed frozen capture/plans")
			}
			if phase == "receipt" && auditRecoveryFirstReceipt(t, caseCtx, f, args) != prefix {
				t.Fatal("first receipt changed after response loss")
			}
			for ref, old := range saved {
				if !reflect.DeepEqual(old, auditRecoveryInventory(p)[ref]) {
					t.Fatal("saved physical version/body/metadata replaced")
				}
			}
			generation := 2
			if ready {
				generation = 1
			}
			auditRecoveryFinal(t, caseCtx, f, args, events, p, generation, 1)
			wantPuts, wantHeads, wantGets, wantDiscoveries := 3, 6, 6, 0
			if phase == "stale" || phase == "manifest" {
				wantPuts, wantHeads, wantGets, wantDiscoveries = 4, 9, 8, 1
			}
			p.mu.Lock()
			exactRequests := p.puts == wantPuts && p.heads == wantHeads && p.gets == wantGets && p.recoveryDiscoveries == wantDiscoveries
			t.Logf("exact provider requests: puts=%d heads=%d gets=%d discoveries=%d", p.puts, p.heads, p.gets, p.recoveryDiscoveries)
			p.mu.Unlock()
			if !exactRequests {
				t.Fatal("unexpected provider re-execution or unpinned discovery")
			}
			before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
			inventory := auditRecoveryInventory(p)
			p.mu.Lock()
			puts, heads, gets := p.puts, p.heads, p.gets
			p.mu.Unlock()
			p.redeliver(t)
			cBarrier := newAuditRecoveryBarrier(t, owner)
			c := launcher.startRecovery(t, caseCtx, owner, f, p, ca, token, "terminal", cBarrier)
			cPID := c.join(t, caseCtx, false)
			if cPID == aPID || cPID == bPID || cPID == publisher {
				t.Fatal("terminal replay PID reused")
			}
			auditRecoveryTerminal(t, cBarrier)
			auditRecoveryFinal(t, caseCtx, f, args, events, p, generation, 2)
			p.mu.Lock()
			noIO := puts == p.puts && heads == p.heads && gets == p.gets
			p.mu.Unlock()
			if !noIO || before != auditExportProcessSQLSnapshot(t, caseCtx, f, args) || !reflect.DeepEqual(inventory, auditRecoveryInventory(p)) {
				t.Fatal("duplicate changed complete inventories")
			}
			t.Logf("joined recovery proof: phase=%s publisher=%d A=%d B=%d C=%d source=1006 chunks=2 completion=1", phase, publisher, aPID, bPID, cPID)
		})
	}
}
