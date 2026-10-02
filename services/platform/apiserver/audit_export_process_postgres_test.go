//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

// Missing outbox Finish or premature executor success must fail persisted-state
// and pre-ACK checks. Parent-owned provider state survives every child process.
func TestAuditExportWorkerPostgresDurableOutboxSDK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	launcher := newAuditExportProcessLauncher(t, ctx)
	for _, empty := range []bool{false, true} {
		name := "populated"
		if empty {
			name = "controlled-zero-source"
		}
		t.Run(name, func(t *testing.T) {
			caseCtx, stop := context.WithTimeout(ctx, 150*time.Second)
			defer stop()
			f := auditExportPGFixture(t, caseCtx)
			f.register(t, caseCtx)
			worker, _ := auditExportWorkerConnections(t, caseCtx, f)
			args := f.createArgs()
			var descriptor json.RawMessage
			if err := f.api.QueryRow(caseCtx, postgresAuditExportCreateSQL, args...).Scan(&descriptor); err != nil {
				t.Fatal("registered durable Create", err)
			}
			var events []json.RawMessage
			if empty {
				// A normal Create contributes its own source audit. Only this disposable
				// owner setup deletes it to exercise the genuine zero-event manifest.
				tag, err := f.admin.Exec(caseCtx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1`, args[0])
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("controlled zero-source setup", err)
				}
			} else {
				events, _ = auditExportPrepareWorkerSource(t, caseCtx, f, args)
			}
			provider := newAuditExportProcessProvider(t, caseCtx, f, worker, args, events)
			caPath := filepath.Join(t.TempDir(), "provider-ca.pem")
			tokenPath := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tokenPath, []byte(auditExportProcessToken), 0600); err != nil {
				t.Fatal(err)
			}
			publisherPID := launcher.run(t, caseCtx, f, provider, "audit-export-outbox", caPath, tokenPath)
			var published bool
			provider.mu.Lock()
			sent := provider.sends
			queued := len(provider.messages)
			objects := len(provider.objects)
			messageID := ""
			if queued == 1 {
				messageID = provider.messages[0].ID
			}
			provider.mu.Unlock()
			ack, valid := jobqueue.CanonicalProviderAcknowledgement(messageID)
			if sent != 1 || queued != 1 || objects != 0 || !valid {
				t.Fatal("actual SDK did not publish the sole durable wakeup", sent, queued, objects, provider.problem())
			}
			if err := f.admin.QueryRow(caseCtx, `SELECT state='published' AND attempt=1 AND generation=1 AND provider_message_id=$3 AND (SELECT status='queued' AND attempt=0 AND NOT captured AND completion_audit_id IS NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2) FROM zasp_audit_export_outbox WHERE organization_id=$1 AND export_id=$2`, args[0], args[7], ack).Scan(&published); err != nil || !published {
				t.Fatal("publisher success lacked durable outbox confirmation", err)
			}
			executorPID := launcher.run(t, caseCtx, f, provider, "audit-export", caPath, tokenPath)
			if executorPID == publisherPID {
				t.Fatal("publisher/executor were not separate processes")
			}
			auditExportAssertProcessCompletion(t, caseCtx, f, args, events, provider, 1)
			before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
			provider.redeliver(t)
			replayPID := launcher.run(t, caseCtx, f, provider, "audit-export", caPath, tokenPath)
			if replayPID == executorPID || replayPID == publisherPID {
				t.Fatal("duplicate did not use a fresh process")
			}
			auditExportAssertProcessCompletion(t, caseCtx, f, args, events, provider, 2)
			if auditExportProcessSQLSnapshot(t, caseCtx, f, args) != before {
				t.Fatal("fresh duplicate rewrote retained SQL authority")
			}
			provider.mu.Lock()
			identityOK := provider.assumes["outbox"] == 1 && provider.assumes["worker"] == 2 && provider.identities["outbox"] >= 1 && provider.identities["worker"] >= 2
			provider.mu.Unlock()
			if !identityOK || provider.problem() != "" {
				t.Fatal("fresh mode-specific SDK identity missing", provider.problem())
			}
			t.Logf("parent-lived provider and registered PG proven: source_events=%d publisher_pid=%d executor_pid=%d replay_pid=%d one SDK Send, exact immutable objects, durable outbox and completion before two ACKs; controlled transport, no process-crash/local-provider claim", len(events), publisherPID, executorPID, replayPID)
		})
	}
}

type auditExportProcessLauncher struct {
	root, binary string
	failed       bool
}

// A saved SDK Send cannot be confirmed from an uncertain response. Conversely,
// losing a committed SQL confirmation cannot cause a second publication.
func TestAuditExportWorkerPostgresOutboxResponseLossSDK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	launcher := newAuditExportProcessLauncher(t, ctx)
	for _, fault := range []string{"saved-send-response", "committed-finish-response"} {
		t.Run(fault, func(t *testing.T) {
			caseCtx, stop := context.WithTimeout(ctx, 150*time.Second)
			defer stop()
			f := auditExportPGFixture(t, caseCtx)
			f.register(t, caseCtx)
			worker, _ := auditExportWorkerConnections(t, caseCtx, f)
			args := f.createArgs()
			var body json.RawMessage
			if err := f.api.QueryRow(caseCtx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil {
				t.Fatal("registered loss-case Create", err)
			}
			events, _ := auditExportPrepareWorkerSource(t, caseCtx, f, args)
			provider := newAuditExportProcessProvider(t, caseCtx, f, worker, args, events)
			root := t.TempDir()
			caPath, tokenPath := filepath.Join(root, "ca.pem"), filepath.Join(root, "token")
			if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tokenPath, []byte(auditExportProcessToken), 0600); err != nil {
				t.Fatal(err)
			}
			childFault := "finish-outbox-response"
			if fault == "saved-send-response" {
				childFault = ""
				provider.mu.Lock()
				provider.loseNextSend = true
				provider.mu.Unlock()
			}
			started := time.Now()
			publisherPID := launcher.runOutcome(t, caseCtx, f, provider, "audit-export-outbox", caPath, tokenPath, childFault, true)
			finished := time.Now()
			provider.mu.Lock()
			sent, queued, losses, puts, deletes := provider.sends, len(provider.messages), provider.lostSends, provider.puts, provider.deletes
			messageID := ""
			if queued == 1 {
				messageID = provider.messages[0].ID
			}
			provider.mu.Unlock()
			wantLosses := 0
			if fault == "saved-send-response" {
				wantLosses = 1
			}
			if sent != 1 || queued != 1 || puts != 0 || deletes != 0 || losses != wantLosses {
				t.Fatal("intended actual Send boundary not reached", sent, queued, losses, provider.problem())
			}
			if fault == "committed-finish-response" {
				auditExportAssertProcessPublication(t, caseCtx, f, args, messageID, 1)
				before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
				nextPID := launcher.run(t, caseCtx, f, provider, "audit-export-outbox", caPath, tokenPath)
				provider.mu.Lock()
				unchanged := provider.sends == 1 && len(provider.messages) == 1
				provider.mu.Unlock()
				if nextPID == publisherPID || !unchanged || auditExportProcessSQLSnapshot(t, caseCtx, f, args) != before {
					t.Fatal("lost committed confirmation caused republish or mutation")
				}
				launcher.run(t, caseCtx, f, provider, "audit-export", caPath, tokenPath)
				auditExportAssertProcessCompletion(t, caseCtx, f, args, events, provider, 1)
				t.Log("committed outbox Finish response was lost after actual SQL; fresh publisher made no second Send, real executor completed original saved queue message")
				return
			}
			var pending bool
			var available time.Time
			var state string
			var confirmed bool
			if err := f.admin.QueryRow(caseCtx, `SELECT state='pending' AND attempt=1 AND generation=1 AND retry_seconds=30 AND provider_message_id IS NULL AND (SELECT status='queued' AND attempt=0 AND NOT captured AND completion_audit_id IS NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2),available_at,state,provider_message_id IS NOT NULL FROM zasp_audit_export_outbox WHERE organization_id=$1 AND export_id=$2`, args[0], args[7]).Scan(&pending, &available, &state, &confirmed); err != nil || !pending || available.Before(started.Add(30*time.Second)) || available.After(finished.Add(30*time.Second)) {
				t.Fatal("uncertain Send lacked durable fixed retry/no-failure state", err, "state", state, "confirmed", confirmed)
			}
			beforeEarly := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
			launcher.run(t, caseCtx, f, provider, "audit-export-outbox", caPath, tokenPath)
			provider.mu.Lock()
			stillOne := provider.sends == 1 && len(provider.messages) == 1
			provider.mu.Unlock()
			if !stillOne || auditExportProcessSQLSnapshot(t, caseCtx, f, args) != beforeEarly {
				t.Fatal("early empty outbox claim changed fixed retry or republished")
			}
			// The uncertain publication already reached SQS. Its consumer may finish
			// before the durable publisher retries; that ready result must survive.
			executorPID := launcher.run(t, caseCtx, f, provider, "audit-export", caPath, tokenPath)
			if executorPID == publisherPID {
				t.Fatal("publication and execution reused process")
			}
			auditExportAssertProcessCompletion(t, caseCtx, f, args, events, provider, 1)
			executionBefore := auditExportProcessExecutionSnapshot(t, caseCtx, f, args)
			tag, err := f.admin.Exec(caseCtx, `UPDATE zasp_audit_export_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND export_id=$2 AND state='pending'`, args[0], args[7])
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatal("declared fixture retry eligibility aging", err)
			}
			latePID := launcher.run(t, caseCtx, f, provider, "audit-export-outbox", caPath, tokenPath)
			if latePID == publisherPID || latePID == executorPID {
				t.Fatal("late publisher was not a fresh process")
			}
			provider.mu.Lock()
			exactSend := provider.sends == 2 && len(provider.messages) == 2 && bytes.Equal(provider.messages[0].Body, provider.messages[1].Body) && provider.messages[0].Deleted && !provider.messages[1].Deleted
			secondID := ""
			if len(provider.messages) == 2 {
				secondID = provider.messages[1].ID
			}
			provider.mu.Unlock()
			if !exactSend {
				t.Fatal("late publication changed original immutable wakeup")
			}
			auditExportAssertProcessPublication(t, caseCtx, f, args, secondID, 2)
			launcher.run(t, caseCtx, f, provider, "audit-export", caPath, tokenPath)
			auditExportAssertProcessCompletionPublications(t, caseCtx, f, args, events, provider, 2, 2)
			if auditExportProcessExecutionSnapshot(t, caseCtx, f, args) != executionBefore {
				t.Fatal("late publisher or ready duplicate changed retained export authority")
			}
			t.Log("actual saved SDK Send/lost HTTP response produced fixed registered Retry30; executor completed before late publisher; explicit fixture availability aging then fresh generation2 confirmed the same bytes and duplicate Terminal caused no new object/audit")
		})
	}
}

func auditExportAssertProcessPublication(t *testing.T, ctx context.Context, f auditExportPG, args []any, messageID string, generation int) {
	t.Helper()
	ack, ok := jobqueue.CanonicalProviderAcknowledgement(messageID)
	if !ok {
		t.Fatal("invalid actual provider acknowledgement")
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT state='published' AND attempt=$4 AND generation=$4 AND provider_message_id=$3 FROM zasp_audit_export_outbox WHERE organization_id=$1 AND export_id=$2`, args[0], args[7], ack, generation).Scan(&exact); err != nil || !exact {
		t.Fatal("actual publication lacks durable exact confirmation", err)
	}
}

func auditExportProcessExecutionSnapshot(t *testing.T, ctx context.Context, f auditExportPG, args []any) string {
	t.Helper()
	var snapshot map[string]json.RawMessage
	if json.Unmarshal([]byte(auditExportProcessSQLSnapshot(t, ctx, f, args)), &snapshot) != nil {
		t.Fatal("invalid execution snapshot")
	}
	delete(snapshot, "outbox")
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func newAuditExportProcessLauncher(t *testing.T, ctx context.Context) *auditExportProcessLauncher {
	t.Helper()
	root, err := os.MkdirTemp("", "zasp-audit-export-process-")
	if err != nil {
		t.Fatal(err)
	}
	launcher := &auditExportProcessLauncher{root: root, binary: filepath.Join(root, "worker.test")}
	t.Cleanup(func() {
		if launcher.failed {
			t.Logf("retaining owned process root after failed command/join: %s", launcher.root)
			return
		}
		if err := os.RemoveAll(launcher.root); err != nil {
			t.Error("owned process root cleanup", err)
			return
		}
		if _, err := os.Stat(launcher.root); !os.IsNotExist(err) {
			t.Error("owned process root remains", err)
		}
	})
	command := exec.Command("go", "test", "-race", "-c", "-o", launcher.binary, "../agentsec-worker")
	output, err := runSandboxWorkerCommand(ctx, command)
	if err != nil {
		launcher.failed = true
		t.Fatalf("owned process compile: %v\n%s", err, output)
	}
	return launcher
}

func (l *auditExportProcessLauncher) run(t *testing.T, ctx context.Context, f auditExportPG, p *auditExportProcessProvider, mode, ca, token string) int {
	return l.runOutcome(t, ctx, f, p, mode, ca, token, "", false)
}

func (l *auditExportProcessLauncher) runOutcome(t *testing.T, ctx context.Context, f auditExportPG, p *auditExportProcessProvider, mode, ca, token, fault string, expectedError bool) int {
	t.Helper()
	target, err := url.Parse(f.admin.Config().ConnString())
	if err != nil || target.Scheme != "postgres" {
		t.Fatal("owned process DSN")
	}
	login := "audit_export_worker_fixture"
	if mode == "audit-export-outbox" {
		login = "audit_export_outbox_fixture"
	}
	target.User = url.User(login)
	command := exec.Command(l.binary, "-test.run=^TestAuditExportProcessWorkerPostgres$", "-test.v", "-test.count=1")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_PROCESS_DSN="+target.String(), "ZASP_AUDIT_EXPORT_PROCESS_MODE="+mode, "ZASP_AUDIT_EXPORT_PROCESS_ADDRESS="+p.server.Listener.Addr().String(), "ZASP_AUDIT_EXPORT_PROCESS_CA="+ca, "ZASP_AUDIT_EXPORT_PROCESS_TOKEN="+token)
	command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_PROCESS_FAULT="+fault)
	if expectedError {
		command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_PROCESS_OUTCOME=error")
	}
	runCtx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	output, err := runSandboxWorkerCommand(runCtx, command)
	if err != nil {
		l.failed = true
		t.Fatalf("owned production child: %v provider=%s\n%s", err, p.problem(), output)
	}
	marker := "registered parent-provider process completed: mode=" + mode + " pid="
	index := strings.Index(string(output), marker)
	if index < 0 || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "PASS") {
		t.Fatalf("process omitted real acceptance\n%s", output)
	}
	var pid int
	if _, err := fmt.Sscanf(string(output)[index+len(marker):], "%d", &pid); err != nil || command.Process == nil || pid != command.Process.Pid {
		t.Fatal("worker marker does not identify owned child")
	}
	t.Logf("owned process terminal:\n%s", output)
	return pid
}

func auditExportProcessSQLSnapshot(t *testing.T, ctx context.Context, f auditExportPG, args []any) string {
	t.Helper()
	var body string
	err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',(SELECT to_jsonb(j) FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM zasp_audit_export_outbox o WHERE organization_id=$1),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY ordinal) FROM zasp_audit_export_events e WHERE organization_id=$1),'chunks',(SELECT jsonb_agg(to_jsonb(c) ORDER BY ordinal) FROM zasp_audit_export_chunks c WHERE organization_id=$1),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY kind,ordinal) FROM zasp_audit_export_intents i WHERE organization_id=$1),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY kind,ordinal) FROM zasp_audit_export_receipts r WHERE organization_id=$1),'retries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY generation) FROM zasp_audit_export_retries r WHERE organization_id=$1),'audits',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM zasp_admin_audit a WHERE organization_id=$1 AND action IN('audit_export.request','audit_export.complete')))::text`, args[0], args[7]).Scan(&body)
	if err != nil {
		t.Fatal("process snapshot", err)
	}
	return body
}

func auditExportAssertProcessCompletion(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, p *auditExportProcessProvider, acks int) {
	auditExportAssertProcessCompletionPublications(t, ctx, f, args, events, p, acks, 1)
}

func auditExportAssertProcessCompletionPublications(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, p *auditExportProcessProvider, acks, sends int) {
	t.Helper()
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
	err = f.admin.QueryRow(ctx, `SELECT status='ready' AND captured AND attempt=1 AND generation=1 AND event_count=$3 AND chunk_count=$4 AND chunk_bytes=$5 AND manifest_bytes=$6 AND reserved_bytes=$5+octet_length($6::bytea) AND lease_worker IS NULL AND lease_token_digest IS NULL AND lease_expires_at IS NULL AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.id=j.completion_audit_id AND a.organization_id=j.organization_id AND a.workspace_id=j.workspace_id AND a.environment_id=j.environment_id AND a.actor_id=j.principal_id AND a.target_id=j.id AND a.action='audit_export.complete' AND a.outcome='succeeded' AND a.occurred_at=j.completed_at AND a.metadata=jsonb_build_object('event_count',$3::bigint,'chunk_count',$4::bigint,'chunk_bytes',$5::bigint,'manifest_sha256',$7::text)) AND (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete')=1 AND (SELECT count(*) FROM zasp_audit_export_retries WHERE organization_id=$1)=0 FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7], len(events), manifest.ChunkCount, manifest.ChunkBytes, expected["manifest:0"], hex.EncodeToString(hash[:])).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("ready authority/one completion differs from source", err)
	}
	rows, err := f.admin.Query(ctx, `SELECT i.kind,i.ordinal,i.object_reference,i.sha256,i.size_bytes,r.version_id,r.sha256,r.size_bytes FROM zasp_audit_export_intents i JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=$1 AND i.export_id=$2 ORDER BY i.kind,i.ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for rows.Next() {
		var kind, reference, version string
		var ordinal, size, receiptSize int64
		var digest, receiptDigest []byte
		if err := rows.Scan(&kind, &ordinal, &reference, &digest, &size, &version, &receiptDigest, &receiptSize); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		body, ok := expected[fmt.Sprintf("%s:%d", kind, ordinal)]
		sum := sha256.Sum256(body)
		p.mu.Lock()
		object, exists := p.objects[reference]
		p.mu.Unlock()
		if !ok || !exists || !bytes.Equal(body, object.Body) || object.Version != version || size != int64(len(body)) || receiptSize != size || !bytes.Equal(digest, sum[:]) || !bytes.Equal(receiptDigest, sum[:]) {
			rows.Close()
			t.Fatal("provider inventory and registered receipt differ from exact source")
		}
		seen++
	}
	rows.Close()
	if rows.Err() != nil || seen != len(expected) {
		t.Fatal("incomplete actual artifact receipts", rows.Err())
	}
	p.mu.Lock()
	terminal := p.sends == sends && p.receives == acks && p.deletes == acks && p.deleteAttempts == acks && len(p.objects) == len(expected) && p.puts == len(expected) && p.heads == 2*len(expected) && p.gets == 2*len(expected) && len(p.messages) == sends && p.failure == ""
	for _, message := range p.messages {
		terminal = terminal && message.Deleted
	}
	p.mu.Unlock()
	if !terminal {
		t.Fatal("process/provider effects changed or ACK preceded authority", p.problem())
	}
	var get json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, args[0], args[1], args[2], args[3], args[4], args[5], args[7], int64(1), nil, args[11], args[12]).Scan(&get); err != nil {
		t.Fatal("registered ready Get", err)
	}
	var envelope struct {
		Export    json.RawMessage `json:"export"`
		Authority struct {
			Chunk json.RawMessage `json:"chunk"`
		} `json:"authority"`
	}
	if json.Unmarshal(get, &envelope) != nil {
		t.Fatal("ready Get envelope")
	}
	descriptor, err := audit.DecodeExportDescriptor(envelope.Export)
	if err != nil || descriptor.Status != "ready" || descriptor.EventCount == nil || *descriptor.EventCount != int64(len(events)) || descriptor.ChunkCount == nil || *descriptor.ChunkCount != manifest.ChunkCount || descriptor.ManifestSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("registered ready descriptor", err)
	}
	if len(events) == 0 && !bytes.Equal(envelope.Authority.Chunk, []byte("null")) {
		t.Fatal("empty export invented a chunk")
	}
}
