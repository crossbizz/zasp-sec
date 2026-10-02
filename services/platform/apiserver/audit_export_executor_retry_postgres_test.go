//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These cases catch scheduled retry being reported as success, skipped fifth
// completion, and released issued bytes. Only the parent owns fixture authority.
func TestAuditExportWorkerPostgresRetrySDKFaultAgreement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel() // Two minutes remain under the 10m Go bound for owned cleanup.
	launcher := newAuditExportProcessLauncher(t, ctx)
	t.Cleanup(func() {
		if t.Failed() {
			launcher.failed = true
		}
	})
	for _, name := range []string{"scheduled-retry-recovery", "committed-retry-response-loss", "five-attempt-saved-object", "direct-retry-zero"} {
		t.Run(name, func(t *testing.T) {
			caseCtx, stop := context.WithTimeout(ctx, 100*time.Second)
			defer stop()
			f := auditExportPGFixture(t, caseCtx)
			f.register(t, caseCtx)
			worker, _ := auditExportWorkerConnections(t, caseCtx, f)
			args := f.createArgs()
			var created json.RawMessage
			if err := f.api.QueryRow(caseCtx, postgresAuditExportCreateSQL, args...).Scan(&created); err != nil {
				t.Fatal("registered retry Create", err)
			}
			events, _ := auditExportPrepareWorkerSource(t, caseCtx, f, args)
			p := newAuditExportProcessProvider(t, caseCtx, f, worker, args, events)
			ca, token := filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(auditExportProcessToken), 0600); err != nil {
				t.Fatal(err)
			}
			launcher.run(t, caseCtx, f, p, "audit-export-outbox", ca, token)
			p.mu.Lock()
			messageID := p.messages[0].ID
			p.mu.Unlock()
			auditExportAssertProcessPublication(t, caseCtx, f, args, messageID, 1)
			permanent, direct := name == "five-attempt-saved-object", name == "direct-retry-zero"
			p.mu.Lock()
			p.executorPutFault = !direct
			p.executorSaveFault = permanent
			p.expectedFailedTerminal = permanent || direct
			p.mu.Unlock()
			// A separate parent observer checks the completion and accounting before
			// Delete is accepted. No worker-supplied success enters this proof.
			gate, err := pgx.ConnectConfig(caseCtx, f.admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				p.server.Close() // All synchronous children have already joined.
				closeCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
				defer done()
				if err := gate.Close(closeCtx); err != nil {
					t.Error("retry ACK observer cleanup", err)
				}
			}()
			failureAttempt := 5
			if direct {
				failureAttempt = 1
			}
			p.mu.Lock()
			p.beforeFailedACK = func(ctx context.Context) error {
				return auditExportExecutorFailureProof(ctx, gate, args, failureAttempt, !direct)
			}
			p.mu.Unlock()
			if direct {
				report := launcher.runExecutorRetry(t, caseCtx, f, p, args, ca, token, "direct-retry-zero")
				auditExportExecutorAssertRetry(t, caseCtx, f, args, report, 1, 0, true, time.Time{}, time.Time{})
				if report.Claims != 1 || report.Captures != 0 || report.RunError || report.Put500 != 0 || report.Head500 != 0 {
					t.Fatal("Retry0 was not a separate live Go authority call", report)
				}
				auditExportExecutorAssertQueue(t, p, 0, 0, 0, 0)
				before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
				duplicate := launcher.runExecutorRetry(t, caseCtx, f, p, args, ca, token, "terminal-duplicate")
				auditExportExecutorAssertDuplicate(t, duplicate, report.PID)
				if auditExportProcessSQLSnapshot(t, caseCtx, f, args) != before {
					t.Fatal("Retry0 terminal consumer rewrote failed job")
				}
				auditExportExecutorAssertQueue(t, p, 1, 1, 0, 0)
				t.Logf("direct Retry0 accepted: live registered claim pid=%d, immutable failed receipt, no capture/provider I/O, terminal consumer pid=%d; not production Retry30", report.PID, duplicate.PID)
				return
			}
			attempts := 1
			if permanent {
				attempts = 5
			}
			frozen := ""
			var saved auditExportProcessObject
			previousPID := 0
			for attempt := 1; attempt <= attempts; attempt++ {
				phase := "sdk-error"
				if name == "committed-retry-response-loss" {
					phase = "retry-response-loss"
				}
				if attempt == 5 {
					phase = "terminal-failure"
				}
				started := time.Now()
				report := launcher.runExecutorRetry(t, caseCtx, f, p, args, ca, token, phase)
				finished := time.Now()
				if report.PID == previousPID {
					t.Fatal("retry did not create a fresh process")
				}
				previousPID = report.PID
				if problem := p.problem(); problem != "" {
					t.Logf("provider rejected ACK: %s", problem)
				}
				// Assert durable rows/ACK attempts before consulting reported RunOnce.
				auditExportExecutorAssertRetry(t, caseCtx, f, args, report, attempt, 30, attempt == 5, started, finished)
				acks := 0
				if attempt == 5 {
					acks = 1
				}
				auditExportExecutorAssertQueue(t, p, attempt, acks, attempt, boolInt(permanent))
				wantLoss := 0
				if phase == "retry-response-loss" {
					wantLoss = 1
				}
				if report.Put500 != 1 || report.Head500 != 1 || report.Claims != 1 || report.NullClaims != 0 || report.Captures != 1 || report.Finishes != 0 || report.Losses != wantLoss || report.RunError != (attempt < 5) {
					t.Fatal("actual delegated SDK/Retry agreement", report)
				}
				current := auditExportExecutorFrozenSnapshot(t, caseCtx, f, args)
				if attempt == 1 {
					frozen = current
					auditExportExecutorAssertIntent(t, caseCtx, f, args, events, p, permanent)
					if permanent {
						p.mu.Lock()
						saved = p.objects[p.executorFaultReference]
						saved.Body = bytes.Clone(saved.Body)
						saved.Headers = saved.Headers.Clone()
						p.mu.Unlock()
					}
					// Owner-only disposable source mutation after actual capture. It
					// changes every old source row and adds a new one, not frozen data.
					tag, err := f.admin.Exec(caseCtx, `UPDATE zasp_admin_audit SET target_id='changed after first capture',metadata='{"counter":99}' WHERE organization_id=$1`, args[0])
					if err != nil || tag.RowsAffected() != int64(len(events)) {
						t.Fatal("fixture source mutation", err)
					}
					_, err = f.admin.Exec(caseCtx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,'pid_53000099-0000-4000-8000-000000000099',$4,'integration.webhook','new after capture','succeeded','{}')`, args[0], args[1], args[2], args[3])
					if err != nil {
						t.Fatal("fixture source append", err)
					}
				} else if current != frozen {
					t.Fatal("retry recaptured or rebound frozen rows/plan/policy/issued intent")
				}
				if permanent {
					p.mu.Lock()
					object := p.objects[p.executorFaultReference]
					p.mu.Unlock()
					if object.Version != saved.Version || !bytes.Equal(object.Body, saved.Body) || !headersEqual(object.Headers, saved.Headers) {
						t.Fatal("later fault replaced saved immutable version")
					}
				}
				if attempt < attempts {
					auditExportExecutorAge(t, caseCtx, f, args, p)
				}
			}
			if permanent {
				if err := auditExportExecutorFailureProof(caseCtx, f.admin, args, 5, true); err != nil {
					t.Fatal(err)
				}
				before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
				p.redeliver(t)
				replay := launcher.runExecutorRetry(t, caseCtx, f, p, args, ca, token, "terminal-duplicate")
				auditExportExecutorAssertDuplicate(t, replay, previousPID)
				auditExportExecutorAssertQueue(t, p, 6, 2, 5, 1)
				if auditExportProcessSQLSnapshot(t, caseCtx, f, args) != before || auditExportExecutorFrozenSnapshot(t, caseCtx, f, args) != frozen {
					t.Fatal("failed Terminal duplicate consumed sixth attempt or rewrote retained state")
				}
				t.Logf("five actual execution attempts: Put500+discoveryHead500 each, frozen source retained, one saved version/no receipt, exact issued bytes retained, one rejected execution_failed before ACK; fresh Terminal pid=%d, no sixth attempt; outage/accounting proof, not saved-object recovery", replay.PID)
				return
			}
			// Make only queue visibility eligible first. The real worker must see
			// claim-null/nonterminal and return error without advancing Retry30.
			before := auditExportProcessSQLSnapshot(t, caseCtx, f, args)
			p.mu.Lock()
			p.messages[0].Visible = time.Time{}
			p.mu.Unlock()
			early := launcher.runExecutorRetry(t, caseCtx, f, p, args, ca, token, "early-nonterminal")
			if early.Claims != 0 || early.NullClaims != 1 || early.Terminal != "nonterminal" || !early.RunError || early.Retries != 0 || early.Put500 != 0 || early.Head500 != 0 || auditExportProcessSQLSnapshot(t, caseCtx, f, args) != before {
				t.Fatal("early actual claim bypassed fixed availability/nonterminal", early)
			}
			auditExportExecutorAssertQueue(t, p, 2, 0, 1, 0)
			auditExportExecutorAge(t, caseCtx, f, args, p)
			p.mu.Lock()
			p.executorPutFault = false
			p.mu.Unlock()
			recovery := launcher.runExecutorRetry(t, caseCtx, f, p, args, ca, token, "recovery")
			if recovery.PID == previousPID || recovery.PID == early.PID || recovery.RunError || recovery.Claims != 1 || recovery.Captures != 1 || recovery.Retries != 0 || recovery.Finishes != 1 || recovery.Put500 != 0 || recovery.Head500 != 0 {
				t.Fatal("fresh recovery did not finish actual captured job", recovery)
			}
			auditExportExecutorAssertRecovery(t, caseCtx, f, args, events, p)
			if auditExportExecutorFrozenSnapshot(t, caseCtx, f, args) != frozen {
				t.Fatal("fresh recovery changed capture/plan/policy/first intent")
			}
			t.Logf("%s accepted: registered Retry30, fixed available_at and cleared lease, actual early nonterminal/no ACK, fixture-only aging, fresh pid=%d finishes original capture bytes", name, recovery.PID)
		})
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func headersEqual(left, right map[string][]string) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}

type auditExportExecutorReport struct {
	PID, Put500, Head500, Claims, NullClaims, Captures, Retries, Losses, Finishes int
	RunError                                                                      bool
	Terminal                                                                      string
	RetryBody                                                                     json.RawMessage
	Worker, TokenDigest, PolicyID, PolicyDigest, CaptureID                        string
	Generation                                                                    int64
	Attempt, Seconds                                                              int
}

func (l *auditExportProcessLauncher) runExecutorRetry(t *testing.T, ctx context.Context, f auditExportPG, p *auditExportProcessProvider, args []any, ca, token, phase string) auditExportExecutorReport {
	t.Helper()
	target, err := url.Parse(f.admin.Config().ConnString())
	if err != nil || target.Scheme != "postgres" {
		t.Fatal("owned retry DSN")
	}
	target.User = url.User("audit_export_worker_fixture")
	command := exec.Command(l.binary, "-test.run=^TestAuditExportExecutorRetryProcessWorkerPostgres$", "-test.v", "-test.count=1")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") && !strings.HasPrefix(entry, "DATABASE_URL=") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_PROCESS_DSN="+target.String(), "ZASP_AUDIT_EXPORT_PROCESS_MODE=audit-export", "ZASP_AUDIT_EXPORT_PROCESS_ADDRESS="+p.server.Listener.Addr().String(), "ZASP_AUDIT_EXPORT_PROCESS_CA="+ca, "ZASP_AUDIT_EXPORT_PROCESS_TOKEN="+token, "ZASP_AUDIT_EXPORT_EXECUTOR_RETRY_PHASE="+phase, "ZASP_AUDIT_EXPORT_WORKER_TEST_ORG="+args[0].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_WORKSPACE="+args[1].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_ENVIRONMENT="+args[2].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_EXPORT="+args[7].(string))
	runCtx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	output, err := runSandboxWorkerCommand(runCtx, command)
	if err != nil {
		l.failed = true
		t.Fatalf("owned retry child: %v provider=%s\n%s", err, p.problem(), output)
	}
	marker := "registered executor retry result: "
	index := strings.Index(string(output), marker)
	if index < 0 || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "PASS") {
		t.Fatalf("retry child omitted real acceptance\n%s", output)
	}
	line := strings.SplitN(string(output)[index+len(marker):], "\n", 2)[0]
	var report auditExportExecutorReport
	if json.Unmarshal([]byte(line), &report) != nil || command.Process == nil || report.PID != command.Process.Pid {
		t.Fatal("retry result does not identify owned child")
	}
	t.Logf("owned retry terminal: phase=%s\n%s", phase, output)
	return report
}

func auditExportExecutorAssertRetry(t *testing.T, ctx context.Context, f auditExportPG, args []any, report auditExportExecutorReport, attempt, seconds int, failed bool, started, finished time.Time) {
	t.Helper()
	var exact bool
	var available *time.Time
	err := f.admin.QueryRow(ctx, `SELECT j.attempt=$3 AND j.generation=$3 AND j.lease_worker IS NULL AND j.lease_token_digest IS NULL AND j.lease_expires_at IS NULL AND r.attempt=$3 AND r.retry_seconds=$4 AND r.worker_name=$5 AND encode(r.token_digest,'hex')=$6 AND r.capture_id=j.capture_id AND r.capture_id=$7 AND r.workspace_id=j.workspace_id AND r.environment_id=j.environment_id AND j.policy_id=$8 AND j.storage_policy->>'policy_digest'=$9 AND (SELECT count(*) FROM zasp_audit_export_retries WHERE organization_id=$1 AND export_id=$2)=$3 AND CASE WHEN $10 THEN j.status='failed' AND r.state='failed' AND r.available_at IS NULL AND r.completion_audit_id=j.completion_audit_id ELSE j.status='processing' AND j.captured AND r.state='retry' AND r.available_at=j.available_at AND r.completion_audit_id IS NULL AND j.completion_audit_id IS NULL AND j.reserved_bytes=j.chunk_bytes+octet_length(j.manifest_bytes) END,r.available_at FROM zasp_audit_export_jobs j JOIN zasp_audit_export_retries r ON r.organization_id=j.organization_id AND r.export_id=j.id AND r.generation=j.generation WHERE j.organization_id=$1 AND j.id=$2`, args[0], args[7], attempt, seconds, report.Worker, report.TokenDigest, report.CaptureID, report.PolicyID, report.PolicyDigest, failed).Scan(&exact, &available)
	if err != nil || !exact {
		t.Fatal("persisted Retry receipt/lease/accounting agreement failed", err, "attempt", attempt, "seconds", seconds)
	}
	policy := auditExportTestPolicy()
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	if report.PolicyID != policy.PolicyID || report.PolicyDigest != digest || report.Attempt != attempt || report.Generation != int64(attempt) || report.Seconds != seconds || report.Retries != 1 {
		t.Fatal("Retry changed trusted policy or exact SQL15 lease inputs", report)
	}
	var body struct {
		State     string  `json:"state"`
		Failure   *string `json:"failure_code"`
		Available *string `json:"available_at"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(report.RetryBody, &body) != nil || json.Unmarshal(report.RetryBody, &fields) != nil || len(fields) != 3 {
		t.Fatal("real Retry response not closed")
	}
	if failed {
		if body.State != "failed" || body.Failure == nil || *body.Failure != "execution_failed" || body.Available != nil || available != nil {
			t.Fatal("real failed Retry result")
		}
		if err := auditExportExecutorFailureProof(ctx, f.admin, args, attempt, seconds != 0); err != nil {
			t.Fatal(err)
		}
	} else {
		if body.State != "retry" || body.Failure != nil || body.Available == nil || available == nil {
			t.Fatal("real scheduled Retry result")
		}
		stamp, err := time.Parse("2006-01-02T15:04:05.000000Z", *body.Available)
		if err != nil || !stamp.Equal(*available) || stamp.Before(started.Add(30*time.Second)) || stamp.After(finished.Add(30*time.Second)) {
			t.Fatal("Retry30 fixed availability differs from actual SQL response", err)
		}
	}
}

func auditExportExecutorFailureProof(ctx context.Context, conn *pgx.Conn, args []any, attempt int, captured bool) error {
	var exact bool
	err := conn.QueryRow(ctx, `SELECT status='failed' AND failure_code='execution_failed' AND attempt=$3 AND generation=$3 AND captured=$4 AND lease_worker IS NULL AND lease_token_digest IS NULL AND lease_expires_at IS NULL AND reserved_bytes=(SELECT COALESCE(sum(size_bytes),0) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2) AND CASE WHEN $4 THEN reserved_bytes>0 AND reserved_bytes<chunk_bytes+octet_length(manifest_bytes) ELSE reserved_bytes=0 END AND (SELECT count(*) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2)=CASE WHEN $4 THEN 1 ELSE 0 END AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2) AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.id=j.completion_audit_id AND a.organization_id=j.organization_id AND a.workspace_id=j.workspace_id AND a.environment_id=j.environment_id AND a.actor_id=j.principal_id AND a.target_id=j.id AND a.action='audit_export.complete' AND a.outcome='rejected' AND a.occurred_at=j.completed_at AND a.metadata=jsonb_build_object('failure_code','execution_failed')) AND (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete')=1 FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7], attempt, captured).Scan(&exact)
	if err != nil || !exact {
		var state string
		var retained, issued, receipts int64
		diagnostic := conn.QueryRow(ctx, `SELECT status,reserved_bytes,(SELECT COALESCE(sum(size_bytes),0) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2),(SELECT count(*) FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2) FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&state, &retained, &issued, &receipts)
		return fmt.Errorf("independent failed completion/issued-byte proof: exact=%t state=%s retained=%d issued=%d receipts=%d err=%v diagnostic=%v", exact, state, retained, issued, receipts, err, diagnostic)
	}
	return nil
}

func auditExportExecutorAssertQueue(t *testing.T, p *auditExportProcessProvider, receives, acks, puts, objects int) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.receives != receives || p.deletes != acks || p.deleteAttempts != acks || p.puts != puts || len(p.objects) != objects || p.sends != 1 || len(p.messages) != 1 || p.messages[0].Deleted != (acks > 0) || p.failure != "" {
		t.Fatalf("persisted-state/ACK effects differ: receives=%d deletes=%d deleteAttempts=%d puts=%d objects=%d failure=%s", p.receives, p.deletes, p.deleteAttempts, p.puts, len(p.objects), p.failure)
	}
}

func auditExportExecutorFrozenSnapshot(t *testing.T, ctx context.Context, f auditExportPG, args []any) string {
	t.Helper()
	var result string
	err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('header',jsonb_build_array(capture_id,captured,captured_at,event_count,chunk_count,chunk_bytes,chain_root,manifest_bytes,policy_id,storage_policy),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY ordinal) FROM zasp_audit_export_events e WHERE organization_id=$1 AND export_id=$2),'plan',(SELECT jsonb_agg(to_jsonb(c) ORDER BY ordinal) FROM zasp_audit_export_chunks c WHERE organization_id=$1 AND export_id=$2),'first_intent',(SELECT to_jsonb(i) FROM zasp_audit_export_intents i WHERE organization_id=$1 AND export_id=$2 AND kind='chunk' AND ordinal=1))::text FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&result)
	if err != nil {
		t.Fatal("retained retry snapshot", err)
	}
	return result
}

func auditExportExecutorAssertIntent(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, p *auditExportProcessProvider, saved bool) {
	t.Helper()
	var capture, reference string
	var digest []byte
	var size int64
	var exact bool
	err := f.admin.QueryRow(ctx, `SELECT i.capture_id,i.object_reference,i.sha256,i.size_bytes,(SELECT count(*) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2)=1 AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2) FROM zasp_audit_export_intents i WHERE organization_id=$1 AND export_id=$2 AND kind='chunk' AND ordinal=1`, args[0], args[7]).Scan(&capture, &reference, &digest, &size, &exact)
	if err != nil || !exact {
		t.Fatal("issued/no-receipt authority", err)
	}
	expected, err := auditExportProcessExpected(audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string), CaptureID: capture}, events)
	if err != nil {
		t.Fatal(err)
	}
	auditExportExecutorAssertFrozenSource(t, ctx, f, args, events, expected)
	body := expected["chunk:1"]
	sum := sha256.Sum256(body)
	p.mu.Lock()
	object, exists := p.objects[reference]
	faultRef := p.executorFaultReference
	p.mu.Unlock()
	if size != int64(len(body)) || !bytes.Equal(digest, sum[:]) || reference != faultRef || exists != saved || saved && (!bytes.Equal(object.Body, body) || object.Version == "") {
		t.Fatal("issued bytes/provider differ from independent original source")
	}
}

func auditExportExecutorAssertFrozenSource(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, expected map[string][]byte) {
	t.Helper()
	rows, err := f.admin.Query(ctx, `SELECT ordinal,canonical_event FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2 ORDER BY ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var ordinal int64
		var body []byte
		if err := rows.Scan(&ordinal, &body); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if count >= len(events) || ordinal != int64(count+1) || !bytes.Equal(body, events[count]) {
			rows.Close()
			t.Fatal("frozen row differs from independently projected original source")
		}
		count++
	}
	rows.Close()
	if rows.Err() != nil || count != len(events) {
		t.Fatal("frozen source coverage", rows.Err())
	}
	rows, err = f.admin.Query(ctx, `SELECT ordinal,first_event,event_count,previous_digest,sha256,size_bytes FROM zasp_audit_export_chunks WHERE organization_id=$1 AND export_id=$2 ORDER BY ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	count = 0
	for rows.Next() {
		var ordinal, first, n, size int64
		var previous, digest []byte
		if err := rows.Scan(&ordinal, &first, &n, &previous, &digest, &size); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		body, ok := expected[fmt.Sprintf("chunk:%d", ordinal)]
		sum := sha256.Sum256(body)
		chunk, decodeErr := audit.DecodeExportChunk(body)
		if !ok || decodeErr != nil || ordinal != int64(count+1) || first != chunk.FirstEvent || n != chunk.EventCount || fmt.Sprintf("%x", previous) != chunk.PreviousDigest || !bytes.Equal(digest, sum[:]) || size != int64(len(body)) {
			rows.Close()
			t.Fatal("frozen chunk plan differs from source")
		}
		count++
	}
	rows.Close()
	if rows.Err() != nil || count != len(expected)-1 {
		t.Fatal("frozen plan coverage", rows.Err())
	}
	manifest, err := audit.DecodeExportManifest(expected["manifest:0"])
	if err != nil {
		t.Fatal(err)
	}
	var exact bool
	err = f.admin.QueryRow(ctx, `SELECT captured AND event_count=$3 AND chunk_count=$4 AND chunk_bytes=$5 AND encode(chain_root,'hex')=$6 AND manifest_bytes=$7 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7], len(events), manifest.ChunkCount, manifest.ChunkBytes, manifest.ChainRoot, expected["manifest:0"]).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("frozen manifest/header differs from source", err)
	}
}

func auditExportExecutorAge(t *testing.T, ctx context.Context, f auditExportPG, args []any, p *auditExportProcessProvider) {
	t.Helper()
	// Fixture-only eligibility aging, after the parent checked a real Retry.
	tag, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2 AND status='processing' AND lease_worker IS NULL AND EXISTS(SELECT 1 FROM zasp_audit_export_retries r WHERE r.organization_id=$1 AND r.export_id=$2 AND r.generation=zasp_audit_export_jobs.generation AND r.state='retry')`, args[0], args[7])
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("fixture-only executor availability aging", err)
	}
	p.mu.Lock()
	p.messages[0].Visible = time.Time{}
	p.mu.Unlock()
}

func auditExportExecutorAssertDuplicate(t *testing.T, r auditExportExecutorReport, priorPID int) {
	t.Helper()
	if r.PID == priorPID || r.RunError || r.Claims != 0 || r.NullClaims != 1 || r.Terminal != "failed" || r.Captures != 0 || r.Retries != 0 || r.Finishes != 0 || r.Put500 != 0 || r.Head500 != 0 {
		t.Fatal("fresh duplicate did not resolve actual Terminal failed", r)
	}
}

func auditExportExecutorAssertRecovery(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, p *auditExportProcessProvider) {
	t.Helper()
	var capture string
	var exact bool
	err := f.admin.QueryRow(ctx, `SELECT capture_id,status='ready' AND captured AND attempt=2 AND generation=2 AND event_count=$3 AND reserved_bytes=chunk_bytes+octet_length(manifest_bytes) AND lease_worker IS NULL AND lease_token_digest IS NULL AND lease_expires_at IS NULL AND (SELECT count(*) FROM zasp_audit_export_retries WHERE organization_id=$1 AND export_id=$2)=1 AND (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete')=1 AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.id=j.completion_audit_id AND a.organization_id=j.organization_id AND a.action='audit_export.complete' AND a.outcome='succeeded' AND a.actor_id=j.principal_id AND a.target_id=j.id AND a.occurred_at=j.completed_at) FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7], len(events)).Scan(&capture, &exact)
	if err != nil || !exact {
		t.Fatal("fresh recovery durable ready authority", err)
	}
	expected, err := auditExportProcessExpected(audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string), CaptureID: capture}, events)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.admin.Query(ctx, `SELECT i.kind,i.ordinal,i.object_reference,i.sha256,i.size_bytes,r.version_id,r.sha256,r.size_bytes FROM zasp_audit_export_intents i JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=$1 AND i.export_id=$2 ORDER BY i.kind,i.ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for rows.Next() {
		var kind, ref, version string
		var ordinal, size, receiptSize int64
		var digest, receiptDigest []byte
		if err := rows.Scan(&kind, &ordinal, &ref, &digest, &size, &version, &receiptDigest, &receiptSize); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		body, ok := expected[fmt.Sprintf("%s:%d", kind, ordinal)]
		sum := sha256.Sum256(body)
		p.mu.Lock()
		object, exists := p.objects[ref]
		p.mu.Unlock()
		if !ok || !exists || !bytes.Equal(body, object.Body) || version != object.Version || size != int64(len(body)) || receiptSize != size || !bytes.Equal(digest, sum[:]) || !bytes.Equal(receiptDigest, sum[:]) {
			rows.Close()
			t.Fatal("recovery artifacts differ from original frozen source/receipts")
		}
		seen++
	}
	rows.Close()
	if rows.Err() != nil || seen != len(expected) {
		t.Fatal("recovery receipt coverage", rows.Err())
	}
	auditExportExecutorAssertQueue(t, p, 3, 1, 1+len(expected), len(expected))
}
