//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

// An >=100 lifetime-exhaustion shortcut must strand a visible queued export
// here. Every generation comes from an actual composed publisher RunOnce.
func TestAuditExportWorkerPostgresOutboxSaturatedSDKRetries(t *testing.T) {
	auditExportSaturationAcceptance(t, false)
}

// A real transport abort at the validated Send boundary must never earn the
// same E/received-500 evidence as an SDK InternalError response.
func TestAuditExportWorkerPostgresOutboxSaturationRejectsAbortedSend(t *testing.T) {
	auditExportSaturationAcceptance(t, true)
}

func auditExportSaturationAcceptance(t *testing.T, abort bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel() // The 10m test bound reserves two minutes for owned cleanup.
	launcher := newAuditExportProcessLauncher(t, ctx)
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	args := f.createArgs()
	var descriptor json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&descriptor); err != nil {
		t.Fatal("registered saturation Create", err)
	}
	events, _ := auditExportPrepareWorkerSource(t, ctx, f, args)
	provider := newAuditExportProcessProvider(t, ctx, f, worker, args, events)
	caPath, tokenPath := filepath.Join(t.TempDir(), "provider-ca.pem"), filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(auditExportProcessToken), 0600); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.failSendsRemaining = 103
	if abort {
		provider.failSendsRemaining = 1
		provider.abortNextFailedSend = true
	}
	provider.mu.Unlock()
	if abort {
		pid := launcher.runSaturation(t, ctx, f, provider, args, caPath, tokenPath, "abort1")
		t.Logf("validated actual SDK Send abort refused500credit: pid=%d RunOnce=1 received500=0 buffered500=0 saved=0; real pending Retry30, queued executor attempt0", pid)
		return
	}
	firstPID := launcher.runSaturation(t, ctx, f, provider, args, caPath, tokenPath, "first100")
	secondPID := launcher.runSaturation(t, ctx, f, provider, args, caPath, tokenPath, "last3")
	if firstPID == secondPID {
		t.Fatal("saturation boundary did not create a distinct publisher process")
	}
	// All 103 observations preceded this one successful publication. Only the
	// parent's availability aging makes retries eligible; no elapsed-backoff claim.
	publisherPID := launcher.run(t, ctx, f, provider, "audit-export-outbox", caPath, tokenPath)
	provider.mu.Lock()
	exactSends := provider.sendAttempts == 104 && provider.bufferedSendErrors == 103 && provider.abortedSends == 0 && provider.failSendsRemaining == 0 && provider.sends == 1 && len(provider.messages) == 1 && len(provider.objects) == 0
	messageID := ""
	if len(provider.messages) == 1 {
		messageID = provider.messages[0].ID
	}
	provider.mu.Unlock()
	ack, valid := jobqueue.CanonicalProviderAcknowledgement(messageID)
	var published bool
	if err := f.admin.QueryRow(ctx, `SELECT state='published' AND attempt=100 AND generation=104 AND provider_message_id=$3 AND (SELECT status='queued' AND attempt=0 AND generation=0 AND NOT captured AND completion_audit_id IS NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2) FROM zasp_audit_export_outbox WHERE organization_id=$1 AND export_id=$2`, args[0], args[7], ack).Scan(&published); err != nil || !published || !valid || !exactSends {
		t.Fatal("saturated publication did not recover queued work at generation104", err, published, exactSends, provider.problem())
	}
	executorPID := launcher.run(t, ctx, f, provider, "audit-export", caPath, tokenPath)
	if publisherPID == firstPID || publisherPID == secondPID || executorPID == publisherPID || executorPID == firstPID || executorPID == secondPID {
		t.Fatal("recovery publication/execution reused a saturation process")
	}
	auditExportAssertProcessCompletion(t, ctx, f, args, events, provider, 1)
	provider.mu.Lock()
	identities := provider.assumes["outbox"] == 3 && provider.assumes["worker"] == 1 && provider.identities["outbox"] >= 3 && provider.identities["worker"] >= 1
	provider.mu.Unlock()
	if !identities || provider.problem() != "" {
		t.Fatal("saturation restart mode identities", provider.problem())
	}
	t.Logf("saturation accepted: actual_failed_RunOnce=103 actual_received_SDK_500_InternalError=103 provider_buffered500=103 accepted_Send=1 publisher_calls=104 final_generation=104 final_attempt=100 first100_pid=%d last3_pid=%d publisher104_pid=%d executor_pid=%d; exact Retry30, parent fixture availability aging, executor attempt0 before consumption, exact completion/one ACK", firstPID, secondPID, publisherPID, executorPID)
}

type auditExportSaturationRow struct {
	State, Worker, JobStatus                              string
	Attempt, Generation, Retry, JobAttempt, JobGeneration int
	Digest                                                []byte
	Expiry, Available                                     time.Time
	Unpublished, Untouched                                bool
}

func auditExportSaturationReadRow(t *testing.T, ctx context.Context, f auditExportPG, args []any) auditExportSaturationRow {
	t.Helper()
	var row auditExportSaturationRow
	err := f.admin.QueryRow(ctx, `SELECT o.state,o.attempt,o.generation,COALESCE(o.retry_seconds,0),o.lease_worker,o.lease_token_digest,o.lease_expires_at,o.available_at,o.provider_message_id IS NULL,j.status,j.attempt,j.generation,NOT j.captured AND j.capture_id IS NULL AND j.completion_audit_id IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete') FROM zasp_audit_export_outbox o JOIN zasp_audit_export_jobs j ON j.organization_id=o.organization_id AND j.id=o.export_id WHERE o.organization_id=$1 AND o.export_id=$2`, args[0], args[7]).Scan(&row.State, &row.Attempt, &row.Generation, &row.Retry, &row.Worker, &row.Digest, &row.Expiry, &row.Available, &row.Unpublished, &row.JobStatus, &row.JobAttempt, &row.JobGeneration, &row.Untouched)
	if err != nil {
		t.Fatal("saturation owner observation", err)
	}
	return row
}

func auditExportSaturationAssertQueued(t *testing.T, row auditExportSaturationRow, call int) {
	t.Helper()
	if row.Generation != call || row.Attempt != min(call, 100) || !row.Unpublished || row.JobStatus != "queued" || row.JobAttempt != 0 || row.JobGeneration != 0 || !row.Untouched {
		t.Fatalf("saturation stranded/changed queued work: call=%d generation=%d attempt=%d state=%s retry=%d job=%s executor_attempt=%d executor_generation=%d unpublished=%t untouched=%t", call, row.Generation, row.Attempt, row.State, row.Retry, row.JobStatus, row.JobAttempt, row.JobGeneration, row.Unpublished, row.Untouched)
	}
}

func (l *auditExportProcessLauncher) runSaturation(t *testing.T, ctx context.Context, f auditExportPG, p *auditExportProcessProvider, args []any, ca, token, phase string) int {
	t.Helper()
	count, offset, budget := 100, 0, 5*time.Minute
	if phase == "last3" {
		count, offset, budget = 3, 100, 45*time.Second
	} else if phase == "abort1" {
		count, budget = 1, 45*time.Second
	} else if phase != "first100" {
		t.Fatal("invalid owner saturation phase")
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < budget {
		t.Fatal("insufficient parent budget to admit saturation phase", phase)
	}
	phaseCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	deadline, _ := phaseCtx.Deadline()
	releaseReader, releaseWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseReader.Close()
	defer releaseWriter.Close()
	resultReader, resultWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer resultReader.Close()
	defer resultWriter.Close()
	if err := releaseWriter.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := resultReader.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(f.admin.Config().ConnString())
	if err != nil || target.Scheme != "postgres" {
		t.Fatal("owned saturation DSN")
	}
	target.User = url.User("audit_export_outbox_fixture")
	command := exec.Command(l.binary, "-test.run=^TestAuditExportOutboxSaturationProcessWorkerPostgres$", "-test.v", "-test.count=1")
	command.ExtraFiles = []*os.File{releaseReader, resultWriter}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_PROCESS_DSN="+target.String(), "ZASP_AUDIT_EXPORT_PROCESS_MODE=audit-export-outbox", "ZASP_AUDIT_EXPORT_PROCESS_ADDRESS="+p.server.Listener.Addr().String(), "ZASP_AUDIT_EXPORT_PROCESS_CA="+ca, "ZASP_AUDIT_EXPORT_PROCESS_TOKEN="+token, "ZASP_AUDIT_EXPORT_SATURATION_PHASE="+phase, "ZASP_AUDIT_EXPORT_SATURATION_RELEASE_FD=3", "ZASP_AUDIT_EXPORT_SATURATION_RESULT_FD=4")
	sendReached, sendRelease := make(chan struct{}, 1), make(chan struct{})
	p.mu.Lock()
	p.beforeFailedSend = func(requestCtx context.Context) error {
		select {
		case sendReached <- struct{}{}:
		case <-requestCtx.Done():
			return requestCtx.Err()
		case <-phaseCtx.Done():
			return phaseCtx.Err()
		}
		select {
		case <-sendRelease:
			return nil
		case <-requestCtx.Done():
			return requestCtx.Err()
		case <-phaseCtx.Done():
			return phaseCtx.Err()
		}
	}
	p.mu.Unlock()
	type processResult struct {
		output []byte
		err    error
	}
	done, exited := make(chan processResult, 1), make(chan struct{})
	go func() {
		output, err := runSandboxWorkerCommand(phaseCtx, command)
		// These parent-side inherited ends must close even when Start fails.
		_ = releaseReader.Close()
		_ = resultWriter.Close()
		done <- processResult{output, err}
		close(exited)
	}()
	joined := false
	defer func() {
		cancel()
		close(sendRelease)
		_ = releaseWriter.Close()
		_ = resultReader.Close()
		if !joined {
			select {
			case result := <-done:
				joined = true
				if result.err != nil {
					l.failed = true
					t.Logf("saturation canceled child joined: %v\n%s", result.err, result.output)
				}
			case <-time.After(10 * time.Second):
				l.failed = true
				t.Error("saturation owned runner did not join; retain process root")
			}
		}
	}()
	for index := 1; index <= count; index++ {
		call := offset + index
		started := time.Now()
		if n, err := releaseWriter.Write([]byte{'N'}); err != nil || n != 1 {
			t.Fatal("saturation release write", call, err)
		}
		select {
		case <-sendReached:
		case <-exited:
			result := <-done
			joined = true
			l.failed = true
			row := auditExportSaturationReadRow(t, ctx, f, args)
			t.Fatalf("saturation child died before SDK Send: call=%d generation=%d attempt=%d state=%s retry=%d job=%s executor_attempt=%d error=%v\n%s", call, row.Generation, row.Attempt, row.State, row.Retry, row.JobStatus, row.JobAttempt, result.err, result.output)
		case <-phaseCtx.Done():
			t.Fatal("saturation Send barrier deadline", call, phaseCtx.Err())
		}
		leased := auditExportSaturationReadRow(t, phaseCtx, f, args)
		auditExportSaturationAssertQueued(t, leased, call)
		if leased.State != "leased" || leased.Retry != 0 || leased.Worker == "" || len(leased.Digest) != 32 || !leased.Expiry.After(time.Now()) {
			t.Fatal("actual Send lacked real bounded claim", call, leased.State, leased.Retry)
		}
		select {
		case sendRelease <- struct{}{}:
		case <-phaseCtx.Done():
			t.Fatal("saturation Send release deadline", call, phaseCtx.Err())
		}
		var completion [1]byte
		_, readErr := io.ReadFull(resultReader, completion[:])
		finished := time.Now()
		if readErr != nil {
			t.Fatal("saturation incomplete/false RunOnce completion", call, readErr, completion)
		}
		retried := auditExportSaturationReadRow(t, phaseCtx, f, args)
		auditExportSaturationAssertQueued(t, retried, call)
		if retried.State != "pending" || retried.Retry != 30 || retried.Worker != leased.Worker || !bytes.Equal(retried.Digest, leased.Digest) || !retried.Expiry.Equal(leased.Expiry) || retried.Available.Before(started.Add(30*time.Second)) || retried.Available.After(finished.Add(30*time.Second)) {
			t.Fatalf("saturation durable Retry30 or exact replay lease changed: call=%d generation=%d attempt=%d state=%s retry=%d job=%s executor_attempt=%d release=%s completion=%s available=%s", call, retried.Generation, retried.Attempt, retried.State, retried.Retry, retried.JobStatus, retried.JobAttempt, started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), retried.Available.Format(time.RFC3339Nano))
		}
		p.mu.Lock()
		exact := p.sendAttempts == call && p.sends == 0 && len(p.messages) == 0 && len(p.objects) == 0 && p.receives == 0 && p.deleteAttempts == 0
		if phase == "abort1" {
			exact = exact && p.bufferedSendErrors == 0 && p.abortedSends == 1 && p.failSendsRemaining == 0
		} else {
			exact = exact && p.bufferedSendErrors == call && p.abortedSends == 0 && p.failSendsRemaining == 103-call
		}
		p.mu.Unlock()
		if !exact || p.problem() != "" {
			t.Fatal("failed SDK Send was missing or saved queue work", call, p.problem())
		}
		expected := byte('E')
		if phase == "abort1" {
			expected = 'U'
		}
		if completion[0] != expected {
			t.Fatalf("SDK response evidence mismatch: phase=%s completion=%q expected=%q validatedSend=%d state=%s retry=%d job=%s executor_attempt=%d", phase, completion[0], expected, call, retried.State, retried.Retry, retried.JobStatus, retried.JobAttempt)
		}
		if phase == "abort1" {
			t.Log("actual validated connection abort produced no500 response; delegated SDK refused E credit and SQL retained Retry30")
			continue
		}
		t.Logf("saturation retry observed: call=%d generation=%d attempt=%d sdk_500=%d release=%s completion=%s available=%s executor_attempt=0 exact_replay_lease=true", call, retried.Generation, retried.Attempt, call, started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), retried.Available.Format(time.RFC3339Nano))
		// Explicit owner fixture eligibility aging, never authority/attempt seeding.
		tag, err := f.admin.Exec(phaseCtx, `UPDATE zasp_audit_export_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND export_id=$2 AND state='pending' AND generation=$3 AND retry_seconds=30`, args[0], args[7], call)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("declared saturation availability aging", call, err)
		}
	}
	_ = releaseWriter.Close() // Exact EOF proves no extra release beyond the phase.
	select {
	case result := <-done:
		joined = true
		if result.err != nil {
			l.failed = true
			t.Fatalf("owned saturation process: %v\n%s", result.err, result.output)
		}
		var extra [1]byte
		if n, err := resultReader.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal("saturation child emitted extra bytes or omitted EOF", n, err)
		}
		marker := fmt.Sprintf("registered saturation process completed: phase=%s calls=%d pid=", phase, count)
		index := strings.Index(string(result.output), marker)
		if index < 0 || strings.Contains(string(result.output), "--- SKIP:") || !strings.Contains(string(result.output), "PASS") {
			t.Fatalf("saturation child omitted real acceptance\n%s", result.output)
		}
		var pid int
		if _, err := fmt.Sscanf(string(result.output)[index+len(marker):], "%d", &pid); err != nil || command.Process == nil || pid != command.Process.Pid {
			t.Fatal("saturation child marker identity mismatch")
		}
		t.Logf("owned saturation terminal:\n%s", result.output)
		return pid
	case <-phaseCtx.Done():
		t.Fatal("saturation child terminal deadline", phaseCtx.Err())
	}
	return 0
}
