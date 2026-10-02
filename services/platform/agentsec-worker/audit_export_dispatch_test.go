package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"strings"
	"testing"
	"time"
)

// Receipts come from real jobqueue decoding. This boundary wrapper can return
// hostile delivery combinations the dispatcher must refuse before execution.
type auditExportDispatchQueueFixture struct {
	queue      *jobqueue.Queue
	deliveries []jobqueue.Delivery
	acks       int
	afterAck   context.CancelFunc
}

func (q *auditExportDispatchQueueFixture) ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error) {
	return q.deliveries, nil
}
func (q *auditExportDispatchQueueFixture) ExtendVisibility(ctx context.Context, receipts []jobqueue.Receipt, visibility time.Duration) error {
	return q.queue.ExtendVisibility(ctx, receipts, visibility)
}
func (q *auditExportDispatchQueueFixture) AcknowledgeBatch(ctx context.Context, receipts []jobqueue.Receipt) error {
	q.acks++
	err := q.queue.AcknowledgeBatch(ctx, receipts)
	if q.afterAck != nil {
		q.afterAck()
	}
	return err
}

func TestAuditExportDispatcherValidatesWholeBatchBeforeAnyExecution(t *testing.T) {
	for _, failure := range []string{"unknown second policy", "duplicate job", "mismatched receipt", "empty receipt"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, true)
			executor, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			job := auditExportDispatchJobFixture(t, f)
			queue, _ := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, job)
			first, err := queue.ConsumeBatch(context.Background(), 1)
			if err != nil || len(first) != 1 {
				t.Fatal("fixture delivery", err)
			}
			secondJob := job
			secondJob.Payload = []byte(strings.Replace(strings.Replace(string(job.Payload), "pid_52000004-0000-4000-8000-000000000004", "pid_52000048-0000-4000-8000-000000000048", 1), "pid_52000041-0000-4000-8000-000000000041", "pid_52000049-0000-4000-8000-000000000049", 1))
			secondJob.JobID = workerID(t, "pid_52000048-0000-4000-8000-000000000048")
			secondJob.AuthorityDigest = sha256.Sum256(secondJob.Payload)
			otherQueue, _ := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, secondJob)
			second, err := otherQueue.ConsumeBatch(context.Background(), 1)
			if err != nil || len(second) != 1 {
				t.Fatal("fixture second delivery", err)
			}
			deliveries := []jobqueue.Delivery{first[0], second[0]}
			switch failure {
			case "duplicate job":
				deliveries[1] = first[0]
			case "mismatched receipt":
				deliveries = []jobqueue.Delivery{first[0]}
				deliveries[0].Receipt = second[0].Receipt
			case "empty receipt":
				deliveries = []jobqueue.Delivery{first[0]}
				deliveries[0].Receipt = jobqueue.Receipt{}
			}
			boundary := &auditExportDispatchQueueFixture{queue: queue, deliveries: deliveries}
			d, err := newAuditExportDispatcher(boundary, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: executor}, 2, 180*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			f.db.queries = nil
			if d.RunOnce(context.Background()) == nil || len(f.db.queries) != 0 || len(f.trace) != 0 || len(f.objects) != 0 || boundary.acks != 0 {
				t.Fatal("hostile later delivery permitted earlier execution or ACK")
			}
		})
	}
}

func TestAuditExportDispatcherRefusesCancellationAtQueueAckReturn(t *testing.T) {
	f := newAuditExportExecutionFixture(t, true)
	executor, err := newAuditExportExecutor(f.config)
	if err != nil {
		t.Fatal(err)
	}
	queue, _ := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, auditExportDispatchJobFixture(t, f))
	deliveries, err := queue.ConsumeBatch(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	boundary := &auditExportDispatchQueueFixture{queue: queue, deliveries: deliveries, afterAck: cancel}
	d, err := newAuditExportDispatcher(boundary, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: executor}, 1, 180*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d.RunOnce(ctx) == nil || !f.finished || boundary.acks != 1 {
		t.Fatal("canceled acknowledgement return was reported successful")
	}
}

func auditExportDispatchJobFixture(t *testing.T, f *auditExportExecutionFixture) jobqueue.Job {
	t.Helper()
	scope, ok := recoveryScope(f.lease.Binding.OrganizationID, f.lease.Binding.WorkspaceID, f.lease.Binding.EnvironmentID)
	if !ok {
		t.Fatal("scope")
	}
	// Literal protocol fixture; do not build the expected bytes with the encoder.
	body := []byte(`{"schema":"audit-export-wakeup-v1","organization_id":"pid_52000001-0000-4000-8000-000000000001","workspace_id":"pid_52000002-0000-4000-8000-000000000002","environment_id":"pid_52000003-0000-4000-8000-000000000003","export_id":"pid_52000004-0000-4000-8000-000000000004","policy_id":"pid_52000041-0000-4000-8000-000000000041"}`)
	return jobqueue.Job{Scope: scope, JobID: workerID(t, f.lease.Binding.ExportID), Kind: "audit-export", Payload: body, AuthorityDigest: sha256.Sum256(body)}
}

func TestAuditExportDispatcherRefusesUnknownPolicyWithoutCurrentFallback(t *testing.T) {
	for _, failure := range []string{"unknown policy", "busy", "capture lost", "put lost", "finish before commit", "finish lost", "provider cancellation", "unready"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, false)
			executor, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			job := auditExportDispatchJobFixture(t, f)
			if failure == "unknown policy" {
				job.Payload = []byte(strings.Replace(string(job.Payload), "pid_52000041-0000-4000-8000-000000000041", "pid_52000049-0000-4000-8000-000000000049", 1))
				job.AuthorityDigest = sha256.Sum256(job.Payload)
			} else {
				f.change = failure
			}
			if failure == "unready" {
				f.ready = false
			}
			queue, driver := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, job)
			d, err := newAuditExportDispatcher(queue, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: executor}, 1, 180*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancel = cancel
			f.db.queries = nil
			if d.RunOnce(ctx) == nil || driver.acknowledgements != 0 {
				t.Fatal("unconfirmed execution released queue receipt")
			}
			if failure == "unknown policy" && (len(f.db.queries) != 0 || len(f.trace) != 0) {
				t.Fatal("unknown policy reached database/provider")
			}
		})
	}
}

func TestAuditExportDispatcherFreezesHistoricalPolicySelection(t *testing.T) {
	historical := newAuditExportExecutionFixture(t, true)
	current := newAuditExportExecutionFixture(t, true)
	current.config.Policy.Configuration.PolicyID = "pid_52000049-0000-4000-8000-000000000049"
	var err error
	current.lease.Policy, err = auditExportPolicyWire(current.config.Policy.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	oldExecutor, err := newAuditExportExecutor(historical.config)
	if err != nil {
		t.Fatal(err)
	}
	currentExecutor, err := newAuditExportExecutor(current.config)
	if err != nil {
		t.Fatal(err)
	}
	queue, driver := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, auditExportDispatchJobFixture(t, historical))
	policies := map[string]*auditExportExecutor{historical.lease.Policy.PolicyID: oldExecutor, current.lease.Policy.PolicyID: currentExecutor}
	d, err := newAuditExportDispatcher(queue, policies, 1, 180*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Caller mutation cannot silently replace a historical policy/client pair.
	policies[historical.lease.Policy.PolicyID] = currentExecutor
	oldExecutor.config.Policy.Configuration.PolicyID = current.lease.Policy.PolicyID
	oldExecutor.authority.policy = current.lease.Policy
	historical.db.queries = nil
	current.db.queries = nil
	if d.RunOnce(context.Background()) != nil || !historical.finished || current.finished || len(current.db.queries) != 0 || driver.acknowledgements != 1 {
		t.Fatal("historical policy fell back to mutable/current configuration")
	}
}

func TestAuditExportWakeupRejectsUntrustedFieldsAndNoncanonicalPayloads(t *testing.T) {
	for _, failure := range []string{"kind", "zero digest", "wrong digest", "foreign org", "foreign workspace", "foreign environment", "foreign export", "unknown", "alias", "duplicate", "null", "wrong schema", "invalid policy", "missing", "reordered", "whitespace", "oversize", "trailing", "invalid utf8"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, true)
			job := auditExportDispatchJobFixture(t, f)
			body := string(job.Payload)
			switch failure {
			case "kind":
				job.Kind = "runtime"
			case "foreign org":
				body = strings.Replace(body, "pid_52000001-0000-4000-8000-000000000001", "pid_52000099-0000-4000-8000-000000000099", 1)
			case "foreign workspace":
				body = strings.Replace(body, "pid_52000002-0000-4000-8000-000000000002", "pid_52000099-0000-4000-8000-000000000099", 1)
			case "foreign environment":
				body = strings.Replace(body, "pid_52000003-0000-4000-8000-000000000003", "pid_52000099-0000-4000-8000-000000000099", 1)
			case "foreign export":
				body = strings.Replace(body, "pid_52000004-0000-4000-8000-000000000004", "pid_52000099-0000-4000-8000-000000000099", 1)
			case "unknown":
				body = strings.Replace(body, `"schema":`, `"bucket":"foreign","schema":`, 1)
			case "alias":
				body = strings.Replace(body, `"policy_id":`, `"Policy_ID":`, 1)
			case "duplicate":
				body = strings.Replace(body, `"schema":`, `"schema":"audit-export-wakeup-v1","schema":`, 1)
			case "null":
				body = strings.Replace(body, `"schema":"audit-export-wakeup-v1"`, `"schema":null`, 1)
			case "wrong schema":
				body = strings.Replace(body, "wakeup-v1", "wakeup-v2", 1)
			case "invalid policy":
				body = strings.Replace(body, "pid_52000041-0000-4000-8000-000000000041", "invalid", 1)
			case "missing":
				body = strings.Replace(body, `"schema":"audit-export-wakeup-v1",`, "", 1)
			case "reordered":
				body = strings.Replace(body, `"schema":"audit-export-wakeup-v1",`, "", 1)
				body = strings.TrimSuffix(body, "}") + `,"schema":"audit-export-wakeup-v1"}`
			case "whitespace":
				body = " " + body
			case "oversize":
				body = strings.Repeat(" ", 1025) + body
			case "trailing":
				body += " {}"
			case "invalid utf8":
				body = string([]byte{255})
			}
			job.Payload = []byte(body)
			job.AuthorityDigest = sha256.Sum256(job.Payload)
			if failure == "zero digest" {
				job.AuthorityDigest = [32]byte{}
			}
			if failure == "wrong digest" {
				job.AuthorityDigest = sha256.Sum256([]byte("different"))
			}
			if _, err := decodeAuditExportWakeup(job); err == nil {
				t.Fatal("untrusted wakeup accepted")
			}
		})
	}
}

func TestAuditExportDispatcherRejectsInvalidConfiguredPolicySelection(t *testing.T) {
	for _, failure := range []string{"nil queue", "typed nil queue", "empty", "nil executor", "wrong key", "unpaired policy", "invalid batch", "too many policies"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, true)
			e, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			queue, _ := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, auditExportDispatchJobFixture(t, f))
			var q auditExportDispatchQueue = queue
			policies := map[string]*auditExportExecutor{f.lease.Policy.PolicyID: e}
			batch := 1
			switch failure {
			case "nil queue":
				q = nil
			case "typed nil queue":
				var nilQueue *jobqueue.Queue
				q = nilQueue
			case "empty":
				policies = nil
			case "nil executor":
				policies[f.lease.Policy.PolicyID] = nil
			case "wrong key":
				policies = map[string]*auditExportExecutor{"unknown": e}
			case "unpaired policy":
				e.config.Policy.Configuration.MaximumExportBytes++
			case "invalid batch":
				batch = 11
			case "too many policies":
				for i := 0; i < 65; i++ {
					policies[strings.Repeat("x", i+1)] = e
				}
			}
			if _, err := newAuditExportDispatcher(q, policies, batch, 180*time.Second); err == nil {
				t.Fatal("invalid configured selection accepted")
			}
		})
	}
}

func TestAuditExportDispatcherAcknowledgesOnlyDurableExecutorCompletion(t *testing.T) {
	for _, lostAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "lost queue ack"}[lostAck], func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, false)
			executor, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			job := auditExportDispatchJobFixture(t, f)
			queue, driver := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, job)
			if lostAck {
				driver.failAcknowledgements = 1
			}
			dispatcher, err := newAuditExportDispatcher(queue, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: executor}, 1, 180*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			err = dispatcher.RunOnce(context.Background())
			if (err != nil) != lostAck || !f.finished || driver.acknowledgements != 1 {
				t.Fatalf("durable execute then queue ack missing: err=%v finished=%v ack=%d", err, f.finished, driver.acknowledgements)
			}
			f.trace = nil
			if dispatcher.RunOnce(context.Background()) != nil || driver.acknowledgements != 2 {
				t.Fatal("duplicate delivery failed")
			}
			if len(f.trace) != 2 || f.trace[0] != "claim" || f.trace[1] != "terminal" {
				t.Fatal("duplicate repeated provider work", f.trace)
			}
		})
	}
}

func TestAuditExportWakeupEncoderHasFixedCanonicalBinding(t *testing.T) {
	f := newAuditExportExecutionFixture(t, true)
	expected := auditExportDispatchJobFixture(t, f)
	var wakeup auditExportWakeup
	if json.Unmarshal(expected.Payload, &wakeup) != nil {
		t.Fatal("fixture")
	}
	actual, err := auditExportWakeupJob(wakeup)
	if err != nil || actual.Scope != expected.Scope || actual.JobID != expected.JobID || actual.Kind != "audit-export" || string(actual.Payload) != string(expected.Payload) || actual.AuthorityDigest != expected.AuthorityDigest {
		t.Fatal("canonical wakeup changed binding or bytes", err)
	}
}
