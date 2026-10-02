package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"time"
)

const auditExportTopic = "audit-exports"
const auditExportWakeupSchema = "audit-export-wakeup-v1"

type auditExportWakeup struct {
	Schema         string `json:"schema"`
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	ExportID       string `json:"export_id"`
	PolicyID       string `json:"policy_id"`
}
type auditExportDispatchQueue interface {
	ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error)
	AcknowledgeBatch(context.Context, []jobqueue.Receipt) error
	jobqueue.VisibilityExtender
}
type auditExportDispatcher struct {
	queue      auditExportDispatchQueue
	executors  map[string]*auditExportExecutor
	batch      int
	newTicker  func(time.Duration) (<-chan time.Time, func())
	visibility time.Duration
}

func newAuditExportDispatcher(queue auditExportDispatchQueue, executors map[string]*auditExportExecutor, batch int, visibility time.Duration) (*auditExportDispatcher, error) {
	if nilWorkerDependency(queue) || len(executors) < 1 || len(executors) > 64 || batch < 1 || batch > 10 || visibility < 60*time.Second || visibility > 300*time.Second || visibility%time.Second != 0 {
		return nil, errWorkerExecution
	}
	selected := make(map[string]*auditExportExecutor, len(executors))
	for id, executor := range executors {
		if executor == nil || executor.authority == nil || id != executor.config.Policy.Configuration.PolicyID || id != executor.authority.policy.PolicyID || nilWorkerDependency(executor.config.Policy.Store) || nilWorkerDependency(executor.config.Database) || executor.config.NewLeaseToken == nil {
			return nil, errWorkerExecution
		}
		wire, err := auditExportPolicyWire(executor.config.Policy.Configuration)
		if err != nil || wire != executor.authority.policy {
			return nil, errWorkerExecution
		}
		// Capture immutable policy/configuration values, not the caller's map or
		// mutable executor struct. Configured provider/database clients remain owned
		// by the production composition; payloads never supply those clients.
		copyExecutor := *executor
		copyAuthority := *executor.authority
		copyExecutor.authority = &copyAuthority
		selected[id] = &copyExecutor
	}
	return &auditExportDispatcher{queue: queue, executors: selected, batch: batch, visibility: visibility, newTicker: func(cadence time.Duration) (<-chan time.Time, func()) {
		ticker := time.NewTicker(cadence)
		return ticker.C, ticker.Stop
	}}, nil
}
func (d *auditExportDispatcher) RunOnce(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
		}
	}()
	if d == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	deliveries, err := d.queue.ConsumeBatch(ctx, d.batch)
	if err != nil || ctx.Err() != nil || len(deliveries) > d.batch {
		return errWorkerExecution
	}
	selected := make([]*auditExportExecutor, len(deliveries))
	seen := make(map[string]bool, len(deliveries))
	for index, delivery := range deliveries {
		wakeup, err := decodeAuditExportWakeup(delivery.Job)
		executor := d.executors[wakeup.PolicyID]
		if err != nil || executor == nil || delivery.Receipt.JobID() != delivery.Job.JobID || delivery.Receipt.MessageKey() == "" || seen[delivery.Job.JobID.String()] {
			return errWorkerExecution
		}
		seen[delivery.Job.JobID.String()] = true
		selected[index] = executor
	}
	if len(deliveries) == 0 {
		return nil
	}
	workCtx, cancel := context.WithCancel(ctx)
	ready, done := make(chan struct{}), make(chan struct{})
	outcome := make(chan error, 1)
	acks := make(chan auditExportReceiptACK)
	go func() {
		var ownerErr error
		defer close(done)
		defer func() {
			if recover() != nil {
				ownerErr = errWorkerExecution
			}
			if ownerErr != nil {
				cancel()
			}
			outcome <- ownerErr
		}()
		ownerErr = d.ownReceipts(workCtx, deliveries, ready, acks)
	}()
	defer func() {
		cancel()
		// A timeout is not a join. Keep runtime active-call ownership until the
		// owner really exits, even for a noncooperating queue dependency.
		<-done
		if <-outcome != nil || ctx.Err() != nil {
			resultErr = errWorkerExecution
		}
	}()
	select {
	case <-ready:
	case <-done:
		return errWorkerExecution
	case <-ctx.Done():
		return errWorkerExecution
	}
	for index, delivery := range deliveries {
		if workCtx.Err() != nil || selected[index].Execute(workCtx, delivery.Job.Scope, delivery.Job.JobID.String()) != nil || workCtx.Err() != nil {
			return errWorkerExecution
		}
		// Only the executor's verified durable terminal result can release a queue
		// receipt. Lost ACKs are replayed through Terminal on the next delivery.
		ack := auditExportReceiptACK{index: index, done: make(chan struct{})}
		select {
		case acks <- ack:
		case <-done:
			return errWorkerExecution
		case <-workCtx.Done():
			return errWorkerExecution
		}
		select {
		case <-ack.done:
		case <-done:
			if workCtx.Err() != nil {
				return errWorkerExecution
			}
		case <-workCtx.Done():
			return errWorkerExecution
		}
	}
	<-done
	return nil
}

type auditExportReceiptACK struct {
	index int
	done  chan struct{}
}

// One owner serializes renewal and deletion for all pending receipts. This is
// queue authority only: capture deadlines and SQL lease authority are unchanged.
func (d *auditExportDispatcher) ownReceipts(ctx context.Context, deliveries []jobqueue.Delivery, ready chan<- struct{}, acks <-chan auditExportReceiptACK) error {
	pending := make([]jobqueue.Receipt, len(deliveries))
	for i, delivery := range deliveries {
		pending[i] = delivery.Receipt
	}
	renew := func() error {
		bounded, cancel := context.WithTimeout(ctx, min(d.visibility/6, 30*time.Second))
		defer cancel()
		if err := d.queue.ExtendVisibility(bounded, pending, d.visibility); err != nil || bounded.Err() != nil {
			return errWorkerExecution
		}
		return nil
	}
	if renew() != nil {
		return errWorkerExecution
	}
	pulses, stop := d.newTicker(d.visibility / 3)
	defer stop()
	close(ready)
	next := 0
	for len(pending) > 0 {
		select {
		case <-ctx.Done():
			return errWorkerExecution
		case <-pulses:
			// Always latch the completed call's failure, including after cancel.
			if renew() != nil {
				return errWorkerExecution
			}
		case ack := <-acks:
			if ack.index != next || ctx.Err() != nil || renew() != nil {
				return errWorkerExecution
			}
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := d.queue.AcknowledgeBatch(bounded, pending[:1])
			expired := bounded.Err() != nil
			cancel()
			if err != nil || expired {
				return errWorkerExecution
			}
			pending = pending[1:]
			next++
			close(ack.done)
		}
	}
	if ctx.Err() != nil {
		return errWorkerExecution
	}
	return nil
}
func auditExportWakeupJob(wakeup auditExportWakeup) (jobqueue.Job, error) {
	scope, ok := recoveryScope(wakeup.OrganizationID, wakeup.WorkspaceID, wakeup.EnvironmentID)
	id, err := domain.ParseProductID(wakeup.ExportID)
	if !ok || err != nil || id.IsZero() || !validRecoveryProductID(wakeup.PolicyID) || wakeup.Schema != auditExportWakeupSchema {
		return jobqueue.Job{}, errWorkerExecution
	}
	body, err := json.Marshal(wakeup)
	if err != nil || len(body) > 1024 {
		return jobqueue.Job{}, errWorkerExecution
	}
	return jobqueue.Job{Scope: scope, JobID: id, Kind: "audit-export", Payload: body, AuthorityDigest: sha256.Sum256(body)}, nil
}
func decodeAuditExportWakeup(job jobqueue.Job) (auditExportWakeup, error) {
	if job.Kind != "audit-export" || job.Scope.Validate() != nil || job.JobID.IsZero() || job.AuthorityDigest != sha256.Sum256(job.Payload) {
		return auditExportWakeup{}, errWorkerExecution
	}
	if _, err := auditExportWorkerObject(job.Payload, 1024, "schema", "organization_id", "workspace_id", "environment_id", "export_id", "policy_id"); err != nil {
		return auditExportWakeup{}, err
	}
	var wakeup auditExportWakeup
	if json.Unmarshal(job.Payload, &wakeup) != nil {
		return auditExportWakeup{}, errWorkerExecution
	}
	canonical, err := auditExportWakeupJob(wakeup)
	if err != nil || canonical.Scope != job.Scope || canonical.JobID != job.JobID || !bytes.Equal(canonical.Payload, job.Payload) {
		return auditExportWakeup{}, errWorkerExecution
	}
	return wakeup, nil
}
