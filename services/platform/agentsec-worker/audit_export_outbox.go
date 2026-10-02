package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
	"time"
)

type auditExportOutboxProcessorConfig struct {
	Authority                             *postgresAuditExportOutboxAuthority
	Publisher                             outboxPublisher
	WorkerID                              string
	LeaseSeconds, BatchSize, RetrySeconds int
	NewLeaseToken                         func() (string, error)
}
type auditExportOutboxProcessor struct {
	config auditExportOutboxProcessorConfig
}

func newAuditExportOutboxProcessor(config auditExportOutboxProcessorConfig) (*auditExportOutboxProcessor, error) {
	if config.Authority == nil || config.Authority.wire == nil || nilWorkerDependency(config.Authority.wire.database) || nilWorkerDependency(config.Publisher) || config.NewLeaseToken == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 60 || config.LeaseSeconds > 300 || config.BatchSize < 1 || config.BatchSize > 10 || config.RetrySeconds < 1 || config.RetrySeconds > 300 {
		return nil, errWorkerExecution
	}
	return &auditExportOutboxProcessor{config: config}, nil
}
func (p *auditExportOutboxProcessor) RunOnce(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
		}
	}()
	if p == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	token, err := p.config.NewLeaseToken()
	if err != nil || !validAuditExportLeaseToken(token) {
		return errWorkerExecution
	}
	leases, err := p.config.Authority.Claim(ctx, p.config.WorkerID, token, p.config.LeaseSeconds, p.config.BatchSize)
	if err != nil {
		return errWorkerExecution
	}
	if len(leases) == 0 {
		return nil
	}
	jobs := make([]jobqueue.Job, len(leases))
	deadline := time.Now().Add(30 * time.Second)
	for index, lease := range leases {
		job, err := auditExportWakeupJob(auditExportWakeup{Schema: auditExportWakeupSchema, OrganizationID: lease.Scope.OrganizationID().String(), WorkspaceID: lease.Scope.WorkspaceID().String(), EnvironmentID: lease.Scope.EnvironmentID().String(), ExportID: lease.ExportID, PolicyID: lease.PolicyID})
		if err != nil {
			return errWorkerExecution
		}
		jobs[index] = job
		if limit := lease.ExpiresAt.Add(-5 * time.Second); limit.Before(deadline) {
			deadline = limit
		}
	}
	if !deadline.After(time.Now()) {
		return errWorkerExecution
	}
	publishCtx, cancel := context.WithDeadline(ctx, deadline)
	result, publishErr := p.config.Publisher.PublishBatch(publishCtx, jobs)
	unknown := publishErr != nil || publishCtx.Err() != nil || !exactOutboxPublishResult(result, jobs)
	cancel()
	if unknown {
		// Uncertain publication never exhausts the export job. SQL retains durable
		// retries (attempt saturates100, generation advances). A canceled caller
		// cannot detach more SQL work; its existing lease expires for recovery.
		for _, lease := range leases {
			if p.config.Authority.Retry(ctx, lease, p.config.RetrySeconds) != nil {
				return errWorkerExecution
			}
		}
		return errWorkerExecution
	}
	for index, lease := range leases {
		if p.config.Authority.Finish(ctx, lease, result.Acknowledgements[index].ProviderAck) != nil {
			return errWorkerExecution
		}
	}
	if ctx.Err() != nil {
		return errWorkerExecution
	}
	return nil
}

const auditExportOutboxClaimSQL = `SELECT zasp_audit_export_claim_outbox($1,$2,$3,$4,$5,$6)`
const auditExportOutboxFinishSQL = `SELECT zasp_audit_export_finish_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
const auditExportOutboxRetrySQL = `SELECT zasp_audit_export_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`

type auditExportOutboxLease struct {
	Scope                        domain.Scope
	OutboxID, ExportID, PolicyID string
	Generation                   int64
	Attempt                      int
	ExpiresAt                    time.Time
	worker, token                string
	owner                        *postgresAuditExportOutboxAuthority
}
type postgresAuditExportOutboxAuthority struct {
	// Reuse only the bounded JSON transport. Outbox readiness is a separate
	// principal; no executor policy or executor authority operation is called.
	wire *postgresAuditExportAuthority
}

func newPostgresAuditExportOutboxAuthorityContext(ctx context.Context, database recoveryJSONDatabase) (*postgresAuditExportOutboxAuthority, error) {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(database) {
		return nil, errWorkerExecution
	}
	a := &postgresAuditExportOutboxAuthority{wire: &postgresAuditExportAuthority{database: database, checksum: migrations.ProductionAuditExports().Checksum(), fingerprint: migrations.ProductionAuditExportsSemanticFingerprint()}}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if a.Ready(ctx) != nil {
		return nil, errWorkerExecution
	}
	return a, nil
}
func newPostgresAuditExportOutboxAuthority(database recoveryJSONDatabase) (*postgresAuditExportOutboxAuthority, error) {
	return newPostgresAuditExportOutboxAuthorityContext(context.Background(), database)
}
func (a *postgresAuditExportOutboxAuthority) Ready(ctx context.Context) error {
	if a == nil || a.wire.runContextReady(ctx) != nil {
		return errWorkerExecution
	}
	body, err := a.wire.query(ctx, 16, auditExportWorkerReadySQL, a.wire.checksum, a.wire.fingerprint, "zasp_audit_export_outbox")
	if err != nil || !bytes.Equal(bytes.TrimSpace(body), []byte("true")) {
		return errWorkerExecution
	}
	return nil
}
func (a *postgresAuditExportOutboxAuthority) Claim(ctx context.Context, worker, token string, seconds, limit int) ([]auditExportOutboxLease, error) {
	if !validAuditExportWorkerCall(worker, token, seconds) || limit < 1 || limit > 10 || a.Ready(ctx) != nil {
		return nil, errWorkerExecution
	}
	body, err := a.wire.query(ctx, 16384, auditExportOutboxClaimSQL, worker, token, seconds, limit, a.wire.checksum, a.wire.fingerprint)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('[') {
		return nil, errWorkerExecution
	}
	leases := make([]auditExportOutboxLease, 0, limit)
	seenOutbox, seenExport := map[string]bool{}, map[string]bool{}
	for dec.More() {
		if len(leases) >= limit {
			return nil, errWorkerExecution
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return nil, errWorkerExecution
		}
		fields, err := auditExportWorkerObject(raw, 2048, "organization_id", "workspace_id", "environment_id", "outbox_id", "export_id", "policy_id", "generation", "attempt", "lease_expires_at")
		if err != nil {
			return nil, err
		}
		var w struct {
			OrganizationID string    `json:"organization_id"`
			WorkspaceID    string    `json:"workspace_id"`
			EnvironmentID  string    `json:"environment_id"`
			OutboxID       string    `json:"outbox_id"`
			ExportID       string    `json:"export_id"`
			PolicyID       string    `json:"policy_id"`
			Generation     int64     `json:"generation"`
			Attempt        int       `json:"attempt"`
			ExpiresAt      time.Time `json:"lease_expires_at"`
		}
		_ = fields
		if json.Unmarshal(raw, &w) != nil {
			return nil, errWorkerExecution
		}
		scope, ok := recoveryScope(w.OrganizationID, w.WorkspaceID, w.EnvironmentID)
		lease := auditExportOutboxLease{Scope: scope, OutboxID: w.OutboxID, ExportID: w.ExportID, PolicyID: w.PolicyID, Generation: w.Generation, Attempt: w.Attempt, ExpiresAt: w.ExpiresAt.UTC(), worker: worker, token: token, owner: a}
		if !ok || !a.validLease(lease) || !lease.ExpiresAt.Before(time.Now().Add(time.Duration(seconds)*time.Second+5*time.Second)) || seenOutbox[lease.OutboxID] || seenExport[lease.ExportID] {
			return nil, errWorkerExecution
		}
		seenOutbox[lease.OutboxID], seenExport[lease.ExportID] = true, true
		leases = append(leases, lease)
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim(']') || dec.Decode(new(any)) != io.EOF || ctx.Err() != nil {
		return nil, errWorkerExecution
	}
	return leases, nil
}
func (a *postgresAuditExportOutboxAuthority) validLease(lease auditExportOutboxLease) bool {
	return a != nil && a.wire != nil && lease.owner == a && lease.Scope.Validate() == nil && validRecoveryProductID(lease.OutboxID) && validRecoveryProductID(lease.ExportID) && validRecoveryProductID(lease.PolicyID) && lease.OutboxID != lease.ExportID && lease.Generation >= 1 && lease.Generation <= 9007199254740991 && lease.Attempt >= 1 && lease.Attempt <= 100 && validAuditExportWorkerCall(lease.worker, lease.token, 60) && lease.ExpiresAt.After(time.Now())
}
func (a *postgresAuditExportOutboxAuthority) transition(ctx context.Context, lease auditExportOutboxLease, sql, key string, value any) error {
	if !a.validLease(lease) || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	deadline := lease.ExpiresAt.Add(-5 * time.Second)
	if !deadline.After(time.Now()) {
		return errWorkerExecution
	}
	operation, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if a.Ready(operation) != nil {
		return errWorkerExecution
	}
	body, err := a.wire.query(operation, 64, sql, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.OutboxID, lease.worker, lease.token, lease.Generation, lease.Attempt, value, a.wire.checksum, a.wire.fingerprint)
	if err != nil {
		return err
	}
	fields, err := auditExportWorkerObject(body, 64, key)
	if err != nil || !bytes.Equal(bytes.TrimSpace(fields[key]), []byte("true")) || operation.Err() != nil {
		return errWorkerExecution
	}
	return nil
}
func (a *postgresAuditExportOutboxAuthority) Finish(ctx context.Context, lease auditExportOutboxLease, ack string) error {
	if !providerAckPattern.MatchString(ack) {
		return errWorkerExecution
	}
	return a.transition(ctx, lease, auditExportOutboxFinishSQL, "finished", ack)
}
func (a *postgresAuditExportOutboxAuthority) Retry(ctx context.Context, lease auditExportOutboxLease, seconds int) error {
	if seconds < 1 || seconds > 300 {
		return errWorkerExecution
	}
	return a.transition(ctx, lease, auditExportOutboxRetrySQL, "retried", seconds)
}
