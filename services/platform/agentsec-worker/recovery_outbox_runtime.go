package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	recoveryBackupOutboxTopic  = "recovery-backup-jobs"
	recoveryRestoreOutboxTopic = "recovery-restore-jobs"
)

var recoveryTargetEnvironmentPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

const (
	recoveryOutboxReadySQL     = `SELECT to_jsonb(zasp_recovery_execution_readiness($1,$2) AND zasp_recovery_principal_ready('zasp_recovery_outbox_worker'))`
	recoveryOutboxClaimSQL     = `SELECT zasp_recovery_claim_outbox($1,$2,$3,$4,$5)`
	recoveryOutboxHeartbeatSQL = `SELECT zasp_recovery_heartbeat_outbox($1,$2,$3,$4,$5)`
	recoveryOutboxAckSQL       = `SELECT zasp_recovery_ack_outbox($1,$2,$3,$4,$5,$6,$7)`
	recoveryOutboxRetrySQL     = `SELECT zasp_recovery_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8)`
)

type recoveryOutboxEvent struct {
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	EnvironmentID  string          `json:"environment_id"`
	ID             string          `json:"outbox_id"`
	Topic          string          `json:"topic"`
	Payload        json.RawMessage `json:"payload"`
	PayloadDigest  string          `json:"payload_digest"`
	Attempt        int             `json:"attempt"`
	LeaseExpiresAt time.Time       `json:"lease_expires_at"`
}

type recoveryOutboxAuthority interface {
	Ready(context.Context) error
	Claim(context.Context, string, string, string, int, int) ([]recoveryOutboxEvent, error)
	Heartbeat(context.Context, string, string, string, int, int) error
	Acknowledge(context.Context, domain.Scope, string, string, string, string) error
	Retry(context.Context, domain.Scope, string, string, string, int, string) error
}

type postgresRecoveryOutboxAuthority struct {
	database    recoveryJSONDatabase
	checksum    string
	fingerprint string
}

func newPostgresRecoveryOutboxAuthority(database recoveryJSONDatabase) (*postgresRecoveryOutboxAuthority, error) {
	if database == nil {
		return nil, errRuntimeUnavailable
	}
	authority := &postgresRecoveryOutboxAuthority{database: database, checksum: migrations.ProductionRecovery().Checksum(), fingerprint: migrations.ProductionRecoverySemanticFingerprint()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if authority.Ready(ctx) != nil {
		return nil, errRuntimeUnavailable
	}
	return authority, nil
}

func (authority *postgresRecoveryOutboxAuthority) Ready(ctx context.Context) error {
	if authority == nil || authority.database == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryOutboxReadySQL, authority.checksum, authority.fingerprint)
	var ready bool
	if err != nil || decodeStrictWorkerJSON(payload, &ready) != nil || !ready {
		return errRuntimeUnavailable
	}
	return nil
}

func (authority *postgresRecoveryOutboxAuthority) Claim(ctx context.Context, topic, worker, token string, leaseSeconds, limit int) ([]recoveryOutboxEvent, error) {
	if !validRecoveryOutboxCall(authority, ctx, topic, worker, token, leaseSeconds) || limit < 1 || limit > 25 {
		return nil, errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryOutboxClaimSQL, topic, worker, []byte(token), leaseSeconds, limit)
	var envelope struct {
		Items []recoveryOutboxEvent `json:"items"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return nil, errWorkerExecution
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validRecoveryOutboxEvent(*item, topic, leaseSeconds) {
			return nil, errWorkerExecution
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}

func (authority *postgresRecoveryOutboxAuthority) Heartbeat(ctx context.Context, topic, worker, token string, leaseSeconds, expected int) error {
	if !validRecoveryOutboxCall(authority, ctx, topic, worker, token, leaseSeconds) || expected < 1 || expected > 25 {
		return errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryOutboxHeartbeatSQL, topic, worker, []byte(token), leaseSeconds, expected)
	var result struct {
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
		Renewed        int       `json:"renewed"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.Renewed != expected || !validRecoveryLeaseExpiration(result.LeaseExpiresAt, leaseSeconds) {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOutboxAuthority) Acknowledge(ctx context.Context, scope domain.Scope, id, worker, token, ack string) error {
	if authority == nil || authority.database == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validRecoveryProductID(id) || !workerIdentityPattern.MatchString(worker) || len(token) != 32 || !providerAckPattern.MatchString(ack) {
		return errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryOutboxAckSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, []byte(token), ack)
	var result struct {
		Replayed bool `json:"replayed"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOutboxAuthority) Retry(ctx context.Context, scope domain.Scope, id, worker, token string, retrySeconds int, code string) error {
	if authority == nil || authority.database == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validRecoveryProductID(id) || !workerIdentityPattern.MatchString(worker) || len(token) != 32 || retrySeconds < 1 || retrySeconds > 86400 || code != "queue_publish_unknown" {
		return errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryOutboxRetrySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, []byte(token), retrySeconds, code)
	var result struct {
		State string `json:"state"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.State != "retryable" && result.State != "exhausted" {
		return errWorkerExecution
	}
	return nil
}

func validRecoveryOutboxCall(authority *postgresRecoveryOutboxAuthority, ctx context.Context, topic, worker, token string, leaseSeconds int) bool {
	return authority != nil && authority.database != nil && ctx != nil && ctx.Err() == nil && (topic == recoveryBackupOutboxTopic || topic == recoveryRestoreOutboxTopic) && workerIdentityPattern.MatchString(worker) && len(token) == 32 && leaseSeconds >= 5 && leaseSeconds <= 900
}

type recoveryOutboxProcessorConfig struct {
	Authority         recoveryOutboxAuthority
	Publisher         outboxPublisher
	Topic             string
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	RetrySeconds      int
	HeartbeatInterval time.Duration
	NewLeaseToken     func() (string, error)
}

type recoveryOutboxProcessor struct{ config recoveryOutboxProcessorConfig }

func newRecoveryOutboxProcessor(config recoveryOutboxProcessorConfig) (*recoveryOutboxProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	if config.Authority == nil || config.Publisher == nil || config.NewLeaseToken == nil || config.Topic != recoveryBackupOutboxTopic && config.Topic != recoveryRestoreOutboxTopic || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 25 || config.RetrySeconds < 1 || config.RetrySeconds > 86400 || config.HeartbeatInterval < time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 {
		return nil, errWorkerExecution
	}
	return &recoveryOutboxProcessor{config: config}, nil
}

func (processor *recoveryOutboxProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil || processor.config.Authority.Ready(ctx) != nil {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	events, err := processor.config.Authority.Claim(ctx, processor.config.Topic, processor.config.WorkerID, token, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil || len(events) > processor.config.BatchSize {
		return errWorkerExecution
	}
	if len(events) == 0 {
		return nil
	}
	jobs := make([]jobqueue.Job, len(events))
	scopes := make([]domain.Scope, len(events))
	seen := make(map[string]struct{}, len(events))
	for index, event := range events {
		job, scope, ok := recoveryJobForOutbox(event, processor.config.Topic)
		if !ok {
			return errWorkerExecution
		}
		if _, duplicate := seen[event.ID]; duplicate {
			return errWorkerExecution
		}
		seen[event.ID] = struct{}{}
		jobs[index], scopes[index] = job, scope
	}
	if processor.config.Authority.Heartbeat(ctx, processor.config.Topic, processor.config.WorkerID, token, processor.config.LeaseSeconds, len(events)) != nil {
		return errWorkerExecution
	}
	var remaining atomic.Int64
	remaining.Store(int64(len(events)))
	var transitionMu sync.Mutex
	leaseCtx, cancelLease := context.WithCancel(context.WithoutCancel(ctx))
	publishCtx, cancelPublish := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go processor.keepLease(leaseCtx, token, &remaining, &transitionMu, cancelPublish, heartbeatDone)
	result, publishErr := processor.config.Publisher.PublishBatch(publishCtx, jobs)
	cancelPublish()
	finalizeCtx, cancelFinalize := context.WithTimeout(leaseCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancelFinalize()
	if publishErr != nil || !exactOutboxPublishResult(result, jobs) {
		for index, event := range events {
			transitionMu.Lock()
			before := int(remaining.Load())
			if processor.config.Authority.Heartbeat(finalizeCtx, processor.config.Topic, processor.config.WorkerID, token, processor.config.LeaseSeconds, before) != nil || processor.config.Authority.Retry(finalizeCtx, scopes[index], event.ID, processor.config.WorkerID, token, processor.config.RetrySeconds, "queue_publish_unknown") != nil {
				transitionMu.Unlock()
				cancelLease()
				<-heartbeatDone
				return errWorkerExecution
			}
			remaining.Add(-1)
			transitionMu.Unlock()
		}
		cancelLease()
		<-heartbeatDone
		return errWorkerExecution
	}
	for index, event := range events {
		transitionMu.Lock()
		before := int(remaining.Load())
		if processor.config.Authority.Heartbeat(finalizeCtx, processor.config.Topic, processor.config.WorkerID, token, processor.config.LeaseSeconds, before) != nil || processor.config.Authority.Acknowledge(finalizeCtx, scopes[index], event.ID, processor.config.WorkerID, token, result.Acknowledgements[index].ProviderAck) != nil {
			transitionMu.Unlock()
			cancelLease()
			<-heartbeatDone
			return errWorkerExecution
		}
		remaining.Add(-1)
		transitionMu.Unlock()
	}
	cancelLease()
	if err := <-heartbeatDone; err != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *recoveryOutboxProcessor) keepLease(ctx context.Context, token string, remaining *atomic.Int64, transitionMu *sync.Mutex, cancelPublish context.CancelFunc, done chan<- error) {
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			transitionMu.Lock()
			count := int(remaining.Load())
			if count == 0 {
				transitionMu.Unlock()
				done <- nil
				return
			}
			err := processor.config.Authority.Heartbeat(ctx, processor.config.Topic, processor.config.WorkerID, token, processor.config.LeaseSeconds, count)
			transitionMu.Unlock()
			if err != nil {
				cancelPublish()
				done <- errWorkerExecution
				return
			}
		}
	}
}

type recoveryBackupOutboxPayload struct {
	BackupID       string `json:"backup_id"`
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
}

type recoveryRestoreOutboxPayload struct {
	EnvironmentID     string `json:"environment_id"`
	OrganizationID    string `json:"organization_id"`
	RestoreID         string `json:"restore_id"`
	TargetEnvironment string `json:"target_environment"`
	WorkspaceID       string `json:"workspace_id"`
}

func recoveryJobForOutbox(event recoveryOutboxEvent, expectedTopic string) (jobqueue.Job, domain.Scope, bool) {
	if !validRecoveryOutboxEvent(event, expectedTopic, 900) {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	scope, ok := recoveryScope(event.OrganizationID, event.WorkspaceID, event.EnvironmentID)
	if !ok {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var operationID string
	kind := ""
	if expectedTopic == recoveryBackupOutboxTopic {
		var payload recoveryBackupOutboxPayload
		if decodeExactRecoveryOutboxPayload(event.Payload, &payload) != nil || payload.OrganizationID != event.OrganizationID || payload.WorkspaceID != event.WorkspaceID || payload.EnvironmentID != event.EnvironmentID {
			return jobqueue.Job{}, domain.Scope{}, false
		}
		operationID, kind = payload.BackupID, "recovery-backup"
	} else {
		var payload recoveryRestoreOutboxPayload
		if decodeExactRecoveryOutboxPayload(event.Payload, &payload) != nil || payload.OrganizationID != event.OrganizationID || payload.WorkspaceID != event.WorkspaceID || payload.EnvironmentID != event.EnvironmentID || !recoveryTargetEnvironmentPattern.MatchString(payload.TargetEnvironment) || payload.TargetEnvironment == "production" || payload.TargetEnvironment == event.EnvironmentID {
			return jobqueue.Job{}, domain.Scope{}, false
		}
		operationID, kind = payload.RestoreID, "recovery-restore"
	}
	jobID, err := domain.ParseProductID(operationID)
	if err != nil || jobID.IsZero() {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var canonical bytes.Buffer
	if json.Compact(&canonical, event.Payload) != nil || canonical.Len() == 0 {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	payload := canonical.Bytes()
	digest := sha256.Sum256(payload)
	return jobqueue.Job{Scope: scope, JobID: jobID, Kind: kind, Payload: bytes.Clone(payload), AuthorityDigest: digest}, scope, true
}

func validRecoveryOutboxEvent(event recoveryOutboxEvent, expectedTopic string, leaseSeconds int) bool {
	digest := sha256.Sum256(event.Payload)
	wantDigest := `\x` + hex.EncodeToString(digest[:])
	_, scopeOK := recoveryScope(event.OrganizationID, event.WorkspaceID, event.EnvironmentID)
	return scopeOK && validRecoveryProductID(event.ID) && event.Topic == expectedTopic && (expectedTopic == recoveryBackupOutboxTopic || expectedTopic == recoveryRestoreOutboxTopic) && len(event.Payload) >= 2 && len(event.Payload) <= 65536 && json.Valid(event.Payload) && recoveryRequestDigestPattern.MatchString(event.PayloadDigest) && event.PayloadDigest != `\x`+strings.Repeat("0", 64) && subtle.ConstantTimeCompare([]byte(event.PayloadDigest), []byte(wantDigest)) == 1 && event.Attempt >= 1 && event.Attempt <= 100 && validRecoveryLeaseExpiration(event.LeaseExpiresAt, leaseSeconds)
}

func validRecoveryLeaseExpiration(value time.Time, leaseSeconds int) bool {
	now := time.Now().UTC()
	return !value.IsZero() && value.Location() == time.UTC && value.After(now) && value.Before(now.Add(time.Duration(leaseSeconds)*time.Second+5*time.Second))
}

func validRecoveryProductID(value string) bool {
	identifier, err := domain.ParseProductID(value)
	return err == nil && !identifier.IsZero()
}

func decodeExactRecoveryOutboxPayload(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errWorkerExecution
	}
	return nil
}

var _ recoveryOutboxAuthority = (*postgresRecoveryOutboxAuthority)(nil)
var _ workerProcessor = (*recoveryOutboxProcessor)(nil)
