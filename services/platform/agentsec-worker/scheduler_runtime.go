package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type schedulerAuthority interface {
	ClaimDiscoverySchedules(context.Context, string, string, int, int) ([]apiserver.DiscoveryScheduleLease, error)
	GetDiscoveryScheduleInput(context.Context, domain.Scope, string, string, string) (apiserver.ExecutionScheduleInput, error)
	RequestScheduledSync(context.Context, apiserver.RequestIdentity, apiserver.ScheduledSyncRequest) (apiserver.SyncRequestResult, error)
	CompleteDiscoverySchedule(context.Context, domain.Scope, apiserver.DiscoveryScheduleCompletion) (apiserver.DiscoveryScheduleCompletionResult, error)
}

type schedulerProcessorConfig struct {
	Authority     schedulerAuthority
	WorkerID      string
	LeaseSeconds  int
	BatchSize     int
	ParserVersion string
	ToolVersion   string
	Now           func() time.Time
	NewLeaseToken func() (string, error)
}

type schedulerProcessor struct{ config schedulerProcessorConfig }

func newSchedulerProcessor(config schedulerProcessorConfig) (*schedulerProcessor, error) {
	if config.Authority == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 64 || !workerVersionPattern.MatchString(config.ParserVersion) || !workerVersionPattern.MatchString(config.ToolVersion) || config.Now == nil || config.NewLeaseToken == nil {
		return nil, errWorkerExecution
	}
	return &schedulerProcessor{config: config}, nil
}

func (processor *schedulerProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) < 16 || len(token) > 128 {
		return errWorkerExecution
	}
	leases, err := processor.config.Authority.ClaimDiscoverySchedules(ctx, processor.config.WorkerID, token, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil {
		return errWorkerExecution
	}
	results := make(chan error, len(leases))
	for _, lease := range leases {
		lease := lease
		go func() { results <- processor.process(ctx, lease, token) }()
	}
	failed := false
	for range leases {
		if err := <-results; err != nil {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (processor *schedulerProcessor) process(ctx context.Context, lease apiserver.DiscoveryScheduleLease, token string) error {
	scope, ok := executionScope(lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID)
	if !ok {
		return errWorkerExecution
	}
	input, err := processor.config.Authority.GetDiscoveryScheduleInput(ctx, scope, lease.ID, processor.config.WorkerID, token)
	if err != nil {
		return errWorkerExecution
	}
	request, identity, ok := scheduledRequest(scope, input, processor.config.ParserVersion, processor.config.ToolVersion)
	if !ok {
		return errWorkerExecution
	}
	_, err = processor.config.Authority.RequestScheduledSync(ctx, identity, apiserver.ScheduledSyncRequest{ScheduleID: input.ScheduleID, Worker: processor.config.WorkerID, LeaseToken: token, SyncRequest: request})
	if err != nil {
		_, _ = processor.config.Authority.CompleteDiscoverySchedule(ctx, scope, apiserver.DiscoveryScheduleCompletion{ID: input.ScheduleID, Worker: processor.config.WorkerID, LeaseToken: token, Outcome: "released", NextRunAt: input.NextRunAt.UTC()})
		return errWorkerExecution
	}
	now := processor.config.Now()
	if now.IsZero() || now.Location() != time.UTC {
		return errWorkerExecution
	}
	next, ok := nextScheduledRun(input.NextRunAt.UTC(), now, input.CadenceSeconds)
	if !ok {
		return errWorkerExecution
	}
	completed, err := processor.config.Authority.CompleteDiscoverySchedule(ctx, scope, apiserver.DiscoveryScheduleCompletion{ID: input.ScheduleID, Worker: processor.config.WorkerID, LeaseToken: token, Outcome: "advanced", NextRunAt: next})
	if err != nil || completed.State != "enabled" || !completed.NextRunAt.Equal(next) {
		return errWorkerExecution
	}
	return nil
}

func nextScheduledRun(previous, now time.Time, cadenceSeconds int) (time.Time, bool) {
	if previous.IsZero() || now.IsZero() || previous.Location() != time.UTC || now.Location() != time.UTC || cadenceSeconds < 300 || cadenceSeconds > 2_678_400 {
		return time.Time{}, false
	}
	cadence := time.Duration(cadenceSeconds) * time.Second
	if previous.After(now) {
		return previous, true
	}
	elapsed := now.Sub(previous)
	if elapsed == time.Duration(math.MaxInt64) {
		return time.Time{}, false
	}
	intervals := elapsed/cadence + 1
	if int64(intervals) > math.MaxInt64/int64(cadence) {
		return time.Time{}, false
	}
	next := previous.Add(intervals * cadence)
	return next, next.After(now)
}

func scheduledRequest(scope domain.Scope, input apiserver.ExecutionScheduleInput, parserVersion, toolVersion string) (apiserver.SyncRequest, apiserver.RequestIdentity, bool) {
	principal, principalErr := domain.ParseProductID(input.ScheduleID)
	if scope.Validate() != nil || principalErr != nil || input.NextRunAt.IsZero() || input.NextRunAt.Location() != time.UTC || input.CadenceSeconds < 300 || input.CadenceSeconds > 2_678_400 || input.Version < 1 {
		return apiserver.SyncRequest{}, apiserver.RequestIdentity{}, false
	}
	seed := strings.Join([]string{input.ScheduleID, input.IntegrationID, input.NextRunAt.Format(time.RFC3339Nano), strconv.FormatInt(input.Version, 10)}, "\x1f")
	syncID, syncErr := apiserver.CanonicalDiscoveryID(scope, "scheduled_sync", seed)
	jobID, jobErr := apiserver.CanonicalDiscoveryID(scope, "scheduled_job", seed)
	outboxID, outboxErr := apiserver.CanonicalDiscoveryID(scope, "scheduled_outbox", seed)
	if syncErr != nil || jobErr != nil || outboxErr != nil {
		return apiserver.SyncRequest{}, apiserver.RequestIdentity{}, false
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{"schedule-sync-v1", scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.IntegrationID, seed, parserVersion, toolVersion}, "\x1f")))
	keyDigest := sha256.Sum256([]byte("schedule-idempotency-v1\x1f" + seed))
	request := apiserver.SyncRequest{IntegrationID: input.IntegrationID, SyncID: syncID, JobID: jobID, OutboxID: outboxID, IdempotencyKey: hex.EncodeToString(keyDigest[:]), RequestDigest: digest[:], TriggerKind: "schedule", ParserVersion: parserVersion, ToolVersion: toolVersion}
	return request, apiserver.RequestIdentity{PrincipalID: principal, Scope: scope}, true
}

func executionScope(organization, workspace, environment string) (domain.Scope, bool) {
	organizationID, organizationErr := domain.ParseProductID(organization)
	workspaceID, workspaceErr := domain.ParseProductID(workspace)
	environmentID, environmentErr := domain.ParseProductID(environment)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil {
		return domain.Scope{}, false
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	return scope, err == nil
}
