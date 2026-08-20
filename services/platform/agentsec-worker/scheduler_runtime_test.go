package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestSchedulerProcessorRequestsDeterministicSyncBeforeAdvancing(t *testing.T) {
	scope := workerScope(t)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	lease := apiserver.DiscoveryScheduleLease{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ID: "pid_10000020-0000-4000-8000-000000000020", IntegrationID: "pid_10000001-0000-4000-8000-000000000001", NextRunAt: now.Add(-2 * time.Minute), LeaseExpiresAt: now.Add(time.Minute)}
	steps := []string{}
	authority := &recordingSchedulerAuthority{lease: lease, steps: &steps}
	processor, err := newSchedulerProcessor(schedulerProcessorConfig{Authority: authority, WorkerID: "scheduler-01", LeaseSeconds: 30, BatchSize: 1, ParserVersion: "inventory-parser-2026.08.20", ToolVersion: "collector-tool-2026.08.20", Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"claim", "input", "request", "complete:advanced"}
	if fmt.Sprint(steps) != fmt.Sprint(want) {
		t.Fatalf("steps = %v, want %v", steps, want)
	}
	if authority.request.IdempotencyKey == "" || len(authority.request.RequestDigest) != 32 || authority.request.TriggerKind != "schedule" || authority.completed.NextRunAt != now.Add(3*time.Minute) {
		t.Fatalf("request/completion = %#v / %#v", authority.request, authority.completed)
	}
	first := authority.request
	steps = nil
	authority.steps = &steps
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first.SyncID != authority.request.SyncID || first.JobID != authority.request.JobID || first.OutboxID != authority.request.OutboxID || first.IdempotencyKey != authority.request.IdempotencyKey {
		t.Fatalf("scheduled replay changed identity: %#v / %#v", first, authority.request)
	}
}

func TestNextScheduledRunSkipsLargeBacklogArithmetically(t *testing.T) {
	current := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	previous := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	started := time.Now()
	next, ok := nextScheduledRun(previous, current, 300)
	if !ok || !next.After(current) || next.After(current.Add(5*time.Minute)) {
		t.Fatalf("next=%s ok=%t", next, ok)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("missed-run arithmetic took %s", elapsed)
	}
}

func TestSchedulerProcessorStartsEveryClaimedLeaseBeforeWaiting(t *testing.T) {
	scope := workerScope(t)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	leases := []apiserver.DiscoveryScheduleLease{
		{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ID: "pid_10000020-0000-4000-8000-000000000020", IntegrationID: "pid_10000001-0000-4000-8000-000000000001", NextRunAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute)},
		{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ID: "pid_10000021-0000-4000-8000-000000000021", IntegrationID: "pid_10000011-0000-4000-8000-000000000011", NextRunAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute)},
	}
	entered := make(chan struct{}, len(leases))
	release := make(chan struct{})
	authority := &parallelSchedulerAuthority{leases: leases, entered: entered, release: release}
	processor, err := newSchedulerProcessor(schedulerProcessorConfig{Authority: authority, WorkerID: "scheduler-01", LeaseSeconds: 30, BatchSize: len(leases), ParserVersion: "inventory-parser-2026.08.20", ToolVersion: "collector-tool-2026.08.20", Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- processor.RunOnce(context.Background()) }()
	for range leases {
		select {
		case <-entered:
		case <-time.After(250 * time.Millisecond):
			close(release)
			t.Fatal("claimed schedule remained queued behind another database call")
		}
	}
	close(release)
	if err := <-done; err != nil || authority.completed != len(leases) {
		t.Fatalf("parallel scheduler error=%v completed=%d", err, authority.completed)
	}
}

type recordingSchedulerAuthority struct {
	lease     apiserver.DiscoveryScheduleLease
	steps     *[]string
	request   apiserver.SyncRequest
	completed apiserver.DiscoveryScheduleCompletion
}

type parallelSchedulerAuthority struct {
	leases    []apiserver.DiscoveryScheduleLease
	entered   chan<- struct{}
	release   <-chan struct{}
	mu        sync.Mutex
	completed int
}

func (authority *parallelSchedulerAuthority) ClaimDiscoverySchedules(context.Context, string, string, int, int) ([]apiserver.DiscoveryScheduleLease, error) {
	return append([]apiserver.DiscoveryScheduleLease(nil), authority.leases...), nil
}
func (authority *parallelSchedulerAuthority) GetDiscoveryScheduleInput(_ context.Context, _ domain.Scope, scheduleID, _, _ string) (apiserver.ExecutionScheduleInput, error) {
	for _, lease := range authority.leases {
		if lease.ID == scheduleID {
			return apiserver.ExecutionScheduleInput{OrganizationID: lease.OrganizationID, WorkspaceID: lease.WorkspaceID, EnvironmentID: lease.EnvironmentID, ScheduleID: lease.ID, IntegrationID: lease.IntegrationID, CadenceSeconds: 300, TimeZone: "UTC", NextRunAt: lease.NextRunAt, Version: 1, LeaseExpiresAt: lease.LeaseExpiresAt}, nil
		}
	}
	return apiserver.ExecutionScheduleInput{}, errWorkerExecution
}
func (authority *parallelSchedulerAuthority) RequestScheduledSync(ctx context.Context, _ apiserver.RequestIdentity, input apiserver.ScheduledSyncRequest) (apiserver.SyncRequestResult, error) {
	authority.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return apiserver.SyncRequestResult{}, ctx.Err()
	case <-authority.release:
		return apiserver.SyncRequestResult{SyncID: input.SyncID, JobID: input.JobID, OutboxID: input.OutboxID, State: "queued"}, nil
	}
}
func (authority *parallelSchedulerAuthority) CompleteDiscoverySchedule(_ context.Context, _ domain.Scope, input apiserver.DiscoveryScheduleCompletion) (apiserver.DiscoveryScheduleCompletionResult, error) {
	authority.mu.Lock()
	authority.completed++
	authority.mu.Unlock()
	return apiserver.DiscoveryScheduleCompletionResult{ID: input.ID, State: "enabled", NextRunAt: input.NextRunAt, Version: 2}, nil
}

func (authority *recordingSchedulerAuthority) ClaimDiscoverySchedules(context.Context, string, string, int, int) ([]apiserver.DiscoveryScheduleLease, error) {
	*authority.steps = append(*authority.steps, "claim")
	return []apiserver.DiscoveryScheduleLease{authority.lease}, nil
}
func (authority *recordingSchedulerAuthority) GetDiscoveryScheduleInput(context.Context, domain.Scope, string, string, string) (apiserver.ExecutionScheduleInput, error) {
	*authority.steps = append(*authority.steps, "input")
	return apiserver.ExecutionScheduleInput{OrganizationID: authority.lease.OrganizationID, WorkspaceID: authority.lease.WorkspaceID, EnvironmentID: authority.lease.EnvironmentID, ScheduleID: authority.lease.ID, IntegrationID: authority.lease.IntegrationID, CadenceSeconds: 300, TimeZone: "UTC", NextRunAt: authority.lease.NextRunAt, Version: 1, LeaseExpiresAt: authority.lease.LeaseExpiresAt}, nil
}
func (authority *recordingSchedulerAuthority) RequestScheduledSync(_ context.Context, _ apiserver.RequestIdentity, input apiserver.ScheduledSyncRequest) (apiserver.SyncRequestResult, error) {
	*authority.steps = append(*authority.steps, "request")
	authority.request = input.SyncRequest
	return apiserver.SyncRequestResult{SyncID: input.SyncID, JobID: input.JobID, OutboxID: input.OutboxID, State: "queued"}, nil
}
func (authority *recordingSchedulerAuthority) CompleteDiscoverySchedule(_ context.Context, _ domain.Scope, input apiserver.DiscoveryScheduleCompletion) (apiserver.DiscoveryScheduleCompletionResult, error) {
	*authority.steps = append(*authority.steps, "complete:"+input.Outcome)
	authority.completed = input
	return apiserver.DiscoveryScheduleCompletionResult{ID: input.ID, State: "enabled", NextRunAt: input.NextRunAt, Version: 2}, nil
}
