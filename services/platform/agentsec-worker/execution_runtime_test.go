package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestDiscoveryProcessorAppliesCompleteSnapshotAndAcknowledgesLast(t *testing.T) {
	scope := workerScope(t)
	jobID := workerID(t, "pid_10000003-0000-4000-8000-000000000003")
	input := workerExecutionInput(scope, jobID.String())
	steps := []string{}
	authority := &recordingDiscoveryAuthority{input: input, steps: &steps}
	queue := &recordingDiscoveryQueue{deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: json.RawMessage(`{"version":1}`)}}}, steps: &steps}
	collector := recordingCollector{steps: &steps, outcome: workerCompleteOutcome(t, input)}
	factory := &recordingDiscoveryCollectorFactory{collector: collector, steps: &steps}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{Authority: authority, Queue: queue, CollectorFactory: factory, WorkerID: "discovery-01", LeaseSeconds: 30, BatchSize: 1, Now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error = %v, steps = %v", err, steps)
	}
	want := []string{"consume", "claim", "input", "factory", "collect", "destroy", "apply", "finish:succeeded", "ack"}
	if fmt.Sprint(steps) != fmt.Sprint(want) {
		t.Fatalf("steps = %v, want %v", steps, want)
	}
	if authority.applied.JobID != jobID.String() || authority.applied.SnapshotID != input.SnapshotID || authority.finished.ResultDigest == nil {
		t.Fatalf("apply/finish = %#v / %#v", authority.applied, authority.finished)
	}
	if len(factory.bindings) != 1 || factory.bindings[0].Scope != scope || factory.bindings[0].Input.JobID != input.JobID || factory.bindings[0].WorkerID != "discovery-01" || factory.bindings[0].LeaseToken != "0123456789abcdef" {
		t.Fatalf("factory bindings = %#v", factory.bindings)
	}
	factory.bindings[0].Input.Configuration[0] = '['
	if authority.input.Configuration[0] == '[' {
		t.Fatal("collector factory retained authority-owned mutable job input")
	}
}

func TestDiscoveryProcessorRejectsForeignHydratedInputBeforeCollectorFactory(t *testing.T) {
	scope := workerScope(t)
	jobID := workerID(t, "pid_10000003-0000-4000-8000-000000000003")
	valid := workerExecutionInput(scope, jobID.String())
	for name, mutate := range map[string]func(*apiserver.ExecutionJobInput){
		"organization": func(input *apiserver.ExecutionJobInput) { input.OrganizationID = input.WorkspaceID },
		"job":          func(input *apiserver.ExecutionJobInput) { input.JobID = input.SnapshotID },
		"subject": func(input *apiserver.ExecutionJobInput) {
			input.ExpectedSubject = collection.SubjectBinding{Kind: input.SubjectKind, ID: "999999999999"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			steps := []string{}
			authority := &recordingDiscoveryAuthority{input: input, steps: &steps}
			queue := &recordingDiscoveryQueue{deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: json.RawMessage(`{"version":1}`)}}}, steps: &steps}
			factory := &recordingDiscoveryCollectorFactory{steps: &steps}
			processor, err := newDiscoveryProcessor(discoveryProcessorConfig{Authority: authority, Queue: queue, CollectorFactory: factory, WorkerID: "discovery-01", LeaseSeconds: 30, BatchSize: 1, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) || len(factory.bindings) != 0 {
				t.Fatalf("RunOnce error=%v factory bindings=%#v", err, factory.bindings)
			}
		})
	}
}

func TestDiscoveryProcessorNeverAppliesOrAcknowledgesPartialResult(t *testing.T) {
	scope := workerScope(t)
	jobID := workerID(t, "pid_10000003-0000-4000-8000-000000000003")
	input := workerExecutionInput(scope, jobID.String())
	steps := []string{}
	authority := &recordingDiscoveryAuthority{input: input, finishState: "retryable", steps: &steps}
	queue := &recordingDiscoveryQueue{deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: json.RawMessage(`{"version":1}`)}}}, steps: &steps}
	request := workerCollectionRequest(t, input)
	partial, err := collection.NewPartialResult(request, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "next"}, workerManifest(t, request), collection.FailurePartial)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{Authority: authority, Queue: queue, CollectorFactory: workerCollectorFactory(recordingCollector{steps: &steps, outcome: partial}), WorkerID: "discovery-01", LeaseSeconds: 30, BatchSize: 1, Now: time.Now, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"consume", "claim", "input", "collect", "checkpoint", "finish:retryable"}
	if fmt.Sprint(steps) != fmt.Sprint(want) {
		t.Fatalf("steps = %v, want %v", steps, want)
	}
	if len(authority.finished.ResultDigest) != sha256.Size {
		t.Fatalf("partial completion omitted checkpoint digest: %#v", authority.finished)
	}
}

func TestDiscoveryProcessorLeavesDeliveryUnacknowledgedWhenSnapshotApplyFails(t *testing.T) {
	scope := workerScope(t)
	jobID := workerID(t, "pid_10000003-0000-4000-8000-000000000003")
	input := workerExecutionInput(scope, jobID.String())
	steps := []string{}
	authority := &recordingDiscoveryAuthority{input: input, applyErr: errors.New("lease lost"), steps: &steps}
	queue := &recordingDiscoveryQueue{deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: json.RawMessage(`{"version":1}`)}}}, steps: &steps}
	processor, _ := newDiscoveryProcessor(discoveryProcessorConfig{Authority: authority, Queue: queue, CollectorFactory: workerCollectorFactory(recordingCollector{steps: &steps, outcome: workerCompleteOutcome(t, input)}), WorkerID: "discovery-01", LeaseSeconds: 30, BatchSize: 1, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err := processor.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce succeeded after snapshot apply failure")
	}
	want := []string{"consume", "claim", "input", "collect", "apply"}
	if fmt.Sprint(steps) != fmt.Sprint(want) {
		t.Fatalf("steps = %v, want %v", steps, want)
	}
}

func TestDiscoveryProcessorRenewsDatabaseLeaseAndQueueVisibilityDuringSlowCollection(t *testing.T) {
	scope := workerScope(t)
	jobID := workerID(t, "pid_10000003-0000-4000-8000-000000000003")
	input := workerExecutionInput(scope, jobID.String())
	heartbeatSeen := make(chan struct{}, 1)
	visibilitySeen := make(chan struct{}, 1)
	authority := &recordingDiscoveryAuthority{input: input, steps: &[]string{}, heartbeatSeen: heartbeatSeen}
	queue := &recordingDiscoveryQueue{deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: json.RawMessage(`{"version":1}`)}}}, steps: &[]string{}, visibilitySeen: visibilitySeen}
	collector := waitingCollector{heartbeatSeen: heartbeatSeen, visibilitySeen: visibilitySeen, outcome: workerCompleteOutcome(t, input)}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{Authority: authority, Queue: queue, CollectorFactory: workerCollectorFactory(collector), WorkerID: "discovery-01", LeaseSeconds: 30, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatalf("slow collection lifecycle error = %v", err)
	}
}

func TestDiscoveryProcessorStartsEveryConsumedDeliveryBeforeWaiting(t *testing.T) {
	scope := workerScope(t)
	firstID := workerID(t, "pid_10000003-0000-4000-8000-000000000003")
	secondID := workerID(t, "pid_10000013-0000-4000-8000-000000000013")
	firstInput := workerExecutionInput(scope, firstID.String())
	secondInput := workerExecutionInput(scope, secondID.String())
	secondInput.JobID = secondID.String()
	secondInput.SyncID = "pid_10000014-0000-4000-8000-000000000014"
	secondInput.SnapshotID = "pid_10000018-0000-4000-8000-000000000018"
	entered := make(chan string, 2)
	release := make(chan struct{})
	queue := &parallelDiscoveryQueue{deliveries: []jobqueue.Delivery{
		{Job: jobqueue.Job{Scope: scope, JobID: firstID, Kind: "discovery", Payload: json.RawMessage(`{"version":1}`)}},
		{Job: jobqueue.Job{Scope: scope, JobID: secondID, Kind: "discovery", Payload: json.RawMessage(`{"version":1}`)}},
	}}
	authority := &parallelDiscoveryAuthority{inputs: map[string]apiserver.ExecutionJobInput{firstID.String(): firstInput, secondID.String(): secondInput}}
	collector := &parallelCollector{entered: entered, release: release, outcomes: map[string]collection.Outcome{firstID.String(): workerCompleteOutcome(t, firstInput), secondID.String(): workerCompleteOutcome(t, secondInput)}}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{Authority: authority, Queue: queue, CollectorFactory: workerCollectorFactory(collector), WorkerID: "discovery-01", LeaseSeconds: 30, BatchSize: 2, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- processor.RunOnce(context.Background()) }()
	for index := 0; index < 2; index++ {
		select {
		case <-entered:
		case <-time.After(250 * time.Millisecond):
			close(release)
			t.Fatal("consumed delivery remained queued behind another provider call")
		}
	}
	close(release)
	if err := <-done; err != nil || queue.acknowledged != 2 {
		t.Fatalf("parallel RunOnce error=%v acknowledged=%d", err, queue.acknowledged)
	}
}

func TestDiscoveryCollectorLifecycleDestroysOnEveryExit(t *testing.T) {
	request := workerCollectionRequest(t, workerExecutionInput(workerScope(t), "pid_10000003-0000-4000-8000-000000000003"))
	for name, setup := range map[string]func(*lifecycleJobCollector) context.Context{
		"success": func(*lifecycleJobCollector) context.Context { return context.Background() },
		"error": func(collector *lifecycleJobCollector) context.Context {
			collector.err = errors.New("provider-secret-must-not-escape")
			return context.Background()
		},
		"panic": func(collector *lifecycleJobCollector) context.Context {
			collector.panicCall = true
			return context.Background()
		},
		"cancel": func(*lifecycleJobCollector) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		},
	} {
		t.Run(name, func(t *testing.T) {
			collector := &lifecycleJobCollector{}
			ctx := setup(collector)
			_, err := callDiscoveryCollector(collector, ctx, request)
			if collector.destroyed != 1 {
				t.Fatalf("Destroy calls = %d", collector.destroyed)
			}
			if name == "panic" && (!errors.Is(err, errWorkerExecution) || strings.Contains(err.Error(), "secret")) {
				t.Fatalf("panic error = %q", err)
			}
			collector.Destroy()
			if collector.destroyed != 1 {
				t.Fatalf("repeated Destroy calls = %d", collector.destroyed)
			}
		})
	}
}

func TestDiscoveryCollectorFactoryFailureDestroysReturnedCollector(t *testing.T) {
	collector := &lifecycleJobCollector{}
	factory := errorDiscoveryCollectorFactory{collector: collector, err: errors.New("factory-secret-must-not-escape")}
	returned, err := buildDiscoveryCollector(factory, context.Background(), discoveryCollectorBinding{})
	if returned != nil || !errors.Is(err, errWorkerExecution) || collector.destroyed != 1 || strings.Contains(err.Error(), "secret") {
		t.Fatalf("build result/error/destroy = %#v / %q / %d", returned, err, collector.destroyed)
	}
}

type recordingDiscoveryQueue struct {
	deliveries     []jobqueue.Delivery
	steps          *[]string
	visibilitySeen chan<- struct{}
}

func (queue *recordingDiscoveryQueue) ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error) {
	*queue.steps = append(*queue.steps, "consume")
	return append([]jobqueue.Delivery(nil), queue.deliveries...), nil
}
func (queue *recordingDiscoveryQueue) AcknowledgeBatch(context.Context, []jobqueue.Receipt) error {
	*queue.steps = append(*queue.steps, "ack")
	return nil
}
func (queue *recordingDiscoveryQueue) ExtendVisibility(context.Context, []jobqueue.Receipt, time.Duration) error {
	if queue.visibilitySeen != nil {
		select {
		case queue.visibilitySeen <- struct{}{}:
		default:
		}
	}
	return nil
}

type recordingCollector struct {
	steps   *[]string
	outcome collection.Outcome
}

type recordingDiscoveryCollectorFactory struct {
	mu        sync.Mutex
	collector discoveryCollector
	steps     *[]string
	bindings  []discoveryCollectorBinding
}

func (factory *recordingDiscoveryCollectorFactory) BuildDiscoveryCollector(_ context.Context, binding discoveryCollectorBinding) (discoveryJobCollector, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	factory.bindings = append(factory.bindings, binding)
	if factory.steps != nil {
		*factory.steps = append(*factory.steps, "factory")
	}
	return &recordingJobCollector{collector: factory.collector, steps: factory.steps}, nil
}

type recordingJobCollector struct {
	collector discoveryCollector
	steps     *[]string
	once      sync.Once
}

type lifecycleJobCollector struct {
	mu        sync.Mutex
	destroyed int
	err       error
	panicCall bool
}

type errorDiscoveryCollectorFactory struct {
	collector discoveryJobCollector
	err       error
}

func (factory errorDiscoveryCollectorFactory) BuildDiscoveryCollector(context.Context, discoveryCollectorBinding) (discoveryJobCollector, error) {
	return factory.collector, factory.err
}

func (collector *lifecycleJobCollector) Collect(ctx context.Context, _ collection.Request) (collection.Outcome, error) {
	if collector.panicCall {
		panic("provider-secret-must-not-escape")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, collector.err
}

func (collector *lifecycleJobCollector) Destroy() {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.destroyed == 0 {
		collector.destroyed++
	}
}

func (collector *recordingJobCollector) Collect(ctx context.Context, request collection.Request) (collection.Outcome, error) {
	return collector.collector.Collect(ctx, request)
}

func (collector *recordingJobCollector) Destroy() {
	collector.once.Do(func() {
		if collector.steps != nil {
			*collector.steps = append(*collector.steps, "destroy")
		}
		collector.collector = nil
	})
}

func workerCollectorFactory(collector discoveryCollector) discoveryCollectorFactory {
	return &recordingDiscoveryCollectorFactory{collector: collector}
}

type waitingCollector struct {
	heartbeatSeen  <-chan struct{}
	visibilitySeen <-chan struct{}
	outcome        collection.Outcome
}

type parallelCollector struct {
	entered  chan<- string
	release  <-chan struct{}
	outcomes map[string]collection.Outcome
}

func (collector *parallelCollector) Collect(ctx context.Context, request collection.Request) (collection.Outcome, error) {
	collector.entered <- request.JobID.String()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-collector.release:
		return collector.outcomes[request.JobID.String()], nil
	}
}

type parallelDiscoveryQueue struct {
	deliveries   []jobqueue.Delivery
	mu           sync.Mutex
	acknowledged int
}

func (queue *parallelDiscoveryQueue) ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error) {
	return append([]jobqueue.Delivery(nil), queue.deliveries...), nil
}
func (queue *parallelDiscoveryQueue) AcknowledgeBatch(_ context.Context, receipts []jobqueue.Receipt) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.acknowledged += len(receipts)
	return nil
}
func (*parallelDiscoveryQueue) ExtendVisibility(context.Context, []jobqueue.Receipt, time.Duration) error {
	return nil
}

type parallelDiscoveryAuthority struct {
	inputs map[string]apiserver.ExecutionJobInput
}

func (authority *parallelDiscoveryAuthority) ClaimDiscoveryDelivery(_ context.Context, _ domain.Scope, jobID, _, _ string, _ int) (apiserver.DiscoveryDeliveryClaim, error) {
	input := authority.inputs[jobID]
	expires := time.Now().UTC().Add(time.Minute)
	return apiserver.DiscoveryDeliveryClaim{ID: jobID, Disposition: "claimed", State: "leased", AuthorityID: input.SyncID, Attempt: input.Attempt, LeaseExpiresAt: &expires}, nil
}
func (authority *parallelDiscoveryAuthority) GetDiscoveryJobInput(_ context.Context, _ domain.Scope, jobID, _, _ string) (apiserver.ExecutionJobInput, error) {
	return authority.inputs[jobID], nil
}
func (*parallelDiscoveryAuthority) HeartbeatDiscoveryJob(_ context.Context, _ domain.Scope, input apiserver.JobHeartbeat) (apiserver.LeaseHeartbeatResult, error) {
	return apiserver.LeaseHeartbeatResult{ID: input.JobID, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}, nil
}
func (*parallelDiscoveryAuthority) CheckpointPartialDiscoveryJob(_ context.Context, _ domain.Scope, input apiserver.ExecutionPartialCheckpoint) (apiserver.ExecutionPartialCheckpointResult, error) {
	return apiserver.ExecutionPartialCheckpointResult{ID: input.JobID, Version: input.ExpectedVersion + 1, CheckpointDigest: bytes.Repeat([]byte{1}, sha256.Size), CursorProvider: input.CursorProvider, CursorVersion: input.CursorVersion, CursorValue: input.CursorValue, ManifestVersionID: input.ManifestVersionID, UpdatedAt: time.Now().UTC()}, nil
}
func (*parallelDiscoveryAuthority) ApplyCompleteSnapshot(_ context.Context, _ domain.Scope, input apiserver.ExecutionCompleteSnapshot) (apiserver.ExecutionSnapshotApplyResult, error) {
	return apiserver.ExecutionSnapshotApplyResult{SnapshotApplyResult: apiserver.SnapshotApplyResult{SnapshotID: input.SnapshotID, CommittedAt: time.Now().UTC()}, CandidateDigest: append([]byte(nil), input.ManifestChecksum...), ManifestVersionID: input.ManifestVersionID}, nil
}
func (*parallelDiscoveryAuthority) FinishDiscoveryJob(_ context.Context, _ domain.Scope, input apiserver.DiscoveryJobCompletion) (apiserver.WorkCompletionResult, error) {
	return apiserver.WorkCompletionResult{ID: input.ID, State: input.Outcome, Attempt: 1}, nil
}

func (collector waitingCollector) Collect(ctx context.Context, _ collection.Request) (collection.Outcome, error) {
	for _, signal := range []<-chan struct{}{collector.heartbeatSeen, collector.visibilitySeen} {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-signal:
		}
	}
	return collector.outcome, nil
}

func (collector recordingCollector) Collect(context.Context, collection.Request) (collection.Outcome, error) {
	*collector.steps = append(*collector.steps, "collect")
	return collector.outcome, nil
}

type recordingDiscoveryAuthority struct {
	input         apiserver.ExecutionJobInput
	applyErr      error
	finishState   string
	steps         *[]string
	applied       apiserver.ExecutionCompleteSnapshot
	finished      apiserver.DiscoveryJobCompletion
	heartbeatSeen chan<- struct{}
}

func (authority *recordingDiscoveryAuthority) ClaimDiscoveryDelivery(context.Context, domain.Scope, string, string, string, int) (apiserver.DiscoveryDeliveryClaim, error) {
	*authority.steps = append(*authority.steps, "claim")
	expires := time.Now().Add(time.Minute)
	return apiserver.DiscoveryDeliveryClaim{ID: authority.input.JobID, Disposition: "claimed", State: "leased", AuthorityID: authority.input.SyncID, Attempt: authority.input.Attempt, LeaseExpiresAt: &expires}, nil
}
func (authority *recordingDiscoveryAuthority) GetDiscoveryJobInput(context.Context, domain.Scope, string, string, string) (apiserver.ExecutionJobInput, error) {
	*authority.steps = append(*authority.steps, "input")
	return authority.input, nil
}
func (authority *recordingDiscoveryAuthority) HeartbeatDiscoveryJob(_ context.Context, _ domain.Scope, input apiserver.JobHeartbeat) (apiserver.LeaseHeartbeatResult, error) {
	if authority.heartbeatSeen != nil {
		select {
		case authority.heartbeatSeen <- struct{}{}:
		default:
		}
	}
	return apiserver.LeaseHeartbeatResult{ID: input.JobID, LeaseExpiresAt: time.Now().UTC().Add(time.Duration(input.LeaseSeconds) * time.Second)}, nil
}
func (authority *recordingDiscoveryAuthority) CheckpointPartialDiscoveryJob(_ context.Context, _ domain.Scope, input apiserver.ExecutionPartialCheckpoint) (apiserver.ExecutionPartialCheckpointResult, error) {
	*authority.steps = append(*authority.steps, "checkpoint")
	return apiserver.ExecutionPartialCheckpointResult{ID: input.JobID, Version: input.ExpectedVersion + 1, CheckpointDigest: bytes.Repeat([]byte{7}, sha256.Size), CursorProvider: input.CursorProvider, CursorVersion: input.CursorVersion, CursorValue: input.CursorValue, ManifestVersionID: input.ManifestVersionID, UpdatedAt: time.Now().UTC()}, nil
}
func (authority *recordingDiscoveryAuthority) ApplyCompleteSnapshot(_ context.Context, _ domain.Scope, input apiserver.ExecutionCompleteSnapshot) (apiserver.ExecutionSnapshotApplyResult, error) {
	*authority.steps = append(*authority.steps, "apply")
	authority.applied = input
	if authority.applyErr != nil {
		return apiserver.ExecutionSnapshotApplyResult{}, authority.applyErr
	}
	return apiserver.ExecutionSnapshotApplyResult{SnapshotApplyResult: apiserver.SnapshotApplyResult{SnapshotID: input.SnapshotID, CommittedAt: time.Now().UTC()}, CandidateDigest: input.ManifestChecksum, ManifestVersionID: input.ManifestVersionID}, nil
}
func (authority *recordingDiscoveryAuthority) FinishDiscoveryJob(_ context.Context, _ domain.Scope, input apiserver.DiscoveryJobCompletion) (apiserver.WorkCompletionResult, error) {
	*authority.steps = append(*authority.steps, "finish:"+input.Outcome)
	authority.finished = input
	state := authority.finishState
	if state == "" {
		state = input.Outcome
	}
	return apiserver.WorkCompletionResult{ID: input.ID, State: state, Attempt: authority.input.Attempt}, nil
}

func workerExecutionInput(scope domain.Scope, jobID string) apiserver.ExecutionJobInput {
	cursorProvider := collection.ProviderAWS
	cursorVersion, cursorValue := "cursor_v1", "initial"
	return apiserver.ExecutionJobInput{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), JobID: jobID, Attempt: 1, LeaseExpiresAt: time.Now().Add(time.Minute), SyncID: "pid_10000004-0000-4000-8000-000000000004", IntegrationID: "pid_10000001-0000-4000-8000-000000000001", ConnectionID: "pid_10000002-0000-4000-8000-000000000002", SnapshotID: "pid_10000008-0000-4000-8000-000000000008", Generation: 1, Provider: collection.ProviderAWS, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialAWSAssumeRole, CredentialReference: "ref:aws/connection/customer-0001", SubjectKind: "aws_account", SubjectID: "123456789012", CursorProvider: &cursorProvider, CursorVersion: &cursorVersion, CursorValue: &cursorValue, ParserVersion: "parser_v1", ToolVersion: "tool_v1", Configuration: json.RawMessage(`{"role_arn":"arn:aws:iam::123456789012:role/read"}`), ExpectedSubject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}}
}

func workerCollectionRequest(t *testing.T, input apiserver.ExecutionJobInput) collection.Request {
	t.Helper()
	scope := workerScope(t)
	integration := workerID(t, input.IntegrationID)
	connection := workerID(t, input.ConnectionID)
	job := workerID(t, input.JobID)
	cursor := collection.Cursor{}
	if input.CursorProvider != nil {
		cursor = collection.Cursor{Provider: *input.CursorProvider, Version: *input.CursorVersion, Value: *input.CursorValue}
	}
	return collection.Request{Scope: scope, IntegrationID: integration, ConnectionID: connection, JobID: job, Attempt: input.Attempt, Provider: input.Provider, CollectorVersion: input.CollectorVersion, CredentialClass: input.CredentialClass, CredentialReference: input.CredentialReference, ExpectedSubject: collection.SubjectBinding{Kind: input.SubjectKind, ID: input.SubjectID}, Cursor: cursor, ParserVersion: input.ParserVersion, ToolVersion: input.ToolVersion, Bounds: collection.Bounds{MaxPages: 100, MaxItems: 10000, MaxRawBytes: 64 << 20, Timeout: 20 * time.Second}}
}

func workerCompleteOutcome(t *testing.T, input apiserver.ExecutionJobInput) collection.CompleteResult {
	t.Helper()
	request := workerCollectionRequest(t, input)
	manifest := workerManifest(t, request)
	entities := []byte(`[{"id":"pid_10000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}]`)
	candidate, err := collection.NewSnapshotCandidate(collection.ProviderAWS, request.ParserVersion, request.ToolVersion, entities, []byte(`[]`), []byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	result, err := collection.NewCompleteResult(request, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "next"}, manifest, candidate)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func workerManifest(t *testing.T, request collection.Request) collection.RawManifest {
	t.Helper()
	objectReference, _ := domain.ParseEvidenceRef("pid_10000006-0000-4000-8000-000000000006")
	objectKey := "organizations/" + request.Scope.OrganizationID().String() + "/workspaces/" + request.Scope.WorkspaceID().String() + "/environments/" + request.Scope.EnvironmentID().String() + "/artifacts/" + objectReference.String()
	object, err := collection.NewRawObject(request.Scope, objectReference, objectKey, "s3-version-object-1", "s3://zasp-evidence/"+objectKey, [sha256.Size]byte{1}, 128, "application/json", "raw_v1", request.ParserVersion, request.ToolVersion)
	if err != nil {
		t.Fatal(err)
	}
	manifestReference, _ := domain.ParseEvidenceRef("pid_10000007-0000-4000-8000-000000000007")
	manifestKey := "organizations/" + request.Scope.OrganizationID().String() + "/workspaces/" + request.Scope.WorkspaceID().String() + "/environments/" + request.Scope.EnvironmentID().String() + "/artifacts/" + manifestReference.String()
	descriptor, err := collection.NewRawObject(request.Scope, manifestReference, manifestKey, "s3-version-manifest-1", "s3://zasp-evidence/"+manifestKey, [sha256.Size]byte{2}, 256, "application/json", "manifest_v1", request.ParserVersion, request.ToolVersion)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := collection.NewRawManifest(descriptor, []collection.RawObject{object})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func workerScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(workerID(t, "pid_10000010-0000-4000-8000-000000000010"), workerID(t, "pid_10000011-0000-4000-8000-000000000011"), workerID(t, "pid_10000012-0000-4000-8000-000000000012"))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func workerID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
