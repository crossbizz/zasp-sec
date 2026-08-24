package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestAttackLabOutboxProcessorPublishesExactTenantRunAndAcknowledges(t *testing.T) {
	scope := fixtureAttackLabOutboxScope(t)
	runID := mustProductID(t, "pid_7d100001-0000-4000-8000-000000000001")
	inputDigest := sha256.Sum256([]byte("attack-lab-production-input"))
	payload, err := json.Marshal(map[string]any{
		"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(),
		"run_id": runID.String(), "source_run_id": "pid_7d100002-0000-4000-8000-000000000002", "definition_id": "pid_7d100003-0000-4000-8000-000000000003", "definition_version": 4,
		"target_id": "pid_7d100004-0000-4000-8000-000000000004", "target_kind": "agent_endpoint", "input_digest": hex.EncodeToString(inputDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	authority := &recordingAttackLabOutboxAuthority{events: []apiserver.AttackLabOutboxEvent{{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		ID: "pid_7d100005-0000-4000-8000-000000000005", Topic: apiserver.AttackLabOutboxTopic, Payload: payload, PayloadDigest: payloadDigest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
	}}}
	publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{
		JobIDs: []domain.ProductID{runID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: runID, ProviderAck: canonicalProviderAck(t, "attack-lab-provider-message")}},
	}}
	processor, err := newAttackLabOutboxProcessor(attackLabOutboxProcessorConfig{
		Authority: authority, Publisher: publisher, WorkerID: "attack-lab-outbox-01", LeaseSeconds: 60, BatchSize: 10, RetrySeconds: 30,
		HeartbeatInterval: 20 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }, Ready: readyOutboxDependency,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publisher.jobs) != 1 || publisher.jobs[0].Kind != "attack-lab" || publisher.jobs[0].Scope != scope || publisher.jobs[0].JobID != runID || publisher.jobs[0].AuthorityDigest != inputDigest {
		t.Fatalf("jobs=%#v", publisher.jobs)
	}
	if authority.acknowledged != 1 || authority.retried != 0 || authority.heartbeats < 1 {
		t.Fatalf("ack=%d retry=%d heartbeat=%d", authority.acknowledged, authority.retried, authority.heartbeats)
	}
}

func TestAttackLabOutboxProcessorSerializesHeartbeatAndAcknowledge(t *testing.T) {
	scope := fixtureAttackLabOutboxScope(t)
	runID := mustProductID(t, "pid_7d200001-0000-4000-8000-000000000001")
	inputDigest := sha256.Sum256([]byte("attack-lab-serialized-transition"))
	payload, err := json.Marshal(map[string]any{
		"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(),
		"run_id": runID.String(), "source_run_id": "pid_7d200002-0000-4000-8000-000000000002", "definition_id": "pid_7d200003-0000-4000-8000-000000000003", "definition_version": 1,
		"target_id": "pid_7d200004-0000-4000-8000-000000000004", "target_kind": "coding_agent", "input_digest": hex.EncodeToString(inputDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	started, release := make(chan struct{}), make(chan struct{})
	authority := &concurrentAttackLabOutboxAuthority{started: started, release: release, event: apiserver.AttackLabOutboxEvent{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		ID: "pid_7d200005-0000-4000-8000-000000000005", Topic: apiserver.AttackLabOutboxTopic, Payload: payload, PayloadDigest: payloadDigest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
	}}
	publisher := &blockingAttackLabOutboxPublisher{started: started, release: release, result: jobqueue.PublishResult{
		JobIDs: []domain.ProductID{runID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: runID, ProviderAck: canonicalProviderAck(t, "attack-lab-serialized-provider-message")}},
	}}
	processor, err := newAttackLabOutboxProcessor(attackLabOutboxProcessorConfig{
		Authority: authority, Publisher: publisher, WorkerID: "attack-lab-outbox-02", LeaseSeconds: 60, BatchSize: 1, RetrySeconds: 30,
		HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("b", 32), nil }, Ready: readyOutboxDependency,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authority.overlap.Load() {
		t.Fatal("database heartbeat and acknowledgement overlapped")
	}
}

type concurrentAttackLabOutboxAuthority struct {
	event    apiserver.AttackLabOutboxEvent
	started  chan struct{}
	release  chan struct{}
	active   atomic.Bool
	overlap  atomic.Bool
	calls    atomic.Int32
	startOne sync.Once
}

func (authority *concurrentAttackLabOutboxAuthority) Ready(context.Context) error { return nil }

func (authority *concurrentAttackLabOutboxAuthority) ClaimAttackLabOutbox(context.Context, string, string, int, int) ([]apiserver.AttackLabOutboxEvent, error) {
	return []apiserver.AttackLabOutboxEvent{authority.event}, nil
}

func (authority *concurrentAttackLabOutboxAuthority) enter() bool {
	if !authority.active.CompareAndSwap(false, true) {
		authority.overlap.Store(true)
		return false
	}
	return true
}

func (authority *concurrentAttackLabOutboxAuthority) HeartbeatAttackLabOutbox(context.Context, string, string, int, int) (apiserver.AttackLabOutboxTransition, error) {
	if !authority.enter() {
		return apiserver.AttackLabOutboxTransition{}, errors.New("overlapping attack lab transition")
	}
	defer authority.active.Store(false)
	if authority.calls.Add(1) == 2 {
		authority.startOne.Do(func() { close(authority.started) })
		<-authority.release
	}
	return apiserver.AttackLabOutboxTransition{Topic: apiserver.AttackLabOutboxTopic, RemainingCount: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}, nil
}

func (authority *concurrentAttackLabOutboxAuthority) AcknowledgeAttackLabOutbox(context.Context, domain.Scope, string, string, string, string) (apiserver.AttackLabOutboxTransition, error) {
	if !authority.enter() {
		return apiserver.AttackLabOutboxTransition{}, errors.New("overlapping attack lab transition")
	}
	defer authority.active.Store(false)
	time.Sleep(20 * time.Millisecond)
	return apiserver.AttackLabOutboxTransition{State: "published", RemainingCount: 0, PublishedAt: time.Now().UTC()}, nil
}

func (authority *concurrentAttackLabOutboxAuthority) RetryAttackLabOutbox(context.Context, domain.Scope, string, string, string, int, string) (apiserver.AttackLabOutboxTransition, error) {
	return apiserver.AttackLabOutboxTransition{}, errors.New("unexpected retry")
}

type blockingAttackLabOutboxPublisher struct {
	started <-chan struct{}
	release chan struct{}
	result  jobqueue.PublishResult
}

func (publisher *blockingAttackLabOutboxPublisher) PublishBatch(context.Context, []jobqueue.Job) (jobqueue.PublishResult, error) {
	<-publisher.started
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(publisher.release)
	}()
	return publisher.result, nil
}

type recordingAttackLabOutboxAuthority struct {
	mu           sync.Mutex
	events       []apiserver.AttackLabOutboxEvent
	heartbeats   int
	acknowledged int
	retried      int
}

func (authority *recordingAttackLabOutboxAuthority) Ready(context.Context) error { return nil }

func (authority *recordingAttackLabOutboxAuthority) ClaimAttackLabOutbox(context.Context, string, string, int, int) ([]apiserver.AttackLabOutboxEvent, error) {
	return append([]apiserver.AttackLabOutboxEvent(nil), authority.events...), nil
}

func (authority *recordingAttackLabOutboxAuthority) HeartbeatAttackLabOutbox(context.Context, string, string, int, int) (apiserver.AttackLabOutboxTransition, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.heartbeats++
	return apiserver.AttackLabOutboxTransition{Topic: apiserver.AttackLabOutboxTopic, RemainingCount: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}, nil
}

func (authority *recordingAttackLabOutboxAuthority) AcknowledgeAttackLabOutbox(context.Context, domain.Scope, string, string, string, string) (apiserver.AttackLabOutboxTransition, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.acknowledged++
	return apiserver.AttackLabOutboxTransition{State: "published", RemainingCount: 0, PublishedAt: time.Now().UTC()}, nil
}

func (authority *recordingAttackLabOutboxAuthority) RetryAttackLabOutbox(context.Context, domain.Scope, string, string, string, int, string) (apiserver.AttackLabOutboxTransition, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.retried++
	return apiserver.AttackLabOutboxTransition{State: "pending", RemainingCount: 0, AvailableAt: time.Now().UTC().Add(time.Minute), ErrorCode: "queue_publish_unknown"}, nil
}

func fixtureAttackLabOutboxScope(t *testing.T) domain.Scope {
	t.Helper()
	organization := mustProductID(t, "pid_7d100010-0000-4000-8000-000000000010")
	workspace := mustProductID(t, "pid_7d100011-0000-4000-8000-000000000011")
	environment := mustProductID(t, "pid_7d100012-0000-4000-8000-000000000012")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
