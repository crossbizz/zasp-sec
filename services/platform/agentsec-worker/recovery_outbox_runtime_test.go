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

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type recoveryOutboxAuthorityFake struct {
	mu         sync.Mutex
	events     []recoveryOutboxEvent
	steps      []string
	heartbeats int
	acked      []string
	retried    []string
}

func (fake *recoveryOutboxAuthorityFake) Ready(context.Context) error { return nil }

func (fake *recoveryOutboxAuthorityFake) Claim(_ context.Context, topic, worker, token string, _ int, _ int) ([]recoveryOutboxEvent, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "claim:"+topic+":"+worker+":"+token)
	return append([]recoveryOutboxEvent(nil), fake.events...), nil
}

func (fake *recoveryOutboxAuthorityFake) Heartbeat(_ context.Context, topic, worker, token string, _ int, expected int) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.heartbeats++
	fake.steps = append(fake.steps, "heartbeat:"+topic+":"+worker+":"+token)
	if expected < 1 {
		return errors.New("invalid expected count")
	}
	return nil
}

func (fake *recoveryOutboxAuthorityFake) Acknowledge(_ context.Context, _ domain.Scope, id, worker, token, ack string) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "ack:"+worker+":"+token+":"+ack)
	fake.acked = append(fake.acked, id)
	return nil
}

func (fake *recoveryOutboxAuthorityFake) Retry(_ context.Context, _ domain.Scope, id, worker, token string, _ int, code string) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "retry:"+worker+":"+token+":"+code)
	fake.retried = append(fake.retried, id)
	return nil
}

type recoveryOutboxPublisherFake struct {
	mu    sync.Mutex
	jobs  []jobqueue.Job
	delay time.Duration
	err   error
}

func (fake *recoveryOutboxPublisherFake) PublishBatch(ctx context.Context, jobs []jobqueue.Job) (jobqueue.PublishResult, error) {
	if fake.delay > 0 {
		select {
		case <-ctx.Done():
			return jobqueue.PublishResult{}, ctx.Err()
		case <-time.After(fake.delay):
		}
	}
	if fake.err != nil {
		return jobqueue.PublishResult{}, fake.err
	}
	fake.mu.Lock()
	fake.jobs = append([]jobqueue.Job(nil), jobs...)
	fake.mu.Unlock()
	result := jobqueue.PublishResult{JobIDs: make([]domain.ProductID, len(jobs)), Acknowledgements: make([]jobqueue.PublishAcknowledgement, len(jobs))}
	for index, job := range jobs {
		result.JobIDs[index] = job.JobID
		result.Acknowledgements[index] = jobqueue.PublishAcknowledgement{JobID: job.JobID, ProviderAck: "sha256:" + string(make([]byte, 64))}
	}
	for index := range result.Acknowledgements {
		result.Acknowledgements[index].ProviderAck = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	return result, nil
}

func TestRecoveryOutboxProcessorPublishesExactTenantJobAndKeepsLeaseThroughAck(t *testing.T) {
	event := recoveryBackupOutboxEvent(t)
	authority := &recoveryOutboxAuthorityFake{events: []recoveryOutboxEvent{event}}
	publisher := &recoveryOutboxPublisherFake{delay: 20 * time.Millisecond}
	processor, err := newRecoveryOutboxProcessor(recoveryOutboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: recoveryBackupOutboxTopic, WorkerID: "recovery-outbox-01",
		LeaseSeconds: 5, BatchSize: 1, RetrySeconds: 30, HeartbeatInterval: 5 * time.Millisecond,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if len(authority.acked) != 1 || authority.acked[0] != event.ID || len(authority.retried) != 0 || authority.heartbeats < 2 {
		t.Fatalf("acked=%v retried=%v heartbeats=%d steps=%v", authority.acked, authority.retried, authority.heartbeats, authority.steps)
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if len(publisher.jobs) != 1 || publisher.jobs[0].Kind != "recovery-backup" || publisher.jobs[0].Payload == nil || publisher.jobs[0].Scope.Validate() != nil {
		t.Fatalf("jobs=%#v", publisher.jobs)
	}
}

func TestRecoveryOutboxProcessorRejectsTamperedPayloadWithoutPublishing(t *testing.T) {
	event := recoveryBackupOutboxEvent(t)
	event.Payload = json.RawMessage(`{"backup_id":"pid_71000009-0000-4000-8000-000000000009","environment_id":"pid_71000003-0000-4000-8000-000000000003","organization_id":"pid_71000001-0000-4000-8000-000000000001","workspace_id":"pid_71000002-0000-4000-8000-000000000002"}`)
	authority := &recoveryOutboxAuthorityFake{events: []recoveryOutboxEvent{event}}
	publisher := &recoveryOutboxPublisherFake{}
	processor, err := newRecoveryOutboxProcessor(recoveryOutboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: recoveryBackupOutboxTopic, WorkerID: "recovery-outbox-01",
		LeaseSeconds: 5, BatchSize: 1, RetrySeconds: 30, HeartbeatInterval: 5 * time.Millisecond,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("error=%v", err)
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if len(publisher.jobs) != 0 {
		t.Fatalf("published=%#v", publisher.jobs)
	}
}

func recoveryBackupOutboxEvent(t *testing.T) recoveryOutboxEvent {
	t.Helper()
	return recoveryBackupOutboxFixture()
}

func TestRecoveryJobCanonicalizesPayloadBeforeBindingQueueDigest(t *testing.T) {
	event := recoveryBackupOutboxFixture()
	event.Payload = json.RawMessage(`{ "workspace_id": "pid_71000002-0000-4000-8000-000000000002", "backup_id": "pid_71000004-0000-4000-8000-000000000004", "organization_id": "pid_71000001-0000-4000-8000-000000000001", "environment_id": "pid_71000003-0000-4000-8000-000000000003" }`)
	eventDigest := sha256.Sum256(event.Payload)
	event.PayloadDigest = `\x` + fmt.Sprintf("%x", eventDigest)
	job, _, ok := recoveryJobForOutbox(event, recoveryBackupOutboxTopic)
	if !ok || sha256.Sum256(job.Payload) != job.AuthorityDigest || bytes.Contains(job.Payload, []byte(" ")) {
		t.Fatalf("ok=%t payload=%s digest=%x", ok, job.Payload, job.AuthorityDigest)
	}
}

func TestRecoveryRestoreJobAcceptsExactTargetEnvironmentBounds(t *testing.T) {
	for _, target := range []string{"x", strings.Repeat("a", 63)} {
		payload := json.RawMessage(fmt.Sprintf(`{"environment_id":"pid_71000003-0000-4000-8000-000000000003","organization_id":"pid_71000001-0000-4000-8000-000000000001","restore_id":"pid_71000004-0000-4000-8000-000000000004","target_environment":%q,"workspace_id":"pid_71000002-0000-4000-8000-000000000002"}`, target))
		digest := sha256.Sum256(payload)
		event := recoveryOutboxEvent{
			OrganizationID: "pid_71000001-0000-4000-8000-000000000001", WorkspaceID: "pid_71000002-0000-4000-8000-000000000002", EnvironmentID: "pid_71000003-0000-4000-8000-000000000003",
			ID: "pid_71000005-0000-4000-8000-000000000005", Topic: recoveryRestoreOutboxTopic, Payload: payload, PayloadDigest: `\x` + fmt.Sprintf("%x", digest), Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(5 * time.Second),
		}
		if job, _, ok := recoveryJobForOutbox(event, recoveryRestoreOutboxTopic); !ok || job.Kind != "recovery-restore" {
			t.Fatalf("target=%q ok=%t job=%#v", target, ok, job)
		}
	}
}

func recoveryBackupOutboxFixture() recoveryOutboxEvent {
	payload := json.RawMessage(`{"backup_id":"pid_71000004-0000-4000-8000-000000000004","environment_id":"pid_71000003-0000-4000-8000-000000000003","organization_id":"pid_71000001-0000-4000-8000-000000000001","workspace_id":"pid_71000002-0000-4000-8000-000000000002"}`)
	digest := sha256.Sum256(payload)
	return recoveryOutboxEvent{
		OrganizationID: "pid_71000001-0000-4000-8000-000000000001", WorkspaceID: "pid_71000002-0000-4000-8000-000000000002", EnvironmentID: "pid_71000003-0000-4000-8000-000000000003",
		ID: "pid_71000005-0000-4000-8000-000000000005", Topic: recoveryBackupOutboxTopic, Payload: payload, PayloadDigest: `\x` + fmt.Sprintf("%x", digest), Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(5 * time.Second),
	}
}
