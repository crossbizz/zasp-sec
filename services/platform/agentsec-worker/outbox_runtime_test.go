package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestOutboxProcessorPublishesDiscoveryJobsAndAcknowledgesProviderMessages(t *testing.T) {
	first := outboxEvent(t, "pid_80000001-0000-4000-8000-000000000001", "pid_80000002-0000-4000-8000-000000000002")
	second := outboxEvent(t, "pid_80000011-0000-4000-8000-000000000011", "pid_80000012-0000-4000-8000-000000000012")
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{first, second}}
	publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{
		JobIDs: []domain.ProductID{mustProductID(t, firstPayloadJobID(t, first)), mustProductID(t, firstPayloadJobID(t, second))},
		Acknowledgements: []jobqueue.PublishAcknowledgement{
			{JobID: mustProductID(t, firstPayloadJobID(t, first)), ProviderAck: canonicalProviderAck(t, "provider-message-1")},
			{JobID: mustProductID(t, firstPayloadJobID(t, second)), ProviderAck: canonicalProviderAck(t, "provider-message-2")},
		},
	}}
	processor, err := newOutboxProcessor(outboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 30,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authority.claimTopic != discoveryOutboxTopic || authority.claimWorker != "outbox-01" || authority.claimToken != "0123456789abcdef" {
		t.Fatalf("claim = topic %q worker %q token %q", authority.claimTopic, authority.claimWorker, authority.claimToken)
	}
	if len(publisher.jobs) != 2 || publisher.jobs[0].Kind != "discovery" || publisher.jobs[1].Kind != "discovery" || !json.Valid(publisher.jobs[0].Payload) {
		t.Fatalf("published jobs = %#v", publisher.jobs)
	}
	if got := fmt.Sprint(authority.acknowledged); got != fmt.Sprint([]string{first.ID + ":" + canonicalProviderAck(t, "provider-message-1"), second.ID + ":" + canonicalProviderAck(t, "provider-message-2")}) {
		t.Fatalf("acknowledged = %v", authority.acknowledged)
	}
	if len(authority.retried) != 0 {
		t.Fatalf("successful publication retried: %v", authority.retried)
	}
}

func TestOutboxProcessorRetriesEveryLeaseAfterUnknownPublishOutcome(t *testing.T) {
	first := outboxEvent(t, "pid_80000021-0000-4000-8000-000000000021", "pid_80000022-0000-4000-8000-000000000022")
	second := outboxEvent(t, "pid_80000031-0000-4000-8000-000000000031", "pid_80000032-0000-4000-8000-000000000032")
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{first, second}}
	publisher := &recordingOutboxPublisher{err: errors.New("sqs body contains secret-value")}
	processor, err := newOutboxProcessor(outboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 45,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("RunOnce error = %v", err)
	}
	if len(authority.acknowledged) != 0 || fmt.Sprint(authority.retried) != fmt.Sprint([]string{first.ID + ":45:queue_publish_unknown", second.ID + ":45:queue_publish_unknown"}) {
		t.Fatalf("acknowledged=%v retried=%v", authority.acknowledged, authority.retried)
	}
	if joined := fmt.Sprint(authority.retried); containsAny(joined, "secret-value", "sqs body") {
		t.Fatalf("provider error leaked into retry state: %s", joined)
	}
}

func TestOutboxProcessorRejectsForeignTopicAndScopeBeforePublish(t *testing.T) {
	event := outboxEvent(t, "pid_80000041-0000-4000-8000-000000000041", "pid_80000042-0000-4000-8000-000000000042")
	event.Topic = "runtime-events"
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}}
	publisher := &recordingOutboxPublisher{}
	processor, err := newOutboxProcessor(outboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 30,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("foreign topic error = %v", err)
	}
	if len(publisher.jobs) != 0 || len(authority.acknowledged) != 0 || len(authority.retried) != 0 {
		t.Fatalf("foreign topic caused side effects: jobs=%d ack=%v retry=%v", len(publisher.jobs), authority.acknowledged, authority.retried)
	}

	event = outboxEvent(t, "pid_80000051-0000-4000-8000-000000000051", "pid_80000052-0000-4000-8000-000000000052")
	var body map[string]any
	if err := json.Unmarshal(event.Payload, &body); err != nil {
		t.Fatal(err)
	}
	body["organization_id"] = "pid_89999999-0000-4000-8000-000000000099"
	event.Payload, _ = json.Marshal(body)
	foreignScopeDigest := sha256.Sum256(event.Payload)
	event.PayloadDigest = foreignScopeDigest[:]
	authority.events = []apiserver.DiscoveryOutboxEvent{event}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("foreign scope error = %v", err)
	}
	if len(publisher.jobs) != 0 {
		t.Fatalf("foreign scope was published: %#v", publisher.jobs)
	}
}

func TestOutboxProcessorRejectsPayloadDigestDriftBeforePublish(t *testing.T) {
	event := outboxEvent(t, "pid_80000071-0000-4000-8000-000000000071", "pid_80000072-0000-4000-8000-000000000072")
	event.Payload = bytesReplaceOnce(t, event.Payload, []byte("000000000004"), []byte("000000000005"))
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}}
	publisher := &recordingOutboxPublisher{}
	processor, err := newOutboxProcessor(outboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 1, RetrySeconds: 30,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("digest drift error = %v", err)
	}
	if len(publisher.jobs) != 0 || len(authority.acknowledged) != 0 || len(authority.retried) != 0 {
		t.Fatalf("digest drift caused side effects: jobs=%d ack=%v retry=%v", len(publisher.jobs), authority.acknowledged, authority.retried)
	}
}

func TestOutboxProcessorRetriesExactDatabaseAcknowledgementWithoutRepublishing(t *testing.T) {
	event := outboxEvent(t, "pid_80000081-0000-4000-8000-000000000081", "pid_80000082-0000-4000-8000-000000000082")
	jobID := mustProductID(t, firstPayloadJobID(t, event))
	for _, lostResponse := range []bool{false, true} {
		authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}, ackFailures: 1, ackLostResponse: lostResponse}
		publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{JobIDs: []domain.ProductID{jobID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "provider-message")}}}}
		processor, err := newOutboxProcessor(outboxProcessorConfig{
			Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 1, RetrySeconds: 30,
			NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := processor.RunOnce(context.Background()); err != nil {
			t.Fatalf("lostResponse=%v RunOnce error=%v", lostResponse, err)
		}
		if publisher.calls != 1 || authority.ackCalls != 2 || len(authority.acknowledged) != 1 {
			t.Fatalf("lostResponse=%v publisher=%d ackCalls=%d acknowledged=%v", lostResponse, publisher.calls, authority.ackCalls, authority.acknowledged)
		}
	}
}

func TestOutboxProcessorRejectsMalformedPublishAcknowledgementsWithoutDatabaseAck(t *testing.T) {
	event := outboxEvent(t, "pid_80000061-0000-4000-8000-000000000061", "pid_80000062-0000-4000-8000-000000000062")
	jobID := mustProductID(t, firstPayloadJobID(t, event))
	for _, result := range []jobqueue.PublishResult{
		{JobIDs: []domain.ProductID{jobID}},
		{JobIDs: []domain.ProductID{jobID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: " changed "}}},
		{JobIDs: []domain.ProductID{mustProductID(t, "pid_89999991-0000-4000-8000-000000000091")}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "provider-message")}}},
	} {
		authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}}
		processor, err := newOutboxProcessor(outboxProcessorConfig{
			Authority: authority, Publisher: &recordingOutboxPublisher{result: result}, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 1, RetrySeconds: 30,
			NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
			t.Fatalf("malformed acknowledgement error = %v", err)
		}
		if len(authority.acknowledged) != 0 || len(authority.retried) != 1 {
			t.Fatalf("malformed acknowledgement ack=%v retry=%v", authority.acknowledged, authority.retried)
		}
	}
}

type recordingOutboxAuthority struct {
	events                              []apiserver.DiscoveryOutboxEvent
	claimTopic, claimWorker, claimToken string
	acknowledged, retried               []string
	ackCalls, ackFailures               int
	ackLostResponse                     bool
	ackCommitted                        map[string]struct{}
}

func (authority *recordingOutboxAuthority) ClaimOutboxTopic(_ context.Context, topic, worker, token string, _, _ int) ([]apiserver.DiscoveryOutboxEvent, error) {
	authority.claimTopic, authority.claimWorker, authority.claimToken = topic, worker, token
	return append([]apiserver.DiscoveryOutboxEvent(nil), authority.events...), nil
}

func (authority *recordingOutboxAuthority) AcknowledgeOutbox(_ context.Context, _ domain.Scope, id, _, _, providerAck string) error {
	authority.ackCalls++
	key := id + ":" + providerAck
	if authority.ackCommitted != nil {
		if _, replay := authority.ackCommitted[key]; replay {
			return nil
		}
	}
	if authority.ackFailures > 0 {
		authority.ackFailures--
		if authority.ackLostResponse {
			if authority.ackCommitted == nil {
				authority.ackCommitted = map[string]struct{}{}
			}
			authority.ackCommitted[key] = struct{}{}
			authority.acknowledged = append(authority.acknowledged, key)
		}
		return errors.New("database response unavailable")
	}
	authority.acknowledged = append(authority.acknowledged, key)
	return nil
}

func (authority *recordingOutboxAuthority) RetryOutbox(_ context.Context, _ domain.Scope, id, _, _ string, seconds int, code string) error {
	authority.retried = append(authority.retried, fmt.Sprintf("%s:%d:%s", id, seconds, code))
	return nil
}

type recordingOutboxPublisher struct {
	jobs   []jobqueue.Job
	result jobqueue.PublishResult
	err    error
	calls  int
}

func (publisher *recordingOutboxPublisher) PublishBatch(_ context.Context, jobs []jobqueue.Job) (jobqueue.PublishResult, error) {
	publisher.calls++
	publisher.jobs = append([]jobqueue.Job(nil), jobs...)
	return publisher.result, publisher.err
}

func outboxEvent(t *testing.T, outboxID, jobID string) apiserver.DiscoveryOutboxEvent {
	t.Helper()
	scope := workerScope(t)
	syncID := "pid_80000003-0000-4000-8000-000000000003"
	payload, err := json.Marshal(map[string]string{
		"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(),
		"job_id": jobID, "sync_id": syncID, "integration_id": "pid_80000004-0000-4000-8000-000000000004",
		"request_digest": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return apiserver.DiscoveryOutboxEvent{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		ID: outboxID, Topic: discoveryOutboxTopic, DeterministicKey: "sync:" + syncID, PayloadVersion: 1, Payload: payload, PayloadDigest: digest[:], Attempt: 1,
	}
}

func firstPayloadJobID(t *testing.T, event apiserver.DiscoveryOutboxEvent) string {
	t.Helper()
	var body struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(event.Payload, &body); err != nil {
		t.Fatal(err)
	}
	return body.JobID
}

func mustProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func canonicalProviderAck(t *testing.T, value string) string {
	t.Helper()
	acknowledgement, ok := jobqueue.CanonicalProviderAcknowledgement(value)
	if !ok {
		t.Fatalf("invalid provider acknowledgement fixture %q", value)
	}
	return acknowledgement
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if len(needle) > 0 && len(value) >= len(needle) {
			for index := 0; index+len(needle) <= len(value); index++ {
				if value[index:index+len(needle)] == needle {
					return true
				}
			}
		}
	}
	return false
}

func bytesReplaceOnce(t *testing.T, value, old, replacement []byte) []byte {
	t.Helper()
	index := -1
	for candidate := 0; candidate+len(old) <= len(value); candidate++ {
		if string(value[candidate:candidate+len(old)]) == string(old) {
			index = candidate
			break
		}
	}
	if index < 0 || len(old) != len(replacement) {
		t.Fatal("invalid same-length replacement fixture")
	}
	result := append([]byte(nil), value...)
	copy(result[index:index+len(old)], replacement)
	return result
}
