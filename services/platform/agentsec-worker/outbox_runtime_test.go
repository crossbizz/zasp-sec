package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

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
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency,
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

func TestOutboxProcessorPublishesRuntimeJobsWithExactOutboxAuthority(t *testing.T) {
	event := runtimeOutboxEvent(t)
	jobID := mustProductID(t, firstPayloadJobID(t, event))
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}}
	publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{
		JobIDs:           []domain.ProductID{jobID},
		Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "runtime-message-1")}},
	}}
	processor, err := newOutboxProcessor(outboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: runtimeOutboxTopic, WorkerID: "runtime-outbox-01", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 30,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publisher.jobs) != 1 || publisher.jobs[0].Kind != "runtime" || publisher.jobs[0].JobID != jobID {
		t.Fatalf("published jobs = %#v", publisher.jobs)
	}
	var wantDigest [sha256.Size]byte
	copy(wantDigest[:], event.PayloadDigest)
	if publisher.jobs[0].AuthorityDigest != wantDigest || !json.Valid(publisher.jobs[0].Payload) {
		t.Fatalf("published authority = %x payload=%q", publisher.jobs[0].AuthorityDigest, publisher.jobs[0].Payload)
	}
	if got := fmt.Sprint(authority.acknowledged); got != fmt.Sprint([]string{event.ID + ":" + canonicalProviderAck(t, "runtime-message-1")}) {
		t.Fatalf("acknowledged = %v", authority.acknowledged)
	}
}

func TestRuntimeOutboxJobRejectsAuthorityDriftBeforePublish(t *testing.T) {
	base := runtimeOutboxEvent(t)
	cases := []struct {
		name   string
		mutate func(*apiserver.DiscoveryOutboxEvent, map[string]any)
	}{
		{name: "topic", mutate: func(event *apiserver.DiscoveryOutboxEvent, _ map[string]any) { event.Topic = discoveryOutboxTopic }},
		{name: "version", mutate: func(event *apiserver.DiscoveryOutboxEvent, _ map[string]any) { event.PayloadVersion = 1 }},
		{name: "key", mutate: func(event *apiserver.DiscoveryOutboxEvent, _ map[string]any) { event.DeterministicKey += "-drift" }},
		{name: "batch", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) {
			payload["batch_id"] = "pid_90000009-0000-4000-8000-000000000009"
		}},
		{name: "generation", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) { payload["generation"] = float64(2) }},
		{name: "pipeline", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) {
			payload["pipeline_version"] = float64(14)
		}},
		{name: "artifact key", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) {
			payload["artifact_key"] = "runtime/v15/foreign"
		}},
		{name: "artifact reference", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) {
			payload["artifact_reference"] = "s3://foreign/runtime/v15/foreign"
		}},
		{name: "checksum", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) { payload["artifact_checksum"] = "00" }},
		{name: "media", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) {
			payload["payload_media_type"] = "text/plain"
		}},
		{name: "schema", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) {
			payload["payload_schema_version"] = "runtime-event-v2"
		}},
		{name: "extra", mutate: func(_ *apiserver.DiscoveryOutboxEvent, payload map[string]any) { payload["secret"] = "must-not-pass" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			event := base
			event.Payload = append([]byte(nil), base.Payload...)
			event.PayloadDigest = append([]byte(nil), base.PayloadDigest...)
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(&event, payload)
			if body, err := json.Marshal(payload); err == nil && !jsonEqual(body, base.Payload) {
				event.Payload = body
				digest := sha256.Sum256(body)
				event.PayloadDigest = digest[:]
			}
			if job, _, ok := discoveryJobForOutbox(event, runtimeOutboxTopic); ok || job.JobID != (domain.ProductID{}) {
				t.Fatalf("drift accepted: %#v", job)
			}
		})
	}
}

func TestOutboxProcessorRenewsLeaseWhilePublisherIsBlocked(t *testing.T) {
	event := outboxEvent(t, "pid_80000091-0000-4000-8000-000000000091", "pid_80000092-0000-4000-8000-000000000092")
	jobID := mustProductID(t, firstPayloadJobID(t, event))
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}}
	release := make(chan struct{})
	publisher := &blockingOutboxPublisher{entered: make(chan struct{}, 1), release: release, result: jobqueue.PublishResult{JobIDs: []domain.ProductID{jobID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "provider-heartbeat")}}}}
	processor, err := newOutboxProcessor(outboxProcessorConfig{Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 5, BatchSize: 1, RetrySeconds: 30, HeartbeatInterval: 20 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- processor.RunOnce(context.Background()) }()
	select {
	case <-publisher.entered:
	case <-time.After(time.Second):
		t.Fatal("publisher did not start")
	}
	deadline := time.Now().Add(time.Second)
	for authority.heartbeatCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if authority.heartbeatCount() < 2 {
		t.Fatalf("heartbeat calls=%d", authority.heartbeatCount())
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestOutboxProcessorRenewsLeaseWhileDatabaseAcknowledgementIsBlocked(t *testing.T) {
	event := outboxEvent(t, "pid_80000101-0000-4000-8000-000000000101", "pid_80000102-0000-4000-8000-000000000102")
	jobID := mustProductID(t, firstPayloadJobID(t, event))
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}, ackEntered: make(chan struct{}, 1), ackRelease: make(chan struct{})}
	publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{JobIDs: []domain.ProductID{jobID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "provider-blocked-ack")}}}}
	processor, err := newOutboxProcessor(outboxProcessorConfig{Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 5, BatchSize: 1, RetrySeconds: 30, HeartbeatInterval: 20 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- processor.RunOnce(context.Background()) }()
	select {
	case <-authority.ackEntered:
	case <-time.After(time.Second):
		t.Fatal("acknowledgement did not start")
	}
	before := authority.heartbeatCount()
	deadline := time.Now().Add(time.Second)
	for authority.heartbeatCount() <= before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if authority.heartbeatCount() <= before {
		t.Fatalf("lease was not renewed during blocked acknowledgement: before=%d after=%d", before, authority.heartbeatCount())
	}
	close(authority.ackRelease)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestOutboxProcessorCancelsBlockedPublishWhenLeaseHeartbeatFails(t *testing.T) {
	event := outboxEvent(t, "pid_80000111-0000-4000-8000-000000000111", "pid_80000112-0000-4000-8000-000000000112")
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}, heartbeatFailAfter: 1}
	publisher := &contextOutboxPublisher{entered: make(chan struct{}, 1), cancelled: make(chan struct{}, 1)}
	processor, err := newOutboxProcessor(outboxProcessorConfig{Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 5, BatchSize: 1, RetrySeconds: 30, HeartbeatInterval: 20 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- processor.RunOnce(context.Background()) }()
	select {
	case <-publisher.entered:
	case <-time.After(time.Second):
		t.Fatal("publisher did not start")
	}
	select {
	case <-publisher.cancelled:
	case <-time.After(time.Second):
		t.Fatal("lease loss did not cancel blocked publisher")
	}
	if err := <-result; !errors.Is(err, errWorkerExecution) {
		t.Fatalf("lease loss error=%v", err)
	}
}

func TestOutboxProcessorCancelsBlockedAcknowledgementWhenLeaseHeartbeatFails(t *testing.T) {
	event := outboxEvent(t, "pid_80000131-0000-4000-8000-000000000131", "pid_80000132-0000-4000-8000-000000000132")
	jobID := mustProductID(t, firstPayloadJobID(t, event))
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}, heartbeatFailAfter: 2, ackEntered: make(chan struct{}, 1), ackRelease: make(chan struct{})}
	publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{JobIDs: []domain.ProductID{jobID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "provider-lease-loss")}}}}
	processor, err := newOutboxProcessor(outboxProcessorConfig{Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 5, BatchSize: 1, RetrySeconds: 30, HeartbeatInterval: 20 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- processor.RunOnce(context.Background()) }()
	select {
	case <-authority.ackEntered:
	case <-time.After(time.Second):
		t.Fatal("acknowledgement did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, errWorkerExecution) {
			t.Fatalf("lease loss error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease loss did not cancel blocked acknowledgement")
	}
}

func TestOutboxProcessorRequiresHeartbeatByHalfLease(t *testing.T) {
	_, err := newOutboxProcessor(outboxProcessorConfig{Authority: &recordingOutboxAuthority{}, Publisher: &recordingOutboxPublisher{}, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 5, BatchSize: 1, RetrySeconds: 30, HeartbeatInterval: 2501 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency})
	if !errors.Is(err, errWorkerExecution) {
		t.Fatalf("late heartbeat error=%v", err)
	}
}

func TestOutboxProcessorRetriesEveryLeaseAfterUnknownPublishOutcome(t *testing.T) {
	first := outboxEvent(t, "pid_80000021-0000-4000-8000-000000000021", "pid_80000022-0000-4000-8000-000000000022")
	second := outboxEvent(t, "pid_80000031-0000-4000-8000-000000000031", "pid_80000032-0000-4000-8000-000000000032")
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{first, second}}
	publisher := &recordingOutboxPublisher{err: errors.New("sqs body contains secret-value")}
	processor, err := newOutboxProcessor(outboxProcessorConfig{
		Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 45,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency,
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
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency,
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
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency,
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
			NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency,
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
			NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency,
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

func TestOutboxProcessorChecksLiveQueueBeforeClaiming(t *testing.T) {
	authority := &recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{outboxEvent(t, "pid_80000121-0000-4000-8000-000000000121", "pid_80000122-0000-4000-8000-000000000122")}}
	publisher := &recordingOutboxPublisher{}
	processor, err := newOutboxProcessor(outboxProcessorConfig{Authority: authority, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: "outbox-01", LeaseSeconds: 30, BatchSize: 1, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: func(context.Context) error { return errRuntimeUnavailable }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("not-ready error=%v", err)
	}
	if authority.claimCount() != 0 || publisher.calls != 0 {
		t.Fatalf("not-ready side effects: claims=%d publishes=%d", authority.claimCount(), publisher.calls)
	}
}

func readyOutboxDependency(context.Context) error { return nil }

type recordingOutboxAuthority struct {
	mu                                  sync.Mutex
	events                              []apiserver.DiscoveryOutboxEvent
	claimTopic, claimWorker, claimToken string
	acknowledged, retried               []string
	ackCalls, ackFailures               int
	ackLostResponse                     bool
	ackCommitted                        map[string]struct{}
	heartbeatCalls                      int
	heartbeatFailAfter                  int
	claimCalls                          int
	remaining                           int
	claimed                             bool
	ackEntered                          chan struct{}
	ackRelease                          chan struct{}
}

func (authority *recordingOutboxAuthority) HeartbeatOutboxTopic(_ context.Context, topic, _, _ string, seconds, _ int) (apiserver.OutboxLeaseHeartbeatResult, error) {
	authority.mu.Lock()
	authority.heartbeatCalls++
	calls := authority.heartbeatCalls
	failAfter := authority.heartbeatFailAfter
	remaining := authority.remaining
	authority.mu.Unlock()
	if failAfter > 0 && calls > failAfter {
		return apiserver.OutboxLeaseHeartbeatResult{}, errors.New("lease lost")
	}
	expires := time.Now().Add(time.Duration(seconds) * time.Second).UTC()
	return apiserver.OutboxLeaseHeartbeatResult{ID: topic, LeaseExpiresAt: expires, RemainingCount: remaining}, nil
}

func (authority *recordingOutboxAuthority) heartbeatCount() int {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.heartbeatCalls
}

func (authority *recordingOutboxAuthority) ClaimOutboxTopic(_ context.Context, topic, worker, token string, _, _ int) ([]apiserver.DiscoveryOutboxEvent, error) {
	authority.mu.Lock()
	authority.claimCalls++
	if !authority.claimed {
		authority.remaining = len(authority.events)
		authority.claimed = true
	}
	authority.mu.Unlock()
	authority.claimTopic, authority.claimWorker, authority.claimToken = topic, worker, token
	return append([]apiserver.DiscoveryOutboxEvent(nil), authority.events...), nil
}

func (authority *recordingOutboxAuthority) claimCount() int {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.claimCalls
}

func (authority *recordingOutboxAuthority) AcknowledgeOutboxTopic(ctx context.Context, _ string, _ domain.Scope, id, _, _, providerAck string) (apiserver.OutboxLeaseTransitionResult, error) {
	if authority.ackEntered != nil {
		select {
		case authority.ackEntered <- struct{}{}:
		default:
		}
		select {
		case <-authority.ackRelease:
		case <-ctx.Done():
			return apiserver.OutboxLeaseTransitionResult{}, ctx.Err()
		}
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.ackCalls++
	key := id + ":" + providerAck
	if authority.ackCommitted != nil {
		if _, replay := authority.ackCommitted[key]; replay {
			return apiserver.OutboxLeaseTransitionResult{ID: id, ProviderAck: providerAck, PublishedAt: time.Now().UTC(), RemainingCount: authority.remaining}, nil
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
			authority.remaining--
		}
		return apiserver.OutboxLeaseTransitionResult{}, errors.New("database response unavailable")
	}
	authority.acknowledged = append(authority.acknowledged, key)
	authority.remaining--
	return apiserver.OutboxLeaseTransitionResult{ID: id, ProviderAck: providerAck, PublishedAt: time.Now().UTC(), RemainingCount: authority.remaining}, nil
}

func (authority *recordingOutboxAuthority) RetryOutboxTopic(_ context.Context, _ string, _ domain.Scope, id, _, _ string, seconds int, code string) (apiserver.OutboxLeaseTransitionResult, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.retried = append(authority.retried, fmt.Sprintf("%s:%d:%s", id, seconds, code))
	authority.remaining--
	return apiserver.OutboxLeaseTransitionResult{ID: id, AvailableAt: time.Now().UTC().Add(time.Duration(seconds) * time.Second), RemainingCount: authority.remaining}, nil
}

type recordingOutboxPublisher struct {
	jobs   []jobqueue.Job
	result jobqueue.PublishResult
	err    error
	calls  int
}

type blockingOutboxPublisher struct {
	entered chan struct{}
	release <-chan struct{}
	result  jobqueue.PublishResult
}

type contextOutboxPublisher struct {
	entered   chan struct{}
	cancelled chan struct{}
}

func (publisher *contextOutboxPublisher) PublishBatch(ctx context.Context, _ []jobqueue.Job) (jobqueue.PublishResult, error) {
	publisher.entered <- struct{}{}
	<-ctx.Done()
	publisher.cancelled <- struct{}{}
	return jobqueue.PublishResult{}, ctx.Err()
}

func (publisher *blockingOutboxPublisher) PublishBatch(context.Context, []jobqueue.Job) (jobqueue.PublishResult, error) {
	publisher.entered <- struct{}{}
	<-publisher.release
	return publisher.result, nil
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

func runtimeOutboxEvent(t *testing.T) apiserver.DiscoveryOutboxEvent {
	t.Helper()
	scope := workerScope(t)
	batchID := "pid_89000001-0000-4000-8000-000000000001"
	jobID := "pid_89000002-0000-4000-8000-000000000002"
	sensorID := "pid_89000003-0000-4000-8000-000000000003"
	key := fmt.Sprintf("runtime/v15/%s/%s/%s/%s/%020d/%s.json", scope.OrganizationID(), scope.WorkspaceID(), scope.EnvironmentID(), sensorID, 1, batchID)
	payload, err := json.Marshal(map[string]any{
		"batch_id": batchID, "job_id": jobID, "generation": int64(1), "pipeline_version": 15,
		"artifact_reference": "s3://zasp-runtime-prod/" + key, "artifact_key": key, "artifact_version_id": "version-1",
		"artifact_checksum": "10112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "artifact_size_bytes": int64(4096),
		"payload_media_type": "application/json", "payload_schema_version": "runtime-event-v1", "event_count": 2,
		"request_digest": "20112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return apiserver.DiscoveryOutboxEvent{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ID: "pid_89000004-0000-4000-8000-000000000004", Topic: runtimeOutboxTopic, DeterministicKey: "runtime:" + batchID, PayloadVersion: 15, Payload: payload, PayloadDigest: digest[:], Attempt: 1}
}

func jsonEqual(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil && fmt.Sprint(leftValue) == fmt.Sprint(rightValue)
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
