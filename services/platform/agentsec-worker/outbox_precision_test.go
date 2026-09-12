package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type preciseOutboxAuthority struct {
	recordingOutboxAuthority
	unready bool
	checks  int
}

func (authority *preciseOutboxAuthority) ReadyPrecision(context.Context) error {
	authority.checks++
	if authority.unready {
		return errWorkerExecution
	}
	return nil
}

func TestPreciseOutboxPublishesBothSchemasWithoutChangingAuthority(t *testing.T) {
	for _, schema := range []string{"runtime-event-v1", "runtime-event-v2"} {
		t.Run(schema, func(t *testing.T) {
			event := runtimeOutboxEvent(t)
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			payload["payload_schema_version"] = schema
			event.Payload, _ = json.Marshal(payload)
			digest := sha256.Sum256(event.Payload)
			event.PayloadDigest = digest[:]
			jobID := mustProductID(t, firstPayloadJobID(t, event))
			authority := &preciseOutboxAuthority{recordingOutboxAuthority: recordingOutboxAuthority{events: []apiserver.DiscoveryOutboxEvent{event}}}
			publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{JobIDs: []domain.ProductID{jobID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "precise-message-1")}}}}
			processor, err := newPreciseOutboxProcessor(outboxProcessorConfig{Authority: authority, Publisher: publisher, Topic: runtimeOutboxTopic, WorkerID: "runtime-outbox-01", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); err != nil || len(publisher.jobs) != 1 || len(authority.acknowledged) != 1 {
				t.Fatal("precise publication failed", err)
			}
			if !bytes.Equal(publisher.jobs[0].Payload, event.Payload) || publisher.jobs[0].AuthorityDigest != digest {
				t.Fatal("publication changed authority")
			}
		})
	}
}

func TestPreciseOutboxRequiresFreshAuthorityBeforeClaim(t *testing.T) {
	authority := &preciseOutboxAuthority{unready: true}
	config := outboxProcessorConfig{Authority: authority, Publisher: &recordingOutboxPublisher{}, Topic: runtimeOutboxTopic, WorkerID: "runtime-outbox-01", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }, Ready: readyOutboxDependency}
	processor, err := newPreciseOutboxProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err == nil || authority.claimCount() != 0 || authority.checks != 1 {
		t.Fatal("unready authority claimed work", err)
	}
	config.Authority = &recordingOutboxAuthority{}
	if processor, err := newPreciseOutboxProcessor(config); err == nil || processor != nil {
		t.Fatal("legacy authority enabled precision")
	}
	var missing *preciseOutboxAuthority
	config.Authority = missing
	if processor, err := newPreciseOutboxProcessor(config); err == nil || processor != nil {
		t.Fatal("typed nil authority enabled precision")
	}
	config.Authority, config.Topic = authority, discoveryOutboxTopic
	if processor, err := newPreciseOutboxProcessor(config); err == nil || processor != nil {
		t.Fatal("discovery topic enabled precision")
	}
}

func TestPreciseOutboxSchemaAllowlistAndLegacyFence(t *testing.T) {
	for _, schema := range []string{"runtime-event-v1", "runtime-event-v2", "runtime-event-v3", ""} {
		event := runtimeOutboxEvent(t)
		var payload map[string]any
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		payload["payload_schema_version"] = schema
		event.Payload, _ = json.Marshal(payload)
		digest := sha256.Sum256(event.Payload)
		event.PayloadDigest = digest[:]
		_, _, old := runtimeJobForOutbox(event)
		job, _, precise := versionedRuntimeJobForOutbox(event, true)
		if old != (schema == "runtime-event-v1") || precise != (schema == "runtime-event-v1" || schema == "runtime-event-v2") || precise && !bytes.Equal(job.Payload, event.Payload) {
			t.Fatal("schema fence changed payload or allowed unsupported schema", schema)
		}
	}
}
