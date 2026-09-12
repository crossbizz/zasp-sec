package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type precisionOutboxCompositionDatabase struct {
	readyWorkerDatabase
	event                    apiserver.DiscoveryOutboxEvent
	healthy                  bool
	claims, acknowledgements int
}

func (database *precisionOutboxCompositionDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	switch {
	case strings.Contains(statement, "zasp_production_runtime_precision_readiness"):
		return json.Marshal(database.healthy)
	case statement == `SELECT zasp_runtime_claim_outbox_v2($1,$2,$3,$4,$5)`:
		database.claims++
		return json.Marshal(map[string]any{"items": []apiserver.DiscoveryOutboxEvent{database.event}})
	case statement == `SELECT zasp_runtime_heartbeat_outbox($1,$2,$3,$4,$5)`:
		return json.Marshal(map[string]any{"id": "runtime-events", "lease_expires_at": time.Now().UTC().Add(30 * time.Second), "remaining_count": 1})
	case statement == `SELECT zasp_runtime_ack_outbox($1,$2,$3,$4,$5,$6,$7,$8)`:
		if len(args) != 8 || args[0] != "runtime-events" || args[1] != database.event.OrganizationID || args[2] != database.event.WorkspaceID || args[3] != database.event.EnvironmentID || args[4] != database.event.ID {
			return nil, fmt.Errorf("wrong acknowledgement authority")
		}
		database.acknowledgements++
		return json.Marshal(map[string]any{"id": database.event.ID, "published_at": time.Now().UTC(), "provider_ack": args[7], "remaining_count": 0})
	default:
		return nil, fmt.Errorf("unexpected database operation: %s", statement)
	}
}

func TestPreciseOutboxProductionCompositionPublishesV2(t *testing.T) {
	config := validSchedulerRuntimeConfig()
	config.Mode, config.DatabaseAuthority, config.WorkerID = workerModeRuntimeOutbox, "zasp_outbox_worker", "runtime-outbox-01"
	config.RuntimeQueueURL, config.AWSRegion = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events", "us-west-2"
	config.OutboxRoleARN, config.OutboxTokenFile = "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox", "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	config.RuntimeDeliverySchema = "runtime-event-v2"
	event := runtimeOutboxEvent(t)
	event.Payload = bytes.Replace(event.Payload, []byte("runtime-event-v1"), []byte("runtime-event-v2"), 1)
	digest := sha256.Sum256(event.Payload)
	event.PayloadDigest, event.LeaseExpiresAt = digest[:], time.Now().UTC().Add(30*time.Second)
	database := &precisionOutboxCompositionDatabase{event: event, healthy: true}
	jobID := mustProductID(t, firstPayloadJobID(t, event))
	publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{JobIDs: []domain.ProductID{jobID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: jobID, ProviderAck: canonicalProviderAck(t, "composed-message-1")}}}}
	dependencies, err := composeOutboxWorkerRuntime(config, database, publisher, readyOutboxDependency)
	if err != nil {
		t.Fatal("precision composition refused", err)
	}
	if err := dependencies.Processor.RunOnce(context.Background()); err != nil || database.acknowledgements != 1 || len(publisher.jobs) != 1 {
		t.Fatal("composed publication failed", err)
	}
	if !bytes.Equal(publisher.jobs[0].Payload, event.Payload) || publisher.jobs[0].AuthorityDigest != digest {
		t.Fatal("composition changed durable authority")
	}
	database.healthy = false
	if err := dependencies.Processor.RunOnce(context.Background()); err == nil || database.claims != 1 || database.acknowledgements != 1 {
		t.Fatal("drifted composition performed work", err)
	}
}
