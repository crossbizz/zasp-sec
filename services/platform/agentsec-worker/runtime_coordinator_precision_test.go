package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type preciseCoordinatorAuthority struct {
	runtimeCoordinatorAuthority
	unready bool
	checks  int
}

func (authority *preciseCoordinatorAuthority) ReadyPrecision(context.Context) error {
	authority.checks++
	if authority.unready {
		return errRuntimeUnavailable
	}
	return nil
}

func TestPreciseRuntimeCoordinatorAcceptsV2WithoutChangingAuthority(t *testing.T) {
	steps := &runtimeCoordinatorSteps{}
	job := runtimeCoordinatorJob(t)
	payload := runtimeCoordinatorPayload(t, job)
	payload.PayloadSchema = "runtime-event-v2"
	job.Payload, _ = json.Marshal(payload)
	queue, driver := runtimeCoordinatorQueueForJob(t, steps, job)
	authority := &preciseCoordinatorAuthority{runtimeCoordinatorAuthority: runtimeCoordinatorAuthority{steps: steps}}
	processor, err := newPreciseRuntimeCoordinator(runtimeCoordinatorConfig{Authority: authority, Queue: queue, WorkerID: "runtime-coordinator-01", LeaseSeconds: 5, VisibilitySeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := processor.RunOnce(ctx); err != nil || driver.acknowledgements != 1 || authority.claimRequest.MessageDigest != job.AuthorityDigest {
		t.Fatal("V2 coordinator rejected or changed durable authority", err)
	}
}

type precisionObservedQueue struct {
	runtimeDeliveryQueue
	consumes int
}

func (queue *precisionObservedQueue) ConsumeBatch(ctx context.Context, limit int) ([]jobqueue.Delivery, error) {
	queue.consumes++
	return queue.runtimeDeliveryQueue.ConsumeBatch(ctx, limit)
}

func TestPreciseRuntimeCoordinatorRefusesDriftBeforeQueue(t *testing.T) {
	steps := &runtimeCoordinatorSteps{}
	queue, _, _ := runtimeCoordinatorQueue(t, steps)
	observed := &precisionObservedQueue{runtimeDeliveryQueue: queue}
	authority := &preciseCoordinatorAuthority{runtimeCoordinatorAuthority: runtimeCoordinatorAuthority{steps: steps}, unready: true}
	config := runtimeCoordinatorConfig{Authority: authority, Queue: observed, WorkerID: "runtime-coordinator-01", LeaseSeconds: 5, VisibilitySeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }}
	processor, err := newPreciseRuntimeCoordinator(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err == nil || observed.consumes != 0 || authority.claims != 0 || authority.checks != 1 {
		t.Fatal("drifted precision consumed queue", err)
	}
	config.Authority = &runtimeCoordinatorAuthority{steps: steps}
	if processor, err := newPreciseRuntimeCoordinator(config); err == nil || processor != nil {
		t.Fatal("historical authority enabled precision")
	}
}

func TestRuntimeDeliverySchemaSelectionRemainsExplicit(t *testing.T) {
	for _, schema := range []string{"runtime-event-v1", "runtime-event-v2", "runtime-event-v3", ""} {
		job := runtimeCoordinatorJob(t)
		payload := runtimeCoordinatorPayload(t, job)
		payload.PayloadSchema = schema
		job.Payload, _ = json.Marshal(payload)
		_, _, legacy := decodeRuntimeDeliveryJob(job)
		precise, _, valid := decodeVersionedRuntimeDeliveryJob(job, true)
		if legacy != (schema == "runtime-event-v1") || valid != (schema == "runtime-event-v1" || schema == "runtime-event-v2") || valid && precise.PayloadSchema != schema {
			t.Fatal("delivery schema fence", schema, legacy, valid)
		}
	}
}

func TestPreciseCoordinatorCompositionRequiresFreshRelease51(t *testing.T) {
	config := validRuntimeCoordinatorConfig()
	config.RuntimeDeliverySchema = "runtime-event-v2"
	database := &precisionStartupDatabase{healthy: true}
	queue, driver, _ := runtimeCoordinatorQueue(t, &runtimeCoordinatorSteps{})
	dependencies, err := composeRuntimeCoordinatorWorkerRuntime(config, database, &productionRuntimeQueueDependencies{
		Queue: queue, ready: func(context.Context) error { return nil }, close: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Ready(context.Background()); err != nil || database.checks == 0 {
		t.Fatal("composition did not require release 51", err)
	}
	database.healthy = false
	checks := database.checks
	if err := dependencies.Processor.RunOnce(context.Background()); err == nil || database.checks <= checks || len(database.claims) != 0 || driver.consumes != 0 {
		t.Fatal("cached readiness bypassed fresh precision guard", err)
	}
}
