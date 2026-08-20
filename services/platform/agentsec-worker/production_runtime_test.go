package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestComposeWorkerRuntimeMountsOnlyProductionReadyModes(t *testing.T) {
	database := readyWorkerDatabase{}
	scheduler := validSchedulerRuntimeConfig()
	dependencies, err := composeWorkerRuntime(context.Background(), scheduler, database)
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil {
		t.Fatalf("scheduler dependencies=%#v err=%v", dependencies, err)
	}
	discovery := scheduler
	discovery.Mode = workerModeDiscovery
	discovery.DatabaseAuthority = "zasp_discovery_worker"
	discovery.DiscoveryQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/zasp-discovery"
	discovery.AWSRegion = "us-west-2"
	discovery.EvidenceBucket = "zasp-production-evidence"
	discovery.EvidenceOwner = "123456789012"
	discovery.EvidenceKMSKeyARN = "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"
	if _, err := composeWorkerRuntime(context.Background(), discovery, database); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("uncomposed discovery mode error=%v", err)
	}
}

func TestComposeOutboxWorkerRuntimeBindsExactTopicAuthority(t *testing.T) {
	t.Parallel()
	config := validSchedulerRuntimeConfig()
	config.Mode, config.DatabaseAuthority, config.WorkerID = workerModeOutbox, "zasp_outbox_worker", "outbox-01"
	config.DiscoveryQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs"
	config.AWSRegion = "us-west-2"
	config.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-outbox"
	config.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	dependencies, err := composeOutboxWorkerRuntime(config, readyWorkerDatabase{}, &recordingOutboxPublisher{}, readyOutboxDependency)
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("outbox dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatalf("outbox readiness = %v", err)
	}
}

func TestComposeProjectionWorkerRuntimeBindsExactSearchAuthority(t *testing.T) {
	t.Parallel()
	config := validSchedulerRuntimeConfig()
	config.Mode, config.ProjectionKind = workerModeProjectionSearch, "search"
	config.DatabaseAuthority, config.WorkerID = "zasp_projection_search_worker", "projection-search-01"
	config.AWSRegion = "us-west-2"
	config.ProjectionRoleARN = "arn:aws:iam::123456789012:role/zasp-production-projection-search"
	config.ProjectionTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	config.OpenSearchURL, config.OpenSearchIndex = "https://vpc-zasp.us-west-2.es.amazonaws.com", "zasp-inventory-v1"
	closed := false
	projector := &projectionProjectorStub{}
	dependencies, err := composeProjectionWorkerRuntime(config, readyWorkerDatabase{}, productionProjectionProjector{
		projectionProjector: projector,
		ready:               func(context.Context) error { return nil },
		close:               func() error { closed = true; return nil },
	})
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("projection dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatalf("projection readiness = %v", err)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("projection close = %v, closed=%v", err, closed)
	}

	config.Mode, config.ProjectionKind, config.DatabaseAuthority = workerModeProjectionRisk, "risk", "zasp_projection_risk_worker"
	if _, err := composeProjectionWorkerRuntime(config, readyWorkerDatabase{}, productionProjectionProjector{projectionProjector: projector, ready: func(context.Context) error { return nil }, close: func() error { return nil }}); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("risk composition error = %v", err)
	}
}

func TestServeWorkerRuntimeBoundsShutdownWhenProcessorIgnoresCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	processor := blockingWorkerProcessor{entered: entered, release: release}
	closed := make(chan struct{}, 1)
	config := validSchedulerRuntimeConfig()
	config.ShutdownTimeout = time.Second
	listeners := make(chan net.Listener, 1)
	listen := func(string, string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listeners <- listener
		}
		return listener, err
	}
	result := make(chan error, 1)
	go func() {
		result <- serveWorkerRuntime(ctx, &bytes.Buffer{}, "test", config, workerRuntimeDependencies{Processor: processor, Ready: func(context.Context) error { return nil }, Close: func() error { closed <- struct{}{}; return nil }}, listen)
	}()
	select {
	case <-listeners:
	case <-time.After(time.Second):
		t.Fatal("worker did not listen")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start processor")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("bounded shutdown error = %v", err)
		}
	case <-time.After(1250 * time.Millisecond):
		close(release)
		<-result
		t.Fatal("worker waited indefinitely for a noncooperative processor")
	}
	select {
	case <-closed:
	default:
		t.Fatal("worker dependencies were not closed")
	}
	close(release)
}

func TestServeWorkerRuntimeSurfacesDependencyDrainFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := validSchedulerRuntimeConfig()
	listeners := make(chan net.Listener, 1)
	result := make(chan error, 1)
	go func() {
		result <- serveWorkerRuntime(ctx, &bytes.Buffer{}, "test", config, workerRuntimeDependencies{Processor: immediateWorkerProcessor{}, Ready: func(context.Context) error { return nil }, Close: func() error { return errors.New("redacted drain failure") }}, func(string, string) (net.Listener, error) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				listeners <- listener
			}
			return listener, err
		})
	}()
	select {
	case <-listeners:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("worker did not listen")
	}
	if err := <-result; !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("drain failure error=%v", err)
	}
}

type immediateWorkerProcessor struct{}

func (immediateWorkerProcessor) RunOnce(context.Context) error { return nil }

type blockingWorkerProcessor struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (processor blockingWorkerProcessor) RunOnce(context.Context) error {
	processor.entered <- struct{}{}
	<-processor.release
	return nil
}

func validSchedulerRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeScheduler, PostgresDSN: "postgres://scheduler@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_discovery_scheduler", WorkerID: "scheduler-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 1, ShutdownTimeout: 20 * time.Second,
		ParserVersion: "inventory-parser-2026.08.20", ToolVersion: "collector-tool-2026.08.20",
	}
}

type readyWorkerDatabase struct{}

func (readyWorkerDatabase) SchemaVersion(context.Context) (string, error) {
	return "production-discovery-execution-v1", nil
}
func (readyWorkerDatabase) QueryJSON(_ context.Context, _ string, _ ...any) (json.RawMessage, error) {
	return json.RawMessage(`true`), nil
}
func (readyWorkerDatabase) Exec(context.Context, string, ...any) error { return nil }
