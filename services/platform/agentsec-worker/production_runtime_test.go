package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
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
	discovery := validDiscoveryRuntimeConfig()
	discoveryDependencies, err := composeWorkerRuntime(context.Background(), discovery, database)
	if err != nil || discoveryDependencies.Processor == nil || discoveryDependencies.Ready == nil || discoveryDependencies.Close == nil {
		t.Fatalf("discovery dependencies=%#v error=%v", discoveryDependencies, err)
	}
	if err := discoveryDependencies.Close(); err != nil {
		t.Fatalf("discovery close=%v", err)
	}
}

func TestComposeDiscoveryWorkerRuntimeBindsRepositoryQueueFactoryAndClose(t *testing.T) {
	closed := false
	discovery := &productionDiscoveryDependencies{
		Factory: &errorDiscoveryCollectorFactory{collector: &lifecycleJobCollector{}}, Queue: &recordingDiscoveryQueue{},
		ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil },
	}
	dependencies, err := composeDiscoveryWorkerRuntime(validDiscoveryRuntimeConfig(), readyWorkerDatabase{}, discovery)
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("close=%v closed=%v", err, closed)
	}
}

func TestComposeDiscoveryWorkerRuntimeReadinessGatesQueueConsumption(t *testing.T) {
	steps := []string{}
	discovery := &productionDiscoveryDependencies{
		Factory: &errorDiscoveryCollectorFactory{collector: &lifecycleJobCollector{}}, Queue: &recordingDiscoveryQueue{steps: &steps},
		ready: func(context.Context) error { return errRuntimeUnavailable }, close: func() error { return nil },
	}
	dependencies, err := composeDiscoveryWorkerRuntime(validDiscoveryRuntimeConfig(), readyWorkerDatabase{}, discovery)
	if err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("not-ready discovery RunOnce error = %v", err)
	}
	if len(steps) != 0 {
		t.Fatalf("not-ready discovery consumed the queue: %v", steps)
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

func TestComposeOutboxWorkerRuntimeStopsBeforeClaimWhenRepositoryDrifts(t *testing.T) {
	config := validSchedulerRuntimeConfig()
	config.Mode, config.DatabaseAuthority, config.WorkerID = workerModeOutbox, "zasp_outbox_worker", "outbox-01"
	config.DiscoveryQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs"
	config.AWSRegion = "us-west-2"
	config.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-outbox"
	config.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	database := &driftingWorkerDatabase{}
	publisher := &recordingOutboxPublisher{}
	dependencies, err := composeOutboxWorkerRuntime(config, database, publisher, readyOutboxDependency)
	if err != nil {
		t.Fatal(err)
	}
	database.resetAndDrift()
	if err := dependencies.Processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("repository-drift RunOnce error = %v", err)
	}
	if publisher.calls != 0 {
		t.Fatalf("repository drift published %d batches", publisher.calls)
	}
	for _, statement := range database.statementsSnapshot() {
		if strings.Contains(statement, "claim_outbox") {
			t.Fatalf("repository drift reached claim: %q", statement)
		}
	}
}

func TestWorkerReadinessCachesEmptyPollsThenFailsClosedAfterExpiry(t *testing.T) {
	now := time.Now()
	drifted := false
	calls := 0
	readiness := &boundedCachedWorkerReadiness{
		check: func(context.Context) error {
			calls++
			if drifted {
				return errRuntimeUnavailable
			}
			return nil
		},
		timeout: time.Second, ttl: workerReadinessCacheTTL(time.Second), now: func() time.Time { return now },
	}
	if readiness.ttl != 30*time.Second {
		t.Fatalf("readiness TTL = %s", readiness.ttl)
	}
	for index := 0; index < 100; index++ {
		if err := readiness.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("100 empty polls performed %d live checks", calls)
	}
	drifted = true
	now = now.Add(readiness.ttl + time.Nanosecond)
	if err := readiness.Ready(context.Background()); !errors.Is(err, errRuntimeUnavailable) || calls != 2 {
		t.Fatalf("expired drift error=%v calls=%d", err, calls)
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

func validDiscoveryRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeDiscovery, PostgresDSN: "postgres://discovery@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_discovery_worker", WorkerID: "discovery-01",
		PollInterval: time.Second, LeaseDuration: 30 * time.Second, BatchSize: 8, ShutdownTimeout: 15 * time.Second,
		DiscoveryQueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs", AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		ParserVersion: "inventory-parser-2026.08.20", ToolVersion: "collector-tool-2026.08.20", DiscoveryRoleARN: "arn:aws:iam::123456789012:role/zasp-production-discovery-worker", DiscoveryTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", DiscoverySecretPrefix: "zasp-production/connectors",
		AWSCollectorVersion: "aws-collector-v1", KubernetesCollectorVersion: "kubernetes-collector-v1", GitHubCollectorVersion: "github-collector-v1", OktaCollectorVersion: "okta-collector-v1", KubernetesEgressCIDRs: []string{"203.0.113.0/24"},
		GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", ProviderTimeout: 5 * time.Second, DiscoveryReadinessTimeout: 5 * time.Second,
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

type driftingWorkerDatabase struct {
	mu         sync.Mutex
	drifted    bool
	statements []string
}

func (*driftingWorkerDatabase) SchemaVersion(context.Context) (string, error) {
	return "production-discovery-execution-v1", nil
}

func (database *driftingWorkerDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	database.mu.Lock()
	defer database.mu.Unlock()
	database.statements = append(database.statements, statement)
	if database.drifted {
		return json.RawMessage(`false`), nil
	}
	return json.RawMessage(`true`), nil
}

func (*driftingWorkerDatabase) Exec(context.Context, string, ...any) error { return nil }

func (database *driftingWorkerDatabase) resetAndDrift() {
	database.mu.Lock()
	database.statements = nil
	database.drifted = true
	database.mu.Unlock()
}

func (database *driftingWorkerDatabase) statementsSnapshot() []string {
	database.mu.Lock()
	defer database.mu.Unlock()
	return append([]string(nil), database.statements...)
}
