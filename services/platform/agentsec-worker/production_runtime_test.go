package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
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
	securityAgentDependencies, err := composeWorkerRuntime(context.Background(), validSecurityAgentRuntimeConfig(), database)
	if err != nil || securityAgentDependencies.Processor == nil || securityAgentDependencies.Ready == nil || securityAgentDependencies.Close == nil {
		t.Fatalf("security-agent dependencies=%#v error=%v", securityAgentDependencies, err)
	}
	_, actionPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	actionDependencies, err := composeSecurityAgentActionWorkerRuntime(validSecurityAgentActionRuntimeConfig(), database, actionPrivateKey)
	if err != nil || actionDependencies.Processor == nil || actionDependencies.Ready == nil || actionDependencies.Close == nil {
		t.Fatalf("security-agent-action dependencies=%#v error=%v", actionDependencies, err)
	}
	if err := actionDependencies.Close(); err != nil {
		t.Fatal(err)
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

func TestComposeRedTeamRuntimesBindSeparateV25Authorities(t *testing.T) {
	closed := false
	dependencies, err := composeRedTeamWorkerRuntime(validRedTeamRuntimeConfig(), readyWorkerDatabase{}, &productionRedTeamDependencies{
		Queue: &recordingDiscoveryQueue{}, Runner: &recordingRedTeamRunner{}, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil },
	})
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("red team dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("close=%v closed=%v", err, closed)
	}
	outboxConfig := validRedTeamOutboxRuntimeConfig()
	outbox, err := composeRedTeamOutboxWorkerRuntime(outboxConfig, readyWorkerDatabase{}, &recordingOutboxPublisher{}, readyOutboxDependency)
	if err != nil || outbox.Processor == nil || outbox.Ready == nil || outbox.Close == nil {
		t.Fatalf("red team outbox dependencies=%#v err=%v", outbox, err)
	}
}

func TestComposeAttackLabOutboxBindsV26AuthorityAndPublisher(t *testing.T) {
	config := validAttackLabOutboxRuntimeConfig()
	dependencies, err := composeAttackLabOutboxWorkerRuntime(config, readyWorkerDatabase{}, &recordingOutboxPublisher{}, readyOutboxDependency)
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("attack lab outbox dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreign := config
	foreign.DatabaseAuthority = "zasp_red_team_outbox_worker"
	if _, err := composeAttackLabOutboxWorkerRuntime(foreign, readyWorkerDatabase{}, &recordingOutboxPublisher{}, readyOutboxDependency); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("foreign authority error=%v", err)
	}
}

func TestComposeRecoveryRuntimesBindSeparateV27Authorities(t *testing.T) {
	scope := recoveryWorkerScope(t)
	authority := &recoveryAuthorityFake{claim: recoveryOperationClaim{Kind: "backup", Scope: scope, OperationID: "pid_71000001-0000-4000-8000-000000000001", Attempt: 1, RetentionDays: 30}}
	closed := false
	queueSteps := []string{}
	queue := &recordingDiscoveryQueue{steps: &queueSteps}
	dependencies, err := composeRecoveryWorkerRuntime(validRecoveryRuntimeConfig(), authority, &productionRecoveryDependencies{
		Queue: queue, Publisher: &recoveryPublisherFake{manifest: recoveryWorkerManifest(scope)}, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil },
	})
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil || dependencies.Metrics == nil {
		t.Fatalf("recovery dependencies=%#v error=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if metrics := dependencies.Metrics(); !strings.Contains(metrics, "zasp_recovery_driver_ready 1\n") {
		t.Fatalf("recovery metrics=%q", metrics)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("close=%v closed=%v", err, closed)
	}
	restoreConfig := validRecoveryRuntimeConfig()
	restoreConfig.PostgresDSN = "postgres://recovery@ep-main.us-west-2.aws.neon.tech/zasp?sslmode=verify-full"
	restoreConfig.RecoveryOperationKind = "restore"
	restoreConfig.RecoveryQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-recovery-restore-jobs"
	restoreConfig.RecoveryNeonSecretReference = "ref:neon/project-api-key"
	restoreConfig.RecoveryKubernetesURL = "https://kubernetes.default.svc"
	restoreConfig.RecoveryKubernetesToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	restoreConfig.RecoveryKubernetesCA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	restoreConfig.RecoveryRunnerImage = "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/agentsec-worker@sha256:" + strings.Repeat("a", 64)
	restoreConfig.RecoveryRunnerServiceAccount = "agentsec-recovery-runner"
	restoreConfig.RecoveryNeonEgressCIDRs = []string{"10.24.8.0/24"}
	restoreAuthority := &recoveryRestoreAuthorityFake{claim: recoveryRestoreClaim(scope)}
	restoreInfrastructure := &recoveryRestoreInfrastructureFake{}
	restoreDependencies, err := composeRecoveryWorkerRuntime(restoreConfig, restoreAuthority, &productionRecoveryDependencies{
		Queue: queue, Loader: &recoveryManifestLoaderFake{manifest: recoveryRestoreManifest(t, scope)}, Infrastructure: restoreInfrastructure,
		ready: func(context.Context) error { return nil }, close: func() error { return nil },
	})
	if err != nil || restoreDependencies.Processor == nil || restoreDependencies.Ready == nil || restoreDependencies.Close == nil {
		t.Fatalf("restore dependencies=%#v error=%v", restoreDependencies, err)
	}
	outboxConfig := validRecoveryOutboxRuntimeConfig()
	outbox, err := composeRecoveryOutboxWorkerRuntime(outboxConfig, &recoveryOutboxAuthorityFake{}, &recordingOutboxPublisher{}, readyOutboxDependency)
	if err != nil || outbox.Processor == nil || outbox.Ready == nil || outbox.Close == nil {
		t.Fatalf("recovery outbox dependencies=%#v error=%v", outbox, err)
	}
	foreign := outboxConfig
	foreign.DatabaseAuthority = "zasp_recovery_worker"
	if _, err := composeRecoveryOutboxWorkerRuntime(foreign, &recoveryOutboxAuthorityFake{}, &recordingOutboxPublisher{}, readyOutboxDependency); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("foreign authority error=%v", err)
	}
}

func TestComposeAttackLabControllerBindsV26QueueSandboxEvidenceAndCleanup(t *testing.T) {
	config, err := loadWorkerRuntimeConfig(mapLookup(validAttackLabControllerRuntimeEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	dependencies, err := composeAttackLabWorkerRuntime(config, readyWorkerDatabase{}, &productionAttackLabDependencies{
		Queue: &recordingDiscoveryQueue{}, Provider: &recordingAttackLabProvider{}, Evidence: &recordingAttackLabEvidenceWriter{},
		ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil },
	})
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("attack lab dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("close=%v closed=%v", err, closed)
	}
}

func TestComposeRuntimeCoordinatorBindsV15RepositoryAndQueueReadiness(t *testing.T) {
	steps := &runtimeCoordinatorSteps{}
	queue, _, _ := runtimeCoordinatorQueue(t, steps)
	closed := false
	config := validRuntimeCoordinatorConfig()
	dependencies, err := composeRuntimeCoordinatorWorkerRuntime(config, readyWorkerDatabase{}, &productionRuntimeQueueDependencies{
		Queue: queue, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil },
	})
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

func TestComposeRuntimeArchiveBindsExactStageRepositoryAndExecutor(t *testing.T) {
	closed := false
	config := validRuntimeArchiveConfig()
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageArchive)
	executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	})
	dependencies, err := composeRuntimeStageWorkerRuntime(config, readyWorkerDatabase{}, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageArchive, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil }})
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil || lease.Stage != runtimeevent.RuntimeStageArchive {
		t.Fatalf("dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("close=%v closed=%v", err, closed)
	}
}

func TestComposeRuntimeIndexBindsExactStageRepositoryAndExecutor(t *testing.T) {
	closed := false
	config := validRuntimeIndexConfig()
	executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	})
	dependencies, err := composeRuntimeStageWorkerRuntime(config, readyWorkerDatabase{}, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageIndex, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil }})
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

func TestComposeRuntimeCorrelationBindsExactStageRepositoryAndExecutor(t *testing.T) {
	closed := false
	config := validRuntimeCorrelationConfig()
	executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	})
	dependencies, err := composeRuntimeStageWorkerRuntime(config, readyWorkerDatabase{}, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageCorrelate, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil }})
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

func TestComposeRuntimeProjectionBindsExactStageRepositoryAndExecutor(t *testing.T) {
	closed := false
	config := validRuntimeProjectionConfig()
	executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	})
	dependencies, err := composeRuntimeStageWorkerRuntime(config, readyWorkerDatabase{}, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageProject, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil }})
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

func TestComposeRuntimeCompleteBindsCoordinatorStageWithoutQueueAuthority(t *testing.T) {
	closed := false
	config := validRuntimeCompleteConfig()
	executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	})
	dependencies, err := composeRuntimeStageWorkerRuntime(config, readyWorkerDatabase{}, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageComplete, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil }})
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

func TestComposeRuntimeOutboxWorkerBindsV15RepositoryAndTopic(t *testing.T) {
	t.Parallel()
	config := validSchedulerRuntimeConfig()
	config.Mode, config.DatabaseAuthority, config.WorkerID = workerModeRuntimeOutbox, "zasp_outbox_worker", "runtime-outbox-01"
	config.RuntimeQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events"
	config.AWSRegion = "us-west-2"
	config.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox"
	config.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	database := readyWorkerDatabase{}
	dependencies, err := composeOutboxWorkerRuntime(config, database, &recordingOutboxPublisher{}, readyOutboxDependency)
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("runtime outbox dependencies=%#v err=%v", dependencies, err)
	}
	processor, ok := dependencies.Processor.(*outboxProcessor)
	if !ok || processor.config.Topic != runtimeOutboxTopic {
		t.Fatalf("runtime processor=%T topic=%q", dependencies.Processor, processor.config.Topic)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatalf("runtime outbox readiness=%v", err)
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
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil || dependencies.Metrics == nil {
		t.Fatalf("projection dependencies=%#v err=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatalf("projection readiness = %v", err)
	}
	if payload := dependencies.Metrics(); !strings.Contains(payload, "zasp_worker_driver_ready 1\n") {
		t.Fatalf("projection metrics do not reflect exact driver readiness:\n%s", payload)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("projection close = %v, closed=%v", err, closed)
	}

	config.Mode, config.ProjectionKind, config.DatabaseAuthority = workerModeProjectionRisk, "risk", "zasp_projection_risk_worker"
	riskDependencies, err := composeProjectionWorkerRuntime(config, readyWorkerDatabase{}, productionProjectionProjector{projectionProjector: projector, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
	if err != nil || riskDependencies.Processor == nil || riskDependencies.Ready == nil {
		t.Fatalf("risk composition dependencies=%#v error=%v", riskDependencies, err)
	}
}

func TestServeWorkerRuntimeExposesOperationalMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := validSchedulerRuntimeConfig()
	listeners := make(chan net.Listener, 1)
	result := make(chan error, 1)
	go func() {
		result <- serveWorkerRuntime(ctx, &bytes.Buffer{}, "test", config, workerRuntimeDependencies{
			Processor: immediateWorkerProcessor{}, Ready: func(context.Context) error { return nil }, Close: func() error { return nil },
			Metrics: func() string { return "zasp_worker_claimed_total 7\n" },
		}, func(string, string) (net.Listener, error) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				listeners <- listener
			}
			return listener, err
		})
	}()
	var listener net.Listener
	select {
	case listener = <-listeners:
	case <-time.After(time.Second):
		t.Fatal("worker did not listen")
	}
	assertContains(t, "http://"+listener.Addr().String()+"/metrics", "zasp_worker_claimed_total 7\n")
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("serveWorkerRuntime() error = %v", err)
	}
}

func TestComposeWorkerRuntimeMountsDurableRiskProjection(t *testing.T) {
	config := validSchedulerRuntimeConfig()
	config.Mode, config.ProjectionKind = workerModeProjectionRisk, "risk"
	config.DatabaseAuthority, config.WorkerID = "zasp_projection_risk_worker", "projection-risk-01"
	dependencies, err := composeWorkerRuntime(context.Background(), config, readyWorkerDatabase{})
	if err != nil || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("risk production dependencies=%#v error=%v", dependencies, err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatalf("risk production readiness=%v", err)
	}
}

func TestComposeProjectionWorkerRuntimeStopsBeforeClaimWhenRepositoryDrifts(t *testing.T) {
	config := validSchedulerRuntimeConfig()
	config.Mode, config.ProjectionKind = workerModeProjectionRisk, "risk"
	config.DatabaseAuthority, config.WorkerID = "zasp_projection_risk_worker", "projection-risk-01"
	database := &driftingWorkerDatabase{}
	projector := &projectionProjectorStub{}
	dependencies, err := composeProjectionWorkerRuntime(config, database, productionProjectionProjector{
		projectionProjector: projector, ready: func(context.Context) error { return nil }, close: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	database.resetAndDrift()
	if err := dependencies.Processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("repository-drift RunOnce error = %v", err)
	}
	if payload := dependencies.Metrics(); !strings.Contains(payload, "zasp_worker_driver_ready 0\n") {
		t.Fatalf("repository drift did not clear driver readiness:\n%s", payload)
	}
	for _, statement := range database.statementsSnapshot() {
		if strings.Contains(statement, "claim_projection_work") {
			t.Fatalf("repository drift reached projection claim: %q", statement)
		}
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

func validSecurityAgentRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeSecurityAgent, PostgresDSN: "postgres://security_agent@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_security_agent_worker", WorkerID: "security-agent-worker-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 60 * time.Second, BatchSize: 8, ShutdownTimeout: 20 * time.Second,
	}
}

func validSecurityAgentActionRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeSecurityAgentAction, PostgresDSN: "postgres://security_agent_action@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_security_agent_action_worker", WorkerID: "security-agent-action-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 60 * time.Second, BatchSize: 8, ShutdownTimeout: 20 * time.Second,
		GatewaySigningKeyID: "gateway-key-01", GatewaySigningPrivateFile: "/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key",
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

func validRedTeamRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRedTeam, PostgresDSN: "postgres://red_team@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_red_team_worker", WorkerID: "red-team-worker-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 60 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		RedTeamQueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-red-team-tests", AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		RedTeamRoleARN: "arn:aws:iam::123456789012:role/zasp-production-red-team", RedTeamTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", RedTeamTargetEndpoint: "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate", RedTeamTargetTokenFile: "/var/run/secrets/zasp-red-team/adapter-token", RedTeamTargetCAFile: "/var/run/secrets/zasp-red-team/adapter-ca.crt", RedTeamRunnerTimeout: 10 * time.Minute,
	}
}

func validRedTeamOutboxRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRedTeamOutbox, PostgresDSN: "postgres://red_team_outbox@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_red_team_outbox_worker", WorkerID: "red-team-outbox-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 60 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		RedTeamQueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-red-team-tests", AWSRegion: "us-west-2", OutboxRoleARN: "arn:aws:iam::123456789012:role/zasp-production-red-team-outbox", OutboxTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
}

func validAttackLabOutboxRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeAttackLabOutbox, PostgresDSN: "postgres://attack_lab_outbox@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_attack_lab_outbox_worker", WorkerID: "attack-lab-outbox-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 60 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		AttackLabQueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-attack-lab-jobs", AWSRegion: "us-west-2", OutboxRoleARN: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-outbox", OutboxTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
}

func validRecoveryOutboxRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRecoveryOutbox, PostgresDSN: "postgres://recovery_outbox@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_recovery_outbox_worker", WorkerID: "recovery-outbox-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		RecoveryQueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-recovery-backup-jobs", RecoveryOutboxTopic: recoveryBackupOutboxTopic, AWSRegion: "us-west-2",
		RecoveryRoleARN: "arn:aws:iam::123456789012:role/zasp-production-recovery-outbox", RecoveryTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
}

func validRecoveryRuntimeConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRecovery, PostgresDSN: "postgres://recovery@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_recovery_worker", WorkerID: "recovery-worker-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		RecoveryQueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-recovery-backup-jobs", AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-recovery", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		RecoveryRoleARN: "arn:aws:iam::123456789012:role/zasp-production-recovery", RecoveryTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", RecoveryOperationKind: "backup",
		RecoverySigningKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/22222222-2222-4222-8222-222222222222", RecoveryNeonProjectID: "silent-moon-12345678", RecoveryNeonBranchID: "br-production-main",
	}
}

func validRuntimeCoordinatorConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRuntimeCoordinator, PostgresDSN: "postgres://runtime_coordinator@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_runtime_coordinator", WorkerID: "runtime-coordinator-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		RuntimeQueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events", AWSRegion: "us-west-2",
		RuntimeRoleARN: "arn:aws:iam::123456789012:role/zasp-production-runtime-coordinator", RuntimeTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
}

func validRuntimeArchiveConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRuntimeArchive, PostgresDSN: "postgres://runtime_archive@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_runtime_archive_worker", WorkerID: "runtime-archive-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		RuntimeStageRoleARN: "arn:aws:iam::123456789012:role/zasp-production-runtime-archive", RuntimeStageTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", RuntimeStageVersion: "runtime-archive-v1",
	}
}

func validRuntimeIndexConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRuntimeIndex, PostgresDSN: "postgres://runtime_index@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_runtime_index_worker", WorkerID: "runtime-index-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		RuntimeStageRoleARN: "arn:aws:iam::123456789012:role/zasp-production-runtime-index", RuntimeStageTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", RuntimeStageVersion: "runtime-index-v1",
		OpenSearchURL: "https://vpc-zasp.us-west-2.es.amazonaws.com", OpenSearchIndex: "zasp-runtime-events-v1",
	}
}

func validRuntimeCorrelationConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRuntimeCorrelation, PostgresDSN: "postgres://runtime_correlation@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_runtime_correlation_worker", WorkerID: "runtime-correlation-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		RuntimeStageRoleARN: "arn:aws:iam::123456789012:role/zasp-production-runtime-correlation", RuntimeStageTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", RuntimeStageVersion: "runtime-correlation-v1",
		ProjectionSecretPrefix: "zasp-production/projection", Neo4jURI: "neo4j+s://graph.example.com:7687", Neo4jCredential: "ref:neo4j/auth/runtime", Neo4jExpectedPrincipal: "zasp_projection_runtime", Neo4jExpectedRole: "publisher",
	}
}

func validRuntimeProjectionConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRuntimeProjection, PostgresDSN: "postgres://runtime_projection@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_runtime_projection_worker", WorkerID: "runtime-projection-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		RuntimeStageRoleARN: "arn:aws:iam::123456789012:role/zasp-production-runtime-projection", RuntimeStageTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", RuntimeStageVersion: "runtime-projection-v1",
	}
}

func validRuntimeCompleteConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		Mode: workerModeRuntimeComplete, PostgresDSN: "postgres://runtime_complete@postgres.internal/zasp?sslmode=verify-full", DatabaseAuthority: "zasp_runtime_coordinator", WorkerID: "runtime-complete-01",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 30 * time.Second, BatchSize: 10, ShutdownTimeout: 20 * time.Second,
		AWSRegion: "us-west-2", EvidenceBucket: "zasp-production-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		RuntimeStageRoleARN: "arn:aws:iam::123456789012:role/zasp-production-runtime-complete", RuntimeStageTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", RuntimeStageVersion: "runtime-complete-v1",
	}
}

type readyWorkerDatabase struct{}

func (readyWorkerDatabase) SchemaVersion(context.Context) (string, error) {
	return apiserver.SecurityAgentAutonomousSchemaVersion, nil
}

func (readyWorkerDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	if strings.Contains(statement, "jsonb_build_object('ready'") {
		return json.RawMessage(`{"ready":true}`), nil
	}
	if strings.Contains(statement, "zasp_security_agent_temporary_policy_readiness") || strings.Contains(statement, "zasp_security_agent_autonomous_readiness") || strings.Contains(statement, "zasp_security_agent_readiness") {
		return json.RawMessage(`{"release":true,"principal":true}`), nil
	}
	if strings.Contains(statement, "zasp_runtime_ingest_reconciliation_readiness") || strings.Contains(statement, "zasp_runtime_gateway_reconciliation_readiness") {
		return json.RawMessage(`{"ready":true}`), nil
	}
	return json.RawMessage(`true`), nil
}
func (readyWorkerDatabase) Exec(context.Context, string, ...any) error { return nil }

type driftingWorkerDatabase struct {
	mu         sync.Mutex
	drifted    bool
	statements []string
}

func (*driftingWorkerDatabase) SchemaVersion(context.Context) (string, error) {
	return apiserver.SecurityAgentAutonomousSchemaVersion, nil
}

func (database *driftingWorkerDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	database.mu.Lock()
	defer database.mu.Unlock()
	database.statements = append(database.statements, statement)
	if database.drifted {
		return json.RawMessage(`false`), nil
	}
	if strings.Contains(statement, "jsonb_build_object('ready'") {
		return json.RawMessage(`{"ready":true}`), nil
	}
	if strings.Contains(statement, "zasp_runtime_ingest_reconciliation_readiness") || strings.Contains(statement, "zasp_runtime_gateway_reconciliation_readiness") {
		return json.RawMessage(`{"ready":true}`), nil
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
