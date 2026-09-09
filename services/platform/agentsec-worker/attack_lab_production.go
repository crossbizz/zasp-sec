package main

import (
	"context"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type productionAttackLabDependencies struct {
	Queue     discoveryQueue
	Provider  attackLabSandboxProvider
	Evidence  attackLabEvidenceWriter
	ready     func(context.Context) error
	close     func() error
	closeOnce sync.Once
	closeErr  error
}

func newProductionAttackLabDependencies(config workerRuntimeConfig) (*productionAttackLabDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeAttackLabController {
		return nil, errRuntimeUnavailable
	}
	requestTimeout := config.AttackLabOperationTimeout
	cloudConfig := productionDiscoveryCloudConfig{
		Region: config.AWSRegion, RoleARN: config.AttackLabRoleARN, TokenFile: config.AttackLabTokenFile,
		SecretRoot: "zasp/attack-lab", Timeout: requestTimeout, Clock: func() time.Time { return time.Now().UTC() }, Session: "zasp-attack-lab-controller",
	}
	artifactConfig := productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: requestTimeout, MaximumBytes: 1 << 20}
	cloud, err := newProductionDiscoveryCloudAuthority(cloudConfig)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	queue, err := newProductionDiscoveryQueue(cloud.sqs, productionDiscoveryQueueConfig{
		Region: config.AWSRegion, QueueURL: config.AttackLabQueueURL, ExpectedQueueName: "agentsec-attack-lab-jobs",
		OperationTimeout: requestTimeout, Visibility: config.LeaseDuration, ShutdownTimeout: config.ShutdownTimeout,
	})
	if err != nil {
		_ = cloud.Close()
		return nil, errRuntimeUnavailable
	}
	var kubernetes *productionAttackLabKubernetesAPI
	fail := func() (*productionAttackLabDependencies, error) {
		if kubernetes != nil {
			_ = kubernetes.Close()
		}
		_ = queue.Close()
		_ = cloud.Close()
		return nil, errRuntimeUnavailable
	}
	artifacts, err := newProductionDiscoveryArtifactAuthority(cloud.s3, artifactConfig)
	if err != nil {
		return fail()
	}
	evidence, err := newProductionAttackLabEvidenceWriter(artifacts)
	if err != nil {
		return fail()
	}
	kubernetes, err = newProductionAttackLabKubernetesAPI(config.AttackLabKubernetesURL, config.AttackLabKubernetesToken, config.AttackLabKubernetesCA, config.AttackLabSecurityGroup, config.AttackLabRunnerTestRoleARN, requestTimeout)
	if err != nil {
		return fail()
	}
	signingKey, ok := readRedTeamPinnedFile(config.AttackLabSigningKeyFile, 32, 64)
	if !ok {
		return fail()
	}
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{
		RunnerTestRoleARN: config.AttackLabRunnerTestRoleARN, Cluster: kubernetes, Namespace: config.AttackLabNamespace, ServiceAccount: config.AttackLabRunnerService, RunnerImage: config.AttackLabRunnerImage,
		ProxyEndpoint: config.AttackLabProxyEndpoint, ProxyCAFile: config.AttackLabProxyCAFile, SigningKey: signingKey, OperationTimeout: requestTimeout, Now: func() time.Time { return time.Now().UTC() },
	})
	clear(signingKey)
	if err != nil {
		return fail()
	}
	ready := func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil || readyProductionDiscoveryRole(ctx, cloud.assumeRole, cloudConfig, artifactConfig) != nil || readyProductionDiscoveryArtifactAuthority(ctx, cloud.s3, cloud.kms, cloudConfig, artifactConfig) != nil || queue.Ready(ctx) != nil || provider.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	closeDependencies := func() error {
		clear(provider.config.SigningKey)
		kubernetesErr := kubernetes.Close()
		queueErr := queue.Close()
		cloudErr := cloud.Close()
		if kubernetesErr != nil {
			return kubernetesErr
		}
		if queueErr != nil {
			return queueErr
		}
		return cloudErr
	}
	return &productionAttackLabDependencies{Queue: queue.Queue, Provider: provider, Evidence: evidence, ready: ready, close: closeDependencies}, nil
}

func (dependencies *productionAttackLabDependencies) Ready(ctx context.Context) error {
	if dependencies == nil || dependencies.ready == nil || readyAttackLabSandboxProvider(ctx, dependencies.Provider) != nil {
		return errRuntimeUnavailable
	}
	return dependencies.ready(ctx)
}

func (dependencies *productionAttackLabDependencies) Close() error {
	if dependencies == nil {
		return nil
	}
	dependencies.closeOnce.Do(func() {
		if dependencies.close != nil {
			dependencies.closeErr = dependencies.close()
		}
	})
	return dependencies.closeErr
}

func composeAttackLabWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, dependencies *productionAttackLabDependencies) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeAttackLabController || database == nil || dependencies == nil || dependencies.Queue == nil || dependencies.Provider == nil || dependencies.Evidence == nil || dependencies.ready == nil || dependencies.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewAttackLabExecutionRepository(database, apiserver.AttackLabExecutionAuthorityController)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || dependencies.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{
		Authority: repository, Queue: dependencies.Queue, Provider: dependencies.Provider, Evidence: dependencies.Evidence, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), HeartbeatInterval: config.LeaseDuration / 3, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: dependencies.Close}, nil
}

func composeAttackLabOutboxWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, publisher outboxPublisher, publisherReady func(context.Context) error) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeAttackLabOutbox || database == nil || publisher == nil || publisherReady == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewAttackLabExecutionRepository(database, apiserver.AttackLabExecutionAuthorityOutbox)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || publisherReady(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newAttackLabOutboxProcessor(attackLabOutboxProcessorConfig{
		Authority: repository, Publisher: publisher, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), RetrySeconds: int(config.LeaseDuration / time.Second),
		HeartbeatInterval: config.LeaseDuration / 3, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken, Ready: ready,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: processor, Ready: ready, Close: func() error { return nil }}, nil
}
