package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type productionRedTeamDependencies struct {
	Queue  discoveryQueue
	Runner redTeamRunner
	ready  func(context.Context) error
	close  func() error
}

func newProductionRedTeamDependencies(config workerRuntimeConfig) (*productionRedTeamDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeRedTeam {
		return nil, errRuntimeUnavailable
	}
	requestTimeout := minDuration(config.LeaseDuration/3, 30*time.Second)
	cloudConfig := productionDiscoveryCloudConfig{
		Region: config.AWSRegion, RoleARN: config.RedTeamRoleARN, TokenFile: config.RedTeamTokenFile,
		SecretRoot: "zasp/red-team", Timeout: requestTimeout, Clock: func() time.Time { return time.Now().UTC() }, Session: "zasp-red-team-worker",
	}
	artifactConfig := productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: requestTimeout, MaximumBytes: 1 << 20}
	cloud, err := newProductionDiscoveryCloudAuthority(cloudConfig)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	queue, err := newProductionDiscoveryQueue(cloud.sqs, productionDiscoveryQueueConfig{
		Region: config.AWSRegion, QueueURL: config.RedTeamQueueURL, ExpectedQueueName: "agentsec-red-team-tests",
		OperationTimeout: requestTimeout, Visibility: config.LeaseDuration, ShutdownTimeout: config.ShutdownTimeout,
	})
	if err != nil {
		_ = cloud.Close()
		return nil, errRuntimeUnavailable
	}
	fail := func() (*productionRedTeamDependencies, error) {
		_ = queue.Close()
		_ = cloud.Close()
		return nil, errRuntimeUnavailable
	}
	artifacts, err := newProductionDiscoveryArtifactAuthority(cloud.s3, artifactConfig)
	if err != nil {
		return fail()
	}
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{
		Artifacts: artifacts, Command: productionRedTeamCommand{}, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js",
		TargetEndpoint: config.RedTeamTargetEndpoint, TargetTokenFile: config.RedTeamTargetTokenFile, TargetCAFile: config.RedTeamTargetCAFile, TempRoot: "/tmp", Timeout: config.RedTeamRunnerTimeout, Clock: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return fail()
	}
	ready := func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil || !validRedTeamTokenFile(config.RedTeamTargetTokenFile) || !validRedTeamCAFile(config.RedTeamTargetCAFile) || readyProductionDiscoveryRole(ctx, cloud.assumeRole, cloudConfig, artifactConfig) != nil || readyProductionDiscoveryArtifactAuthority(ctx, cloud.s3, cloud.kms, cloudConfig, artifactConfig) != nil || queue.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	closeDependencies := func() error {
		queueErr := queue.Close()
		cloudErr := cloud.Close()
		if queueErr != nil {
			return queueErr
		}
		return cloudErr
	}
	return &productionRedTeamDependencies{Queue: queue.Queue, Runner: runner, ready: ready, close: closeDependencies}, nil
}

func (dependencies *productionRedTeamDependencies) Ready(ctx context.Context) error {
	if dependencies == nil || dependencies.ready == nil {
		return errRuntimeUnavailable
	}
	return dependencies.ready(ctx)
}

func (dependencies *productionRedTeamDependencies) Close() error {
	if dependencies == nil || dependencies.close == nil {
		return nil
	}
	return dependencies.close()
}

func composeRedTeamWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, dependencies *productionRedTeamDependencies) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeRedTeam || database == nil || dependencies == nil || dependencies.Queue == nil || dependencies.Runner == nil || dependencies.ready == nil || dependencies.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewRedTeamExecutionRepository(database, apiserver.RedTeamExecutionAuthorityWorker)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.ReadyArtifacts(ctx) != nil || dependencies.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newRedTeamProcessor(redTeamProcessorConfig{
		Authority: repository, Queue: dependencies.Queue, Runner: dependencies.Runner, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), HeartbeatInterval: config.LeaseDuration / 3, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: dependencies.Close}, nil
}

func composeRedTeamOutboxWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, publisher outboxPublisher, publisherReady func(context.Context) error) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeRedTeamOutbox || database == nil || publisher == nil || publisherReady == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewRedTeamExecutionRepository(database, apiserver.RedTeamExecutionAuthorityOutbox)
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
	processor, err := newRedTeamOutboxProcessor(redTeamOutboxProcessorConfig{
		Authority: repository, Publisher: publisher, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), RetrySeconds: int(config.LeaseDuration / time.Second), HeartbeatInterval: config.LeaseDuration / 3, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken, Ready: ready,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: processor, Ready: ready, Close: func() error { return nil }}, nil
}
