package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"time"
)

func composeAttackLabLinkRuntime(c workerRuntimeConfig, db existingTestQuery, deps existingTestRuntimeDependencies) (workerRuntimeDependencies, error) {
	if c.Mode != workerModeAttackLabReconciler || !validWorkerRuntimeConfig(c) || nilWorkerDependency(db) || nilWorkerDependency(deps.Artifacts) || deps.Ready == nil || deps.Close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	client, err := newAttackLabLinkClient(db, c.WorkerID, time.Now)
	if err != nil {
		return workerRuntimeDependencies{}, err
	}
	scheduler, err := newAttackLabLinkScheduler(client, deps.Artifacts)
	if err != nil {
		return workerRuntimeDependencies{}, err
	}
	ready, err := newBoundedCachedWorkerReadiness(func(ctx context.Context) error {
		if deps.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		_, _, err := client.NextScope(ctx, domain.Scope{})
		return err
	}, 5*time.Second, workerReadinessCacheTTL(c.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, err
	}
	root, cancel := context.WithCancel(context.Background())
	r := &existingTestProductionRuntime{scheduler: scheduler, ready: ready, closeDependencies: deps.Close, root: root, cancel: cancel, idle: make(chan struct{}), timeout: c.ShutdownTimeout}
	return workerRuntimeDependencies{Processor: r, Ready: r.Ready, Close: r.Close}, nil
}

func newAttackLabLinkProductionDependencies(c workerRuntimeConfig) (existingTestRuntimeDependencies, error) {
	if c.Mode != workerModeAttackLabReconciler || !validWorkerRuntimeConfig(c) {
		return existingTestRuntimeDependencies{}, errRuntimeUnavailable
	}
	config := productionDiscoveryCloudConfig{Region: c.AWSRegion, RoleARN: c.AttackLabReconcilerRoleARN, TokenFile: c.AttackLabReconcilerTokenFile, SecretRoot: "zasp/attack-lab-reconciler", Timeout: 5 * time.Second, Clock: func() time.Time { return time.Now().UTC() }, Session: "zasp-attack-lab-reconciler"}
	cloud, err := newProductionDiscoveryCloudAuthority(config)
	if err != nil {
		return existingTestRuntimeDependencies{}, errRuntimeUnavailable
	}
	artifacts := productionDiscoveryArtifactConfig{Bucket: c.EvidenceBucket, ExpectedBucketOwner: c.EvidenceOwner, KMSKeyARN: c.EvidenceKMSKeyARN, OperationTimeout: 5 * time.Second, MaximumBytes: 64 << 20}
	reader, err := newExistingTestArtifactReader(cloud.s3, artifacts)
	if err != nil {
		_ = cloud.Close()
		return existingTestRuntimeDependencies{}, errRuntimeUnavailable
	}
	// Bucket discovery and KMS metadata permissions are intentionally absent.
	// Readiness proves the explicit role and (in composition) registered SQL
	// authority. Each versioned Get verifies owner, key, encryption and checksum.
	return existingTestRuntimeDependencies{Artifacts: reader, Ready: func(ctx context.Context) error {
		return readyProductionDiscoveryRole(ctx, cloud.assumeRole, config, artifacts)
	}, Close: cloud.Close}, nil
}
