package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
)

// Deliberately do not embed the writable store. The runtime receives no write
// method even through a type assertion. Deployment IAM must enforce this too.
type existingTestReadOnlyArtifacts struct {
	get       func(context.Context, artifactstore.Locator) (artifactstore.Artifact, error)
	reference func(artifactstore.Locator) (string, error)
}

func (a *existingTestReadOnlyArtifacts) Get(ctx context.Context, l artifactstore.Locator) (artifactstore.Artifact, error) {
	return a.get(ctx, l)
}
func (a *existingTestReadOnlyArtifacts) ObjectReference(l artifactstore.Locator) (string, error) {
	return a.reference(l)
}

func newExistingTestArtifactReader(api s3driver.API, config productionDiscoveryArtifactConfig) (existingTestArtifactReader, error) {
	store, err := newProductionDiscoveryArtifactAuthority(api, config)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	return &existingTestReadOnlyArtifacts{get: store.Get, reference: store.ObjectReference}, nil
}

func newExistingTestProductionDependencies(c workerRuntimeConfig) (existingTestRuntimeDependencies, error) {
	if c.Mode != workerModeTestReconciler || !validWorkerRuntimeConfig(c) {
		return existingTestRuntimeDependencies{}, errRuntimeUnavailable
	}
	cloudConfig := productionDiscoveryCloudConfig{Region: c.AWSRegion, RoleARN: c.TestReconcilerRoleARN, TokenFile: c.TestReconcilerTokenFile, SecretRoot: "zasp/test-reconciler", Timeout: 5 * time.Second, Clock: func() time.Time { return time.Now().UTC() }, Session: "zasp-test-reconciler"}
	cloud, err := newProductionDiscoveryCloudAuthority(cloudConfig)
	if err != nil {
		return existingTestRuntimeDependencies{}, errRuntimeUnavailable
	}
	artifacts := productionDiscoveryArtifactConfig{Bucket: c.EvidenceBucket, ExpectedBucketOwner: c.EvidenceOwner, KMSKeyARN: c.EvidenceKMSKeyARN, OperationTimeout: 5 * time.Second, MaximumBytes: 1 << 20}
	reader, err := newExistingTestArtifactReader(cloud.s3, artifacts)
	if err != nil {
		_ = cloud.Close()
		return existingTestRuntimeDependencies{}, errRuntimeUnavailable
	}
	return existingTestRuntimeDependencies{Artifacts: reader, Ready: func(ctx context.Context) error {
		if readyProductionDiscoveryRole(ctx, cloud.assumeRole, cloudConfig, artifacts) != nil || readyProductionDiscoveryArtifactAuthority(ctx, cloud.s3, cloud.kms, cloudConfig, artifacts) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}, Close: cloud.Close}, nil
}
