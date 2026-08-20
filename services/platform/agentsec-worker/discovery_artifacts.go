package main

import (
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
)

type productionDiscoveryArtifactConfig struct {
	Bucket              string
	ExpectedBucketOwner string
	KMSKeyARN           string
	OperationTimeout    time.Duration
	MaximumBytes        int64
}

func newProductionDiscoveryArtifactAuthority(client s3driver.API, config productionDiscoveryArtifactConfig) (artifactstore.ObjectReferencingArtifactStore, error) {
	driver, err := s3driver.New(client, s3driver.Config{Bucket: config.Bucket, ExpectedBucketOwner: config.ExpectedBucketOwner, KMSKeyARN: config.KMSKeyARN, MaximumBytes: config.MaximumBytes})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: config.OperationTimeout, MaximumBytes: config.MaximumBytes})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	return store, nil
}
