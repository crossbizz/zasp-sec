package main

import (
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
)

type productionDiscoveryArtifactConfig struct {
	Bucket              string
	ExpectedBucketOwner string
	KMSKeyARN           string
	Encryption          string
	OperationTimeout    time.Duration
	MaximumBytes        int64
}

func newProductionDiscoveryArtifactAuthority(client s3driver.API, config productionDiscoveryArtifactConfig) (artifactstore.ObjectReferencingArtifactStore, error) {
	newDriver := s3driver.New
	switch config.Encryption {
	case "", "aws-kms":
	case "provider-managed":
		newDriver = s3driver.NewSSES3
	default:
		return nil, errRuntimeUnavailable
	}
	driver, err := newDriver(client, s3driver.Config{Bucket: config.Bucket, ExpectedBucketOwner: config.ExpectedBucketOwner, KMSKeyARN: config.KMSKeyARN, MaximumBytes: config.MaximumBytes})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: config.OperationTimeout, MaximumBytes: config.MaximumBytes})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	return store, nil
}

var evidenceKeyARN = regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func validEvidenceEncryptionAuthority(mode, key, region, owner string) bool {
	if mode == "provider-managed" && key == "" {
		return true
	}
	parts := evidenceKeyARN.FindStringSubmatch(key)
	return (mode == "" || mode == "aws-kms" || mode == "provider-managed") && len(parts) == 3 && parts[1] == region && parts[2] == owner
}
