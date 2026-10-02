package apiserver

import (
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type auditExportStoragePolicy struct {
	Schema                string `json:"schema"`
	PolicyID              string `json:"policy_id"`
	PolicyDigest          string `json:"policy_digest"`
	Bucket                string `json:"bucket"`
	ExpectedBucketOwner   string `json:"expected_bucket_owner"`
	KMSKeyARN             string `json:"kms_key_arn"`
	MaximumExportBytes    int64  `json:"maximum_export_bytes"`
	MaximumRetainedBytes  int64  `json:"maximum_retained_bytes"`
	MaximumInflight       int    `json:"maximum_inflight"`
	CaptureTimeoutSeconds int    `json:"capture_timeout_seconds"`
}

type auditExportStorageEntry struct {
	Configuration migrations.AuditExportConfiguration
	Client        s3driver.API
}
type auditExportTrustedStorage struct {
	policy auditExportStoragePolicy
	reader auditExportArtifactReader
}
type auditExportStorageRegistry struct {
	entries map[string]auditExportTrustedStorage
}

func newAuditExportStorageRegistry(entries []auditExportStorageEntry, timeout time.Duration) (*auditExportStorageRegistry, error) {
	if len(entries) == 0 {
		return nil, ErrRepositoryConfiguration
	}
	registry := &auditExportStorageRegistry{entries: make(map[string]auditExportTrustedStorage, len(entries))}
	for _, entry := range entries {
		config := entry.Configuration
		digest, err := migrations.AuditExportPolicyDigest(config)
		if err != nil || nilInterface(entry.Client) {
			return nil, ErrRepositoryConfiguration
		}
		if _, exists := registry.entries[config.PolicyID]; exists {
			return nil, ErrRepositoryConfiguration
		}
		driver, err := s3driver.NewExport(entry.Client, s3driver.Config{Bucket: config.Bucket, ExpectedBucketOwner: config.ExpectedBucketOwner, KMSKeyARN: config.KMSKeyARN, MaximumBytes: 1 << 20})
		if err != nil {
			return nil, ErrRepositoryConfiguration
		}
		store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: timeout, MaximumBytes: 1 << 20})
		if err != nil {
			return nil, ErrRepositoryConfiguration
		}
		policy := auditExportStoragePolicy{Schema: "audit-export-policy-v1", PolicyID: config.PolicyID, PolicyDigest: digest, Bucket: config.Bucket, ExpectedBucketOwner: config.ExpectedBucketOwner, KMSKeyARN: config.KMSKeyARN, MaximumExportBytes: config.MaximumExportBytes, MaximumRetainedBytes: config.MaximumRetainedBytes, MaximumInflight: config.MaximumInflight, CaptureTimeoutSeconds: config.CaptureTimeoutSeconds}
		registry.entries[config.PolicyID] = auditExportTrustedStorage{policy: policy, reader: store}
	}
	return registry, nil
}
func (registry *auditExportStorageRegistry) Resolve(policy auditExportStoragePolicy) (auditExportArtifactReader, error) {
	if registry == nil {
		return nil, ErrRepositoryUnavailable
	}
	entry, ok := registry.entries[policy.PolicyID]
	if !ok || entry.policy != policy {
		return nil, ErrRepositoryUnavailable
	}
	return entry.reader, nil
}
func decodeAuditExportStoragePolicy(body []byte) (auditExportStoragePolicy, error) {
	if _, err := auditExportClosedObject(body, 2048, "schema", "policy_id", "policy_digest", "bucket", "expected_bucket_owner", "kms_key_arn", "maximum_export_bytes", "maximum_retained_bytes", "maximum_inflight", "capture_timeout_seconds"); err != nil {
		return auditExportStoragePolicy{}, err
	}
	var policy auditExportStoragePolicy
	if json.Unmarshal(body, &policy) != nil || policy.Schema != "audit-export-policy-v1" {
		return auditExportStoragePolicy{}, ErrRepositoryUnavailable
	}
	digest, err := migrations.AuditExportPolicyDigest(migrations.AuditExportConfiguration{PolicyID: policy.PolicyID, Bucket: policy.Bucket, ExpectedBucketOwner: policy.ExpectedBucketOwner, KMSKeyARN: policy.KMSKeyARN, MaximumExportBytes: policy.MaximumExportBytes, MaximumRetainedBytes: policy.MaximumRetainedBytes, MaximumInflight: policy.MaximumInflight, CaptureTimeoutSeconds: policy.CaptureTimeoutSeconds})
	if err != nil || policy.PolicyDigest != digest {
		return auditExportStoragePolicy{}, ErrRepositoryUnavailable
	}
	return policy, nil
}
