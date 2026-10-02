package main

import (
	"strconv"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func loadAuditExportConfiguration(getenv func(string) string) (migrations.AuditExportConfiguration, error) {
	if getenv == nil {
		return migrations.AuditExportConfiguration{}, errInvalidMigrationCommand
	}
	config := migrations.AuditExportConfiguration{
		PolicyID:                getenv("ZASP_AUDIT_EXPORT_POLICY_ID"),
		ExpectedCurrentPolicyID: getenv("ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID"),
		Bucket:                  getenv("ZASP_AUDIT_EXPORT_BUCKET"),
		ExpectedBucketOwner:     getenv("ZASP_AUDIT_EXPORT_EXPECTED_BUCKET_OWNER"),
		KMSKeyARN:               getenv("ZASP_AUDIT_EXPORT_KMS_KEY_ARN"),
	}
	limits := []struct {
		key      string
		fallback int64
	}{
		{"ZASP_AUDIT_EXPORT_MAXIMUM_EXPORT_BYTES", 1073741824},
		{"ZASP_AUDIT_EXPORT_MAXIMUM_RETAINED_BYTES", 10737418240},
		{"ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT", 2},
		{"ZASP_AUDIT_EXPORT_CAPTURE_TIMEOUT_SECONDS", 120},
	}
	values := make([]int64, len(limits))
	for index, limit := range limits {
		value := getenv(limit.key)
		values[index] = limit.fallback
		if value == "" {
			continue
		}
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil || number < 1 || strconv.FormatInt(number, 10) != value {
			return migrations.AuditExportConfiguration{}, errInvalidMigrationCommand
		}
		values[index] = number
	}
	if values[2] > 1<<31-1 || values[3] > 120 {
		return migrations.AuditExportConfiguration{}, errInvalidMigrationCommand
	}
	config.MaximumExportBytes, config.MaximumRetainedBytes = values[0], values[1]
	config.MaximumInflight, config.CaptureTimeoutSeconds = int(values[2]), int(values[3])
	if _, err := migrations.AuditExportPolicyDigest(config); err != nil {
		return migrations.AuditExportConfiguration{}, errInvalidMigrationCommand
	}
	return config, nil
}
