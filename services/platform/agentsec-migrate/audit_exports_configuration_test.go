package main

import (
	"errors"
	"testing"
)

func auditExportConfigurationEnvironment() map[string]string {
	return map[string]string{
		"ZASP_AUDIT_EXPORT_POLICY_ID":             "pid_75000001-0000-4000-8000-000000000001",
		"ZASP_AUDIT_EXPORT_BUCKET":                "owned-cli-export-fixture",
		"ZASP_AUDIT_EXPORT_EXPECTED_BUCKET_OWNER": "123456789012",
		"ZASP_AUDIT_EXPORT_KMS_KEY_ARN":           "arn:aws:kms:us-east-1:123456789012:key/75000002-0000-4000-8000-000000000002",
	}
}

func TestAuditExportConfigurationUsesExplicitPinsAndBoundedDefaults(t *testing.T) {
	environment := auditExportConfigurationEnvironment()
	config, err := loadAuditExportConfiguration(func(key string) string { return environment[key] })
	if err != nil || config.PolicyID != "pid_75000001-0000-4000-8000-000000000001" || config.ExpectedCurrentPolicyID != "" || config.Bucket != "owned-cli-export-fixture" || config.ExpectedBucketOwner != "123456789012" || config.KMSKeyARN != environment["ZASP_AUDIT_EXPORT_KMS_KEY_ARN"] || config.MaximumExportBytes != 1073741824 || config.MaximumRetainedBytes != 10737418240 || config.MaximumInflight != 2 || config.CaptureTimeoutSeconds != 120 {
		t.Fatalf("invalid explicit/default policy: %#v %v", config, err)
	}
	environment["ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID"] = "pid_75000003-0000-4000-8000-000000000003"
	environment["ZASP_AUDIT_EXPORT_MAXIMUM_EXPORT_BYTES"] = "9007199254740991"
	environment["ZASP_AUDIT_EXPORT_MAXIMUM_RETAINED_BYTES"] = "4096"
	environment["ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT"] = "2147483647"
	environment["ZASP_AUDIT_EXPORT_CAPTURE_TIMEOUT_SECONDS"] = "1"
	config, err = loadAuditExportConfiguration(func(key string) string { return environment[key] })
	if err != nil || config.ExpectedCurrentPolicyID != environment["ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID"] || config.MaximumExportBytes != 9007199254740991 || config.MaximumRetainedBytes != 4096 || config.MaximumInflight != 2147483647 || config.CaptureTimeoutSeconds != 1 {
		t.Fatalf("operator bounds/CAS not preserved: %#v %v", config, err)
	}
}

func TestAuditExportConfigurationRejectsInvalidPinsAndNoncanonicalLimits(t *testing.T) {
	for _, key := range []string{"ZASP_AUDIT_EXPORT_POLICY_ID", "ZASP_AUDIT_EXPORT_BUCKET", "ZASP_AUDIT_EXPORT_EXPECTED_BUCKET_OWNER", "ZASP_AUDIT_EXPORT_KMS_KEY_ARN"} {
		for _, value := range []string{"", " private invalid configuration "} {
			environment := auditExportConfigurationEnvironment()
			environment[key] = value
			if _, err := loadAuditExportConfiguration(func(key string) string { return environment[key] }); !errors.Is(err, errInvalidMigrationCommand) {
				t.Fatalf("accepted invalid required pin %s", key)
			}
		}
	}
	for _, key := range []string{"ZASP_AUDIT_EXPORT_MAXIMUM_EXPORT_BYTES", "ZASP_AUDIT_EXPORT_MAXIMUM_RETAINED_BYTES", "ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT", "ZASP_AUDIT_EXPORT_CAPTURE_TIMEOUT_SECONDS"} {
		for _, value := range []string{"0", "-1", "+1", "01", "1.0", "1e2", " 1", "1 ", "9007199254740992", "999999999999999999999999999999"} {
			environment := auditExportConfigurationEnvironment()
			environment[key] = value
			if _, err := loadAuditExportConfiguration(func(key string) string { return environment[key] }); !errors.Is(err, errInvalidMigrationCommand) {
				t.Fatalf("accepted noncanonical/out-of-range %s=%s", key, value)
			}
		}
	}
	for key, value := range map[string]string{"ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID": "pid_75000001-0000-4000-8000-000000000001", "ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT": "2147483648", "ZASP_AUDIT_EXPORT_CAPTURE_TIMEOUT_SECONDS": "121"} {
		environment := auditExportConfigurationEnvironment()
		environment[key] = value
		if _, err := loadAuditExportConfiguration(func(key string) string { return environment[key] }); !errors.Is(err, errInvalidMigrationCommand) {
			t.Fatalf("accepted invalid boundary %s", key)
		}
	}
	if _, err := loadAuditExportConfiguration(nil); !errors.Is(err, errInvalidMigrationCommand) {
		t.Fatal("nil reader accepted")
	}
}
