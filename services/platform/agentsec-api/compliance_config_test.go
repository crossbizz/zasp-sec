package main

import (
	"strings"
	"testing"
)

func complianceAPIEnvironment() map[string]string {
	v := fixtureAuditExportEnvironment()
	v["ZASP_COMPLIANCE_EXPORT_BUCKET"] = "compliance-exports"
	v["ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER"] = "123456789012"
	v["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"] = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4234-8234-123456789012"
	v["ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN"] = "arn:aws:iam::123456789012:role/compliance-reader"
	v["ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE"] = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	return v
}
func TestComplianceAPIConfiguration(t *testing.T) {
	v := complianceAPIEnvironment()
	load := func() (RuntimeConfig, error) {
		return loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { s, ok := v[k]; return s, ok })
	}
	c, err := load()
	if err != nil || c.ComplianceExports == nil {
		t.Fatalf("missing complete read service: %v", err)
	}
	resources, err := newComplianceStorageResources(c)
	if err != nil || resources.transport == nil || resources.config.Client == nil {
		t.Fatalf("read client: %v", err)
	}
	resources.transport.CloseIdleConnections()
	for _, key := range []string{"ZASP_COMPLIANCE_EXPORT_BUCKET", "ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER", "ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN", "ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN", "ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE"} {
		old := v[key]
		delete(v, key)
		if _, err := load(); err == nil {
			t.Errorf("partial %s", key)
		}
		v[key] = old
	}
	v["ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN"] = v["ZASP_AUDIT_EXPORT_READER_ROLE_ARN"]
	if _, err := load(); err == nil {
		t.Fatal("shared audit reader identity accepted")
	}
	v = complianceAPIEnvironment()
	v["ZASP_COMPLIANCE_EXPORT_ROLE_ARN"] = "arn:aws:iam::123456789012:role/worker"
	if _, err := load(); err == nil {
		t.Fatal("worker authority reached API")
	}
	v = complianceAPIEnvironment()
	v["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"] = strings.ReplaceAll(v["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"], "123456789012", "987654321098")
	if _, err := load(); err == nil {
		t.Fatal("foreign KMS owner accepted")
	}
}
