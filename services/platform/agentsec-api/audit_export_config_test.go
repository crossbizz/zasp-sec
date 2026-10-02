package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const apiAuditExportPolicyJSON = `[{"schema":"audit-export-policy-v1","policy_id":"pid_52000001-0000-4000-8000-000000000001","bucket":"audit-exports-owned","expected_bucket_owner":"123456789012","kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4234-8234-123456789012","maximum_export_bytes":1073741824,"maximum_retained_bytes":10737418240,"maximum_inflight":2,"capture_timeout_seconds":120}]`

func fixtureAuditExportEnvironment() map[string]string {
	values := fixtureRuntimeEnvironment()
	values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = apiAuditExportPolicyJSON
	values["ZASP_AUDIT_EXPORT_READER_ROLE_ARN"] = "arn:aws:iam::123456789012:role/zasp-audit-export-reader"
	values["ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE"] = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	values["ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY"] = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	return values
}

func TestAuditExportRuntimeEnvironment(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	config, err := loadRuntimeConfigFromEnvironment(lookup)
	if err != nil || config.AuditExports != nil || !validRuntimeConfig(config) {
		t.Fatal("existing runtime configuration rejected", err)
	}
	values = fixtureAuditExportEnvironment()
	config, err = loadRuntimeConfigFromEnvironment(lookup)
	if err != nil || config.AuditExports == nil {
		t.Fatal("explicit export configuration unavailable", err)
	}
	exports := config.AuditExports
	if len(exports.Policies) != 1 || exports.Policies[0].Bucket != "audit-exports-owned" || exports.Policies[0].ExpectedCurrentPolicyID != "" || exports.ReaderRoleARN != values["ZASP_AUDIT_EXPORT_READER_ROLE_ARN"] || exports.TokenFile != values["ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE"] || string(exports.CursorSigningKey) != strings.Repeat("x", 32) || !validRuntimeConfig(config) {
		t.Fatal("export configuration changed trusted pins")
	}
	other, err := loadRuntimeConfigFromEnvironment(lookup)
	if err != nil {
		t.Fatal(err)
	}
	other.AuditExports.Policies[0].Bucket = "changed"
	other.AuditExports.CursorSigningKey[0] = 'y'
	if exports.Policies[0].Bucket != "audit-exports-owned" || exports.CursorSigningKey[0] != 'x' {
		t.Fatal("loaded configurations share mutable authority")
	}
}

func TestAuditExportRuntimeEnvironmentRejectsPartialOrInvalid(t *testing.T) {
	for _, key := range []string{"ZASP_AUDIT_EXPORT_POLICIES_JSON", "ZASP_AUDIT_EXPORT_READER_ROLE_ARN", "ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE", "ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY"} {
		for _, mode := range []string{"missing", "empty", "only-empty"} {
			t.Run(key+mode, func(t *testing.T) {
				values := fixtureAuditExportEnvironment()
				switch mode {
				case "missing":
					delete(values, key)
				case "empty":
					values[key] = ""
				case "only-empty":
					values = fixtureRuntimeEnvironment()
					values[key] = ""
				}
				config, err := loadRuntimeConfigFromEnvironment(func(key string) (string, bool) { v, ok := values[key]; return v, ok })
				if err != errInvalidRuntimeConfig || config.AuditExports != nil {
					t.Fatal("partial authority accepted")
				}
			})
		}
	}
	for _, test := range [][2]string{
		{"ZASP_AUDIT_EXPORT_POLICIES_JSON", "[]"},
		{"ZASP_AUDIT_EXPORT_READER_ROLE_ARN", "invalid"},
		{"ZASP_AUDIT_EXPORT_READER_ROLE_ARN", fixtureRuntimeEnvironment()["ZASP_CONNECTOR_ROLE_ARN"]},
		{"ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE", "/tmp/token"},
		{"ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		{"ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY", "secret"},
		{"ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY", fixtureAuditExportEnvironment()["ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY"] + "="},
	} {
		values := fixtureAuditExportEnvironment()
		values[test[0]] = test[1]
		if config, err := loadRuntimeConfigFromEnvironment(func(key string) (string, bool) { v, ok := values[key]; return v, ok }); err != errInvalidRuntimeConfig || config.AuditExports != nil {
			t.Fatal("invalid authority accepted")
		}
	}
	if _, err := loadRuntimeConfigFromEnvironment(nil); err != errInvalidRuntimeConfig {
		t.Fatal("nil environment accepted")
	}
}

func TestAuditExportRuntimeTypedConfigurationRevalidated(t *testing.T) {
	for name, change := range map[string]func(*auditExportRuntimeConfig){
		"empty policies":     func(c *auditExportRuntimeConfig) { c.Policies = nil },
		"duplicate policies": func(c *auditExportRuntimeConfig) { c.Policies = append(c.Policies, c.Policies[0]) },
		"too many policies":  func(c *auditExportRuntimeConfig) { c.Policies = make([]migrations.AuditExportConfiguration, 65) },
		"selector": func(c *auditExportRuntimeConfig) {
			c.Policies[0].ExpectedCurrentPolicyID = "pid_52000002-0000-4000-8000-000000000002"
		},
		"bad bucket": func(c *auditExportRuntimeConfig) { c.Policies[0].Bucket = "bad/bucket" },
		"zero key":   func(c *auditExportRuntimeConfig) { clear(c.CursorSigningKey) },
		"short key":  func(c *auditExportRuntimeConfig) { c.CursorSigningKey = c.CursorSigningKey[:31] },
		"long key":   func(c *auditExportRuntimeConfig) { c.CursorSigningKey = append(c.CursorSigningKey, 1) },
		"token path": func(c *auditExportRuntimeConfig) { c.TokenFile = "/tmp/token" },
		"role":       func(c *auditExportRuntimeConfig) { c.ReaderRoleARN = "invalid" },
		"connector role": func(c *auditExportRuntimeConfig) {
			c.ReaderRoleARN = fixtureRuntimeEnvironment()["ZASP_CONNECTOR_ROLE_ARN"]
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := fixtureAuditExportEnvironment()
			config, err := loadRuntimeConfigFromEnvironment(func(key string) (string, bool) { v, ok := values[key]; return v, ok })
			if err != nil {
				t.Fatal(err)
			}
			change(config.AuditExports)
			if validRuntimeConfig(config) {
				t.Fatal("mutated typed configuration accepted")
			}
		})
	}
}
