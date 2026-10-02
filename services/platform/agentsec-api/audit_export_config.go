package main

import (
	"encoding/base64"

	"github.com/zasp-ai/zasp-sec/services/platform/auditexportconfig"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type auditExportRuntimeConfig struct {
	Policies         []migrations.AuditExportConfiguration
	ReaderRoleARN    string
	TokenFile        string
	CursorSigningKey []byte
}

func loadRuntimeConfigFromEnvironment(lookup func(string) (string, bool)) (RuntimeConfig, error) {
	if lookup == nil {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	config, err := loadRuntimeConfig(func(key string) string { value, _ := lookup(key); return value })
	if err != nil {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	config.ComplianceExports, err = loadComplianceAPIConfiguration(lookup)
	if err != nil || !validRuntimeConfig(config) {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	keys := []string{"ZASP_AUDIT_EXPORT_POLICIES_JSON", "ZASP_AUDIT_EXPORT_READER_ROLE_ARN", "ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE", "ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY"}
	values := make([]string, len(keys))
	present := 0
	for index, key := range keys {
		value, exists := lookup(key)
		if exists {
			if value == "" {
				return RuntimeConfig{}, errInvalidRuntimeConfig
			}
			present++
		}
		values[index] = value
	}
	if present == 0 {
		return config, nil
	}
	if present != len(keys) {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	policies, err := auditexportconfig.ParsePolicies([]byte(values[0]))
	if err != nil {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	key, err := base64.RawURLEncoding.DecodeString(values[3])
	if err != nil || base64.RawURLEncoding.EncodeToString(key) != values[3] {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	config.AuditExports = &auditExportRuntimeConfig{Policies: policies, ReaderRoleARN: values[1], TokenFile: values[2], CursorSigningKey: key}
	if !validRuntimeConfig(config) {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	return config, nil
}

func validAuditExportRuntimeConfig(config *auditExportRuntimeConfig, connectorRole string) bool {
	if config == nil {
		return true
	}
	if !connectorRolePattern.MatchString(config.ReaderRoleARN) || config.ReaderRoleARN == connectorRole || config.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || len(config.CursorSigningKey) != 32 || len(config.Policies) == 0 || len(config.Policies) > 64 {
		return false
	}
	var nonzero byte
	for _, value := range config.CursorSigningKey {
		nonzero |= value
	}
	if nonzero == 0 {
		return false
	}
	seen := make(map[string]bool, len(config.Policies))
	for _, policy := range config.Policies {
		if _, err := migrations.AuditExportPolicyDigest(policy); err != nil || policy.ExpectedCurrentPolicyID != "" || seen[policy.PolicyID] {
			return false
		}
		seen[policy.PolicyID] = true
	}
	return true
}
