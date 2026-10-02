// Package auditexportconfig decodes explicitly trusted operator configuration.
package auditexportconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var ErrConfiguration = errors.New("invalid audit export storage configuration")

// ParsePolicies accepts one to 64 historical revisions. This bound never
// authorizes removing a revision that existing exports still require.
// No selection state, supplied digest, provider endpoint or credentials are read.
func ParsePolicies(body []byte) ([]migrations.AuditExportConfiguration, error) {
	if len(body) == 0 || len(body) > 128<<10 || !utf8.Valid(body) {
		return nil, ErrConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, ErrConfiguration
	}
	var policies []migrations.AuditExportConfiguration
	seen := make(map[string]bool)
	for decoder.More() {
		if len(policies) == 64 {
			return nil, ErrConfiguration
		}
		policy, err := decodePolicy(decoder)
		if err != nil || seen[policy.PolicyID] {
			return nil, ErrConfiguration
		}
		seen[policy.PolicyID] = true
		policies = append(policies, policy)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') || len(policies) == 0 {
		return nil, ErrConfiguration
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrConfiguration
	}
	return policies, nil
}

func decodePolicy(decoder *json.Decoder) (migrations.AuditExportConfiguration, error) {
	var policy migrations.AuditExportConfiguration
	var schema string
	fields := map[string]any{
		"schema": &schema, "policy_id": &policy.PolicyID,
		"bucket": &policy.Bucket, "expected_bucket_owner": &policy.ExpectedBucketOwner,
		"kms_key_arn": &policy.KMSKeyARN, "maximum_export_bytes": &policy.MaximumExportBytes,
		"maximum_retained_bytes": &policy.MaximumRetainedBytes,
		"maximum_inflight":       &policy.MaximumInflight, "capture_timeout_seconds": &policy.CaptureTimeoutSeconds,
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return migrations.AuditExportConfiguration{}, ErrConfiguration
	}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] == nil {
			return migrations.AuditExportConfiguration{}, ErrConfiguration
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, fields[key]) != nil {
			return migrations.AuditExportConfiguration{}, ErrConfiguration
		}
		delete(fields, key)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(fields) != 0 || schema != "audit-export-policy-v1" {
		return migrations.AuditExportConfiguration{}, ErrConfiguration
	}
	if _, err := migrations.AuditExportPolicyDigest(policy); err != nil {
		return migrations.AuditExportConfiguration{}, ErrConfiguration
	}
	return policy, nil
}
