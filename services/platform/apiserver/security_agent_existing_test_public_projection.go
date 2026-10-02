package apiserver

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// These identities are evidence metadata, not storage references or download authority.
type SecurityAgentExistingTestArtifactIdentity struct {
	ReferenceDigest string `json:"reference_digest"`
	VersionID       string `json:"version_id"`
	SHA256          string `json:"sha256"`
	SizeBytes       int64  `json:"size_bytes"`
}

type SecurityAgentExistingTestAttemptProof struct {
	RunID          string                                    `json:"run_id"`
	Attempt        int                                       `json:"attempt"`
	InputDigest    string                                    `json:"input_digest"`
	InputArtifact  SecurityAgentExistingTestArtifactIdentity `json:"input_artifact"`
	OutputArtifact SecurityAgentExistingTestArtifactIdentity `json:"output_artifact"`
}

type SecurityAgentExistingTestCheckChange struct {
	Category         string `json:"category"`
	CheckID          string `json:"check_id"`
	PromptDigest     string `json:"prompt_digest"`
	AssertionDigest  string `json:"assertion_digest"`
	BeforeProtected  bool   `json:"before_protected"`
	AfterProtected   bool   `json:"after_protected"`
	BeforeHTTPStatus int    `json:"before_http_status"`
	AfterHTTPStatus  int    `json:"after_http_status"`
}

type SecurityAgentExistingTestVerification struct {
	Outcome     string                                 `json:"outcome"`
	Reason      string                                 `json:"reason"`
	ProofDigest string                                 `json:"proof_digest"`
	Before      *SecurityAgentExistingTestAttemptProof `json:"before"`
	After       *SecurityAgentExistingTestAttemptProof `json:"after"`
	Checks      []SecurityAgentExistingTestCheckChange `json:"checks"`
}

type SecurityAgentExistingTestDetail struct {
	DefinitionID        string                                 `json:"definition_id"`
	DefinitionVersion   int64                                  `json:"definition_version"`
	TestRunID           string                                 `json:"test_run_id"`
	State               string                                 `json:"state"`
	CancellationOutcome *string                                `json:"cancellation_outcome"`
	Verification        *SecurityAgentExistingTestVerification `json:"verification"`
}

// Check each object before decoding typed values: encoding/json otherwise
// collapses duplicate keys and treats scalar nulls as zero values.
func existingTestPublicObject(raw json.RawMessage, nullable []string, fields ...string) (map[string]json.RawMessage, bool) {
	object, err := auditExportClosedObject(raw, 65536, fields...)
	if err != nil {
		return nil, false
	}
	for key, value := range object {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !stringIn(key, nullable...) {
			return nil, false
		}
	}
	return object, true
}

func existingTestPublicAttemptFields(raw json.RawMessage) bool {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	object, ok := existingTestPublicObject(raw, nil, "run_id", "attempt", "input_digest", "input_artifact", "output_artifact")
	if !ok {
		return false
	}
	for _, key := range []string{"input_artifact", "output_artifact"} {
		if _, ok := existingTestPublicObject(object[key], nil, "reference_digest", "version_id", "sha256", "size_bytes"); !ok {
			return false
		}
	}
	return true
}

func decodeSecurityAgentExistingTestPublic(raw json.RawMessage, action SecurityAgentActionDetail) (*SecurityAgentExistingTestDetail, error) {
	object, ok := existingTestPublicObject(raw, []string{"cancellation_outcome", "verification"}, "definition_id", "definition_version", "test_run_id", "state", "cancellation_outcome", "verification")
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	if !bytes.Equal(bytes.TrimSpace(object["verification"]), []byte("null")) {
		v, ok := existingTestPublicObject(object["verification"], []string{"before", "after"}, "outcome", "reason", "proof_digest", "before", "after", "checks")
		if !ok || !existingTestPublicAttemptFields(v["before"]) || !existingTestPublicAttemptFields(v["after"]) {
			return nil, ErrRepositoryUnavailable
		}
		var checks []json.RawMessage
		if json.Unmarshal(v["checks"], &checks) != nil || checks == nil || len(checks) > 6 {
			return nil, ErrRepositoryUnavailable
		}
		for _, check := range checks {
			if _, ok := existingTestPublicObject(check, nil, "category", "check_id", "prompt_digest", "assertion_digest", "before_protected", "after_protected", "before_http_status", "after_http_status"); !ok {
				return nil, ErrRepositoryUnavailable
			}
		}
	}
	var value SecurityAgentExistingTestDetail
	if decodeStrictDiscovery(raw, &value) != nil || !validSecurityAgentExistingTestPublic(&value, action) {
		return nil, ErrRepositoryUnavailable
	}
	return &value, nil
}

func validExistingTestPublicDigest(value string) bool {
	if len(value) != 64 || value == strings.Repeat("0", 64) {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validExistingTestPublicArtifact(value SecurityAgentExistingTestArtifactIdentity, limit int64) bool {
	if !validExistingTestPublicDigest(value.ReferenceDigest) || !validExistingTestPublicDigest(value.SHA256) || !utf8.ValidString(value.VersionID) || len(value.VersionID) < 1 || len(value.VersionID) > 512 || value.SizeBytes < 1 || value.SizeBytes > limit {
		return false
	}
	for _, r := range value.VersionID {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validExistingTestPublicAttempt(value *SecurityAgentExistingTestAttemptProof) bool {
	return value == nil || validProductID(value.RunID) && value.Attempt >= 1 && value.Attempt <= 5 && validExistingTestPublicDigest(value.InputDigest) && validExistingTestPublicArtifact(value.InputArtifact, 65536) && validExistingTestPublicArtifact(value.OutputArtifact, 16777216)
}

func validSecurityAgentExistingTestPublic(value *SecurityAgentExistingTestDetail, action SecurityAgentActionDetail) bool {
	if value == nil {
		return true
	}
	// OutcomeID identifies the security-agent effect, not the linked test run.
	// SQL proves the scoped step/effect/link association; After binds the run here.
	if !stringIn(action.Action, "run_test", "rerun_test") || action.Arguments == nil || action.Result == nil || !validProductID(action.Result.OutcomeID) || !validProductID(value.DefinitionID) || value.DefinitionID != action.Arguments.TargetID || value.DefinitionVersion < 1 || value.DefinitionVersion > 1000000 || value.DefinitionVersion != action.Arguments.ExpectedVersion || !validProductID(value.TestRunID) {
		return false
	}
	if value.CancellationOutcome != nil && !stringIn(*value.CancellationOutcome, "cancelled_before_execution", "cancelled_after_partial_execution", "outcome_unknown") {
		return false
	}
	if value.State == "pending" {
		return value.Verification == nil
	}
	v := value.Verification
	if value.State != "settled" || v == nil || !strings.HasPrefix(v.ProofDigest, "sha256:") || !validExistingTestPublicDigest(strings.TrimPrefix(v.ProofDigest, "sha256:")) || v.ProofDigest != action.Result.ResultDigest || v.Checks == nil || !validExistingTestPublicAttempt(v.Before) || !validExistingTestPublicAttempt(v.After) || v.After != nil && v.After.RunID != value.TestRunID {
		return false
	}
	if value.CancellationOutcome != nil && *value.CancellationOutcome == "outcome_unknown" && (v.Outcome != "inconclusive" || v.Reason != "test_outcome_unknown") {
		return false
	}
	switch v.Outcome {
	case "remediated":
		if v.Reason != "test_condition_changed" || v.Before == nil || v.After == nil || v.Before.RunID == v.After.RunID || len(v.Checks) < 1 || len(v.Checks) > 6 {
			return false
		}
	case "needs_human":
		if !stringIn(v.Reason, "test_baseline_unavailable", "test_condition_persists") || v.After == nil {
			return false
		}
	case "inconclusive":
		if !stringIn(v.Reason, "test_outcome_unknown", "test_evidence_unavailable", "test_evaluation_inconclusive") {
			return false
		}
	case "failed":
		if v.Reason != "test_run_failed" {
			return false
		}
	case "cancelled":
		if v.Reason != "test_run_cancelled" {
			return false
		}
	default:
		return false
	}
	if v.Outcome != "remediated" {
		return len(v.Checks) == 0
	}
	seen := make(map[string]bool, len(v.Checks))
	unsafe := false
	for _, check := range v.Checks {
		if !stringIn(check.Category, "prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information") || seen[check.Category] || check.CheckID != "zasp.curated."+check.Category+".v1" || !validExistingTestPublicDigest(check.PromptDigest) || !validExistingTestPublicDigest(check.AssertionDigest) || !check.AfterProtected || check.BeforeHTTPStatus != 200 || check.AfterHTTPStatus != 200 {
			return false
		}
		seen[check.Category] = true
		unsafe = unsafe || !check.BeforeProtected
	}
	return unsafe
}
