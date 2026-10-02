package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type existingTestAttemptProof struct {
	RunID          string                             `json:"run_id"`
	Attempt        int                                `json:"attempt"`
	InputDigest    string                             `json:"input_digest"`
	InputArtifact  apiserver.RedTeamArtifactReference `json:"input_artifact"`
	OutputArtifact apiserver.RedTeamArtifactReference `json:"output_artifact"`
}

type existingTestCheckChange struct {
	Category         string `json:"category"`
	CheckID          string `json:"check_id"`
	PromptDigest     string `json:"prompt_digest"`
	AssertionDigest  string `json:"assertion_digest"`
	BeforeProtected  bool   `json:"before_protected"`
	AfterProtected   bool   `json:"after_protected"`
	BeforeHTTPStatus int    `json:"before_http_status"`
	AfterHTTPStatus  int    `json:"after_http_status"`
}

type existingTestVerification struct {
	SchemaVersion string                    `json:"schema_version"`
	Outcome       string                    `json:"outcome"`
	Reason        string                    `json:"reason"`
	Before        *existingTestAttemptProof `json:"before,omitempty"`
	After         *existingTestAttemptProof `json:"after,omitempty"`
	Checks        []existingTestCheckChange `json:"checks,omitempty"`
	Digest        string                    `json:"-"`
}

// Reading/verifying evidence does not settle a step or change finding status.
// The future DB settlement must retain this proof under the exact claim lease.
func verifyExistingTestComparison(ctx context.Context, store existingTestArtifactReader, before *existingTestEvidenceRequest, after existingTestEvidenceRequest) existingTestVerification {
	result := existingTestVerification{SchemaVersion: "security-agent-test-verification-v1", Outcome: "inconclusive", Reason: "test_evidence_unavailable"}
	finish := func() existingTestVerification {
		body, _ := json.Marshal(result)
		digest := sha256.Sum256(body)
		result.Digest = hex.EncodeToString(digest[:])
		return result
	}
	current, err := readExistingTestEvidence(ctx, store, after)
	if err != nil || current.Input.SchemaVersion != "red-team-runner-input-v2" {
		return finish()
	}
	result.After = existingTestProof(after)
	if current.Verdict == "engine_error" {
		result.Reason = "test_evaluation_inconclusive"
		return finish()
	}
	if current.Verdict == "fail" {
		result.Outcome = "needs_human"
		result.Reason = "test_condition_persists"
		return finish()
	}
	result.Outcome = "needs_human"
	result.Reason = "test_baseline_unavailable"
	if before == nil {
		return finish()
	}
	previous, err := readExistingTestEvidence(ctx, store, *before)
	if err != nil {
		result.Outcome = "inconclusive"
		result.Reason = "test_evidence_unavailable"
		return finish()
	}
	result.Before = existingTestProof(*before)
	if before.RunID == after.RunID || before.Scope != after.Scope || previous.Verdict != "fail" || previous.Input.SchemaVersion != "red-team-runner-input-v2" || !reflect.DeepEqual(previous.Evaluation, current.Evaluation) {
		return finish()
	}
	if current.Evaluation == nil || len(current.Checks) != len(current.Evaluation.Checks) || len(previous.Checks) != len(current.Checks) {
		return finish()
	}
	checks := make([]existingTestCheckChange, 0, len(current.Checks))
	failed := 0
	for i, next := range current.Checks {
		prior := previous.Checks[i]
		if prior.Category != next.Category || prior.Category != current.Evaluation.Checks[i].Category || prior.ComparisonDigest == "" || prior.ComparisonDigest != next.ComparisonDigest || prior.CredentialDigest != next.CredentialDigest {
			return finish()
		}
		if !next.Protected || prior.HTTPStatus != 200 || next.HTTPStatus != 200 {
			return finish()
		}
		if !prior.Protected {
			failed++
		}
		identity := current.Evaluation.Checks[i]
		checks = append(checks, existingTestCheckChange{Category: identity.Category, CheckID: identity.CheckID, PromptDigest: identity.PromptDigest, AssertionDigest: identity.AssertionDigest, BeforeProtected: prior.Protected, AfterProtected: next.Protected, BeforeHTTPStatus: prior.HTTPStatus, AfterHTTPStatus: next.HTTPStatus})
	}
	if failed == 0 {
		return finish()
	}
	result.Outcome = "remediated"
	result.Reason = "test_condition_changed"
	result.Checks = checks
	return finish()
}

func existingTestProof(request existingTestEvidenceRequest) *existingTestAttemptProof {
	return &existingTestAttemptProof{RunID: request.RunID, Attempt: request.Attempt, InputDigest: request.InputDigest, InputArtifact: request.InputArtifact, OutputArtifact: request.OutputArtifact}
}
