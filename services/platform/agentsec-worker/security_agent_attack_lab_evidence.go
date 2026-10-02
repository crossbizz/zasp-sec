package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type attackLabLinkSource struct {
	Run               string          `json:"source_run_id"`
	Attempt           int             `json:"source_attempt"`
	Definition        string          `json:"definition_id"`
	DefinitionVersion int64           `json:"definition_version"`
	Target            string          `json:"target_id"`
	Kind              string          `json:"target_kind"`
	InputDigest       string          `json:"source_input_digest"`
	Completed         string          `json:"source_completed_at"`
	Evidence          json.RawMessage `json:"source_evidence"`
	Preflight         json.RawMessage `json:"preflight"`
}
type attackLabLinkExecution struct {
	Run             string                       `json:"run_id"`
	Attempt         int                          `json:"attempt"`
	InputDigest     string                       `json:"input_digest"`
	State           string                       `json:"state"`
	Verdict         *string                      `json:"verdict"`
	Error           *string                      `json:"error_code"`
	Cancelled       *bool                        `json:"cancel_requested"`
	CleanupState    string                       `json:"cleanup_state"`
	CleanupComplete *bool                        `json:"cleanup_complete"`
	Sandbox         *string                      `json:"sandbox_reference"`
	Artifact        *existingTestSnapshotReceipt `json:"artifact"`
	Unknown         *bool                        `json:"outcome_unknown"`
	Denied          *bool                        `json:"pre_execution_denied"`
}
type attackLabLinkSnapshot struct {
	Schema       string                 `json:"schema_version"`
	Organization string                 `json:"organization_id"`
	Workspace    string                 `json:"workspace_id"`
	Environment  string                 `json:"environment_id"`
	Run          string                 `json:"run_id"`
	Step         string                 `json:"step_id"`
	Source       attackLabLinkSource    `json:"source"`
	SourceValid  *bool                  `json:"source_valid"`
	Execution    attackLabLinkExecution `json:"execution"`
	scope        domain.Scope
	raw          json.RawMessage
}
type attackLabLinkProof struct {
	Schema          string                       `json:"schema_version"`
	Outcome         string                       `json:"outcome"`
	Reason          string                       `json:"reason"`
	Verdict         *string                      `json:"verdict"`
	Execution       string                       `json:"execution_id"`
	Attempt         int                          `json:"attempt"`
	InputDigest     string                       `json:"input_digest"`
	Artifact        *existingTestSnapshotReceipt `json:"artifact"`
	CleanupComplete bool                         `json:"cleanup_complete"`
}

// Explicit Attack Lab outcomes never enter EvaluateRunOutcome. A proof is not
// permission to close a finding, and cleanup must already be confirmed by SQL.
func verifyAttackLabLink(ctx context.Context, store existingTestArtifactReader, s attackLabLinkSnapshot) (attackLabLinkProof, bool) {
	x := s.Execution
	p := attackLabLinkProof{Schema: "security-agent-attack-lab-verification-v1", Outcome: "inconclusive", Reason: "attack_lab_evidence_unavailable", Verdict: x.Verdict, Execution: x.Run, Attempt: x.Attempt, InputDigest: x.InputDigest, Artifact: x.Artifact}
	if x.CleanupComplete == nil || !*x.CleanupComplete || !stringInWorker(x.State, "complete", "failed", "cancelled") {
		return p, true
	}
	p.CleanupComplete = true
	if ctx == nil || ctx.Err() != nil || x.Unknown == nil || x.Denied == nil || x.Cancelled == nil || s.SourceValid == nil {
		return p, false
	}
	if x.State == "cancelled" && *x.Cancelled {
		p.Outcome, p.Reason = "cancelled", "attack_lab_cancelled"
		return p, false
	}
	if x.State == "failed" && *x.Denied {
		p.Outcome, p.Reason = "failed", "attack_lab_pre_execution_denied"
		return p, false
	}
	if *x.Unknown || !*s.SourceValid || x.State == "failed" {
		p.Reason = "attack_lab_outcome_unknown"
		return p, false
	}
	if x.State != "complete" || x.Verdict == nil || !stringInWorker(*x.Verdict, "verified", "not_reproduced") || x.Artifact == nil || x.Sandbox == nil || nilWorkerDependency(store) {
		return p, false
	}
	receipt := apiserver.RedTeamArtifactReference{Reference: x.Artifact.Reference, VersionID: x.Artifact.VersionID, SHA256: x.Artifact.SHA256, SizeBytes: x.Artifact.SizeBytes}
	locator, err := existingTestArtifactLocator(s.scope, receipt, 64<<20)
	reference, key, idErr := attackLabEvidenceIdentity(s.scope, x.Run, x.Attempt)
	if err != nil || idErr != nil || locator.Reference != reference || x.Artifact.Key != key {
		return p, false
	}
	body, err := readExistingTestArtifact(ctx, store, locator, receipt)
	if err != nil {
		return p, false
	}
	var doc attackLabEvidenceDocument
	if strictAttackLabJSON(body, &doc, "schema_version", "organization_id", "workspace_id", "environment_id", "run_id", "attempt", "source_run_id", "definition_id", "definition_version", "target_id", "target_kind", "input_digest", "sandbox_reference", "verdict", "criterion_observed", "canary_touched", "error_code", "evidence") != nil {
		return p, false
	}
	if doc.SchemaVersion != "attack-lab-evidence-v1" || doc.OrganizationID != s.scope.OrganizationID().String() || doc.WorkspaceID != s.scope.WorkspaceID().String() || doc.EnvironmentID != s.scope.EnvironmentID().String() || doc.RunID != x.Run || doc.Attempt != x.Attempt || doc.SourceRunID != s.Source.Run || doc.DefinitionID != s.Source.Definition || doc.DefinitionVersion != s.Source.DefinitionVersion || doc.TargetID != s.Source.Target || doc.TargetKind != s.Source.Kind || doc.InputDigest != x.InputDigest || doc.SandboxReference != *x.Sandbox || doc.Verdict != *x.Verdict || doc.ErrorCode != nil {
		return p, false
	}
	result := attackLabSandboxResult{Verdict: doc.Verdict, CriterionObserved: doc.CriterionObserved, CanaryTouched: doc.CanaryTouched, Evidence: doc.Evidence}
	if !validAttackLabSandboxResult(result) {
		return p, false
	}
	p.Outcome = "needs_human"
	p.Reason = "attack_lab_not_reproduced_in_bounded_run"
	if doc.Verdict == "verified" {
		p.Reason = "attack_lab_unsafe_condition_reproduced"
	}
	return p, false
}

func strictAttackLabJSON(raw []byte, value any, required ...string) error {
	if decodeAttackLabJSON(raw, value) != nil {
		return errRuntimeUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errRuntimeUnavailable
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return errRuntimeUnavailable
		}
	}
	return nil
}

func attackLabProofBytes(p attackLabLinkProof) ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	h := sha256.Sum256(b)
	return append(b[:len(b)-1], []byte(`,"sha256":"`+hex.EncodeToString(h[:])+`"}`)...), nil
}
func validAttackLabLinkDigest(value string) bool {
	return redTeamLinkedDigestPattern.MatchString(value) && value != strings.Repeat("0", 64)
}
