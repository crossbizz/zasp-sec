package main

import (
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type capturedTestSnapshotAttempt struct {
	RunID          string                              `json:"run_id"`
	State          string                              `json:"state"`
	Attempt        int                                 `json:"attempt"`
	InputDigest    string                              `json:"input_digest"`
	Verdict        *string                             `json:"verdict"`
	ErrorCode      *string                             `json:"error_code"`
	CompletedAt    *string                             `json:"completed_at"`
	InputArtifact  *apiserver.RedTeamArtifactReference `json:"input_artifact"`
	OutputArtifact *existingTestSnapshotReceipt        `json:"output_artifact"`
	Observations   []capturedTestObservation           `json:"observations"`
	Receipts       []completedTestReceipt              `json:"completed_receipts"`
	OutcomeUnknown *bool                               `json:"outcome_unknown"`
}
type capturedTestSnapshotBody struct {
	Schema            string                       `json:"schema_version"`
	Organization      string                       `json:"organization_id"`
	Workspace         string                       `json:"workspace_id"`
	Environment       string                       `json:"environment_id"`
	Run               string                       `json:"run_id"`
	Step              string                       `json:"step_id"`
	Definition        string                       `json:"definition_id"`
	DefinitionVersion int64                        `json:"definition_version"`
	Target            string                       `json:"target_id"`
	Kind              string                       `json:"target_kind"`
	Categories        []string                     `json:"categories"`
	Before            *capturedTestSnapshotAttempt `json:"before"`
	After             *capturedTestSnapshotAttempt `json:"after"`
}

// This decoder only consumes the signed, parent-selected compensation entry.
// It neither reconstructs a target comparison nor reads arbitrary history.
func decodeCapturedTestSnapshot(raw []byte, scope domain.Scope, parent, step, child string, now time.Time) (existingTestSnapshot, string, error) {
	var wire struct {
		Digest   string                    `json:"snapshot_digest"`
		Snapshot *capturedTestSnapshotBody `json:"snapshot"`
	}
	fail := func() (existingTestSnapshot, string, error) { return existingTestSnapshot{}, "", errRuntimeUnavailable }
	if len(raw) == 0 || len(raw) > 131072 || scope.Validate() != nil || now.IsZero() || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &wire) != nil || wire.Snapshot == nil || !redTeamLinkedDigestPattern.MatchString(wire.Digest) || wire.Digest == strings.Repeat("0", 64) {
		return fail()
	}
	s := wire.Snapshot
	if s.Schema != "security-agent-test-captured-snapshot-v1" || s.Organization != scope.OrganizationID().String() || s.Workspace != scope.WorkspaceID().String() || s.Environment != scope.EnvironmentID().String() || s.Run != parent || s.Step != step || s.After == nil || s.After.RunID != child || s.DefinitionVersion < 1 || s.DefinitionVersion > 1000000 || !stringInWorker(s.Kind, "agent_endpoint", "mcp_server", "coding_agent") || len(s.Categories) < 1 || len(s.Categories) > 6 {
		return fail()
	}
	for _, id := range []string{parent, step, child, s.Definition, s.Target} {
		if !validRecoveryProductID(id) {
			return fail()
		}
	}
	seen := map[string]bool{}
	for _, c := range s.Categories {
		if seen[c] || redTeamCuratedPrompt(c) == "" {
			return fail()
		}
		seen[c] = true
	}
	convert := func(a *capturedTestSnapshotAttempt, before bool) (*existingTestEvidenceRequest, error) {
		if a == nil {
			return nil, nil
		}
		if !validRecoveryProductID(a.RunID) || a.State != "complete" || a.Attempt < 1 || a.Attempt > 5 || a.Verdict == nil || !stringInWorker(*a.Verdict, "pass", "fail", "engine_error") || a.CompletedAt == nil || a.InputArtifact == nil || a.OutputArtifact == nil || a.OutcomeUnknown == nil || a.Observations == nil || a.Receipts == nil || len(a.Observations) > len(s.Categories) || len(a.Receipts) > len(s.Categories) || !redTeamLinkedDigestPattern.MatchString(a.InputDigest) || a.InputDigest == strings.Repeat("0", 64) || before && (*a.Verdict != "fail" || a.RunID == child) {
			return nil, errRuntimeUnavailable
		}
		stamp, err := time.Parse(time.RFC3339Nano, *a.CompletedAt)
		if err != nil || stamp.After(now) || *a.Verdict != "engine_error" && a.ErrorCode != nil && *a.ErrorCode != "" {
			return nil, errRuntimeUnavailable
		}
		inLoc, err := existingTestArtifactLocator(scope, *a.InputArtifact, 65536)
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		out := a.OutputArtifact
		ref := apiserver.RedTeamArtifactReference{Reference: out.Reference, VersionID: out.VersionID, SHA256: out.SHA256, SizeBytes: out.SizeBytes}
		outLoc, err := existingTestArtifactLocator(scope, ref, 1<<20)
		if err != nil || outLoc.Reference.String() != a.RunID || outLoc.Reference == inLoc.Reference || out.Key != release61ArtifactKey(scope, a.RunID) {
			return nil, errRuntimeUnavailable
		}
		input := redTeamRunnerInput{OrganizationID: s.Organization, WorkspaceID: s.Workspace, EnvironmentID: s.Environment, RunID: a.RunID}
		categories := map[string]bool{}
		for _, o := range a.Observations {
			if !seen[o.Category] || categories[o.Category] {
				return nil, errRuntimeUnavailable
			}
			if _, err := capturedCheck(input, o, o.Category); err != nil {
				return nil, err
			}
			categories[o.Category] = true
		}
		return &existingTestEvidenceRequest{Scope: scope, RunID: a.RunID, Attempt: a.Attempt, DefinitionID: s.Definition, DefinitionVersion: s.DefinitionVersion, TargetID: s.Target, TargetKind: s.Kind, Categories: append([]string(nil), s.Categories...), InputDigest: a.InputDigest, Verdict: *a.Verdict, InputArtifact: *a.InputArtifact, OutputArtifact: ref, Captured: &capturedTestEvidence{Observations: a.Observations, Receipts: a.Receipts}}, nil
	}
	var result existingTestSnapshot
	var err error
	result.Before, err = convert(s.Before, true)
	if err != nil {
		return fail()
	}
	result.After, err = convert(s.After, false)
	if err != nil {
		return fail()
	}
	result.State = s.After.State
	result.OutcomeUnknown = *s.After.OutcomeUnknown || s.Before != nil && *s.Before.OutcomeUnknown
	if s.After.ErrorCode != nil {
		result.ErrorCode = *s.After.ErrorCode
		result.OutcomeUnknown = result.OutcomeUnknown || *s.After.ErrorCode == "outcome_unknown"
	}
	if s.Before != nil && s.Before.ErrorCode != nil && *s.Before.ErrorCode == "outcome_unknown" {
		result.OutcomeUnknown = true
	}
	return result, wire.Digest, nil
}
