package main

import (
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

type existingTestSnapshot struct {
	source         string
	State          string
	ErrorCode      string
	OutcomeUnknown bool
	ExpiresAt      time.Time
	Before, After  *existingTestEvidenceRequest
}

type existingTestSnapshotReceipt struct {
	Reference string `json:"reference"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type existingTestSnapshotAttempt struct {
	RunID          string                                     `json:"run_id"`
	State          string                                     `json:"state"`
	Attempt        int                                        `json:"attempt"`
	InputDigest    string                                     `json:"input_digest"`
	Verdict        *string                                    `json:"verdict"`
	ErrorCode      *string                                    `json:"error_code"`
	CompletedAt    *string                                    `json:"completed_at"`
	InputArtifact  *apiserver.RedTeamArtifactReference        `json:"input_artifact"`
	OutputArtifact *existingTestSnapshotReceipt               `json:"output_artifact"`
	Observations   []redteamadapter.LinkedObservationResponse `json:"observations"`
	OutcomeUnknown *bool                                      `json:"outcome_unknown"`
}

type existingTestSnapshotBody struct {
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
	Before            *existingTestSnapshotAttempt `json:"before"`
	After             *existingTestSnapshotAttempt `json:"after"`
}

// Only use bytes returned by the guarded database evidence entrypoint. Shape
// validation does not authenticate arbitrary JSON or replace settlement CAS.
func decodeExistingTestSnapshot(raw []byte, scope domain.Scope, run, step, testRun string, version int64, generation string, now time.Time) (existingTestSnapshot, error) {
	var wire struct {
		Generation string                    `json:"generation"`
		Version    int64                     `json:"version"`
		ExpiresAt  string                    `json:"lease_expires_at"`
		Snapshot   *existingTestSnapshotBody `json:"snapshot"`
	}
	fail := func() (existingTestSnapshot, error) { return existingTestSnapshot{}, errRuntimeUnavailable }
	if len(raw) == 0 || len(raw) > 131072 || scope.Validate() != nil || now.IsZero() || version < 1 || version > 1000000 || !validExistingTestGeneration(generation) || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &wire) != nil || wire.Generation != generation || wire.Version != version || wire.Snapshot == nil {
		return fail()
	}
	expiry, err := time.Parse(time.RFC3339Nano, wire.ExpiresAt)
	if err != nil || !expiry.After(now) {
		return fail()
	}
	result, err := decodeExistingTestSnapshotBody(wire.Snapshot, scope, run, step, testRun, now)
	if err != nil {
		return fail()
	}
	result.ExpiresAt = expiry
	result.source = string(raw)
	return result, nil
}

// The lease-free owner reads the same native evidence schema, without creating
// a retained lease envelope or treating a caller's JSON as database authority.
func decodeSingleTestSnapshot(raw []byte, scope domain.Scope, run, step, testRun string, now time.Time) (existingTestSnapshot, error) {
	var s existingTestSnapshotBody
	if len(raw) == 0 || len(raw) > 131072 || scope.Validate() != nil || now.IsZero() || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &s) != nil {
		return existingTestSnapshot{}, errRuntimeUnavailable
	}
	result, err := decodeExistingTestSnapshotBody(&s, scope, run, step, testRun, now)
	result.source = string(raw)
	return result, err
}

func decodeExistingTestSnapshotBody(s *existingTestSnapshotBody, scope domain.Scope, run, step, testRun string, now time.Time) (existingTestSnapshot, error) {
	var result existingTestSnapshot
	fail := func() (existingTestSnapshot, error) { return existingTestSnapshot{}, errRuntimeUnavailable }
	var err error
	if s.Schema != "security-agent-test-evidence-snapshot-v1" || s.Organization != scope.OrganizationID().String() || s.Workspace != scope.WorkspaceID().String() || s.Environment != scope.EnvironmentID().String() || s.Run != run || s.Step != step || s.DefinitionVersion < 1 || s.DefinitionVersion > 1000000 || !stringInWorker(s.Kind, "agent_endpoint", "mcp_server", "coding_agent") || len(s.Categories) < 1 || len(s.Categories) > 6 || s.After == nil || s.After.RunID != testRun {
		return fail()
	}
	for _, id := range []string{run, step, testRun, s.Definition, s.Target} {
		if _, err := domain.ParseProductID(id); err != nil {
			return fail()
		}
	}
	seen := map[string]bool{}
	for _, category := range s.Categories {
		if seen[category] || redTeamCuratedPrompt(category) == "" {
			return fail()
		}
		seen[category] = true
	}
	input := redTeamRunnerInput{OrganizationID: s.Organization, WorkspaceID: s.Workspace, EnvironmentID: s.Environment, DefinitionID: s.Definition, DefinitionVersion: s.DefinitionVersion, TargetID: s.Target, TargetKind: s.Kind, Categories: s.Categories}
	convert := func(a *existingTestSnapshotAttempt, before bool) (*existingTestEvidenceRequest, error) {
		if a == nil {
			return nil, nil
		}
		if _, err := domain.ParseProductID(a.RunID); err != nil {
			return nil, errRuntimeUnavailable
		}
		if a.Attempt < 0 || a.Attempt > 5 || !redTeamLinkedDigestPattern.MatchString(a.InputDigest) || a.InputDigest == strings.Repeat("0", 64) || a.OutcomeUnknown == nil || a.Observations == nil || len(a.Observations) > len(s.Categories) || !stringInWorker(a.State, "queued", "leased", "retryable", "complete", "failed", "cancelled") {
			return nil, errRuntimeUnavailable
		}
		categories := map[string]bool{}
		for _, o := range a.Observations {
			if o.SchemaVersion != "red-team-linked-observation-v1" || o.RunID != a.RunID || !seen[o.Category] || categories[o.Category] || o.Observation.HTTPStatus != 200 || o.Observation.Protected == nil || !redTeamLinkedDigestPattern.MatchString(o.Observation.ResponseDigest) || o.Observation.ResponseDigest == strings.Repeat("0", 64) || !redTeamLinkedDigestPattern.MatchString(o.CredentialVersionDigest) || o.CredentialVersionDigest == strings.Repeat("0", 64) || !validRedTeamTargetComparison(input, o.TargetComparison) {
				return nil, errRuntimeUnavailable
			}
			categories[o.Category] = true
		}
		if before && (a.State != "complete" || a.Verdict == nil || *a.Verdict != "fail" || a.RunID == testRun) {
			return nil, errRuntimeUnavailable
		}
		if a.State != "complete" {
			if a.InputArtifact != nil || a.OutputArtifact != nil || a.Verdict != nil {
				return nil, errRuntimeUnavailable
			}
			return nil, nil
		}
		if a.Attempt < 1 || a.Verdict == nil || !stringInWorker(*a.Verdict, "pass", "fail", "engine_error") || a.CompletedAt == nil || a.InputArtifact == nil || a.OutputArtifact == nil {
			return nil, errRuntimeUnavailable
		}
		completed, err := time.Parse(time.RFC3339Nano, *a.CompletedAt)
		if err != nil || completed.After(now) {
			return nil, errRuntimeUnavailable
		}
		if *a.Verdict != "engine_error" && a.ErrorCode != nil && *a.ErrorCode != "" {
			return nil, errRuntimeUnavailable
		}
		out := a.OutputArtifact
		receipt := apiserver.RedTeamArtifactReference{Reference: out.Reference, VersionID: out.VersionID, SHA256: out.SHA256, SizeBytes: out.SizeBytes}
		inLoc, err := existingTestArtifactLocator(scope, *a.InputArtifact, 65536)
		if err != nil {
			return nil, err
		}
		outLoc, err := existingTestArtifactLocator(scope, receipt, 1<<20)
		if err != nil || outLoc.Reference.String() != a.RunID || inLoc.Reference == outLoc.Reference || out.Key != "organizations/"+s.Organization+"/workspaces/"+s.Workspace+"/environments/"+s.Environment+"/artifacts/"+a.RunID {
			return nil, errRuntimeUnavailable
		}
		return &existingTestEvidenceRequest{Scope: scope, RunID: a.RunID, Attempt: a.Attempt, DefinitionID: s.Definition, DefinitionVersion: s.DefinitionVersion, TargetID: s.Target, TargetKind: s.Kind, Categories: append([]string(nil), s.Categories...), InputDigest: a.InputDigest, Verdict: *a.Verdict, InputArtifact: *a.InputArtifact, OutputArtifact: receipt, Observations: a.Observations}, nil
	}
	result.Before, err = convert(s.Before, true)
	if err != nil {
		return fail()
	}
	result.After, err = convert(s.After, false)
	if err != nil {
		return fail()
	}
	result.State = s.After.State
	unknown := func(a *existingTestSnapshotAttempt) bool {
		return a != nil && (*a.OutcomeUnknown || a.ErrorCode != nil && *a.ErrorCode == "outcome_unknown")
	}
	result.OutcomeUnknown = unknown(s.After) || unknown(s.Before)
	if s.After.ErrorCode != nil {
		result.ErrorCode = *s.After.ErrorCode
	}
	return result, nil
}
