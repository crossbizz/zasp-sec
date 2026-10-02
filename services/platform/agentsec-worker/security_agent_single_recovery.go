package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func (runner *productionRedTeamRunner) capturedSingleInput(ctx context.Context, x singleTestExecution) ([]byte, apiserver.RedTeamArtifactReference, error) {
	var value struct {
		Run        string                             `json:"run_id"`
		Step       string                             `json:"step_id"`
		Child      string                             `json:"test_run_id"`
		Effect     string                             `json:"effect_key"`
		Generation int                                `json:"generation"`
		Manifest   apiserver.RedTeamArtifactReference `json:"input_manifest"`
	}
	raw, err := x.query(ctx, `SELECT zasp_temporal74.test_settle($1::jsonb)`, "input", map[string]any{})
	if err != nil {
		return nil, value.Manifest, err
	}
	if len(raw) > 16384 || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &value) != nil || value.Run != x.parent || value.Step != x.step || value.Child != x.child || value.Effect != x.key || value.Generation != 1 {
		return nil, value.Manifest, errRuntimeUnavailable
	}
	loc, err := existingTestArtifactLocator(x.scope, value.Manifest, 65536)
	if err != nil {
		return nil, value.Manifest, err
	}
	id, _ := apiserver.CanonicalDiscoveryID(x.scope, "security_agent_ordered_test_input", x.parent+"\x1f"+x.step)
	if loc.Reference.String() != id {
		return nil, value.Manifest, errRuntimeUnavailable
	}
	body, err := readExistingTestArtifact(ctx, runner.config.Artifacts, loc, value.Manifest)
	if err != nil {
		return nil, value.Manifest, err
	}
	var input redTeamRunnerInput
	if decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, body, &input) != nil || input.SchemaVersion != "red-team-runner-input-v2" || input.OrganizationID != x.scope.OrganizationID().String() || input.WorkspaceID != x.scope.WorkspaceID().String() || input.EnvironmentID != x.scope.EnvironmentID().String() || input.RunID != x.child || input.RunnerImageDigest != redTeamRunnerImageDigest(runner.config.RunnerImage) {
		return nil, value.Manifest, errRuntimeUnavailable
	}
	return body, value.Manifest, nil
}

func validCapturedParentReceipt(raw []byte, x singleTestExecution, proof existingTestVerification, body []byte, unknown bool) bool {
	var receipt struct {
		Run         string `json:"run_id"`
		Step        string `json:"step_id"`
		State       string `json:"state"`
		StepState   string `json:"step_state"`
		EffectState string `json:"effect_state"`
		Outcome     string `json:"outcome"`
		Reason      string `json:"reason"`
		Proof       string `json:"proof_sha256"`
		Version     int    `json:"reconcile_version"`
		Effect      string `json:"effect_key"`
		Invocation  string `json:"invocation_id"`
	}
	digest := sha256.Sum256(body)
	invocation, _ := apiserver.CanonicalDiscoveryID(x.scope, "security_agent_temporal_test_invocation", x.key)
	if len(raw) > 16384 || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &receipt) != nil || receipt.Run != x.parent || receipt.Step != x.step || receipt.Effect != x.key || receipt.Invocation != invocation || receipt.Version != 2 || receipt.Outcome != proof.Outcome || receipt.Reason != proof.Reason || receipt.Proof != hex.EncodeToString(digest[:]) || !stringInWorker(receipt.State, "remediated", "needs_human", "inconclusive", "failed", "cancelled") {
		return false
	}
	step := receipt.State
	if step == "remediated" || step == "needs_human" {
		step = "succeeded"
	}
	if receipt.StepState != step {
		return false
	}
	if unknown {
		return receipt.EffectState == "unknown_outcome"
	}
	effect := "succeeded"
	if receipt.State == "remediated" {
		effect = "verified"
	} else if receipt.State == "failed" || receipt.State == "cancelled" {
		effect = "known_failure"
	}
	return receipt.EffectState == effect
}

func (runner *productionRedTeamRunner) recoverCapturedSingleTest(ctx context.Context, x singleTestExecution) error {
	body, manifest, err := runner.capturedSingleInput(ctx, x)
	if err != nil {
		return err
	}
	output, err := runner.runLinkedArtifact(ctx, x.scope, x.parent, x.step, "", x.key, x.action, body, manifest, true)
	if err != nil {
		return err
	}
	return runner.settleCapturedSingleChild(ctx, x, output)
}

// Every object version is read back before the compensation entry validates
// the same input and completed journal under native locks.
func (runner *productionRedTeamRunner) settleCapturedSingleChild(ctx context.Context, x singleTestExecution, output apiserver.RedTeamArtifactReference) error {
	inputBody, inputManifest, err := runner.capturedSingleInput(ctx, x)
	if err != nil {
		return err
	}
	var input redTeamRunnerInput
	if decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, inputBody, &input) != nil {
		return errRuntimeUnavailable
	}
	locator, err := existingTestArtifactLocator(x.scope, output, 1<<20)
	if err != nil || locator.Reference.String() != x.child {
		return errRuntimeUnavailable
	}
	body, err := readExistingTestArtifact(ctx, runner.config.Artifacts, locator, output)
	if err != nil {
		return err
	}
	var format struct {
		Schema string `json:"schema_version"`
	}
	if json.Unmarshal(body, &format) != nil {
		return errRuntimeUnavailable
	}
	switch format.Schema {
	case "red-team-completed-receipts-v1":
		a, err := decodeCompletedTestArtifact(input, body)
		if err != nil || a.InputArtifact == nil || *a.InputArtifact != inputManifest {
			return errRuntimeUnavailable
		}
		for _, r := range a.Receipts {
			if r.Parent != x.parent || r.Step != x.step || r.Effect != x.key {
				return errRuntimeUnavailable
			}
		}
	case "red-team-evidence-bundle-v2":
		var a existingTestEvidenceBundle
		if decodeRedTeamEvidenceJSON(input, body, &a) != nil || a.InputArtifact == nil || *a.InputArtifact != inputManifest || !stringInWorker(a.Summary.Verdict, "pass", "fail") {
			return errRuntimeUnavailable
		}
		native, _ := json.Marshal(a.NativeArtifact)
		if _, err := buildRedTeamEvidenceBundle(input, a.Summary, a.InputArtifact, native); err != nil {
			return err
		}
	default:
		return errRuntimeUnavailable
	}
	raw, err := x.query(ctx, `SELECT zasp_temporal74.test_settle($1::jsonb)`, "child", map[string]any{"output_manifest": output, "output_body": base64.StdEncoding.EncodeToString(body)})
	if err != nil {
		return err
	}
	var receipt struct {
		Child    string                             `json:"test_run_id"`
		State    string                             `json:"state"`
		Attempt  int                                `json:"attempt"`
		Effect   string                             `json:"effect_key"`
		Manifest apiserver.RedTeamArtifactReference `json:"output_manifest"`
		Snapshot string                             `json:"snapshot_digest"`
	}
	if len(raw) > 16384 || decodeRedTeamEvidenceJSON(input, raw, &receipt) != nil || receipt.Child != x.child || receipt.State != "complete" || receipt.Attempt != 1 || receipt.Effect != x.key || receipt.Manifest != output || !redTeamLinkedDigestPattern.MatchString(receipt.Snapshot) {
		return errRuntimeUnavailable
	}
	state, err := x.state(ctx)
	if err != nil {
		return err
	}
	if state != "child" && state != "verified" {
		return errRuntimeUnavailable
	}
	return nil
}
