package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// runRelease61 uses the canonical input already committed by test_dispatch.
// No default worker or handler calls this entry. Commands must use the explicit
// release61 category journal; settlement independently verifies every journal.
func (runner *productionRedTeamRunner) runRelease61(ctx context.Context, scope domain.Scope, parent, step, lease string, inputBody []byte, manifest apiserver.RedTeamArtifactReference) (apiserver.RedTeamArtifactReference, error) {
	if !redTeamRunLeasePattern.MatchString(lease) {
		return apiserver.RedTeamArtifactReference{}, errWorkerExecution
	}
	return runner.runLinked(ctx, scope, parent, step, lease, "", inputBody, manifest)
}

func (runner *productionRedTeamRunner) runTemporalEffect(ctx context.Context, scope domain.Scope, parent, step, effectKey string, inputBody []byte, manifest apiserver.RedTeamArtifactReference) (apiserver.RedTeamArtifactReference, error) {
	if !redteamadapter.ValidEffectKey(effectKey) {
		return apiserver.RedTeamArtifactReference{}, errWorkerExecution
	}
	return runner.runLinked(ctx, scope, parent, step, "", effectKey, inputBody, manifest)
}

func (runner *productionRedTeamRunner) runLinked(ctx context.Context, scope domain.Scope, parent, step, lease, effectKey string, inputBody []byte, manifest apiserver.RedTeamArtifactReference) (apiserver.RedTeamArtifactReference, error) {
	return runner.runLinkedAction(ctx, scope, parent, step, lease, effectKey, "run_test", inputBody, manifest)
}

func (runner *productionRedTeamRunner) runLinkedAction(ctx context.Context, scope domain.Scope, parent, step, lease, effectKey, action string, inputBody []byte, manifest apiserver.RedTeamArtifactReference) (apiserver.RedTeamArtifactReference, error) {
	return runner.runLinkedArtifact(ctx, scope, parent, step, lease, effectKey, action, inputBody, manifest, false)
}

func (runner *productionRedTeamRunner) runLinkedArtifact(ctx context.Context, scope domain.Scope, parent, step, lease, effectKey, action string, inputBody []byte, manifest apiserver.RedTeamArtifactReference, recovered bool) (apiserver.RedTeamArtifactReference, error) {
	fail := func() (apiserver.RedTeamArtifactReference, error) {
		return apiserver.RedTeamArtifactReference{}, errWorkerExecution
	}
	validAuthority := lease == "" && redteamadapter.ValidEffectKey(effectKey) || effectKey == "" && redTeamRunLeasePattern.MatchString(lease)
	if recovered && (lease != "" || !redteamadapter.ValidEffectKey(effectKey)) {
		return fail()
	}
	if runner == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validAuthority || !stringInWorker(action, "run_test", "rerun_test") || action == "rerun_test" && lease != "" || len(inputBody) > 65536 || !validRedTeamTokenFile(runner.config.TargetTokenFile) || !validRedTeamCAFile(runner.config.TargetCAFile) {
		return fail()
	}
	var input redTeamRunnerInput
	if decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, inputBody, &input) != nil || input.SchemaVersion != "red-team-runner-input-v2" || input.RunnerImageDigest != redTeamRunnerImageDigest(runner.config.RunnerImage) || input.OrganizationID != scope.OrganizationID().String() || input.WorkspaceID != scope.WorkspaceID().String() || input.EnvironmentID != scope.EnvironmentID().String() {
		return fail()
	}
	child, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_test_run", parent+"\x1f"+step+"\x1f"+action)
	id, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", parent+"\x1f"+step)
	if input.RunID != child {
		return fail()
	}
	pid, err := domain.ParseProductID(id)
	if err != nil {
		return fail()
	}
	ref, err := domain.NewEvidenceRef(pid)
	if err != nil {
		return fail()
	}
	artifact, err := runner.config.Artifacts.Get(ctx, artifactstore.Locator{Scope: scope, Reference: ref, VersionID: manifest.VersionID})
	if err != nil || !validRedTeamPersistedArtifact(artifact, scope, ref, inputBody) || artifact.VersionID != manifest.VersionID || hex.EncodeToString(artifact.SHA256[:]) != manifest.SHA256 || artifact.Size != manifest.SizeBytes {
		return fail()
	}
	object, err := runner.config.Artifacts.ObjectReference(artifact.Locator)
	if err != nil || object != manifest.Reference || !validRedTeamArtifactObjectReference(object, release61ArtifactKey(scope, id)) {
		return fail()
	}
	workspace, err := os.MkdirTemp(runner.config.TempRoot, "zasp-release61-red-team-")
	if err != nil {
		return fail()
	}
	defer os.RemoveAll(workspace)
	if os.Chmod(workspace, 0700) != nil {
		return fail()
	}
	in, out := filepath.Join(workspace, "input.json"), filepath.Join(workspace, "output.json")
	if writeRedTeamFile(in, inputBody) != nil {
		return fail()
	}
	bounded, cancel := context.WithTimeout(ctx, runner.config.Timeout)
	defer cancel()
	path, authority := "/v1/linked/evaluate", "ZASP_RED_TEAM_RUN_LEASE="+lease
	if effectKey != "" {
		path, authority = "/v1/effects/evaluate", "ZASP_RED_TEAM_EFFECT_KEY="+effectKey
	}
	env := []string{"HOME=" + workspace, "ZASP_PROMPTFOO_BIN=" + runner.config.PromptfooPath, "ZASP_RED_TEAM_TARGET_ENDPOINT=" + strings.TrimSuffix(runner.config.TargetEndpoint, "/v1/evaluate") + path, "ZASP_RED_TEAM_ADAPTER_TOKEN_FILE=" + runner.config.TargetTokenFile, "ZASP_RED_TEAM_TARGET_CA_FILE=" + runner.config.TargetCAFile, authority}
	command := "run"
	if recovered {
		command = "recover-completed"
		env = []string{"HOME=" + workspace, "ZASP_RED_TEAM_TARGET_ENDPOINT=" + strings.TrimSuffix(runner.config.TargetEndpoint, "/v1/evaluate") + "/v1/effects/completed-receipt", "ZASP_RED_TEAM_ADAPTER_TOKEN_FILE=" + runner.config.TargetTokenFile, "ZASP_RED_TEAM_TARGET_CA_FILE=" + runner.config.TargetCAFile, "ZASP_RED_TEAM_EFFECT_KEY=" + effectKey, "ZASP_RED_TEAM_RECOVERY_PARENT_RUN_ID=" + parent, "ZASP_RED_TEAM_RECOVERY_STEP_ID=" + step, "ZASP_RED_TEAM_RECOVERY_GENERATION=1"}
	}
	if runner.config.Command.Run(bounded, runner.config.NodePath, []string{runner.config.ScriptPath, command, in, out}, env, workspace) != nil || bounded.Err() != nil {
		return fail()
	}
	body, err := readRedTeamOutput(out)
	if err != nil {
		return fail()
	}
	if recovered {
		artifact, err := decodeCompletedTestArtifact(input, body)
		if err != nil || artifact.InputArtifact != nil {
			return fail()
		}
		for _, receipt := range artifact.Receipts {
			if receipt.Parent != parent || receipt.Step != step || receipt.Effect != effectKey {
				return fail()
			}
		}
		artifact.InputArtifact = &manifest
		bundle, err := json.Marshal(artifact)
		if err != nil {
			return fail()
		}
		return release61PutArtifact(ctx, runner.config.Artifacts, scope, child, bundle)
	}
	var output redTeamRunnerOutput
	if decodeRedTeamEvidenceJSON(input, body, &output) != nil || !validRedTeamRunnerOutput(input, output) {
		return fail()
	}
	native, err := readRedTeamOutput(filepath.Join(workspace, "artifact.json"))
	if err != nil {
		return fail()
	}
	bundle, err := buildRedTeamEvidenceBundle(input, output, &manifest, native)
	if err != nil {
		return fail()
	}
	return release61PutArtifact(ctx, runner.config.Artifacts, scope, child, bundle)
}

func release61ArtifactKey(scope domain.Scope, id string) string {
	return "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + id
}

func release61PutArtifact(ctx context.Context, store artifactstore.ObjectReferencingArtifactStore, scope domain.Scope, id string, body []byte) (apiserver.RedTeamArtifactReference, error) {
	var result apiserver.RedTeamArtifactReference
	pid, err := domain.ParseProductID(id)
	if err != nil {
		return result, errWorkerExecution
	}
	ref, err := domain.NewEvidenceRef(pid)
	if err != nil {
		return result, errWorkerExecution
	}
	written, err := store.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: bytes.Clone(body)})
	if err != nil || !validRedTeamPersistedArtifact(written, scope, ref, body) {
		return result, errWorkerExecution
	}
	read, err := store.Get(ctx, written.Locator)
	if err != nil || !validRedTeamPersistedArtifact(read, scope, ref, body) || read.VersionID != written.VersionID {
		return result, errWorkerExecution
	}
	object, err := store.ObjectReference(read.Locator)
	if err != nil || !validRedTeamArtifactObjectReference(object, release61ArtifactKey(scope, id)) {
		return result, errWorkerExecution
	}
	result = apiserver.RedTeamArtifactReference{Reference: object, VersionID: read.VersionID, SHA256: hex.EncodeToString(read.SHA256[:]), SizeBytes: read.Size}
	return result, nil
}

type release61TestState struct {
	TestRunID         string                             `json:"test_run_id"`
	DefinitionID      string                             `json:"test_definition_id"`
	DefinitionVersion int64                              `json:"test_definition_version"`
	TargetID          string                             `json:"target_id"`
	TargetKind        string                             `json:"target_kind"`
	Categories        []string                           `json:"categories"`
	InputDigest       string                             `json:"input_digest"`
	State             string                             `json:"child_state"`
	Owned             bool                               `json:"owned"`
	LeaseExpiresAt    string                             `json:"lease_expires_at"`
	InputManifest     apiserver.RedTeamArtifactReference `json:"input_manifest"`
	InputBody         string                             `json:"input_body"`
	Observations      []struct {
		Category    string          `json:"category"`
		State       string          `json:"state"`
		Observation json.RawMessage `json:"observation"`
	} `json:"observations"`
}

func (r *securityAgentRelease61Runtime) testTick(ctx context.Context, state securityAgentRelease61State) (string, error) {
	step := state.Steps[1]
	q := r.scopeRequest()
	q["step_id"], q["run_version"], q["effect_version"], q["worker_id"], q["lease_token"], q["lease_seconds"], q["payload"] = step.StepID, state.RunVersion, step.EffectVersion, r.planning.WorkerID, r.planning.LeaseToken, 300, map[string]any{}
	if step.State == "authorized" && step.EffectVersion == 0 {
		q["operation"] = "claim"
		return "test_claim", r.call(ctx, r.composition.TestAction, q)
	}
	if !step.Owned {
		if step.EffectState == "leased" && release61Expired(step.LeaseExpiresAt) && len(state.Test.Observations) > 0 && state.Test.State == "leased" && release61Expired(state.Test.LeaseExpiresAt) {
			reconcile := r.scopeRequest()
			reconcile["step_id"], reconcile["run_version"], reconcile["effect_version"], reconcile["worker_id"], reconcile["operation"] = step.StepID, state.RunVersion, step.EffectVersion, r.planning.WorkerID, "reconcile_uncertain"
			return "test_reconcile", r.call(ctx, r.composition.TestReconcile, reconcile)
		}
		if step.EffectState == "leased" && release61Expired(step.LeaseExpiresAt) && len(state.Test.Observations) == 0 && (state.Test.State == "queued" || state.Test.State == "leased" && release61Expired(state.Test.LeaseExpiresAt)) {
			q["operation"] = "claim"
			return "test_claim", r.call(ctx, r.composition.TestAction, q)
		}
		return "lease_wait", nil
	}
	if r.testRunner == nil {
		return "", errWorkerExecution
	}
	deadlines := []string{step.LeaseExpiresAt}
	if state.Test.State == "leased" {
		if !state.Test.Owned {
			return "lease_wait", nil
		}
		deadlines = append(deadlines, state.Test.LeaseExpiresAt)
	}
	ownedCtx, ownedCancel, ownedErr := release61OwnedContext(ctx, deadlines...)
	if ownedErr != nil {
		return "", ownedErr
	}
	defer ownedCancel()
	ctx = ownedCtx
	for _, deadline := range deadlines {
		if release61HeartbeatDue(deadline) {
			q["operation"] = "heartbeat"
			return "test_heartbeat", r.call(ctx, r.composition.TestAction, q)
		}
	}
	o, err := domain.ParseProductID(r.planning.Selection.OrganizationID)
	if err != nil {
		return "", errWorkerExecution
	}
	w, err := domain.ParseProductID(r.planning.Selection.WorkspaceID)
	if err != nil {
		return "", errWorkerExecution
	}
	e, err := domain.ParseProductID(r.planning.Selection.EnvironmentID)
	if err != nil {
		return "", errWorkerExecution
	}
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		return "", errWorkerExecution
	}
	if state.Test.State == "queued" {
		input := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2", OrganizationID: r.planning.Selection.OrganizationID, WorkspaceID: r.planning.Selection.WorkspaceID, EnvironmentID: r.planning.Selection.EnvironmentID, RunID: state.Test.TestRunID, DefinitionID: state.Test.DefinitionID, DefinitionVersion: state.Test.DefinitionVersion, TargetID: state.Test.TargetID, TargetKind: state.Test.TargetKind, Categories: state.Test.Categories, InputDigest: state.Test.InputDigest, RunnerImageDigest: redTeamRunnerImageDigest(r.testRunner.config.RunnerImage)}
		body, err := json.Marshal(input)
		if err != nil {
			return "", errWorkerExecution
		}
		id, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", r.planning.RunID+"\x1f"+step.StepID)
		manifest, err := release61PutArtifact(ctx, r.testRunner.config.Artifacts, scope, id, body)
		if err != nil {
			return "", err
		}
		q["operation"], q["payload"] = "dispatch", map[string]any{"input_artifact": manifest}
		return "test_dispatch", r.call(ctx, r.composition.TestDispatch, q)
	}
	if state.Test.State != "leased" || !state.Test.Owned {
		return "lease_wait", nil
	}
	for _, item := range state.Test.Observations {
		if item.State == "started" {
			q["operation"] = "uncertain"
			return "test_uncertain", r.call(ctx, r.composition.TestUncertain, q)
		}
	}
	output, err := r.testRunner.runRelease61(ctx, scope, r.planning.RunID, step.StepID, r.planning.LeaseToken, []byte(state.Test.InputBody), state.Test.InputManifest)
	if err != nil {
		return "", err
	}
	q["operation"], q["payload"] = "settle", map[string]any{"input_artifact": state.Test.InputManifest, "output_artifact": output}
	return "test_settle", r.call(ctx, r.composition.TestSettle, q)
}
