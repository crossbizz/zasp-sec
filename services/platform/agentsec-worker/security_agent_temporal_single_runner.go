package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"strings"
	"time"
)

type singleTestExecution struct {
	database                         apiserver.JSONDatabase
	scope                            domain.Scope
	parent, step, action, child, key string
}

func singleTestExecutionFor(database apiserver.JSONDatabase, scope domain.Scope, parent, step, action string) (singleTestExecution, error) {
	x := singleTestExecution{database: database, scope: scope, parent: parent, step: step, action: action}
	canonical, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", parent+"\x1f0")
	if nilWorkerDependency(database) || scope.Validate() != nil || !validRecoveryProductID(parent) || step != canonical || !stringInWorker(action, "run_test", "rerun_test") {
		return x, errWorkerExecution
	}
	x.child, _ = apiserver.CanonicalDiscoveryID(scope, "security_agent_test_run", parent+"\x1f"+step+"\x1f"+action)
	digest := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), parent, step, "1"}, "\x1f")))
	x.key = hex.EncodeToString(digest[:])
	return x, nil
}
func (x singleTestExecution) request(op string, payload any) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"organization_id": x.scope.OrganizationID().String(), "workspace_id": x.scope.WorkspaceID().String(), "environment_id": x.scope.EnvironmentID().String(), "run_id": x.parent, "step_id": x.step, "generation": 1, "operation": op, "payload": payload})
	return raw
}
func (x singleTestExecution) query(ctx context.Context, statement, op string, payload any) (json.RawMessage, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return x.database.QueryJSON(bounded, statement, x.request(op, payload))
}
func (x singleTestExecution) state(ctx context.Context) (string, error) {
	raw, err := x.query(ctx, `SELECT zasp_temporal74.test_state($1::jsonb)`, "read", map[string]any{})
	var value struct {
		Run    string `json:"run_id"`
		Step   string `json:"step_id"`
		Action string `json:"action_key"`
		Child  string `json:"test_run_id"`
		Key    string `json:"effect_key"`
		State  string `json:"state"`
	}
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 || decodeStrictWorkerJSON(raw, &value) != nil || value.Run != x.parent || value.Step != x.step || value.Action != x.action || value.Child != x.child || value.Key != x.key || !stringInWorker(value.State, "absent", "reserved", "started", "unknown", "child", "verified", "stopped") {
		return "", errWorkerExecution
	}
	return value.State, nil
}

// RunSingleTest consumes one persisted74 dispatch permit. Re-entry after an
// uncertain dispatch cannot invoke the native runner again.
func (runner *productionRedTeamRunner) RunSingleTest(ctx context.Context, database apiserver.JSONDatabase, scope domain.Scope, parent, step, action string) error {
	if runner == nil || ctx == nil || ctx.Err() != nil || nilWorkerDependency(runner.config.Artifacts) {
		return errWorkerExecution
	}
	x, err := singleTestExecutionFor(database, scope, parent, step, action)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, runner.config.Timeout+30*time.Second)
	defer cancel()
	state, err := x.state(ctx)
	if err != nil {
		return err
	}
	if state == "child" || state == "verified" {
		return nil
	}
	if state == "started" || state == "unknown" {
		if _, worker := database.(*workerSingleTestDatabase); worker {
			return runner.recoverCapturedSingleTest(ctx, x)
		}
		return errRuntimeUnavailable
	}
	if state == "stopped" {
		return errRuntimeUnavailable
	}
	if state == "absent" {
		if _, err = x.query(ctx, `SELECT zasp_temporal74.effect($1::jsonb)`, "reserve", map[string]any{}); err != nil {
			return err
		}
	}
	repository, err := apiserver.NewSecurityAgentTemporalExecutorRepository(database)
	if err != nil {
		return err
	}
	linked := func(op string, payload any) (temporalRunnerLinkedState, error) {
		var value temporalRunnerLinkedState
		raw, err := repository.SingleTestLinked(ctx, x.request(op, payload), runner.config.Artifacts, action)
		if err != nil {
			return value, err
		}
		if decodeStrictWorkerJSON(raw, &value) != nil || value.EffectKey != x.key || value.TestRunID != x.child {
			return value, errWorkerExecution
		}
		return value, nil
	}
	prepared, err := linked("read", map[string]any{})
	if err != nil {
		return err
	}
	if prepared.InputManifest == nil {
		input := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2", OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: x.child, DefinitionID: prepared.DefinitionID, DefinitionVersion: prepared.DefinitionVersion, TargetID: prepared.TargetID, TargetKind: prepared.TargetKind, Categories: prepared.Categories, InputDigest: prepared.InputDigest, RunnerImageDigest: redTeamRunnerImageDigest(runner.config.RunnerImage)}
		body, err := json.Marshal(input)
		if err != nil {
			return errWorkerExecution
		}
		id, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", parent+"\x1f"+step)
		manifest, err := release61PutArtifact(ctx, runner.config.Artifacts, scope, id, body)
		if err != nil {
			return err
		}
		if _, err = linked("input", map[string]any{"manifest": manifest, "body": base64.StdEncoding.EncodeToString(body)}); err != nil {
			return err
		}
	}
	dispatched, err := linked("dispatch", map[string]any{})
	if err != nil {
		return err
	}
	if !dispatched.SendPermit || dispatched.InputManifest == nil || dispatched.InputBody == nil {
		return errRuntimeUnavailable
	}
	output, err := runner.runLinkedAction(ctx, scope, parent, step, "", x.key, action, []byte(*dispatched.InputBody), *dispatched.InputManifest)
	if err != nil {
		return err
	}
	if _, worker := database.(*workerSingleTestDatabase); worker {
		return runner.settleCapturedSingleChild(ctx, x, output)
	}
	pid, _ := domain.ParseProductID(x.child)
	ref, _ := domain.NewEvidenceRef(pid)
	persisted, err := runner.config.Artifacts.Get(ctx, artifactstore.Locator{Scope: scope, Reference: ref, VersionID: output.VersionID})
	if err != nil {
		return err
	}
	if _, err = repository.SingleTestChildSettle(ctx, x.request("child", map[string]any{"output_manifest": output, "output_body": base64.StdEncoding.EncodeToString(persisted.Body)}), runner.config.Artifacts, action); err != nil {
		return err
	}
	state, err = x.state(ctx)
	if err != nil {
		return err
	}
	if state != "child" && state != "verified" {
		return errWorkerExecution
	}
	return nil
}

func (runner *productionRedTeamRunner) SettleSingleTest(ctx context.Context, database apiserver.JSONDatabase, scope domain.Scope, parent, step, action string) error {
	if runner == nil || ctx == nil || ctx.Err() != nil || nilWorkerDependency(runner.config.Artifacts) {
		return errWorkerExecution
	}
	x, err := singleTestExecutionFor(database, scope, parent, step, action)
	if err != nil {
		return err
	}
	state, err := x.state(ctx)
	if err != nil {
		return err
	}
	if state == "verified" {
		return nil
	}
	if state != "child" {
		return errRuntimeUnavailable
	}
	raw, err := x.query(ctx, `SELECT zasp_temporal74.test_settle($1::jsonb)`, "snapshot", map[string]any{})
	if err != nil {
		return err
	}
	var snapshot existingTestSnapshot
	var snapshotDigest string
	_, worker := database.(*workerSingleTestDatabase)
	if worker {
		snapshot, snapshotDigest, err = decodeCapturedTestSnapshot(raw, scope, parent, step, x.child, time.Now())
	} else {
		snapshot, err = decodeSingleTestSnapshot(raw, scope, parent, step, x.child, time.Now())
	}
	if err != nil || snapshot.After == nil {
		return errWorkerExecution
	}
	proof := verifyExistingTestComparison(ctx, runner.config.Artifacts, snapshot.Before, *snapshot.After)
	body, err := json.Marshal(proof)
	if err != nil {
		return errWorkerExecution
	}
	payload := map[string]any{"snapshot": json.RawMessage(raw), "proof_body": base64.StdEncoding.EncodeToString(body)}
	if worker {
		delete(payload, "snapshot")
		payload["snapshot_digest"] = snapshotDigest
	}
	completed, err := x.query(ctx, `SELECT zasp_temporal74.test_settle($1::jsonb)`, "complete", payload)
	if err != nil {
		return err
	}
	if worker && !validCapturedParentReceipt(completed, x, proof, body, snapshot.OutcomeUnknown) {
		return errWorkerExecution
	}
	state, err = x.state(ctx)
	if err != nil {
		return err
	}
	if state != "verified" {
		return errWorkerExecution
	}
	return nil
}
