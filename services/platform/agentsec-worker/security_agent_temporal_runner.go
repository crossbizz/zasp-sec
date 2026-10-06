package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// RunTemporalTest is a reusable, lease-free operation. It is not registered
// with a scheduler or workflow here. A committed dispatch permit belongs to
// this one call; a resumed started effect is stopped, never sent again.
func (runner *productionRedTeamRunner) RunTemporalTest(ctx context.Context, database apiserver.JSONDatabase, scope domain.Scope, parent, step string, definitionVersion int64) (string, error) {
	if runner == nil || ctx == nil || ctx.Err() != nil || nilWorkerDependency(database) || scope.Validate() != nil || !validRecoveryProductID(parent) || definitionVersion < 1 || definitionVersion > 1000000 || redTeamRunnerImageDigest(runner.config.RunnerImage) == "" || !validRedTeamTokenFile(runner.config.TargetTokenFile) || !validRedTeamCAFile(runner.config.TargetCAFile) {
		return "", errWorkerExecution
	}
	canonical, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", parent+"\x1f1")
	if step != canonical {
		return "", errWorkerExecution
	}
	ctx, cancel := context.WithTimeout(ctx, runner.config.Timeout+30*time.Second)
	defer cancel()
	repository, err := apiserver.NewSecurityAgentTemporalExecutorRepository(database)
	if err != nil {
		return "", err
	}
	q := map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "run_id": parent, "step_id": step, "generation": 1, "operation": "read", "payload": map[string]any{}}
	statusQ, _ := json.Marshal(map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "run_id": parent, "definition_version": definitionVersion})
	keyBytes := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), parent, step, "1"}, "\x1f")))
	key := hex.EncodeToString(keyBytes[:])
	query := func(statement string, args ...any) (json.RawMessage, error) {
		bounded, done := context.WithTimeout(ctx, 10*time.Second)
		defer done()
		return database.QueryJSON(bounded, statement, args...)
	}
	ready, err := query(`SELECT to_jsonb(zasp_temporal68.ready($1,$2))`, migrations.TemporalExecutorChecksum(), migrations.TemporalExecutorFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(ready), []byte("true")) {
		return "", errWorkerExecution
	}
	readState := func() (string, error) {
		// status authenticates the retained public projection, including terminal
		// settlement/stop evidence. Only these small fields leave this operation.
		raw, err := query(orderedTestStateStatement, statusQ)
		var value struct {
			RunID             string `json:"run_id"`
			DefinitionVersion int64  `json:"definition_version"`
			RunState          string `json:"run_state"`
			Effects           []struct {
				StepID     string `json:"step_id"`
				EffectKey  string `json:"effect_key"`
				Generation int64  `json:"generation"`
				State      string `json:"state"`
				ActionKey  string `json:"action_key"`
			} `json:"effects"`
		}
		if err != nil || len(raw) > 4096 || decodeAttackLabJSON(raw, &value) != nil || value.RunID != parent || value.DefinitionVersion != definitionVersion || value.RunState == "" || len(value.Effects) > 1 {
			return "", errWorkerExecution
		}
		if len(value.Effects) == 0 {
			return "absent", nil
		}
		f := value.Effects[0]
		if f.StepID != step || f.EffectKey != key || f.Generation != 1 || f.ActionKey != "run_test" {
			return "", errWorkerExecution
		}
		switch f.State {
		case "reserved", "started", "unknown", "verified", "completed", "stopped":
			return f.State, nil
		default:
			return "", errWorkerExecution
		}
	}
	state, err := readState()
	if err != nil {
		return "", err
	}
	switch state {
	case "verified", "completed":
		return "settled", nil
	case "stopped":
		return "stopped", nil
	}
	call := func(entry, op string) (json.RawMessage, error) {
		q["operation"] = op
		q["payload"] = map[string]any{}
		raw, _ := json.Marshal(q)
		return query(entry, raw)
	}
	stop := func() (string, error) {
		if _, err := call(`SELECT zasp_temporal68.test_stop($1::jsonb)`, "stop"); err != nil {
			return "", err
		}
		state, err := readState()
		if err != nil || state != "stopped" {
			return "", errWorkerExecution
		}
		return "stopped", nil
	}
	recoverReserved := func(original error) (string, error) {
		// Stop only a still-unsent intent and only when SQL proves a current
		// stop condition. Ambiguous committed dispatch remains for recovery.
		current, err := readState()
		if err == nil && current == "reserved" {
			if result, err := stop(); err == nil {
				return result, nil
			}
		}
		return "", original
	}
	if state == "started" || state == "unknown" {
		return stop()
	}
	if state == "absent" {
		if _, err := call(`SELECT zasp_temporal68.effect($1::jsonb)`, "reserve"); err != nil {
			return "", err
		}
	}
	linked := func(op string, payload any) (temporalRunnerLinkedState, error) {
		q["operation"], q["payload"] = op, payload
		raw, _ := json.Marshal(q)
		result, err := repository.TemporalLinked(ctx, raw, runner.config.Artifacts)
		var value temporalRunnerLinkedState
		if err != nil {
			return value, err
		}
		if decodeStrictWorkerJSON(result, &value) != nil || value.EffectKey != key {
			return value, errWorkerExecution
		}
		return value, nil
	}
	inputState, err := linked("read", map[string]any{})
	if err != nil {
		return recoverReserved(err)
	}
	if inputState.InputManifest == nil {
		input := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2", OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: inputState.TestRunID, DefinitionID: inputState.DefinitionID, DefinitionVersion: inputState.DefinitionVersion, TargetID: inputState.TargetID, TargetKind: inputState.TargetKind, Categories: inputState.Categories, InputDigest: inputState.InputDigest, RunnerImageDigest: redTeamRunnerImageDigest(runner.config.RunnerImage)}
		body, err := json.Marshal(input)
		if err != nil {
			return "", errWorkerExecution
		}
		id, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", parent+"\x1f"+step)
		manifest, err := release61PutArtifact(ctx, runner.config.Artifacts, scope, id, body)
		if err != nil {
			return "", err
		}
		if _, err := linked("input", map[string]any{"manifest": manifest, "body": base64.StdEncoding.EncodeToString(body)}); err != nil {
			return recoverReserved(err)
		}
	}
	dispatched, err := linked("dispatch", map[string]any{})
	if err != nil {
		return recoverReserved(err)
	}
	if !dispatched.SendPermit {
		return "pending", nil
	}
	if dispatched.InputManifest == nil || dispatched.InputBody == nil {
		return "", errWorkerExecution
	}
	output, err := runner.runTemporalEffect(ctx, scope, parent, step, key, []byte(*dispatched.InputBody), *dispatched.InputManifest)
	if err != nil {
		return stop()
	}
	// Read the output version after the runner's Put/Get. Settlement independently
	// re-reads this version and the prepared input, then verifies every journal.
	pid, err := domain.ParseProductID(dispatched.TestRunID)
	if err != nil {
		return "", errWorkerExecution
	}
	reference, err := domain.NewEvidenceRef(pid)
	if err != nil {
		return "", errWorkerExecution
	}
	persisted, err := runner.config.Artifacts.Get(ctx, artifactstore.Locator{Scope: scope, Reference: reference, VersionID: output.VersionID})
	if err != nil {
		return "", err
	}
	q["operation"], q["payload"] = "complete", map[string]any{"output_manifest": output, "output_body": base64.StdEncoding.EncodeToString(persisted.Body)}
	raw, _ := json.Marshal(q)
	if _, err := repository.TemporalTestSettle(ctx, raw, runner.config.Artifacts); err != nil {
		return "", err
	}
	// Settlement verifies terminal Test evidence in its committed transaction;
	// the repository has also validated the receipt and both artifact versions.
	// Initial resume and stop paths still require their independent status read.
	return "settled", nil
}

type temporalRunnerLinkedState struct {
	EffectKey         string                              `json:"effect_key"`
	Generation        int64                               `json:"generation"`
	TestRunID         string                              `json:"test_run_id"`
	InputDigest       string                              `json:"input_digest"`
	DefinitionID      string                              `json:"definition_id"`
	DefinitionVersion int64                               `json:"definition_version"`
	TargetID          string                              `json:"target_id"`
	TargetKind        string                              `json:"target_kind"`
	Categories        []string                            `json:"categories"`
	TargetResolution  json.RawMessage                     `json:"target_resolution"`
	InputManifest     *apiserver.RedTeamArtifactReference `json:"input_manifest"`
	InputBody         *string                             `json:"input_body"`
	SendPermit        bool                                `json:"send_permit"`
}
