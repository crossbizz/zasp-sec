package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

type settlementRunnerDatabase struct {
	apiserver.JSONDatabase
	query func(context.Context, string, ...any) (json.RawMessage, error)
}

func (d settlementRunnerDatabase) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	return d.query(ctx, sql, args...)
}

// Exercise the real runner, repository validators and versioned artifact store.
// Only SQL responses and the engine process are controlled here; this is not
// a native journal/authority test. The native happy consumer covers those.
func TestTemporalRunnerUsesValidatedCommittedSettlement(t *testing.T) {
	for _, mode := range []string{"valid", "error", "malformed", "effect", "child", "state", "receipt", "output", "digest"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			templateStore, _, fixture := fixtureExistingTestEvidence(t)
			scope := fixture.Scope
			parent := "pid_89000020-0000-4000-8000-000000000001"
			step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", parent+"\x1f1")
			child, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_test_run", parent+"\x1f"+step+"\x1frun_test")
			inputID, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", parent+"\x1f"+step)
			keyBytes := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), parent, step, "1"}, "\x1f")))
			key := hex.EncodeToString(keyBytes[:])
			template, err := readExistingTestEvidence(ctx, templateStore, fixture)
			if err != nil {
				t.Fatal(err)
			}
			input := template.Input
			input.RunID = child
			inputBody, _ := json.Marshal(input)
			store, err := artifactstore.New(&existingTestEvidenceDriver{objects: make(map[artifactstore.DriverLocator]artifactstore.DriverObject)}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			inputManifest, err := release61PutArtifact(ctx, store, scope, inputID, inputBody)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := "https://target.example/evaluate"
			endpointHash := sha256.Sum256([]byte(endpoint))
			comparison := *fixture.Observations[0].TargetComparison
			comparison.Endpoint = hex.EncodeToString(endpointHash[:])
			resolution, _ := json.Marshal(map[string]any{"binding": map[string]any{"target_id": input.TargetID, "target_kind": input.TargetKind, "endpoint": endpoint, "credential_reference": "ref:red-team/fixture_credential", "version": 1}, "comparison": comparison, "provenance": map[string]any{"integration_id": input.TargetID, "snapshot_id": input.TargetID, "evidence_id": input.TargetID, "source": "fixture", "generation": 1}})
			bodyText := string(inputBody)
			linked := temporalRunnerLinkedState{EffectKey: key, Generation: 1, TestRunID: child, InputDigest: input.InputDigest, DefinitionID: input.DefinitionID, DefinitionVersion: 1, TargetID: input.TargetID, TargetKind: input.TargetKind, Categories: input.Categories, TargetResolution: resolution, InputManifest: &inputManifest, InputBody: &bodyText}
			stateReads, settlements, commands := 0, 0, 0
			settled := false
			db := settlementRunnerDatabase{query: func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if strings.Contains(sql, ".ready(") {
					return json.RawMessage(`true`), nil
				}
				if sql == orderedTestStateStatement {
					stateReads++
					// A post-settlement query must not turn a validated committed
					// result into unavailable when its parent budget is exhausted.
					if settled {
						return nil, context.DeadlineExceeded
					}
					return json.Marshal(map[string]any{"run_id": parent, "definition_version": 1, "run_state": "verifying", "effects": []any{map[string]any{"step_id": step, "effect_key": key, "generation": 1, "state": "reserved", "action_key": "run_test"}}})
				}
				var q struct {
					Operation string          `json:"operation"`
					Payload   json.RawMessage `json:"payload"`
				}
				if len(args) != 1 || json.Unmarshal(args[0].(json.RawMessage), &q) != nil {
					t.Fatal("bad runner query")
				}
				if sql == `SELECT zasp_temporal68.linked($1::jsonb)` {
					if q.Operation != "read" && q.Operation != "dispatch" {
						t.Fatal("unexpected linked operation", q.Operation)
					}
					v := linked
					v.SendPermit = q.Operation == "dispatch"
					return json.Marshal(v)
				}
				if sql != `SELECT zasp_temporal68.test_settle($1::jsonb)` || q.Operation != "complete" {
					t.Fatal("unexpected SQL boundary")
				}
				settlements++
				if mode == "error" {
					return nil, apiserver.ErrRepositoryConflict
				}
				var payload struct {
					Manifest apiserver.RedTeamArtifactReference `json:"output_manifest"`
				}
				if json.Unmarshal(q.Payload, &payload) != nil {
					t.Fatal("bad settlement payload")
				}
				snapshot := strings.Repeat("c", 64)
				inputDigest, _ := hex.DecodeString(input.InputDigest)
				snapshotBytes, _ := hex.DecodeString(snapshot)
				proof, _ := hex.DecodeString(payload.Manifest.SHA256)
				resultDigest := sha256.Sum256(append(append(inputDigest, snapshotBytes...), proof...))
				invocation, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_temporal_test_invocation", key)
				response := map[string]any{"effect_key": key, "generation": 1, "test_run_id": child, "run_state": "needs_human", "outcome": "reproduced", "result_digest": "sha256:" + hex.EncodeToString(resultDigest[:]), "input_digest": "sha256:" + input.InputDigest, "plan_hash": "sha256:" + strings.Repeat("e", 64), "receipt": map[string]any{"invocation_id": invocation, "snapshot_digest": snapshot, "proof_digest": payload.Manifest.SHA256, "settlement_generation": 1, "outcome": "reproduced"}, "input_artifact": inputManifest, "output_artifact": payload.Manifest}
				switch mode {
				case "malformed":
					return json.RawMessage(`{}`), nil
				case "effect":
					response["effect_key"] = strings.Repeat("a", 64)
				case "child":
					response["test_run_id"] = parent
				case "state":
					response["run_state"] = "verifying"
				case "receipt":
					response["receipt"].(map[string]any)["settlement_generation"] = 2
				case "output":
					response["output_artifact"] = inputManifest
				case "digest":
					response["result_digest"] = "sha256:" + strings.Repeat("a", 64)
				}
				settled = true
				return json.Marshal(response)
			}}
			root := t.TempDir()
			token := filepath.Join(root, "token")
			if err := os.WriteFile(token, []byte(strings.Repeat("t", 64)), 0400); err != nil {
				t.Fatal(err)
			}
			command := redTeamCommandFunc(func(ctx context.Context, executable string, args, env []string, dir string) error {
				commands++
				if len(args) != 4 || executable != "/usr/local/bin/node" || !containsWorkerString(env, "ZASP_RED_TEAM_EFFECT_KEY="+key) {
					t.Fatal("wrong engine invocation")
				}
				summary := template.Bundle.Summary
				summary.RunID = child
				native := template.Bundle.NativeArtifact
				native.RunID = child
				native.NativeOutput.Results.Results[0].Response.LinkedObservation.RunID = child
				native.NativeOutput.Results.Results[0].Response.LinkedObservation.TargetComparison = &comparison
				summaryBytes, _ := json.Marshal(summary)
				nativeBytes, _ := json.Marshal(native)
				if err := os.WriteFile(filepath.Join(dir, "artifact.json"), nativeBytes, 0600); err != nil {
					return err
				}
				return os.WriteFile(args[3], summaryBytes, 0600)
			})
			runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "fixture/runner@sha256:" + strings.Repeat("d", 64), Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/evaluate", TargetTokenFile: token, TargetCAFile: writeRedTeamTestCA(t, root), TempRoot: root, Timeout: 30 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
			if err != nil {
				t.Fatal(err)
			}
			got, err := runner.RunTemporalTest(ctx, db, scope, parent, step, 1)
			if commands != 1 || settlements != 1 {
				t.Fatalf("did not reach real settlement validator: commands=%d settlements=%d err=%v", commands, settlements, err)
			}
			if mode == "valid" {
				if err != nil || got != "settled" || stateReads != 1 {
					t.Fatalf("committed settlement lost: got=%q err=%v status_reads=%d", got, err, stateReads)
				}
			} else if err == nil || got != "" || stateReads != 1 {
				t.Fatalf("invalid receipt accepted: mode=%s got=%q err=%v status_reads=%d", mode, got, err, stateReads)
			}
			if mode == "error" && !errors.Is(err, apiserver.ErrRepositoryConflict) {
				t.Fatal("settlement error lost", err)
			}
		})
	}
}
