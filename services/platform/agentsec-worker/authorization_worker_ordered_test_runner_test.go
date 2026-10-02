package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type orderedRunnerCapturedExecutor struct {
	*orderedTestRecordingExecutor
	response json.RawMessage
	stopped  json.RawMessage
	op       authorization.WorkerOperation
}

func (e *orderedRunnerCapturedExecutor) Authorize(ctx context.Context, op authorization.WorkerOperation, raw json.RawMessage) (authorization.WorkerDecision, error) {
	e.op = op
	if op != "ordered68.test.state" && op != "ordered68.test.stop" {
		e.t.Fatal("recovery reached forward authority", op)
	}
	return e.orderedTestRecordingExecutor.Authorize(ctx, op, raw)
}
func (e *orderedRunnerCapturedExecutor) Execute(ctx context.Context, d authorization.WorkerDecision) (json.RawMessage, error) {
	if _, err := e.orderedTestRecordingExecutor.Execute(ctx, d); err != nil {
		return nil, err
	}
	if e.op == "ordered68.test.stop" {
		e.response = e.stopped
		return json.RawMessage(`{}`), nil
	}
	return e.response, nil
}

// This consumes the actual runner and closed database adapter. Native status
// evidence is represented at the signed client's response boundary; real SQL,
// Node/TLS and artifact settlement remain the separate native fixture gate.
func TestOrderedTestRunnerCapturedRecoveryNeverResends(t *testing.T) {
	start := workerPlanningStartFixture()
	scope, _ := temporalScope(start)
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", start.Ref.RunID+"\x1f1")
	digest := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID, step, "1"}, "\x1f")))
	status := func(state string) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"run_id": start.Ref.RunID, "definition_version": start.DefinitionVersion, "run_state": "verifying", "effects": []any{map[string]any{"step_id": step, "effect_key": hex.EncodeToString(digest[:]), "generation": 1, "state": state, "action_key": "run_test"}}})
		return raw
	}
	for _, state := range []string{"started", "unknown", "verified", "completed", "stopped"} {
		t.Run(state, func(t *testing.T) {
			var events []string
			forward := &orderedTestRecordingExecutor{t: t, events: &events, label: "forward"}
			captured := &orderedRunnerCapturedExecutor{orderedTestRecordingExecutor: &orderedTestRecordingExecutor{t: t, events: &events, label: "captured"}, response: status(state), stopped: status("stopped")}
			db := &workerOrderedTestDatabase{start: start, forward: forward, compensation: captured}
			dir := t.TempDir()
			token := filepath.Join(dir, "worker-token")
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0400); err != nil {
				t.Fatal(err)
			}
			runner := &productionRedTeamRunner{config: productionRedTeamRunnerConfig{RunnerImage: "owned/runner@sha256:" + strings.Repeat("a", 64), TargetTokenFile: token, TargetCAFile: writeRedTeamTestCA(t, dir), Timeout: 30 * time.Second, Command: redTeamCommandFunc(func(context.Context, string, []string, []string, string) error {
				t.Fatal("captured recovery launched Node")
				return nil
			})}}
			got, err := runner.RunTemporalTest(context.Background(), db, scope, start.Ref.RunID, step, start.DefinitionVersion)
			want := "stopped"
			if state == "verified" || state == "completed" {
				want = "settled"
			}
			if err != nil || got != want {
				t.Fatal(got, err)
			}
			for _, event := range events {
				if strings.HasPrefix(event, "forward:") && event != "forward:ready:ordered68.linked.read" {
					t.Fatal("captured recovery used forward authorization", events)
				}
			}
			stops := 0
			for _, event := range events {
				if event == "captured:authorize:ordered68.test.stop" {
					stops++
				}
			}
			if (state == "started" || state == "unknown") && stops != 1 || (state != "started" && state != "unknown") && stops != 0 {
				t.Fatal("wrong conservative stop", events)
			}
		})
	}
}
