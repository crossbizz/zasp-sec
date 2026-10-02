package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recoveryCleanupFunc func(context.Context, orchestration.CleanupRequest) error

func (f recoveryCleanupFunc) Cleanup(c context.Context, q orchestration.CleanupRequest) error {
	return f(c, q)
}
func workerRecoveryRef() orchestration.SingleTestRecoveryRef {
	return orchestration.SingleTestRecoveryRef{Start: orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "pid_10000000-0000-4000-8000-000000000001", WorkspaceID: "pid_10000000-0000-4000-8000-000000000002", EnvironmentID: "pid_10000000-0000-4000-8000-000000000003", RunID: "pid_10000000-0000-4000-8000-000000000004"}, DefinitionVersion: 1, InputDigest: strings.Repeat("a", 64)}, CommandID: "pid_10000000-0000-4000-8000-000000000005", CommandDigest: strings.Repeat("b", 64)}
}
func TestSingleTestRecoveryWorkerNoSend(t *testing.T) {
	t.Run("actual indirect captured runner", testSingleRecoveryCapturedRunner)
	for _, mode := range []string{"complete", "pending", "missing_command", "finish_pending"} {
		t.Run(mode, func(t *testing.T) {
			q := workerRecoveryRef()
			trace := []string{}
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				switch sql {
				case singleRecoveryLoadSQL:
					trace = append(trace, "load")
					if mode == "missing_command" {
						return nil, orchestration.ErrConflict
					}
					return json.Marshal(q)
				case singleRecoveryFinishSQL:
					trace = append(trace, "finish")
					return json.Marshal(map[string]any{"complete": mode != "finish_pending", "reference": q})
				case singleRecoveryObserveSQL:
					trace = append(trace, "observe")
					if mode == "missing_command" {
						return nil, orchestration.ErrConflict
					}
					return json.RawMessage(`true`), nil
				default:
					t.Fatal("recovery attempted an undeclared operation", sql)
					return nil, nil
				}
			})
			p := &singleTestRecoveryProduct{database: db, cleanup: recoveryCleanupFunc(func(_ context.Context, got orchestration.CleanupRequest) error {
				trace = append(trace, "cleanup")
				if got.Start != q.Start || got.Reason != "workflow_cancelled" {
					t.Fatal("cleanup intent changed")
				}
				if mode == "pending" {
					return orchestration.ErrCleanupPending
				}
				return nil
			})}
			err := p.Step(context.Background(), q)
			want := []string{"load", "cleanup", "finish"}
			switch mode {
			case "missing_command":
				want = []string{"load", "observe"}
				if err == nil {
					t.Fatal("missing authority accepted")
				}
			case "pending":
				want = []string{"load", "cleanup", "observe"}
				if !errors.Is(err, orchestration.ErrCleanupPending) {
					t.Fatal(err)
				}
			case "finish_pending":
				want = []string{"load", "cleanup", "finish", "observe"}
				if !errors.Is(err, orchestration.ErrCleanupPending) {
					t.Fatal(err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(trace, want) {
				t.Fatal(trace, want)
			}
		})
	}
}

// A verified command must not stay queued after a permanent finish failure.
// The primary failure still wins when the bounded progress write is unavailable.
func TestSingleTestRecoveryProgressFailures(t *testing.T) {
	for _, mode := range []string{"finish_conflict", "finish_malformed", "finish_pending", "finish_unavailable", "progress_failure", "cleanup_progress_failure", "known_load_conflict", "untrusted_load"} {
		t.Run(mode, func(t *testing.T) {
			q := workerRecoveryRef()
			observed := ""
			cleanupCalls := 0
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				switch sql {
				case singleRecoveryLoadSQL:
					if mode == "untrusted_load" || mode == "known_load_conflict" {
						return nil, orchestration.ErrConflict
					}
					return json.Marshal(q)
				case singleRecoveryFinishSQL:
					switch mode {
					case "finish_conflict", "progress_failure":
						return nil, orchestration.ErrConflict
					case "finish_unavailable":
						return nil, orchestration.ErrUnavailable
					case "finish_malformed":
						return json.RawMessage(`{"complete":true}`), nil
					default:
						return json.Marshal(map[string]any{"complete": false, "reference": q})
					}
				case singleRecoveryObserveSQL:
					if mode == "untrusted_load" {
						return nil, orchestration.ErrConflict
					}
					observed = args[1].(string)
					if mode == "progress_failure" || mode == "cleanup_progress_failure" {
						return nil, orchestration.ErrUnavailable
					}
					return json.RawMessage(`true`), nil
				default:
					t.Fatal("undeclared SQL")
					return nil, nil
				}
			})
			p := &singleTestRecoveryProduct{database: db, cleanup: recoveryCleanupFunc(func(context.Context, orchestration.CleanupRequest) error {
				cleanupCalls++
				if mode == "cleanup_progress_failure" {
					return orchestration.ErrConflict
				}
				return nil
			})}
			err := p.Step(context.Background(), q)
			wantErr, wantReason := orchestration.ErrConflict, "evidence_conflict"
			if mode == "finish_pending" {
				wantErr, wantReason = orchestration.ErrCleanupPending, "cleanup_pending"
			}
			if mode == "finish_unavailable" {
				wantErr, wantReason = orchestration.ErrUnavailable, "dependency_unavailable"
			}
			if mode == "untrusted_load" {
				wantReason = ""
				if cleanupCalls != 0 {
					t.Fatal("untrusted cleanup")
				}
			}
			if !errors.Is(err, wantErr) || observed != wantReason {
				t.Fatalf("error=%v progress=%q, want %v/%q", err, observed, wantErr, wantReason)
			}
		})
	}
}

func TestSingleTestRecoveryAvailability(t *testing.T) {
	metadata := migrations.ProductionTemporalSingleRecoveryMetadata()
	for _, mode := range []string{"absent", "valid", "malformed", "source_drift", "source_error", "invalid", "ready_error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			db := singleDeliveryDatabaseFunc(func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				calls++
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 9*time.Second {
					t.Fatal("metadata derivation spent worker database budget")
				}
				if mode == "source_error" && calls == 2 || mode == "ready_error" && calls == 3 {
					return nil, errRuntimeUnavailable
				}
				if mode == "malformed" {
					return json.RawMessage(`null`), nil
				}
				if calls == 1 && mode == "absent" || calls == 2 && mode == "source_drift" || calls == 3 && mode == "invalid" {
					return json.RawMessage(`false`), nil
				}
				if calls == 2 && (!strings.HasPrefix(sql, "SELECT to_jsonb((EXISTS") || len(args) != 1 || args[0] != metadata.ReadyBodyDigest) {
					t.Fatal("source metadata query changed")
				}
				if calls == 3 && (sql != `SELECT to_jsonb(zasp_temporal_single_recovery.ready($1))` || len(args) != 1 || args[0] != metadata.Checksum) {
					t.Fatal("readiness metadata query changed")
				}
				return json.RawMessage(`true`), nil
			})
			available, err := singleRecoveryRuntimeAvailable(context.Background(), db)
			if available != (mode == "valid") || (err == nil) != (mode == "absent" || mode == "valid") {
				t.Fatal("startup admission", available, err)
			}
			if mode == "absent" && calls != 1 || mode == "source_drift" && calls != 2 {
				t.Fatal("invalid source called readiness")
			}
		})
	}

	calls := 0
	db := singleDeliveryDatabaseFunc(func(_ context.Context, _ string, _ ...any) (json.RawMessage, error) {
		calls++
		if calls == 5 {
			return json.RawMessage(`false`), nil
		}
		return json.RawMessage(`true`), nil
	})
	first, firstErr := singleRecoveryRuntimeAvailable(context.Background(), db)
	second, secondErr := singleRecoveryRuntimeAvailable(context.Background(), db)
	if !first || firstErr != nil || second || secondErr == nil || calls != 5 {
		t.Fatalf("database drift was cached: first=%t/%v second=%t/%v calls=%d", first, firstErr, second, secondErr, calls)
	}
}

func TestSingleTestRecoveryAvailabilityHonorsParentContext(t *testing.T) {
	_ = migrations.ProductionTemporalSingleRecoveryMetadata()
	for _, mode := range []string{"canceled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "expired" {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			cancel()
			calls := 0
			db := singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				calls++
				return json.RawMessage(`true`), nil
			})
			if available, err := singleRecoveryRuntimeAvailable(ctx, db); available || err == nil || calls != 0 {
				t.Fatalf("invalid parent reached database: available=%t err=%v calls=%d", available, err, calls)
			}
		})
	}

	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	calls := 0
	db := singleDeliveryDatabaseFunc(func(ctx context.Context, _ string, _ ...any) (json.RawMessage, error) {
		calls++
		deadline, ok := ctx.Deadline()
		parentDeadline, _ := parent.Deadline()
		if !ok || deadline.After(parentDeadline) {
			t.Fatal("caller deadline broadened")
		}
		return json.RawMessage(`true`), nil
	})
	if available, err := singleRecoveryRuntimeAvailable(parent, db); err != nil || !available || calls != 3 {
		t.Fatalf("valid parent refused: available=%t err=%v calls=%d", available, err, calls)
	}
}

// Consumes the actual artifact/command/receipt path. The command boundary emits
// explicitly synthetic receipts; native authority is tested only by the gated
// SQL+Temporal consumer. No forward executor interface is loosened for this test.
func testSingleRecoveryCapturedRunner(t *testing.T) {
	for _, mode := range []string{"complete", "unknown", "wrong_manifest", "wrong_receipt"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			start := workerRecoveryRef().Start
			scope, _ := temporalScope(start)
			step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", start.Ref.RunID+"\x1f0")
			var manifest apiserver.RedTeamArtifactReference
			var x singleTestExecution
			settles, commands := 0, 0
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				var q struct {
					Operation string          `json:"operation"`
					Payload   json.RawMessage `json:"payload"`
				}
				if len(args) != 1 || json.Unmarshal(args[0].(json.RawMessage), &q) != nil {
					t.Fatal("bad captured request")
				}
				if sql == `SELECT zasp_temporal74.test_state($1::jsonb)` {
					return json.Marshal(map[string]any{"run_id": x.parent, "step_id": x.step, "action_key": x.action, "test_run_id": x.child, "effect_key": x.key, "state": "child"})
				}
				if sql != `SELECT zasp_temporal74.test_settle($1::jsonb)` {
					t.Fatal("forward SQL reached", sql)
				}
				if q.Operation == "input" {
					m := manifest
					if mode == "wrong_manifest" {
						m.SHA256 = strings.Repeat("0", 64)
					}
					return json.Marshal(map[string]any{"run_id": x.parent, "step_id": x.step, "test_run_id": x.child, "effect_key": x.key, "generation": 1, "input_manifest": m})
				}
				if q.Operation != "child" {
					t.Fatal("forward operation", q.Operation)
				}
				settles++
				var p struct {
					Manifest apiserver.RedTeamArtifactReference `json:"output_manifest"`
				}
				_ = json.Unmarshal(q.Payload, &p)
				return json.Marshal(map[string]any{"test_run_id": x.child, "state": "complete", "attempt": 1, "effect_key": x.key, "output_manifest": p.Manifest, "snapshot_digest": strings.Repeat("e", 64)})
			})
			var err error
			x, err = singleTestExecutionFor(db, scope, start.Ref.RunID, step, "run_test")
			if err != nil {
				t.Fatal(err)
			}
			store, err := artifactstore.New(&release61ArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			input := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2", RunnerImageDigest: "sha256:" + strings.Repeat("a", 64), OrganizationID: start.Ref.OrganizationID, WorkspaceID: start.Ref.WorkspaceID, EnvironmentID: start.Ref.EnvironmentID, RunID: x.child, DefinitionID: start.Ref.RunID, DefinitionVersion: 1, TargetID: step, TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, InputDigest: start.InputDigest}
			body, _ := json.Marshal(input)
			iid, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", x.parent+"\x1f"+x.step)
			manifest, err = release61PutArtifact(ctx, store, scope, iid, body)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			token := filepath.Join(root, "synthetic-token")
			if os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0400) != nil {
				t.Fatal("fixture file")
			}
			runner := &productionRedTeamRunner{config: productionRedTeamRunnerConfig{RunnerImage: "owned/runner@" + input.RunnerImageDigest, Artifacts: store, TargetTokenFile: token, TargetCAFile: writeRedTeamTestCA(t, root), TempRoot: root, Timeout: time.Second, NodePath: "/synthetic/node", ScriptPath: "/synthetic/runner", TargetEndpoint: "https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/evaluate", Command: redTeamCommandFunc(func(_ context.Context, _ string, args, env []string, _ string) error {
				commands++
				joined := strings.Join(env, "\n")
				if len(args) != 4 || args[1] != "recover-completed" || !strings.Contains(joined, "/v1/effects/completed-receipt") || strings.Contains(joined, "/effects/evaluate") || strings.Contains(joined, "PROMPTFOO") || strings.Contains(joined, "RUN_LEASE") {
					t.Fatal("recovery acquired a send path")
				}
				if mode == "unknown" {
					return errRuntimeUnavailable
				}
				protected := true
				receipt := completedTestReceipt{Organization: input.OrganizationID, Workspace: input.WorkspaceID, Environment: input.EnvironmentID, Parent: x.parent, Run: x.child, Step: x.step, Effect: x.key, Generation: 1, Category: "prompt_injection", InputDigest: input.InputDigest, RequestDigest: completedRequestDigest(input, "prompt_injection"), State: "completed", Attempt: 1, HTTPStatus: 200, Protected: &protected, ResponseDigest: strings.Repeat("b", 64), CredentialDigest: strings.Repeat("c", 64), CompletedAt: "2026-09-25T12:00:00.123456Z", ResolutionDigest: strings.Repeat("d", 64)}
				if mode == "wrong_receipt" {
					receipt.Effect = strings.Repeat("0", 64)
				}
				artifact := completedTestArtifact{Schema: "red-team-completed-receipts-v1", Run: input.RunID, InputDigest: input.InputDigest, Evaluation: expectedRedTeamEvaluationIdentity(input), Receipts: []completedTestReceipt{receipt}, Summary: completedTestSummary{"red-team-completed-evidence-v1", input.RunID, input.InputDigest, "Recover completed categories: prompt_injection", "1 of 1 captured security checks passed; 0 exposed unsafe behavior.", "pass", []string{"prompt_injection: protected"}}}
				raw, _ := json.Marshal(artifact)
				return os.WriteFile(args[3], raw, 0600)
			})}}
			err = runner.recoverCapturedSingleTest(ctx, x)
			if (err == nil) != (mode == "complete") || settles != map[bool]int{true: 1, false: 0}[mode == "complete"] {
				t.Fatal("captured settlement", mode, settles, err)
			}
			if commands != map[bool]int{true: 0, false: 1}[mode == "wrong_manifest"] {
				t.Fatal("command boundary", commands)
			}
		})
	}
}
func TestSingleTestRecoveryRelayContracts(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "accept", true: "not_accepted"}[fail], func(t *testing.T) {
			q := workerRecoveryRef()
			trace := []string{}
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				switch sql {
				case singleRecoveryPendingSQL:
					trace = append(trace, "pending")
					return json.Marshal([]orchestration.SingleTestRecoveryRef{q})
				case singleRecoveryAttemptSQL:
					trace = append(trace, "attempt")
					return json.RawMessage(`true`), nil
				case singleRecoveryAckSQL:
					trace = append(trace, "ack")
					return json.RawMessage(`true`), nil
				default:
					t.Fatal(sql)
					return nil, nil
				}
			})
			r := &singleTestRecoveryRelay{database: db, start: func(_ context.Context, got orchestration.SingleTestRecoveryRef) error {
				if got != q {
					t.Fatal(got)
				}
				trace = append(trace, "start")
				if fail {
					return orchestration.ErrUnavailable
				}
				return nil
			}}
			err := r.RunOnce(context.Background())
			want := []string{"pending", "attempt", "start"}
			if !fail {
				want = append(want, "ack")
			}
			if !reflect.DeepEqual(trace, want) || (err != nil) != fail {
				t.Fatal(trace, err)
			}
		})
	}
}
