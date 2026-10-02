package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

// The composed flow must not read artifacts for unknown/pending work, invent
// remediation without a baseline, or rebuild a changed proof after a lost ack.
func TestExistingTestReconcilerClassifiesAndSettles(t *testing.T) {
	for _, mode := range []string{"complete", "comparable", "unknown", "failed", "cancelled", "queued", "retryable", "leased_live", "leased_expired", "lost_ack", "heartbeat_failure", "cancel_artifacts", "cancel_settle"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store, driver, r := fixtureExistingTestEvidence(t)
			var beforeEnvelope map[string]any
			if mode == "comparable" {
				_ = json.Unmarshal(fixtureExistingTestSnapshot(t, r), &beforeEnvelope)
				_, afterDriver, afterRequest := fixtureExistingTestEvidence(t, true)
				for locator, object := range afterDriver.objects {
					driver.objects[locator] = object
				}
				r = afterRequest
			}
			now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
			var envelope map[string]any
			_ = json.Unmarshal(fixtureExistingTestSnapshot(t, r), &envelope)
			if mode == "comparable" {
				envelope["snapshot"].(map[string]any)["before"] = beforeEnvelope["snapshot"].(map[string]any)["after"]
			}
			after := envelope["snapshot"].(map[string]any)["after"].(map[string]any)
			state := mode
			switch mode {
			case "unknown", "lost_ack", "heartbeat_failure", "comparable", "cancel_artifacts", "cancel_settle":
				state = "complete"
			case "leased_live", "leased_expired":
				state = "leased"
			}
			after["state"] = state
			if state != "complete" {
				after["verdict"] = nil
				after["input_artifact"] = nil
				after["output_artifact"] = nil
			}
			if mode == "unknown" {
				after["outcome_unknown"] = true
			}
			raw, _ := json.Marshal(envelope)
			wantOutcome, wantReason := "needs_human", "test_condition_persists"
			switch mode {
			case "comparable":
				wantOutcome, wantReason = "remediated", "test_condition_changed"
			case "unknown", "leased_expired", "leased_live":
				wantOutcome, wantReason = "inconclusive", "test_outcome_unknown"
			case "failed":
				wantOutcome, wantReason = "failed", "test_run_failed"
			case "cancelled":
				wantOutcome, wantReason = "cancelled", "test_run_cancelled"
			}
			var events []string
			var submitted []byte
			settles := 0
			db := &reconcileQueryFixture{call: func(callCtx context.Context, q string, args ...any) (json.RawMessage, error) {
				switch {
				case strings.Contains(q, "reconcile_claim("):
					events = append(events, "claim")
					if args[5] != 60 || args[6] != 1 {
						t.Fatal("unbounded claim")
					}
					return json.Marshal([]any{map[string]any{"organization_id": r.Scope.OrganizationID().String(), "workspace_id": r.Scope.WorkspaceID().String(), "environment_id": r.Scope.EnvironmentID().String(), "run_id": snapshotRun, "step_id": snapshotStep, "test_run_id": r.RunID, "generation": snapshotGeneration, "version": 2, "lease_expires_at": "2026-09-17T00:00:30Z"}})
				case strings.Contains(q, "reconcile_heartbeat("):
					events = append(events, "heartbeat")
					if mode == "heartbeat_failure" {
						return nil, errors.New("private failure")
					}
					return json.Marshal(map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "generation": snapshotGeneration, "version": 2, "lease_expires_at": "2026-09-17T00:01:00Z"})
				case strings.Contains(q, "reconcile_cancel_stopped("):
					events = append(events, "stop")
					return json.Marshal(map[string]any{"test_run_id": r.RunID, "state": state, "generation": snapshotGeneration, "cancellation_outcome": nil, "changed": false})
				case strings.Contains(q, "reconcile_evidence("):
					events = append(events, "evidence")
					return raw, nil
				case strings.Contains(q, "reconcile_release("):
					events = append(events, "release")
					return json.Marshal(map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "generation": snapshotGeneration, "version": 3, "state": "pending", "next_check_at": "2026-09-17T00:00:30Z"})
				case strings.Contains(q, "reconcile_settle("):
					events = append(events, "settle")
					settles++
					body := args[10].([]byte)
					if submitted != nil && string(submitted) != string(body) {
						t.Fatal("replay rebuilt proof")
					}
					submitted = append([]byte(nil), body...)
					var proof existingTestVerification
					if json.Unmarshal(body, &proof) != nil || proof.Outcome != wantOutcome || proof.Reason != wantReason {
						t.Fatalf("wrong proof %s", body)
					}
					if mode == "cancel_settle" {
						cancel()
						select {
						case <-callCtx.Done():
						case <-time.After(time.Second):
							t.Fatal("settlement lost cancellation context")
						}
						return nil, callCtx.Err()
					}
					if mode == "leased_live" || mode == "lost_ack" && settles == 1 {
						return nil, errors.New("unavailable")
					}
					step, effect := wantOutcome, "known_failure"
					if wantOutcome == "needs_human" {
						step, effect = "succeeded", "succeeded"
					}
					if wantOutcome == "remediated" {
						step, effect = "succeeded", "verified"
					}
					if wantOutcome == "inconclusive" {
						effect = "unknown_outcome"
					}
					// Independent hash of bytes received at the SQL boundary.
					return settlementTestReceipt(body, snapshotRun, snapshotStep, wantOutcome, step, effect, wantReason)
				default:
					t.Fatalf("unexpected SQL %s", q)
					return nil, nil
				}
			}}
			client, _ := newExistingTestClient(db, "reconcile-loop", func() time.Time { return now })
			var reader existingTestArtifactReader = store
			if mode == "cancel_artifacts" {
				reader = cancellingExistingTestReader{existingTestArtifactReader: store, cancel: cancel, t: t}
			}
			err := client.ReconcileOne(ctx, r.Scope, reader)
			if mode == "cancel_artifacts" || mode == "cancel_settle" {
				want := "claim,heartbeat,stop,evidence"
				reads := 0
				if mode == "cancel_settle" {
					want += ",settle"
					reads = 2
				}
				if err == nil || strings.Join(events, ",") != want || len(driver.reads) != reads {
					t.Fatalf("cancelled work progressed: %v %v reads%d", err, events, len(driver.reads))
				}
				return
			}
			if mode == "heartbeat_failure" {
				if err == nil || strings.Contains(err.Error(), "private") || strings.Join(events, ",") != "claim,heartbeat" {
					t.Fatalf("heartbeat failure leaked/progressed: %v %v", err, events)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := "claim,heartbeat,stop,evidence,settle"
			switch mode {
			case "queued", "retryable":
				want = "claim,heartbeat,stop,evidence,release"
			case "leased_live":
				want = "claim,heartbeat,stop,evidence,settle,settle,release"
			case "lost_ack":
				want += ",settle"
			}
			if strings.Join(events, ",") != want {
				t.Fatalf("flow %v want %s", events, want)
			}
			reads := 0
			if mode == "complete" || mode == "lost_ack" {
				reads = 2
			}
			if mode == "comparable" {
				reads = 4
			}
			if len(driver.reads) != reads {
				t.Fatalf("artifact reads %d want %d", len(driver.reads), reads)
			}
		})
	}
}

type cancellingExistingTestReader struct {
	existingTestArtifactReader
	cancel context.CancelFunc
	t      *testing.T
}

func (r cancellingExistingTestReader) Get(ctx context.Context, _ artifactstore.Locator) (artifactstore.Artifact, error) {
	r.cancel()
	select {
	case <-ctx.Done():
		return artifactstore.Artifact{}, ctx.Err()
	case <-time.After(time.Second):
		r.t.Error("artifact reader lost cancellation context")
		return artifactstore.Artifact{}, errRuntimeUnavailable
	}
}

func settlementTestReceipt(body []byte, run, step, state, stepState, effect, reason string) (json.RawMessage, error) {
	d := sha256.Sum256(body)
	return json.Marshal(map[string]any{"run_id": run, "step_id": step, "state": state, "step_state": stepState, "effect_state": effect, "outcome": state, "reason": reason, "proof_sha256": hex.EncodeToString(d[:]), "generation": snapshotGeneration, "reconcile_version": 3})
}
