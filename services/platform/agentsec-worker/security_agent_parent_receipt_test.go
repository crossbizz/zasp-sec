package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// These controls catch omitted receipt bindings or acceptance of a terminal
// state whose step/effect accounting does not match. No database is simulated.
func TestCapturedParentReceiptBindings(t *testing.T) {
	x := singleTestExecution{scope: fixtureRedTeamScope(t), parent: snapshotRun, step: snapshotStep, key: strings.Repeat("a", 64)}
	invocation, err := apiserver.CanonicalDiscoveryID(x.scope, "security_agent_temporal_test_invocation", x.key)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("{}")
	const digest = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	for _, tc := range []struct {
		state, step, effect, outcome string
		unknown                      bool
	}{
		{"remediated", "succeeded", "verified", "remediated", false},
		{"needs_human", "succeeded", "succeeded", "needs_human", false},
		{"inconclusive", "inconclusive", "succeeded", "inconclusive", false},
		{"failed", "failed", "known_failure", "failed", false},
		{"cancelled", "cancelled", "known_failure", "cancelled", false},
		{"inconclusive", "inconclusive", "unknown_outcome", "inconclusive", true},
		{"cancelled", "cancelled", "known_failure", "remediated", false},
		{"failed", "failed", "known_failure", "needs_human", false},
		{"needs_human", "succeeded", "succeeded", "remediated", false},
	} {
		t.Run(tc.state+"/"+tc.effect+"/"+tc.outcome, func(t *testing.T) {
			proof := existingTestVerification{Outcome: tc.outcome, Reason: "captured_test_result"}
			base := map[string]any{"run_id": x.parent, "step_id": x.step, "state": tc.state, "step_state": tc.step, "effect_state": tc.effect, "outcome": proof.Outcome, "reason": proof.Reason, "proof_sha256": digest, "reconcile_version": 2, "effect_key": x.key, "invocation_id": invocation}
			raw, err := json.Marshal(base)
			if err != nil || !validCapturedParentReceipt(raw, x, proof, body, tc.unknown) {
				t.Fatal("valid native receipt rejected", err)
			}
			for _, field := range []string{"run_id", "step_id", "state", "step_state", "effect_state", "outcome", "reason", "proof_sha256", "reconcile_version", "effect_key", "invocation_id"} {
				for _, kind := range []string{"changed", "missing", "null"} {
					t.Run(field+"/"+kind, func(t *testing.T) {
						bad := make(map[string]any, len(base))
						for k, v := range base {
							bad[k] = v
						}
						switch kind {
						case "missing":
							delete(bad, field)
						case "null":
							bad[field] = nil
						case "changed":
							bad[field] = "foreign"
							if field == "reconcile_version" {
								bad[field] = 1
							}
						}
						b, err := json.Marshal(bad)
						if err != nil {
							t.Fatal(err)
						}
						if validCapturedParentReceipt(b, x, proof, body, tc.unknown) {
							t.Fatal("changed receipt accepted")
						}
					})
				}
			}
			for field, values := range map[string][]string{
				"step_state":   {"succeeded", "cancelled", "failed", "inconclusive"},
				"effect_state": {"verified", "succeeded", "known_failure", "unknown_outcome"},
			} {
				for _, value := range values {
					if base[field] == value {
						continue
					}
					bad := make(map[string]any, len(base))
					for k, v := range base {
						bad[k] = v
					}
					bad[field] = value
					b, err := json.Marshal(bad)
					if err != nil {
						t.Fatal(err)
					}
					if validCapturedParentReceipt(b, x, proof, body, tc.unknown) {
						t.Fatal("valid enum with wrong accounting accepted", field, value)
					}
				}
			}
			for name, bad := range map[string][]byte{
				"extra":     append([]byte(`{"unexpected":true,`), raw[1:]...),
				"duplicate": append([]byte(`{"run_id":"`+x.parent+`",`), raw[1:]...),
				"trailing":  append(append([]byte{}, raw...), []byte(`{}`)...),
				"oversized": append(append([]byte{}, raw...), []byte(strings.Repeat(" ", 16385))...),
				"null":      []byte("null"),
			} {
				t.Run(name, func(t *testing.T) {
					if validCapturedParentReceipt(bad, x, proof, body, tc.unknown) {
						t.Fatal("non-closed receipt accepted")
					}
				})
			}
			if validCapturedParentReceipt(raw, x, proof, []byte("{ }"), tc.unknown) {
				t.Fatal("different proof bytes accepted")
			}
			if validCapturedParentReceipt(raw, x, proof, body, !tc.unknown) {
				t.Fatal("different unknown-debt state accepted")
			}
		})
	}
}
