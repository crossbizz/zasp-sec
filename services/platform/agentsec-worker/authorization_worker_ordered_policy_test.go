package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// A named authorization profile must never fetch legacy private material,
// including when the new composition is incomplete or authorization fails.
func TestOrderedPolicyNamedProfileNeverLoadsLegacySigner(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		calls := 0
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, ed25519.SeedSize))
		keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": private.Public().(ed25519.PublicKey)})
		if err != nil {
			t.Fatal(err)
		}
		p := &temporalSecurityAgentProduct{workerForward: &authorization.WorkerExecutor{}, workerCompensation: &authorization.WorkerExecutor{},
			orderedPolicyKeyID: "gateway-key-1", orderedPolicyKeys: keys,
			orderedPolicySigner: func(context.Context, policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
				calls++
				return policy.GatewayPolicyEnvelope{}, errRuntimeUnavailable
			},
			executor: singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				t.Fatal("named profile reached raw database")
				return nil, nil
			}),
			compensation: singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				t.Fatal("named compensation reached raw database")
				return nil, nil
			}),
			signing: func() (string, ed25519.PrivateKey, policy.GatewayPolicyKeys, error) {
				calls++
				return "", nil, policy.GatewayPolicyKeys{}, errRuntimeUnavailable
			}}
		if err := p.policy(context.Background(), workerPlanningStartFixture(), "pid_99200005-0000-4000-8000-000000000005", cleanup, temporalProductState{}); err == nil {
			t.Fatal("incomplete named profile accepted")
		}
		if calls != 0 {
			t.Fatal("named profile loaded legacy private material")
		}
	}
}

// These choices protect the grant boundary, not SQL formatting: a read/ack
// must not borrow forward effect authority and apply must not enter cleanup.
func TestOrderedPolicyDatabaseClosedRoutes(t *testing.T) {
	start := workerPlanningStartFixture()
	step := "pid_99200005-0000-4000-8000-000000000005"
	for _, tc := range []struct {
		family, operation, phase, want string
		cleanup, captured              bool
	}{
		{"effect", "reserve", "", "ordered68.effect.reserve", false, false},
		{"effect", "start", "", "ordered68.effect.start", false, false},
		{"application", "read", "", "ordered68.application.read", false, false},
		{"application", "complete", "", "ordered68.application.complete", false, false},
		{"cleanup", "prepare", "", "ordered68.cleanup.prepare", true, true},
		{"cleanup", "read", "", "ordered68.cleanup.read", true, true},
		{"cleanup", "complete", "", "ordered68.cleanup.complete", true, true},
		{"delivery", "prepare", "apply", "ordered68.delivery.apply.prepare", false, false},
		{"delivery", "read", "apply", "ordered68.delivery.apply.read", false, true},
		{"delivery", "ack", "apply", "ordered68.delivery.apply.ack", false, true},
		{"delivery", "prepare", "cleanup", "ordered68.delivery.cleanup.prepare", true, true},
		{"delivery", "read", "cleanup", "ordered68.delivery.cleanup.read", true, true},
		{"delivery", "ack", "cleanup", "ordered68.delivery.cleanup.ack", true, true},
	} {
		t.Run(tc.want, func(t *testing.T) {
			d := &workerOrderedPolicyDatabase{start: start, step: step, cleanup: tc.cleanup}
			payload := map[string]any{}
			if tc.phase != "" {
				payload["device_id"] = "pid_99200006-0000-4000-8000-000000000006"
				payload["phase"] = tc.phase
			}
			if tc.operation == "read" && tc.phase != "" || tc.operation == "ack" {
				payload["digest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			fields := temporalEffectFields(start, step, tc.operation, payload)
			raw, _ := json.Marshal(fields)
			statement := "SELECT zasp_temporal68." + tc.family + "($1::jsonb)"
			op, captured, err := d.route(statement, raw)
			if err != nil || string(op) != tc.want || captured != tc.captured {
				t.Fatal("wrong operation authority", op, captured, err)
			}
			for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation"} {
				bad := map[string]any{}
				for k, v := range fields {
					bad[k] = v
				}
				bad[field] = "foreign"
				changed, _ := json.Marshal(bad)
				if _, _, err := d.route(statement, changed); err == nil {
					t.Fatal("foreign immutable identity accepted", field)
				}
			}
			if _, _, err := d.route(statement, append([]byte(`{"operation":"ignored",`), raw[1:]...)); err == nil {
				t.Fatal("duplicate operation accepted")
			}
			if _, _, err := d.route("SELECT arbitrary($1::jsonb)", raw); err == nil {
				t.Fatal("arbitrary SQL accepted")
			}
			if tc.phase != "" {
				d.cleanup = !d.cleanup
				if _, _, err := d.route(statement, raw); err == nil {
					t.Fatal("foreign delivery phase accepted")
				}
				d.cleanup = !d.cleanup
			}
			fields["operation"] = "store"
			bad, _ := json.Marshal(fields)
			if _, _, err := d.route(statement, bad); err == nil {
				t.Fatal("signing bypass accepted")
			}
		})
	}
}

func TestOrderedPolicyCompletionRequiresForwardAndClosedPayload(t *testing.T) {
	d := &workerOrderedPolicyDatabase{start: workerPlanningStartFixture(), step: "pid_99200005-0000-4000-8000-000000000005"}
	raw, _ := json.Marshal(temporalEffectFields(d.start, d.step, "complete", map[string]any{}))
	if op, captured, err := d.route(`SELECT zasp_temporal68.application($1::jsonb)`, raw); err != nil || captured || op != "ordered68.application.complete" {
		t.Fatal("completion missing current forward authority", op, captured, err)
	}
	for _, payload := range []any{nil, []any{}, map[string]any{"receipt": "forged"}, map[string]any{"operation": "read"}} {
		bad, _ := json.Marshal(temporalEffectFields(d.start, d.step, "complete", payload))
		if _, _, err := d.route(`SELECT zasp_temporal68.application($1::jsonb)`, bad); err == nil {
			t.Fatal("extended completion payload accepted", payload)
		}
	}
	d.cleanup = true
	if _, _, err := d.route(`SELECT zasp_temporal68.application($1::jsonb)`, raw); err == nil {
		t.Fatal("cleanup authority accepted for application completion")
	}
	d.cleanup = false
	d.compensation = &authorization.WorkerExecutor{}
	if _, err := d.QueryJSON(context.Background(), `SELECT zasp_temporal68.application($1::jsonb)`, raw); err == nil {
		t.Fatal("completion without forward executor bypassed authorization")
	}
	if err := d.Exec(context.Background(), "SELECT anything"); err == nil {
		t.Fatal("generic Exec bypass")
	}
	if _, err := d.SchemaVersion(context.Background()); err == nil {
		t.Fatal("generic repository bypass")
	}
}
