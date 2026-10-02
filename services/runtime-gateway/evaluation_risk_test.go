package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestEvaluationRiskResolvedContributors(t *testing.T) {
	for _, tc := range []struct {
		name             string
		actions, risks   []string
		decision, risk   string
		contributors     []string
		expired, noMatch bool
	}{
		{name: "losing unknown monitor", actions: []string{"monitor", "block"}, risks: []string{"", "high"}, decision: "block", risk: "high", contributors: []string{"policy-b"}},
		{name: "unknown winning block", actions: []string{"block", "block"}, risks: []string{"high", ""}, decision: "block", contributors: []string{"policy-a", "policy-b"}},
		{name: "maximum complete winning set", actions: []string{"block", "block"}, risks: []string{"low", "critical"}, decision: "block", risk: "critical", contributors: []string{"policy-a", "policy-b"}},
		{name: "monitor wins", actions: []string{"monitor"}, risks: []string{"medium"}, decision: "monitor", risk: "medium", contributors: []string{"policy-a"}},
		{name: "no matching policy", actions: []string{"block"}, risks: []string{"critical"}, decision: "allow", contributors: []string{}, noMatch: true},
		{name: "expired fail closed", actions: []string{"block"}, risks: []string{"critical"}, decision: "block", contributors: []string{}, expired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, private, _ := ed25519.GenerateKey(rand.Reader)
			now := gatewayRuntimeTime()
			authority := gatewayRuntimeAuthority()
			var compiled []policy.CompiledPolicy
			for i, action := range tc.actions {
				value := map[string]any{"id": "policy-" + string(rune('a'+i)), "trigger": "tool_call", "action": action, "conditions": []policy.Condition{{Field: "tool.name", Operator: "equals", Value: "shell"}}}
				if tc.risks[i] != "" {
					value["risk"] = tc.risks[i]
				}
				raw, _ := json.Marshal(value)
				var p policy.Policy
				json.Unmarshal(raw, &p)
				c, err := policy.Compile(p)
				if err != nil {
					t.Fatal(err)
				}
				compiled = append(compiled, c)
			}
			envelope := signedGatewayRuntimePolicies(t, private, authority, now, "closed", compiled)
			control := &gatewayControlStub{authority: authority, envelope: &envelope}
			keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
			cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "evidence")
			store, err := newGatewayEvidenceDiskStore(path, authority, 8, 16<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { store.Close() }()
			config := gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: store, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }}
			runtime, err := newGatewayRuntime(config)
			if err != nil || runtime.SyncOnce(context.Background()) != nil {
				t.Fatal("runtime setup", err)
			}
			if tc.expired {
				now = now.Add(2 * time.Hour)
			}
			classification := gatewayRuntimeClassification("requested")
			classification["session_id"] = gatewayRuntimeSequenceID(41)
			attributes := map[string]string{"tool.name": "shell", "action": "tool_execute", "agent_id": gatewayRuntimeSequenceID(40), "session_id": classification["session_id"]}
			if tc.noMatch {
				attributes["tool.name"] = "read"
			}
			request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: attributes, Classification: classification}
			result, err := runtime.Evaluate(context.Background(), request)
			if err != nil || result.Decision != tc.decision {
				t.Fatal("decision changed", result, err)
			}
			raw, _ := json.Marshal(result)
			var got struct {
				Evaluation *struct {
					Version      int      `json:"version"`
					Action       string   `json:"action"`
					AgentID      string   `json:"agent_id"`
					SessionID    string   `json:"session_id"`
					Risk         string   `json:"risk"`
					Contributors []string `json:"contributing_policy_ids"`
				} `json:"evaluation"`
			}
			if json.Unmarshal(raw, &got) != nil || got.Evaluation == nil {
				t.Fatalf("evaluated provenance absent: %s", raw)
			}
			if got.Evaluation.Version != 1 || got.Evaluation.Action != "tool_execute" || got.Evaluation.AgentID != attributes["agent_id"] || got.Evaluation.SessionID != attributes["session_id"] || got.Evaluation.Risk != tc.risk || !reflect.DeepEqual(got.Evaluation.Contributors, tc.contributors) {
				t.Fatalf("resolved provenance=%s want risk=%s contributors=%v", raw, tc.risk, tc.contributors)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = newGatewayEvidenceDiskStore(path, authority, 8, 16<<20)
			if err != nil {
				t.Fatal(err)
			}
			config.Evidence = store
			restarted, err := newGatewayRuntime(config)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := restarted.Evaluate(context.Background(), request)
			if err != nil || !reflect.DeepEqual(replayed, result) {
				t.Fatal("restart lost exact evaluation", replayed, err)
			}
			if restarted.RecordOnce(context.Background()) != nil || len(control.events) != 1 {
				t.Fatal("event not delivered")
			}
			if control.events[0].Classification["outcome"] != "requested" {
				t.Fatal("request classification rewritten")
			}
			wire, _ := json.Marshal(gatewayDecisionEventToWire(control.events[0]))
			var event struct {
				Evaluation json.RawMessage `json:"evaluation"`
			}
			json.Unmarshal(wire, &event)
			var resultObject struct {
				Evaluation json.RawMessage `json:"evaluation"`
			}
			json.Unmarshal(raw, &resultObject)
			if string(event.Evaluation) != string(resultObject.Evaluation) {
				t.Fatalf("delivery lost provenance: %s", wire)
			}
		})
	}
}
