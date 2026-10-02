package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func riskPolicy(t *testing.T, risk string) Policy {
	t.Helper()
	raw := map[string]any{"id": "policy-risk", "name": "Policy risk", "scope": "environment", "trigger": "tool_call", "action": "block", "rollout": "enforced", "failure_mode": "closed", "conditions": []Condition{{Field: "tool.name", Operator: "equals", Value: "shell"}}}
	if risk != "" {
		raw["risk"] = risk
	}
	b, _ := json.Marshal(raw)
	var value Policy
	if err := json.Unmarshal(b, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPolicyRiskCompiledAndSigned(t *testing.T) {
	legacy, err := Compile(riskPolicy(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	oldDigest := sha256.Sum256([]byte(legacy.Rego))
	if legacy.Digest != hex.EncodeToString(oldDigest[:]) {
		t.Fatal("omitted risk changed legacy digest")
	}
	for _, risk := range []string{"low", "medium", "high", "critical"} {
		t.Run(risk, func(t *testing.T) {
			compiled, err := Compile(riskPolicy(t, risk))
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(compiled)
			var wire map[string]any
			json.Unmarshal(encoded, &wire)
			if wire["risk"] != risk || compiled.Digest == legacy.Digest {
				t.Fatalf("annotation lost or unbound: %s", encoded)
			}
			decision, err := Evaluate(context.Background(), compiled, map[string]string{"tool.name": "shell"})
			if err != nil || !decision.Matched || decision.Action != ActionBlock {
				t.Fatal(decision, err)
			}
			secret := []byte("0123456789abcdef0123456789abcdef")
			bundle, err := SignBundle(secret, "environment-1", []CompiledPolicy{compiled})
			if err != nil || VerifyBundle(secret, bundle) != nil {
				t.Fatal("annotated signed bundle", err)
			}
			wire["risk"] = "low"
			if risk == "low" {
				wire["risk"] = "critical"
			}
			forged, _ := json.Marshal(wire)
			var tampered CompiledPolicy
			json.Unmarshal(forged, &tampered)
			bundle.Policies[0] = tampered
			if VerifyBundle(secret, bundle) == nil {
				t.Fatal("risk tamper retained signature authority")
			}
		})
	}
	t.Run("unknown annotation rejected", func(t *testing.T) {
		value := riskPolicy(t, "")
		value.Risk = "severe"
		if _, err := Compile(value); err == nil {
			t.Fatal("unknown risk compiled")
		}
		if Validate(value, Capabilities{Triggers: []string{"tool_call"}, Fields: []string{"tool.name"}, Actions: []Action{ActionBlock}}) == nil {
			t.Fatal("unknown risk validated")
		}
	})
}
