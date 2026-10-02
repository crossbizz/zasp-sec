package policy

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// Missing or unconfigured key IDs must be refused before a caller loads a
// private key. Membership cannot depend on possession of that private key.
func TestGatewayPolicyKeyIDMembershipBeforePrivateKeyAccess(t *testing.T) {
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	configured, err := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		keys GatewayPolicyKeys
		id   string
		want bool
	}{
		{"configured", configured, "gateway-key-1", true},
		{"unknown", configured, "gateway-key-2", false},
		{"empty", configured, "", false},
		{"unconfigured", GatewayPolicyKeys{}, "gateway-key-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup, ok := any(tc.keys).(interface{ HasKeyID(string) bool })
			if !ok {
				t.Fatal("verifier cannot establish key membership before private-key access")
			}
			if got := lookup.HasKeyID(tc.id); got != tc.want {
				t.Fatalf("membership = %t, want %t", got, tc.want)
			}
		})
	}
}

// The pure preflight must catch unsafe authority and malformed compiled policy
// bytes before the caller is allowed to obtain a private key.
func TestGatewayPolicySigningInputPreflight(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	compiled, err := Compile(Policy{ID: "policy-1", Trigger: "tool_call", Action: ActionBlock, Conditions: []Condition{{Field: "tool.name", Operator: "present"}}})
	if err != nil {
		t.Fatal(err)
	}
	valid := GatewayPolicySigningInput{KeyID: "gateway-key-1", Binding: gatewayFixtureBinding(), Sequence: 7, PolicyVersion: 3, Now: now, IssuedAt: now, ExpiresAt: now.Add(time.Minute), FailureMode: "closed", Policies: []CompiledPolicy{compiled}}
	for _, name := range []string{"policy", "cleanup", "key", "binding", "sequence", "version", "clock", "future", "expired", "ttl", "mode", "digest", "rego", "duplicate", "count"} {
		t.Run(name, func(t *testing.T) {
			input := valid
			input.Policies = append([]CompiledPolicy(nil), valid.Policies...)
			switch name {
			case "cleanup":
				input.Policies = []CompiledPolicy{}
			case "key":
				input.KeyID = "invalid"
			case "binding":
				input.Binding.DeviceID = input.Binding.OrganizationID
			case "sequence":
				input.Sequence = 0
			case "version":
				input.PolicyVersion = 0
			case "clock":
				input.Now = now.Add(time.Nanosecond)
			case "future":
				input.IssuedAt = now.Add(time.Minute)
			case "expired":
				input.ExpiresAt = now
			case "ttl":
				input.ExpiresAt = now.Add(24*time.Hour + time.Second)
			case "mode":
				input.FailureMode = "ignore"
			case "digest":
				input.Policies[0].Digest = "00"
			case "rego":
				input.Policies[0].Rego += "\nallow := true"
			case "duplicate":
				input.Policies = append(input.Policies, compiled)
			case "count":
				input.Policies = make([]CompiledPolicy, 101)
			}
			wantValid := name == "policy" || name == "cleanup"
			if got := ValidateGatewayPolicySigningInput(input) == nil; got != wantValid {
				t.Fatalf("preflight valid=%t, want %t", got, wantValid)
			}
		})
	}
}
