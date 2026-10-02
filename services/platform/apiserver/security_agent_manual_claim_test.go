package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// This exercises the actual SQL response reader. Removing the manual binding
// check must admit a mismatched digest; retaining ProductID-only validation
// must refuse the legitimate manual claim.
func TestSecurityAgentManualClaimBoundary(t *testing.T) {
	digest := strings.Repeat("a", 64)
	productID := "pid_78000003-0000-4000-8000-000000000003"
	manual := `{"kind":"manual","intent_digest":"sha256:` + digest + `","version":1}`
	for _, test := range []struct {
		name, trigger, provenance string
		want                      bool
	}{
		{"manual", digest, manual, true},
		{"maximum version", digest, strings.Replace(manual, `"version":1`, `"version":9007199254740991`, 1), true},
		{"legacy", productID, "", true},
		{"missing provenance", digest, "", false},
		{"null provenance", digest, "null", false},
		{"legacy null", productID, "null", false},
		{"mixed identity", productID, manual, false},
		{"mismatched digest", strings.Repeat("b", 64), manual, false},
		{"prefixed trigger", "sha256:" + digest, manual, false},
		{"wrong kind", digest, strings.Replace(manual, "manual", "finding", 1), false},
		{"zero version", digest, strings.Replace(manual, `"version":1`, `"version":0`, 1), false},
		{"unsafe version", digest, strings.Replace(manual, `"version":1`, `"version":9007199254740992`, 1), false},
		{"fractional version", digest, strings.Replace(manual, `"version":1`, `"version":1.5`, 1), false},
		{"null version", digest, strings.Replace(manual, `"version":1`, `"version":null`, 1), false},
		{"uppercase digest", digest, strings.Replace(manual, digest, strings.ToUpper(digest), 1), false},
		{"missing field", digest, strings.Replace(manual, `,"version":1`, "", 1), false},
		{"unknown field", digest, strings.Replace(manual, `"kind":`, `"private":true,"kind":`, 1), false},
		{"duplicate field", digest, strings.Replace(manual, `"kind":`, `"kind":"manual","kind":`, 1), false},
		{"case alias", digest, strings.Replace(manual, `"kind":`, `"Kind":`, 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := `{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","definition_id":"pid_78000002-0000-4000-8000-000000000002","definition_version":3,"trigger_id":"` + test.trigger + `","state":"planning","version":2,"attempt":1,"lease_expires_at":"2026-09-19T12:01:00Z","prepared":false`
			if test.provenance != "" {
				item += `,"manual_trigger":` + test.provenance
			}
			item += `}`
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentClaimRunsV24SQL: json.RawMessage(`{"items":[` + item + `]}`)}}
			repository := &SecurityAgentWorkerRepository{database: database, claimSQL: postgresSecurityAgentClaimRunsV24SQL}
			claims, err := repository.ClaimSecurityAgentRuns(context.Background(), "worker-manual", "lease-token-000000000001", 60, 1)
			if !test.want {
				if err == nil || len(claims) != 0 {
					t.Fatalf("invalid manual authority returned: %#v %v", claims, err)
				}
				return
			}
			if err != nil || len(claims) != 1 || claims[0].TriggerID != test.trigger {
				t.Fatalf("valid claim refused: %#v %v", claims, err)
			}
			encoded, err := json.Marshal(claims[0])
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if string(roundtrip["manual_trigger"]) != test.provenance {
				t.Fatalf("manual provenance lost or invented: %s", encoded)
			}
		})
	}
}
