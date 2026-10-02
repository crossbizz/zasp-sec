package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityAgentManualPlannerContextBinding(t *testing.T) {
	for _, variant := range []string{"valid", "missing provenance", "null provenance", "wrong digest", "wrong version", "wrong evidence kind", "wrong evidence version", "legacy claim", "alias provenance", "unknown run field"} {
		t.Run(variant, func(t *testing.T) {
			repository, database, claim, _ := exportPlannerRepositoryFixture(t)
			legacyTrigger := claim.TriggerID
			claim.TriggerID = strings.Repeat("a", 64)
			claim.ManualTrigger = &SecurityAgentManualTrigger{Kind: "manual", IntentDigest: "sha256:" + claim.TriggerID, Version: 4}
			var envelope map[string]any
			if json.Unmarshal(database.responses[exportPlannerContextSQLTest], &envelope) != nil {
				t.Fatal("invalid fixture")
			}
			value := envelope["context"].(map[string]any)
			run := value["run"].(map[string]any)
			manual := map[string]any{"kind": "manual", "intent_digest": claim.ManualTrigger.IntentDigest, "version": 4}
			run["manual_trigger"] = manual
			evidence := value["untrusted_evidence"].([]any)[0].(map[string]any)
			evidence["kind"], evidence["id"], evidence["version"] = "manual", claim.TriggerID, 4
			value["export_selection"] = []SecurityAgentExportSelection{{Kind: "manual", ID: claim.TriggerID, Version: 4, AssociationDigest: "sha256:" + strings.Repeat("b", 64)}}
			switch variant {
			case "missing provenance":
				delete(run, "manual_trigger")
			case "null provenance":
				run["manual_trigger"] = nil
			case "wrong digest":
				manual["intent_digest"] = "sha256:" + strings.Repeat("c", 64)
			case "wrong version":
				manual["version"] = 5
			case "wrong evidence kind":
				evidence["kind"] = "finding"
			case "wrong evidence version":
				evidence["version"] = 5
			case "legacy claim":
				claim.TriggerID = legacyTrigger
				claim.ManualTrigger = nil
				evidence["id"] = legacyTrigger
				evidence["kind"] = "finding"
			case "alias provenance":
				delete(run, "manual_trigger")
				run["Manual_trigger"] = manual
			case "unknown run field":
				run["private"] = true
			}
			raw, _ := json.Marshal(envelope)
			database.responses[exportPlannerContextSQLTest] = raw
			loaded, err := repository.LoadSecurityAgentPlannerContext(context.Background(), claim, "worker-1", "worker-lease-00000001")
			if variant != "valid" {
				if err == nil {
					t.Fatal("unbound manual context accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("bound manual context refused: %v", err)
			}
			encoded, _ := json.Marshal(loaded)
			if !strings.Contains(string(encoded), `"ManualTrigger":{"kind":"manual","intent_digest":"sha256:`+strings.Repeat("a", 64)+`","version":4}`) || len(loaded.Evidence) != 1 || loaded.Evidence[0].Kind != "manual" || loaded.Evidence[0].Version != 4 {
				t.Fatalf("manual identity lost: %s", encoded)
			}
		})
	}
}
