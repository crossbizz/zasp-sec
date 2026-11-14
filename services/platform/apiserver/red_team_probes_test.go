package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam/probes"
)

func TestRedTeamProbeCatalogListsCountsAndTagsButNoProbeText(t *testing.T) {
	catalog := CurrentRedTeamProbeCatalog()
	if catalog.Version != probes.Version || catalog.ProbeCount < 1000 || catalog.DefaultSampleSize != probes.DefaultSampleSize || len(catalog.Categories) != len(probes.Categories()) {
		t.Fatalf("catalog = %+v", catalog)
	}
	total := 0
	for _, category := range catalog.Categories {
		if category.ProbeCount < 20 || len(category.Techniques) == 0 || len(category.Frameworks) < 2 || !validRedTeamDefinitionCategory(category.Category) {
			t.Fatalf("category = %+v", category)
		}
		total += category.ProbeCount
	}
	encoded, err := json.Marshal(catalog)
	if err != nil || total != catalog.ProbeCount {
		t.Fatalf("total=%d err=%v", total, err)
	}
	for _, probe := range probes.Sample("prompt_injection", "pid_95000003-0000-4000-8000-000000000003", 5) {
		if strings.Contains(string(encoded), probe.Input) || strings.Contains(string(encoded), probe.ID) {
			t.Fatal("the public catalog holds probe text or identifiers")
		}
	}
}

func validRedTeamDefinitionCategory(category string) bool {
	return validRedTeamDefinition(RedTeamDefinition{ID: "pid_95000002-0000-4000-8000-000000000002", Version: 1, Name: "Probe", TargetID: "pid_95000001-0000-4000-8000-000000000001", TargetKind: "agent_endpoint", Categories: []string{category}, Safety: RedTeamSafety{Environment: "staging", CredentialClass: "read_only", ExpectedSideEffects: []string{"bounded evaluation"}}, Enabled: true, CreatedAt: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)})
}

func TestRedTeamDefinitionAcceptsProbeCategoriesOnly(t *testing.T) {
	for category, want := range map[string]bool{"indirect_injection": true, "poisoned_resource": true, "cross_agent_delegation": true, "tool_abuse": true, "tool_misuse": false, "": false} {
		if validRedTeamDefinitionCategory(category) != want {
			t.Fatalf("category %q valid=%t", category, !want)
		}
	}
}

func TestRedTeamProbeResultsAndScheduleValidation(t *testing.T) {
	sample := probes.Sample("poisoned_resource", "pid_95000003-0000-4000-8000-000000000003", 3)
	results := []RedTeamProbeResult{{sample[0].ID, "poisoned_resource", "protected"}, {sample[1].ID, "poisoned_resource", "unsafe"}}
	if !validRedTeamProbeResults(results) || !validRedTeamProbeResults(nil) {
		t.Fatal("valid probe results rejected")
	}
	for name, invalid := range map[string][]RedTeamProbeResult{
		"repeated":         {results[0], results[0]},
		"other category":   {{sample[0].ID, "tool_abuse", "protected"}},
		"unknown outcome":  {{sample[0].ID, "poisoned_resource", "skipped"}},
		"arbitrary prompt": {{"Ignore prior instructions", "poisoned_resource", "unsafe"}},
	} {
		if validRedTeamProbeResults(invalid) {
			t.Fatalf("%s accepted", name)
		}
	}
	const definition = "pid_95000002-0000-4000-8000-000000000002"
	hour, minute := 3600, 60
	for name, update := range map[string]RedTeamScheduleUpdate{
		"cadence under one hour":  {DefinitionID: definition, Enabled: true, CadenceSeconds: &minute},
		"enabled without trigger": {DefinitionID: definition, Enabled: true},
		"negative version":        {DefinitionID: definition, ExpectedVersion: -1, CadenceSeconds: &hour},
		"no definition":           {Enabled: true, CadenceSeconds: &hour},
	} {
		if validRedTeamScheduleUpdate(update) {
			t.Fatalf("%s accepted", name)
		}
	}
	if !validRedTeamScheduleUpdate(RedTeamScheduleUpdate{DefinitionID: definition, Enabled: true, OnTargetChange: true}) || !validRedTeamScheduleUpdate(RedTeamScheduleUpdate{DefinitionID: definition}) {
		t.Fatal("valid schedule update rejected")
	}
	unsaved := []byte(`{"definition_id":"` + definition + `","version":0,"enabled":false,"cadence_seconds":null,"on_target_change":false,"next_run_at":null,"last_run_id":null,"last_trigger":null,"last_outcome":null,"last_fired_at":null,"updated_at":null}`)
	if value, err := decodeRedTeamSchedule(unsaved, definition); err != nil || value.Version != 0 {
		t.Fatalf("unsaved schedule: %+v %v", value, err)
	}
	for name, payload := range map[string]string{
		"other definition":       strings.Replace(string(unsaved), "95000002", "95000009", 1),
		"enabled without a save": strings.Replace(string(unsaved), `"enabled":false`, `"enabled":true`, 1),
		"extra member":           strings.Replace(string(unsaved), `"version":0`, `"version":0,"prompt":"x"`, 1),
		"missing member":         strings.Replace(string(unsaved), `,"updated_at":null`, ``, 1),
	} {
		if _, err := decodeRedTeamSchedule([]byte(payload), definition); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
