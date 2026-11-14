package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// The activity members of an inventory summary: only an agent has a state,
// "active" needs a time and "unknown" has none.
func TestInventorySummaryActivityMembers(t *testing.T) {
	agent := inventorySummaryJSON("pid_10000001-0000-4000-8000-000000000001", "agent")
	identity := inventorySummaryJSON("pid_10000002-0000-4000-8000-000000000002", "identity")
	unknown := `"last_activity_at":null,"activity_state":"unknown"`
	if !strings.Contains(agent, unknown) || !strings.Contains(identity, `"last_activity_at":null,"activity_state":"not_applicable"`) {
		t.Fatal("the fixtures do not carry the activity members")
	}
	valid := func(raw string, kind InventoryKind) bool {
		t.Helper()
		var item InventorySummary
		if err := decodeStrictInventory(json.RawMessage(raw), &item); err != nil {
			return false
		}
		return validInventorySummary(item, kind)
	}
	seen := `"last_activity_at":"2026-11-01T10:00:00Z",`
	for name, raw := range map[string]string{
		"an agent with no activity source":       agent,
		"an active agent":                        strings.Replace(agent, unknown, seen+`"activity_state":"active"`, 1),
		"an agent last active long ago":          strings.Replace(agent, unknown, seen+`"activity_state":"inactive"`, 1),
		"an agent whose role is reported unused": strings.Replace(agent, unknown, `"last_activity_at":null,"activity_state":"inactive"`, 1),
	} {
		if !valid(raw, InventoryKindAgent) {
			t.Errorf("%s was refused", name)
		}
	}
	if !valid(identity, InventoryKindIdentity) {
		t.Error("an identity was refused")
	}
	for name, raw := range map[string]string{
		"an active agent without a time":  strings.Replace(agent, unknown, `"last_activity_at":null,"activity_state":"active"`, 1),
		"an unknown agent with a time":    strings.Replace(agent, unknown, seen+`"activity_state":"unknown"`, 1),
		"an agent called not applicable":  strings.Replace(agent, unknown, `"last_activity_at":null,"activity_state":"not_applicable"`, 1),
		"an agent without a state":        strings.Replace(agent, unknown, `"last_activity_at":null`, 1),
		"an agent with an unknown state":  strings.Replace(agent, unknown, `"last_activity_at":null,"activity_state":"zombie"`, 1),
		"an agent with a malformed time":  strings.Replace(agent, unknown, `"last_activity_at":"yesterday","activity_state":"inactive"`, 1),
		"an agent with an unknown member": strings.Replace(agent, unknown, unknown+`,"last_invoked_at":null`, 1),
	} {
		if valid(raw, InventoryKindAgent) {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, raw := range map[string]string{
		"an identity called inactive": strings.Replace(identity, `"activity_state":"not_applicable"`, `"activity_state":"inactive"`, 1),
		"an identity with a time":     strings.Replace(identity, `"last_activity_at":null`, `"last_activity_at":"2026-11-01T10:00:00Z"`, 1),
	} {
		if valid(raw, InventoryKindIdentity) {
			t.Errorf("%s was accepted", name)
		}
	}
	// The public summary always carries both members; no time is null.
	var item InventorySummary
	if err := json.Unmarshal([]byte(agent), &item); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(item)
	if !strings.Contains(string(body), unknown) {
		t.Fatalf("public summary = %s", body)
	}
}
