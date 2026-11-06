package apiserver

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
)

// Coverage successor: exercises the real repository method and SQL arguments,
// not PostgreSQL/FGA internals or a provider acceptance substitute.
func TestAgentOwnerFilterRepositorySelectedProfileAndRefusal(t *testing.T) {
	scope := inventoryScope(t)
	item := InventorySummary{ID: "pid_10000001-0000-4000-8000-000000000001", Name: "Agent", Kind: InventoryKindAgent, Owner: " Security 😀 ", Team: "platform", Tags: []string{}, EvidenceID: "pid_20000001-0000-4000-8000-000000000001", ConfidenceBasisPoints: 9500, FirstSeen: "2026-08-19T00:00:00Z", LastSeen: "2026-08-19T01:00:00Z", ObservedAt: "2026-08-19T01:00:00Z", FreshUntil: "2026-08-19T01:15:00Z", FreshnessState: "fresh", Version: 1}
	for _, pin := range []string{migrations.AgentOwnerFilterProfileChecksum(), migrations.AgentOwnerFilterAuditProfileChecksum()} {
		raw, _ := json.Marshal(map[string]any{"items": []InventorySummary{item}, "next_id": nil})
		db := &inventoryJSONDatabase{responses: map[string]json.RawMessage{postgresAgentOwnerPageSQL: raw}}
		r := &PostgresInventoryRepository{database: db, agentOwnerProfileChecksum: pin}
		page, err := r.ListAgentOwnerPage(context.Background(), scope, item.Owner, "", 1)
		if err != nil || len(page.Items) != 1 || page.Items[0].Owner != item.Owner {
			t.Fatal("selected real owner repository refused exact literal")
		}
		if db.statement != postgresAgentOwnerPageSQL || len(db.arguments) != 7 || db.arguments[0] != scope.OrganizationID().String() || db.arguments[1] != scope.WorkspaceID().String() || db.arguments[2] != scope.EnvironmentID().String() || db.arguments[5] != item.Owner || db.arguments[6] != pin {
			t.Fatal("owner SQL purpose/scope/literal/pin arguments changed")
		}
		db.statement = ""
		r.agentOwnerProfileChecksum = ""
		if _, err = r.ListAgentOwnerPage(context.Background(), scope, item.Owner, "", 1); err == nil || db.statement != "" {
			t.Fatal("disabled profile reached legacy or filtered SQL")
		}
		r.agentOwnerProfileChecksum = pin
		db.statement = ""
		if _, err = r.ListAgentOwnerPage(context.Background(), scope, strings.Repeat("😀", 129), "", 1); err == nil || db.statement != "" {
			t.Fatal("invalid owner reached SQL")
		}
		raw, _ = json.Marshal(map[string]any{"items": []InventorySummary{item}, "next_id": nil})
		db.responses[postgresAgentOwnerPageSQL] = raw
		if _, err = r.ListAgentOwnerPage(context.Background(), scope, "different-owner", "", 1); err == nil {
			t.Fatal("repository accepted off-filter authoritative response")
		}
	}
	r := &PostgresRepository{currentAuthorization: true}
	if r.RequireAgentOwnerFilterProfile("unknown") == nil {
		t.Fatal("unknown profile mounted")
	}
	if r.RequireAgentOwnerFilterProfile(migrations.AgentOwnerFilterProfileChecksum()) != nil {
		t.Fatal("compiled selected profile refused")
	}
}
