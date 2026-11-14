package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// A relationship names the two objects it joins when the caller may read
// them: what the agent detail needs to list the identities an agent uses.
func TestInventoryRelationshipsCarryNamedEnds(t *testing.T) {
	agentID := "pid_10000001-0000-4000-8000-000000000001"
	roleID := "pid_10000002-0000-4000-8000-000000000002"
	hiddenID := "pid_10000003-0000-4000-8000-000000000003"
	agentEnd := `"from":{"name":"Support agent","kind":"agent","provider":"aws","source_kind":"aws_bedrock_agent"}`
	roleEnd := `"to":{"name":"support-agent-role","kind":"identity","provider":"aws","source_kind":"aws_role"}`
	named := `{"id":"pid_50000001-0000-4000-8000-000000000001","from_id":"` + agentID + `","to_id":"` + roleID + `","type":"uses_identity","evidence_id":"pid_20000001-0000-4000-8000-000000000001",` + agentEnd + `,` + roleEnd + `}`
	// The caller may not read the second identity: the identifier only.
	unnamed := `{"id":"pid_50000002-0000-4000-8000-000000000002","from_id":"` + agentID + `","to_id":"` + hiddenID + `","type":"uses_identity","evidence_id":"pid_20000001-0000-4000-8000-000000000001",` + agentEnd + `}`
	database := &inventoryJSONDatabase{schema: TypedInventorySchemaVersion, responses: map[string]json.RawMessage{
		postgresInventoryReadinessSQL:     json.RawMessage(`true`),
		postgresInventoryRelationshipsSQL: json.RawMessage(`{"items":[` + named + `,` + unnamed + `],"next_key":null}`),
	}}
	repository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := domain.ParseProductID(agentID)
	page, err := repository.ListAgentRelationshipsPage(context.Background(), inventoryScope(t), id, "", 100)
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("relationships = %#v / %v", page, err)
	}
	first, second := page.Items[0], page.Items[1]
	if first.To == nil || *first.To != (RelationshipEnd{Name: "support-agent-role", Kind: InventoryKindIdentity, Provider: "aws", SourceKind: "aws_role"}) || first.From == nil || first.From.Kind != InventoryKindAgent {
		t.Fatalf("named relationship = %#v", first)
	}
	if second.To != nil || second.ToID != hiddenID {
		t.Fatalf("unreadable end = %#v", second)
	}
	// The public relationship omits an end that was not resolved.
	body, _ := json.Marshal(second)
	if strings.Contains(string(body), `"to":`) || !strings.Contains(string(body), `"from":{"name":"Support agent"`) {
		t.Fatalf("public relationship = %s", body)
	}
	for name, raw := range map[string]string{
		"an end without a name":              strings.Replace(named, `"name":"support-agent-role"`, `"name":""`, 1),
		"an end of an unknown kind":          strings.Replace(named, `"kind":"identity"`, `"kind":"credential"`, 1),
		"an end of an unknown provider":      strings.Replace(named, `"provider":"aws","source_kind":"aws_role"`, `"provider":"gcp","source_kind":"aws_role"`, 1),
		"an end with a malformed source":     strings.Replace(named, `"source_kind":"aws_role"`, `"source_kind":"AWS Role"`, 1),
		"an end with an unknown member":      strings.Replace(named, `"source_kind":"aws_role"`, `"source_kind":"aws_role","arn":"arn:aws:iam::123456789012:role/x"`, 1),
		"the page's agent named as identity": strings.Replace(named, `"kind":"agent"`, `"kind":"identity"`, 1),
	} {
		if raw == named {
			t.Fatalf("%s: the fixture did not change", name)
		}
		database.responses[postgresInventoryRelationshipsSQL] = json.RawMessage(`{"items":[` + raw + `],"next_key":null}`)
		if _, err := repository.ListAgentRelationshipsPage(context.Background(), inventoryScope(t), id, "", 100); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Errorf("%s was accepted: %v", name, err)
		}
	}
}
