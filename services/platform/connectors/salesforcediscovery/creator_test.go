package salesforcediscovery

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// An agent carries the user name and the creation time of its record's audit
// fields. A creator the connection may not read (null), or one that is not a
// user name, attributes nothing; the agent is still listed. Every variant of
// the agents query asks for the two fields.
func TestSalesforceAgentsCarryTheCreatorOfTheRecord(t *testing.T) {
	t.Parallel()
	for index, variant := range salesforceAgentQueryVariants {
		if !strings.Contains(variant.soql, "CreatedDate,CreatedBy.Username") {
			t.Fatalf("variant %d does not ask for the creator: %s", index, variant.soql)
		}
	}
	subject := collection.SubjectBinding{Kind: "salesforce_org", ID: "00D5g000004C9ACEA0"}
	records := []json.RawMessage{
		json.RawMessage(salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"CreatedDate":"2026-05-01T10:00:00.000+0000","CreatedBy":{"attributes":{"type":"User","url":"/services/data/v62.0/sobjects/User/0055g00000A1B2CAAV"},"Username":"dana.reyes@example.com"}`)),
		json.RawMessage(salesforceBotRecord(salesforceTestBotTwo, "Sales_Agent", "Sales Agent", `,"CreatedDate":"2026-05-02T10:00:00.000+0000","CreatedBy":null`)),
	}
	entities, _, ok := normalizeSalesforceAgents(subject, salesforceAgentQueryVariants[3], records, salesforceAgentEnrichment{})
	if !ok || len(entities) != 2 {
		t.Fatalf("ok=%t entities=%d", ok, len(entities))
	}
	for _, raw := range entities {
		var entity struct {
			DisplayName string            `json:"display_name"`
			Attributes  map[string]any    `json:"attributes"`
			Stable      map[string]string `json:"stable_fields"`
		}
		if err := json.Unmarshal(raw, &entity); err != nil {
			t.Fatal(err)
		}
		_, attributed := entity.Attributes["created_by"]
		switch entity.DisplayName {
		case "Support Agent":
			if entity.Attributes["created_by"] != "dana.reyes@example.com" || entity.Attributes["created_at"] != "2026-05-01T10:00:00Z" || entity.Attributes["created_by_source"] != "provider_record" {
				t.Fatalf("attributes = %v", entity.Attributes)
			}
		case "Sales Agent":
			if attributed || entity.Attributes["created_at"] != nil || entity.Attributes["created_by_source"] != nil {
				t.Fatalf("an unreadable creator was attributed: %v", entity.Attributes)
			}
		default:
			t.Fatalf("unexpected agent %q", entity.DisplayName)
		}
	}
	for name, createdBy := range map[string]string{"free text": `{"Username":"Dana Reyes"}`, "not an object": `"dana"`, "empty": `{"Username":""}`} {
		if identity, at := salesforceCreator(json.RawMessage(createdBy), nil); identity != "" || at != "" {
			t.Errorf("%s was attributed: %q %q", name, identity, at)
		}
	}
}
