package idpdiscovery

import (
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// A user carries the email address and department of its profile, so that
// the creator of an agent can be matched to a person and that person's team.
// A login that is an address stands in for a missing email; a value that is
// not an address is left out; no other profile attribute is kept.
func TestOktaUsersCarryEmailAndDepartment(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	objects := []json.RawMessage{
		json.RawMessage(`{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"dana","displayName":"Dana Reyes","email":"Dana.Reyes@Example.com","department":"Customer Platform","mobilePhone":"never-recorded-phone","managerId":"never-recorded-manager"}}`),
		json.RawMessage(`{"id":"00u1234567890ABCDE2","status":"ACTIVE","profile":{"login":"eli@example.com","displayName":"Eli Okafor"}}`),
		json.RawMessage(`{"id":"00u1234567890ABCDE3","status":"SUSPENDED","profile":{"login":"svc-backup","displayName":"Backup","email":"not an address","department":" padded "}}`),
	}
	entities, _, ok := normalizeOktaCollectionPage(subject, "users", false, objects)
	if !ok || len(entities) != 3 {
		t.Fatalf("ok=%t entities=%d", ok, len(entities))
	}
	want := map[string]string{
		"Dana Reyes": `{"department":"Customer Platform","email":"dana.reyes@example.com","status":"ACTIVE"}`,
		"Eli Okafor": `{"email":"eli@example.com","status":"ACTIVE"}`,
		"Backup":     `{"status":"SUSPENDED"}`,
	}
	for _, raw := range entities {
		var entity struct {
			Kind        string          `json:"kind"`
			DisplayName string          `json:"display_name"`
			Attributes  json.RawMessage `json:"attributes"`
		}
		if json.Unmarshal(raw, &entity) != nil || entity.Kind != "okta_user" {
			t.Fatalf("entity = %s", raw)
		}
		if string(entity.Attributes) != want[entity.DisplayName] {
			t.Fatalf("%s attributes = %s, want %s", entity.DisplayName, entity.Attributes, want[entity.DisplayName])
		}
	}
}
