package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// A checked session read must reach the pre-pagination SQL allow-set predicate,
// never a legacy reader followed by page filtering in Go.
func TestP7SessionReadStatements(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	checked := context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{})
	for _, tc := range []struct {
		operation  string
		parameters map[string]string
		want       string
	}{
		{"listSessions", map[string]string{"kind": "console", "limit": "1"}, "SELECT zasp_authorization80.product_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)"},
		{"getSession", map[string]string{"id": "session-console-fixture"}, "SELECT zasp_authorization80.product_session_get($1,$2,$3,$4)"},
		{"listSessionEvents", map[string]string{"id": "session-console-fixture", "limit": "1"}, "SELECT zasp_authorization80.product_session_event_page($1,$2,$3,$4,$5,$6,$7)"},
		{"listSessions", map[string]string{"kind": "runtime", "limit": "1"}, "SELECT zasp_authorization80.runtime_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)"},
		{"getSession", map[string]string{"id": runtimeReadSessionID}, "SELECT zasp_authorization80.runtime_session_get($1,$2,$3,$4,$5)"},
		{"getSession", map[string]string{"id": "unattributed"}, "SELECT zasp_authorization80.runtime_session_get($1,$2,$3,$4,$5)"},
		{"listSessionEvents", map[string]string{"id": runtimeReadSessionID, "limit": "1"}, "SELECT zasp_authorization80.runtime_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)"},
		{"getSessionEvent", map[string]string{"id": runtimeReadSessionID, "eventId": runtimeReadSessionID}, "SELECT zasp_authorization80.runtime_session_event_get($1,$2,$3,$4,$5,$6)"},
	} {
		t.Run(tc.operation+"/"+tc.parameters["kind"]+"/"+tc.parameters["id"], func(t *testing.T) {
			database := &workflowCallDatabase{response: json.RawMessage(`{"items":[]}`)}
			repository, _ := NewPostgresRepository(database)
			_, err := repository.ReadAdministration(checked, identity, tc.operation, tc.parameters)
			if err != nil || database.query != tc.want {
				t.Fatalf("session boundary SQL=%s error=%v; want %s", database.query, err, tc.want)
			}
			expected := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}
			if tc.operation == "listSessionEvents" && tc.parameters["id"] == "session-console-fixture" {
				expected = []any{expected[0], tc.parameters["id"], expected[1], expected[2]}
			}
			if !reflect.DeepEqual(database.args[:len(expected)], expected) {
				t.Fatalf("scope binding=%v want %v", database.args, expected)
			}
		})
	}
}
