package sessionsearch

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
)

func searchScope(t *testing.T) domain.Scope {
	t.Helper()
	org, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(org, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestStructuredSessionQueryBindsEverySelectorToOneTenantEvent(t *testing.T) {
	scope := searchScope(t)
	input := Filters{AgentID: scope.OrganizationID().String(), PrincipalID: scope.WorkspaceID().String(), Tool: "shell", Process: "/usr/bin/agent", File: "/etc/shadow", Domain: "API.EXAMPLE.COM", Credential: scope.EnvironmentID().String(), Resource: "tcp://10.0.0.9:443", Decision: "block", From: time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 9, 11, 0, 0, 0, time.UTC)}
	body, err := BuildQuery(scope, input, "unattributed", 26)
	if err != nil {
		t.Fatal(err)
	}
	var query struct {
		Size  int `json:"size"`
		Query struct {
			Bool struct {
				Filter []map[string]map[string]json.RawMessage `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
		Aggregations struct {
			Sessions struct {
				Composite struct {
					Size  int               `json:"size"`
					After map[string]string `json:"after"`
				} `json:"composite"`
			} `json:"sessions"`
		} `json:"aggs"`
	}
	if json.Unmarshal(body, &query) != nil || query.Size != 0 || query.Aggregations.Sessions.Composite.Size != 26 || query.Aggregations.Sessions.Composite.After["investigation_id"] != "unattributed" {
		t.Fatalf("invalid query envelope: %s", body)
	}
	terms := map[string]string{}
	for _, clause := range query.Query.Bool.Filter {
		for key, value := range clause["term"] {
			var decoded string
			if json.Unmarshal(value, &decoded) != nil {
				t.Fatal("non-exact term")
			}
			terms[key] = decoded
		}
	}
	want := map[string]string{"record_type": "runtime_session_event", "organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "agent_id": input.AgentID, "observed_principal_id": input.PrincipalID, "tool_id": "shell", "credential_id": input.Credential, "decision": "block"}
	for field, value := range map[string]string{"process": input.Process, "file": input.File, "domain": input.Domain, "resource": input.Resource} {
		digest, err := runtimemetadata.DigestSelector(field, value)
		if err != nil {
			t.Fatal(err)
		}
		want[field+"_digest"] = digest
	}
	if len(terms) != len(want) {
		t.Fatalf("terms=%v", terms)
	}
	for field, value := range want {
		if terms[field] != value {
			t.Fatalf("%s not exact: %q", field, terms[field])
		}
	}
	if len(query.Query.Bool.Filter) != 14 || !bytes.Contains(body, []byte(`"gte":"2026-09-09T10:00:00.000Z"`)) || !bytes.Contains(body, []byte(`"lte":"2026-09-09T11:00:00.000Z"`)) {
		t.Fatalf("missing canonical time filter: %s", body)
	}
	for _, raw := range []string{input.Process, input.File, input.Domain, input.Resource} {
		if bytes.Contains(body, []byte(raw)) {
			t.Fatalf("raw provider content retained in query: %s", raw)
		}
	}
}

func TestStructuredSessionQueryRejectsDSLAndInvalidBoundaries(t *testing.T) {
	scope := searchScope(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	for _, input := range []Filters{
		{RawQuery: "*:*"}, {RawQuery: `{"match_all":{}}`}, {AgentID: "agent-demo"}, {PrincipalID: "principal-demo"},
		{Credential: "provider-secret"}, {Tool: strings.Repeat("a", 257)}, {File: "/tmp/file\n"}, {Domain: "*.example.com"},
		{Decision: "permit"}, {From: now, To: now.Add(-time.Hour)}, {From: now.In(time.FixedZone("offset", 3600))},
	} {
		if _, err := BuildQuery(scope, input, "", 26); !errors.Is(err, ErrQuery) {
			t.Fatalf("invalid filters admitted: %#v (%v)", input, err)
		}
	}
	for _, cursor := range []string{"session-console", "*:*", strings.Repeat("a", 129)} {
		if _, err := BuildQuery(scope, Filters{}, cursor, 26); !errors.Is(err, ErrQuery) {
			t.Fatal("invalid cursor admitted")
		}
	}
	for _, limit := range []int{-1, 0, 102} {
		if _, err := BuildQuery(scope, Filters{}, "", limit); !errors.Is(err, ErrQuery) {
			t.Fatal("unbounded query admitted")
		}
	}
	if _, err := BuildQuery(domain.Scope{}, Filters{}, "", 26); !errors.Is(err, ErrQuery) {
		t.Fatal("unscoped query admitted")
	}
}

func TestSessionQueryTimeBoundsDoNotIncludeEventsBeforeSubmillisecondLowerBound(t *testing.T) {
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	body, err := BuildQuery(searchScope(t), Filters{From: now.Add(time.Nanosecond), To: now.Add(time.Millisecond + time.Nanosecond)}, "", 25)
	if err != nil || !bytes.Contains(body, []byte(`"gte":"2026-09-09T10:00:00.001Z"`)) || !bytes.Contains(body, []byte(`"lte":"2026-09-09T10:00:00.001Z"`)) {
		t.Fatalf("millisecond index broadened precise range: %s %v", body, err)
	}
}
