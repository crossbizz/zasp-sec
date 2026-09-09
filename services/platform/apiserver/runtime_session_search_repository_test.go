package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
	"reflect"
	"strings"
	"testing"
	"time"
)

type sessionQueryDatabase struct {
	workflowCallDatabase
	calls     []string
	arguments [][]any
	responses []json.RawMessage
	errors    []error
}

func (d *sessionQueryDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	n := len(d.calls)
	d.calls = append(d.calls, statement)
	d.arguments = append(d.arguments, append([]any(nil), args...))
	if n < len(d.errors) && d.errors[n] != nil {
		return nil, d.errors[n]
	}
	if n >= len(d.responses) {
		return nil, ErrRepositoryUnavailable
	}
	return d.responses[n], nil
}

type sessionQueryIndex struct {
	calls    int
	scope    domain.Scope
	filters  sessionsearch.Filters
	after    string
	limit    int
	page     searchdriver.SessionSearchPage
	err      error
	onSearch func()
}

func (i *sessionQueryIndex) Search(_ context.Context, scope domain.Scope, filters sessionsearch.Filters, after string, limit int) (searchdriver.SessionSearchPage, error) {
	i.calls++
	i.scope, i.filters, i.after, i.limit = scope, filters, after, limit
	if i.onSearch != nil {
		i.onSearch()
	}
	return i.page, i.err
}
func sessionQueryStatusFixture(t *testing.T) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{"state": "catching_up", "pending_batches": 1, "pending_batches_capped": false, "quarantined_batches": 0, "quarantined_batches_capped": false, "last_indexed_at": nil, "oldest_pending_at": time.Now().Add(-time.Minute).UTC(), "checked_at": time.Now().UTC(), "selector_coverage": "observed_only"})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func sessionQuerySummaryFixture(t *testing.T, identity RequestIdentity, id string) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{"kind": "runtime", "id": id, "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "agent_id": nil, "principal_id": nil, "first_event_at": "2026-09-09T10:00:01Z", "last_event_at": "2026-09-09T10:00:03Z", "projected_at": "2026-09-09T10:00:04Z", "event_count": 2, "confidence_counts": map[string]int{"exact": 1, "strong": 1, "probable": 0, "unattributed": 0}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func sessionQueryPageFixture(t *testing.T, status json.RawMessage, items ...json.RawMessage) json.RawMessage {
	t.Helper()
	if items == nil {
		items = []json.RawMessage{}
	}
	body, err := json.Marshal(map[string]any{"items": items, "search": status})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRuntimeSessionSearchRepositoryAuthorizesBeforeSearchAndHydratesAfter(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	status := sessionQueryStatusFixture(t)
	database := &sessionQueryDatabase{responses: []json.RawMessage{status, sessionQueryPageFixture(t, status, sessionQuerySummaryFixture(t, identity, runtimeReadSessionID))}}
	index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}, After: runtimeReadSessionID}}
	repository, err := NewPostgresRepositoryWithRuntimeSessionSearch(database, index)
	if err != nil {
		t.Fatal(err)
	}
	index.onSearch = func() {
		if len(database.calls) != 1 || database.calls[0] != postgresRuntimeSessionQueryStatusSQL {
			t.Fatal("search preceded current database authorization")
		}
	}
	parameters := map[string]string{"kind": "runtime", "limit": "25", "agent_id": identity.PrincipalID.String(), "principal_id": identity.PrincipalID.String(), "tool": "read_file", "process": "/bin/agent", "file": "/data/report", "domain": "api.example.com", "credential_id": identity.PrincipalID.String(), "resource": "https://api.example.com/data", "decision": "allow", "from": "2026-09-09T10:00:00Z", "to": "2026-09-09T11:00:00Z"}
	payload, err := repository.ReadAdministration(context.Background(), identity, "listSessions", parameters)
	if err != nil || index.calls != 1 || index.scope != identity.Scope || index.limit != 26 || index.filters.Process != "/bin/agent" || index.filters.PrincipalID != identity.PrincipalID.String() || index.filters.Credential != identity.PrincipalID.String() || index.filters.RawQuery != "" || len(database.calls) != 2 || database.calls[1] != postgresRuntimeSessionQueryHydrateSQL {
		t.Fatalf("closed search composition failed: calls=%v err=%v", database.calls, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
	for _, args := range database.arguments {
		if !reflect.DeepEqual(args[:4], want) {
			t.Fatal("query omitted current scope/principal")
		}
	}
	if !reflect.DeepEqual(database.arguments[1][4], []string{runtimeReadSessionID}) || !strings.Contains(string(payload), `"event_count":2`) {
		t.Fatal("search counts replaced canonical summary")
	}
}

func TestRuntimeSessionSearchRepositoryWithoutIndexRejectsSearchSelectors(t *testing.T) {
	for _, selector := range []string{"tool", "process", "file", "domain", "credential_id", "resource", "decision", "query", "dsl"} {
		t.Run(selector, func(t *testing.T) {
			database := &sessionQueryDatabase{responses: []json.RawMessage{json.RawMessage(`{"items":[]}`)}}
			repository, err := NewPostgresRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			_, err = repository.ReadAdministration(context.Background(), fixtureRequestIdentity(t), "listSessions", map[string]string{"kind": "runtime", "limit": "25", selector: "unsupported"})
			if !errors.Is(err, ErrRepositoryOperation) || len(database.calls) != 0 {
				t.Fatalf("fallback ignored %s: err=%v calls=%d", selector, err, len(database.calls))
			}
		})
	}
}

func TestRuntimeSessionSearchRepositoryRejectsUnsafeFiltersBeforeIO(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, bad := range []map[string]string{{"query": "*"}, {"dsl": "{}"}, {"principal_id": "not-a-product"}, {"process": "\n/bin/agent"}, {"limit": "101"}, {"limit": "01"}, {"from": "yesterday"}, {"from": "2026-09-09T10:00:00+00:00"}, {"from": "2026-09-09T11:00:00Z", "to": "2026-09-09T10:00:00Z"}, {"after_id": "bad"}, {"after_parent_id": runtimeReadSessionID}} {
		database, index := &sessionQueryDatabase{}, &sessionQueryIndex{}
		repository, err := NewPostgresRepositoryWithRuntimeSessionSearch(database, index)
		if err != nil {
			t.Fatal(err)
		}
		parameters := map[string]string{"kind": "runtime", "limit": "25"}
		for k, v := range bad {
			parameters[k] = v
		}
		if _, err := repository.ReadAdministration(context.Background(), identity, "listSessions", parameters); !errors.Is(err, ErrRepositoryOperation) || index.calls != 0 || len(database.calls) != 0 {
			t.Fatalf("unsafe filter reached IO: %v err=%v", bad, err)
		}
	}
	if _, err := NewPostgresRepositoryWithRuntimeSessionSearch(&sessionQueryDatabase{}, (*sessionQueryIndex)(nil)); err == nil {
		t.Fatal("typed nil search accepted")
	}
}

func TestRuntimeSessionSearchRepositoryNeverReturnsUnauthorizedOrUncertainEmptyResults(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, test := range []struct {
		name                      string
		preErr, postErr, indexErr error
		empty, panicIndex         bool
	}{
		{name: "preflight denied", preErr: ErrRepositoryNotFound},
		{name: "revoked during search", postErr: ErrRepositoryNotFound},
		{name: "empty still reauthorizes", empty: true, postErr: ErrRepositoryNotFound},
		{name: "search unavailable", indexErr: errors.New("provider detail")},
		{name: "search panic", panicIndex: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := sessionQueryStatusFixture(t)
			database := &sessionQueryDatabase{responses: []json.RawMessage{status, sessionQueryPageFixture(t, status)}, errors: []error{test.preErr, test.postErr}}
			index := &sessionQueryIndex{err: test.indexErr, page: searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}, After: runtimeReadSessionID}}
			if test.empty {
				index.page = searchdriver.SessionSearchPage{InvestigationIDs: []string{}}
			}
			if test.panicIndex {
				index.onSearch = func() { panic("secret provider detail") }
			}
			repository, _ := NewPostgresRepositoryWithRuntimeSessionSearch(database, index)
			payload, err := repository.ReadAdministration(context.Background(), identity, "listSessions", map[string]string{"kind": "runtime", "limit": "25"})
			if err == nil || len(payload) > 0 || strings.Contains(err.Error(), "provider detail") {
				t.Fatalf("uncertain/unauthorized search returned result: %s err=%v", payload, err)
			}
			if test.preErr != nil && index.calls != 0 {
				t.Fatal("unauthorized search touched index")
			}
			if test.empty && len(database.calls) != 2 {
				t.Fatal("empty search skipped current authorization")
			}
		})
	}
}

func TestRuntimeSessionSearchRepositoryValidatesCanonicalHydration(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, fault := range []string{"missing", "foreign workspace", "wrong ID", "count drift", "null items", "null capped flag", "null confidence", "unknown status", "false current", "stale status", "capped count"} {
		t.Run(fault, func(t *testing.T) {
			status := sessionQueryStatusFixture(t)
			summary := sessionQuerySummaryFixture(t, identity, runtimeReadSessionID)
			page := sessionQueryPageFixture(t, status, summary)
			switch fault {
			case "null capped flag":
				page = json.RawMessage(strings.Replace(string(page), `"pending_batches_capped":false`, `"pending_batches_capped":null`, 1))
			case "null confidence":
				page = json.RawMessage(strings.Replace(string(page), `"probable":0`, `"probable":null`, 1))
			case "missing":
				page = sessionQueryPageFixture(t, status)
			case "foreign workspace":
				page = json.RawMessage(strings.Replace(string(page), identity.Scope.WorkspaceID().String(), "pid_99000002-0000-4000-8000-000000000002", 1))
			case "wrong ID":
				page = json.RawMessage(strings.Replace(string(page), runtimeReadSessionID, "pid_99000001-0000-4000-8000-000000000001", 1))
			case "count drift":
				page = json.RawMessage(strings.Replace(string(page), `"event_count":2`, `"event_count":3`, 1))
			case "null items":
				page = json.RawMessage(`{"items":null,"search":` + string(status) + `}`)
			case "unknown status":
				page = json.RawMessage(strings.Replace(string(page), `"state":"catching_up"`, `"state":"fresh"`, 1))
			case "false current":
				page = json.RawMessage(strings.Replace(string(page), `"state":"catching_up"`, `"state":"current"`, 1))
			case "stale status":
				var v map[string]any
				json.Unmarshal(status, &v)
				v["checked_at"] = "2020-01-01T00:00:00Z"
				status, _ = json.Marshal(v)
				page = sessionQueryPageFixture(t, status, summary)
			case "capped count":
				page = json.RawMessage(strings.Replace(string(page), `"pending_batches_capped":false`, `"pending_batches_capped":true`, 1))
			}
			database := &sessionQueryDatabase{responses: []json.RawMessage{sessionQueryStatusFixture(t), page}}
			index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}, After: runtimeReadSessionID}}
			repository, _ := NewPostgresRepositoryWithRuntimeSessionSearch(database, index)
			if payload, err := repository.ReadAdministration(context.Background(), identity, "listSessions", map[string]string{"kind": "runtime", "limit": "25"}); err == nil || len(payload) > 0 {
				t.Fatalf("accepted %s hydration", fault)
			}
		})
	}
}

func TestRuntimeSessionSearchRepositoryRejectsMalformedCandidatePages(t *testing.T) {
	for _, test := range []struct {
		name  string
		page  searchdriver.SessionSearchPage
		after string
	}{
		{"null IDs", searchdriver.SessionSearchPage{}, ""},
		{"empty with cursor", searchdriver.SessionSearchPage{InvestigationIDs: []string{}, After: runtimeReadSessionID}, ""},
		{"missing cursor", searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}}, ""},
		{"duplicate", searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID, runtimeReadSessionID}, After: runtimeReadSessionID}, ""},
		{"out of order", searchdriver.SessionSearchPage{InvestigationIDs: []string{"unattributed", runtimeReadSessionID}, After: "unattributed"}, ""},
		{"invalid ID", searchdriver.SessionSearchPage{InvestigationIDs: []string{"secret"}, After: "secret"}, ""},
		{"cursor not advanced", searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}, After: runtimeReadSessionID}, runtimeReadSessionID},
		{"oversized", searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID, runtimeReadSessionID, "unattributed"}, After: "unattributed"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &sessionQueryDatabase{responses: []json.RawMessage{sessionQueryStatusFixture(t)}}
			repository, _ := NewPostgresRepositoryWithRuntimeSessionSearch(database, &sessionQueryIndex{page: test.page})
			result, err := repository.ReadAdministration(context.Background(), fixtureRequestIdentity(t), "listSessions", map[string]string{"kind": "runtime", "limit": "1", "after_id": test.after})
			if !errors.Is(err, ErrRepositoryUnavailable) || len(result) > 0 || len(database.calls) != 1 {
				t.Fatalf("malformed candidate page reached hydration: err=%v calls=%d", err, len(database.calls))
			}
		})
	}
}

func TestRuntimeSessionSearchRepositoryReturnsAuthorizedEmptyMatchesWithStatus(t *testing.T) {
	status := sessionQueryStatusFixture(t)
	expected := sessionQueryPageFixture(t, status)
	database := &sessionQueryDatabase{responses: []json.RawMessage{status, expected}}
	repository, _ := NewPostgresRepositoryWithRuntimeSessionSearch(database, &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{}}})
	result, err := repository.ReadAdministration(context.Background(), fixtureRequestIdentity(t), "listSessions", map[string]string{"kind": "runtime", "limit": "1"})
	if err != nil || !reflect.DeepEqual(result, expected) || len(database.calls) != 2 {
		t.Fatalf("authorized empty search lost checkpoint: %s %v", result, err)
	}
}
