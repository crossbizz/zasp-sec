package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

func checkedSessionSearchContext(identity RequestIdentity) context.Context {
	return context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{
		OperationID: "listSessions", Collection: true, Identity: identity,
		Allowed: []AuthorizationTarget{{Scope: identity.Scope, Kind: "session", ID: runtimeReadSessionID, SourceID: runtimeReadSessionID}},
	})
}

// A checked request must not call legacy role-based admission, even for v1.
func TestP7SessionSearchCheckedStatements(t *testing.T) {
	for _, sandbox := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1", true: "sandbox50"}[sandbox], func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			status := json.RawMessage(`{"visibility":"resource_only"}`)
			database := &sessionQueryDatabase{responses: []json.RawMessage{status, sessionQueryPageFixture(t, status, sessionQuerySummaryFixture(t, identity, runtimeReadSessionID))}}
			prefix := "runtime_session_query"
			offset := 0
			if sandbox {
				prefix = "runtime_sandbox_query"
				offset = 1
				database.responses = append([]json.RawMessage{json.RawMessage("true")}, database.responses...)
			}
			index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}, After: runtimeReadSessionID}}
			repository := &PostgresRepository{database: database, runtimeSessionSearch: index, currentAuthorization: true, sandboxSessionSearch: sandbox}
			body, err := repository.ReadAdministration(checkedSessionSearchContext(identity), identity, "listSessions", map[string]string{"kind": "runtime", "limit": "1"})
			if err != nil || len(body) == 0 {
				t.Fatalf("checked read failed: %v", err)
			}
			if len(database.calls) != offset+2 || database.calls[offset] != "SELECT zasp_authorization80."+prefix+"_status($1,$2,$3,$4)" || database.calls[offset+1] != "SELECT zasp_authorization80."+prefix+"_hydrate($1,$2,$3,$4,$5)" {
				t.Fatalf("checked statements=%v", database.calls)
			}
			if sandbox && database.calls[0] != "SELECT to_jsonb(zasp_authorization80.session_source_readiness(50,$1,$2))" {
				t.Fatalf("legacy sandbox readiness=%s", database.calls[0])
			}
			if !index.filters.AuthorizationRestricted || len(index.filters.AllowedInvestigationIDs) != 1 || index.filters.AllowedInvestigationIDs[0] != runtimeReadSessionID {
				t.Fatalf("index missing exact restriction: %+v", index.filters)
			}
		})
	}
}

// An arbitrary provider implementation must not bypass the checked allow set.
func TestP7SessionSearchRejectsForeignProviderResults(t *testing.T) {
	const foreign = "pid_97000002-0000-4000-8000-000000000002"
	for _, tc := range []struct {
		name  string
		ids   []string
		after string
	}{
		{"foreign bucket", []string{foreign}, foreign},
		{"foreign after", []string{runtimeReadSessionID}, foreign},
		{"unattributed not explicitly allowed", []string{"unattributed"}, "unattributed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			status := json.RawMessage(`{"visibility":"resource_only"}`)
			database := &sessionQueryDatabase{responses: []json.RawMessage{status, sessionQueryPageFixture(t, status)}}
			index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: tc.ids, After: tc.after}}
			repository := &PostgresRepository{database: database, runtimeSessionSearch: index, currentAuthorization: true}
			body, err := repository.ReadAdministration(checkedSessionSearchContext(identity), identity, "listSessions", map[string]string{"kind": "runtime", "limit": "1"})
			if !errors.Is(err, ErrRepositoryUnavailable) || body != nil || len(database.calls) != 1 {
				t.Fatalf("foreign result reached hydration: body=%s err=%v calls=%v", body, err, database.calls)
			}
		})
	}
}

func TestP7SessionSearchResourceOnlyOmitsScopeBacklog(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "resource", true: "empty"}[empty], func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			status := json.RawMessage(`{"visibility":"resource_only"}`)
			c := checkedSessionSearchContext(identity)
			ids := []string{runtimeReadSessionID}
			items := []json.RawMessage{sessionQuerySummaryFixture(t, identity, runtimeReadSessionID)}
			after := runtimeReadSessionID
			if empty {
				grant, _ := requestAuthorizationFromContext(c)
				grant.Allowed = nil
				c = context.WithValue(c, requestAuthorizationContextKey{}, grant)
				ids = []string{}
				items = nil
				after = ""
			}
			database := &sessionQueryDatabase{responses: []json.RawMessage{status, sessionQueryPageFixture(t, status, items...)}}
			index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: ids, After: after}}
			repository := &PostgresRepository{database: database, runtimeSessionSearch: index, currentAuthorization: true}
			body, err := repository.ReadAdministration(c, identity, "listSessions", map[string]string{"kind": "runtime", "limit": "1"})
			var result map[string]json.RawMessage
			if err != nil || json.Unmarshal(body, &result) != nil {
				t.Fatalf("resource query: %s %v", body, err)
			}
			if _, exposed := result["search"]; exposed {
				t.Fatalf("resource-only backlog disclosed: %s", body)
			}
			var got []json.RawMessage
			if json.Unmarshal(result["items"], &got) != nil || len(got) != len(ids) {
				t.Fatalf("restricted items changed: %s", body)
			}
		})
	}
}

func TestP7SessionSearchRevisionConflictRequiresFreshCheck(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &sessionQueryDatabase{responses: []json.RawMessage{json.RawMessage(`{"visibility":"resource_only"}`)}, errors: []error{nil, ErrRepositoryConflict}}
	index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}, After: runtimeReadSessionID}}
	repository := &PostgresRepository{database: database, runtimeSessionSearch: index, currentAuthorization: true}
	body, err := repository.ReadAdministration(checkedSessionSearchContext(identity), identity, "listSessions", map[string]string{"kind": "runtime", "limit": "1"})
	if body != nil || !errors.Is(err, ErrRepositoryConflict) || index.calls != 1 || len(database.calls) != 2 {
		t.Fatalf("stale proof retry or hidden conflict: body=%s err=%v calls=%v", body, err, database.calls)
	}
}

func TestP7SessionSearchEnvironmentViewPreservesBacklog(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	status := sessionQueryStatusFixture(t)
	c := checkedSessionSearchContext(identity)
	grant, _ := requestAuthorizationFromContext(c)
	grant.EnvironmentView = true
	c = context.WithValue(c, requestAuthorizationContextKey{}, grant)
	expected := sessionQueryPageFixture(t, status, sessionQuerySummaryFixture(t, identity, runtimeReadSessionID))
	database := &sessionQueryDatabase{responses: []json.RawMessage{status, expected}}
	index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{runtimeReadSessionID}, After: runtimeReadSessionID}}
	repository := &PostgresRepository{database: database, runtimeSessionSearch: index, currentAuthorization: true}
	body, err := repository.ReadAdministration(c, identity, "listSessions", map[string]string{"kind": "runtime", "limit": "1"})
	if err != nil || string(body) != string(expected) {
		t.Fatalf("environment-view status changed: %s %v", body, err)
	}
}
