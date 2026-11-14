package apiserver

import "testing"

// Every red team statement the handlers send is admitted inside an authorized
// request for its own operation, scope, actor and authorized object, and for
// nothing else.
func TestRedTeamStatementsAreAdmittedOnlyForTheirOwnAuthorizedObject(t *testing.T) {
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const definition, run, correlation, other = "pid_95000002-0000-4000-8000-000000000002", "pid_95000003-0000-4000-8000-000000000003", "pid_95000004-0000-4000-8000-000000000004", "pid_95000009-0000-4000-8000-000000000009"
	const key = "idempotency-key-0001"
	for _, c := range []struct {
		operation, query, kind, id string
		args                       []any
		actor, object              int // zero-based argument positions, -1 when absent
	}{
		{"createTest", postgresRedTeamCreateDefinitionSQL, "environment", e, []any{o, w, e, p, key, definition, "Name", other, "agent_endpoint", `["prompt_injection"]`, `{}`, correlation}, 3, -1},
		{"getTest", postgresRedTeamGetDefinitionSQL, "test", definition, []any{o, w, e, definition}, -1, 3},
		{"updateTest", postgresRedTeamUpdateDefinitionSQL, "test", definition, []any{o, w, e, p, key, definition, int64(1), "Name", other, "agent_endpoint", `["prompt_injection"]`, `{}`, true, correlation}, 3, 5},
		{"runTest", postgresRedTeamRunTestSQL, "test", definition, []any{o, w, e, p, key, definition, int64(1), run, correlation}, 3, 5},
		{"getTestRun", postgresRedTeamGetRunSQL, "test_run", run, []any{o, w, e, run}, -1, 3},
		{"cancelTestRun", postgresRedTeamCancelRunSQL, "test_run", run, []any{o, w, e, p, key, run, int64(1), correlation}, 3, 5},
		{"getTestSchedule", postgresRedTeamGetScheduleSQL, "test", definition, []any{o, w, e, definition}, -1, 3},
		{"putTestSchedule", postgresRedTeamPutScheduleSQL, "test", definition, []any{o, w, e, p, definition, int64(0), true, 3600, true}, 3, 4},
	} {
		grant := func() RequestAuthorization {
			return RequestAuthorization{OperationID: c.operation, Identity: i, PathParameters: map[string]string{"id": c.id}, Allowed: []AuthorizationTarget{{Scope: i.Scope, Kind: c.kind, ID: c.id, Version: 1}}}
		}
		arguments := func() []any { return append([]any(nil), c.args...) }
		if !authorizationStatementAllowed(grant(), c.query, arguments()) {
			t.Fatalf("%s: its own statement is refused", c.operation)
		}
		wrongOperation := grant()
		wrongOperation.OperationID = "listTests"
		if authorizationStatementAllowed(wrongOperation, c.query, arguments()) {
			t.Fatalf("%s: admitted for another operation", c.operation)
		}
		unauthorized := grant()
		unauthorized.Allowed = nil
		if authorizationStatementAllowed(unauthorized, c.query, arguments()) {
			t.Fatalf("%s: admitted without an authorized object", c.operation)
		}
		otherScope := arguments()
		otherScope[0] = other
		if authorizationStatementAllowed(grant(), c.query, otherScope) {
			t.Fatalf("%s: admitted for another Organization", c.operation)
		}
		if c.actor >= 0 {
			otherActor := arguments()
			otherActor[c.actor] = other
			if authorizationStatementAllowed(grant(), c.query, otherActor) {
				t.Fatalf("%s: admitted for another principal", c.operation)
			}
		}
		if c.object >= 0 {
			otherObject := arguments()
			otherObject[c.object] = other
			if authorizationStatementAllowed(grant(), c.query, otherObject) {
				t.Fatalf("%s: admitted for an object that was not authorized", c.operation)
			}
		}
		if authorizationStatementAllowed(grant(), c.query, arguments()[:len(c.args)-1]) {
			t.Fatalf("%s: admitted with another argument count", c.operation)
		}
	}
}
