package apiserver

import (
	"encoding/json"
	"testing"
	"time"
)

// Every Security Agent write statement is admitted only for its own
// operation, scope, actor, credential kind, path object and allowed target.
func TestSecurityAgentWriteStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Microsecond)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const agent, other = "pid_20000001-0000-4000-8000-000000000001", "pid_20000002-0000-4000-8000-000000000002"
	const audit, correlation, receipt, run, trigger = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003", "pid_30000004-0000-4000-8000-000000000004", "pid_30000005-0000-4000-8000-000000000005"
	const key = "idempotency-key-0001"
	environment := AuthorizationTarget{Scope: i.Scope, Kind: "environment", ID: e, Version: 1}
	object := AuthorizationTarget{Scope: i.Scope, Kind: "security_agent", ID: agent, Version: 3}
	admission := func(mutate func(map[string]any)) json.RawMessage {
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": p, "definition_id": agent, "definition_version": 3, "idempotency_key": key, "run_id": run, "trigger_kind": "finding", "trigger_id": trigger, "trigger_version": 1, "trigger_source": "credential", "audit_id": audit, "correlation_id": correlation, "receipt_id": receipt}
		if mutate != nil {
			mutate(q)
		}
		raw, _ := json.Marshal(q)
		return raw
	}
	type contract struct {
		name, query, operation string
		args                   func() []any
		allowed                AuthorizationTarget
		path                   string
		scope, actor           int // Zero-based positions; actor -1 when the statement takes none.
		browserOnly            bool
		object                 int // Zero-based position of the path object, -1 when absent.
	}
	contracts := []contract{
		{"value", currentSecurityAgentDefinitionValueSQL, "getSecurityAgent", func() []any { return []any{o, w, e, agent} }, object, agent, 0, -1, false, 3},
		{"activation", currentSecurityAgentActivationSQL, "getSecurityAgentActivation", func() []any { return []any{o, w, e, agent, p} }, object, agent, 0, 4, false, 3},
		{"replay-create", currentSecurityAgentDefinitionReplaySQL, "createSecurityAgent", func() []any {
			return []any{o, w, e, p, "createSecurityAgent", key, json.RawMessage(`{"resource_id":"","expected_version":0,"body":{}}`)}
		}, environment, "", 0, 3, false, -1},
		{"replay-update", currentSecurityAgentDefinitionReplaySQL, "updateSecurityAgent", func() []any {
			return []any{o, w, e, p, "updateSecurityAgent", key, json.RawMessage(`{"resource_id":"` + agent + `","expected_version":3,"body":{}}`)}
		}, object, agent, 0, 3, false, -1},
		{"create", currentSecurityAgentDefinitionMutateSQL, "createSecurityAgent", func() []any {
			return []any{"create", agent, o, w, e, p, "createSecurityAgent", key, int64(0), json.RawMessage(`{}`), json.RawMessage(`{}`), audit, correlation, receipt}
		}, environment, "", 2, 5, false, -1},
		{"update", currentSecurityAgentDefinitionMutateSQL, "updateSecurityAgent", func() []any {
			return []any{"update", agent, o, w, e, p, "updateSecurityAgent", key, int64(3), json.RawMessage(`{}`), json.RawMessage(`{}`), audit, correlation, receipt}
		}, object, agent, 2, 5, false, 1},
		{"delete", currentSecurityAgentDefinitionMutateSQL, "deleteSecurityAgent", func() []any {
			return []any{"delete", agent, o, w, e, p, "deleteSecurityAgent", key, int64(3), json.RawMessage(`{}`), json.RawMessage(`{}`), audit, correlation, receipt}
		}, object, agent, 2, 5, false, 1},
		{"activate", currentSecurityAgentActivateSQL, "activateSecurityAgent", func() []any {
			return []any{o, w, e, agent, p, key, int64(3), "supervised", i.FreshAuthExpiresAt, audit, correlation, receipt}
		}, object, agent, 0, 4, true, 3},
		{"run", currentSecurityAgentRunSQL, "runSecurityAgent", func() []any { return []any{o, w, e, agent, p, admission(nil)} }, object, agent, 0, 4, false, 3},
		{"control", currentSecurityAgentSetExecutionControlSQL, "setSecurityAgentExecutionControl", func() []any {
			return []any{o, w, e, p, key, "action", "update_finding_response", true, int64(0), i.FreshAuthExpiresAt, audit, correlation, receipt}
		}, environment, "", 0, 3, true, -1},
	}
	operations := []string{"getSecurityAgent", "getSecurityAgentActivation", "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "activateSecurityAgent", "runSecurityAgent", "setSecurityAgentExecutionControl", "listSecurityAgents", "decideSecurityAgentApproval", "createIntegration"}
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			grant := func() RequestAuthorization {
				g := RequestAuthorization{OperationID: c.operation, Identity: i, Allowed: []AuthorizationTarget{c.allowed}}
				if c.path != "" {
					g.PathParameters = map[string]string{"id": c.path}
				}
				return g
			}
			if handled, allowed := securityAgentWriteStatementAllowed(grant(), c.query, c.args()); !handled || !allowed {
				t.Fatalf("own contract handled=%v allowed=%v", handled, allowed)
			}
			if !authorizationStatementAllowed(grant(), c.query, c.args()) {
				t.Fatal("statement allowlist refused the contract")
			}
			for _, operation := range operations {
				if operation == c.operation || c.query == currentSecurityAgentDefinitionValueSQL && stringIn(operation, "updateSecurityAgent", "deleteSecurityAgent") {
					continue
				}
				g := grant()
				g.OperationID = operation
				if authorizationStatementAllowed(g, c.query, c.args()) {
					t.Fatalf("operation %s borrowed the %s statement", operation, c.name)
				}
			}
			g := grant()
			g.Collection = true
			if authorizationStatementAllowed(g, c.query, c.args()) {
				t.Fatal("a collection request was admitted")
			}
			for n, name := range []string{"organization", "workspace", "environment"} {
				args := c.args()
				args[c.scope+n] = p
				if authorizationStatementAllowed(grant(), c.query, args) {
					t.Fatalf("another %s was admitted", name)
				}
			}
			if authorizationStatementAllowed(grant(), c.query, append(c.args(), "extra")) || authorizationStatementAllowed(grant(), c.query, c.args()[:len(c.args())-1]) {
				t.Fatal("argument count was not bound")
			}
			if c.actor >= 0 {
				args := c.args()
				args[c.actor] = o
				if authorizationStatementAllowed(grant(), c.query, args) {
					t.Fatal("another principal was admitted")
				}
			}
			g = grant()
			g.Allowed = nil
			if authorizationStatementAllowed(g, c.query, c.args()) {
				t.Fatal("statement admitted without its checked target")
			}
			g = grant()
			g.Allowed[0].Kind = "finding"
			if authorizationStatementAllowed(g, c.query, c.args()) {
				t.Fatal("a target of another kind was admitted")
			}
			if c.object >= 0 {
				args := c.args()
				args[c.object] = other
				if authorizationStatementAllowed(grant(), c.query, args) {
					t.Fatal("an object other than the path object was admitted")
				}
				g = grant()
				g.PathParameters = map[string]string{"id": other}
				if authorizationStatementAllowed(g, c.query, c.args()) {
					t.Fatal("a request for another path object was admitted")
				}
			}
			g = grant()
			g.Identity.CredentialKind = CredentialBearerToken
			args := c.args()
			if c.query == currentSecurityAgentDefinitionMutateSQL {
				args[13] = "" // An API token carries no mutation receipt.
			}
			if got := authorizationStatementAllowed(g, c.query, args); got == c.browserOnly {
				t.Fatalf("API token admitted=%v for browserOnly=%v", got, c.browserOnly)
			}
			if c.browserOnly {
				g = grant()
				g.Identity.FreshAuthenticated = false
				if authorizationStatementAllowed(g, c.query, c.args()) {
					t.Fatal("admitted without fresh authentication")
				}
				args = c.args()
				args[map[string]int{currentSecurityAgentActivateSQL: 8, currentSecurityAgentSetExecutionControlSQL: 9}[c.query]] = i.FreshAuthExpiresAt.Add(time.Second)
				if authorizationStatementAllowed(grant(), c.query, args) {
					t.Fatal("another fresh authentication instant was admitted")
				}
			}
		})
	}

	object.ID = agent
	base := RequestAuthorization{OperationID: "runSecurityAgent", Identity: i, Allowed: []AuthorizationTarget{object}, PathParameters: map[string]string{"id": agent}}
	for name, mutate := range map[string]func(map[string]any){
		"another organization": func(q map[string]any) { q["organization_id"] = p },
		"another environment":  func(q map[string]any) { q["environment_id"] = p },
		"another actor":        func(q map[string]any) { q["actor_id"] = o },
		"another definition":   func(q map[string]any) { q["definition_id"] = other },
		"unknown field":        func(q map[string]any) { q["operation"] = "trigger" },
		"manual trigger":       func(q map[string]any) { q["trigger_kind"] = "manual" },
		"half a source":        func(q map[string]any) { delete(q, "trigger_source") },
		"zero version":         func(q map[string]any) { q["definition_version"] = 0 },
	} {
		if authorizationStatementAllowed(base, currentSecurityAgentRunSQL, []any{o, w, e, agent, p, admission(mutate)}) {
			t.Fatalf("run admission admitted %s", name)
		}
	}
	if !authorizationStatementAllowed(base, currentSecurityAgentRunSQL, []any{o, w, e, agent, p, admission(func(q map[string]any) { delete(q, "trigger_source"); delete(q, "trigger_version") })}) {
		t.Fatal("run admission without a trigger source was refused")
	}

	create := RequestAuthorization{OperationID: "createSecurityAgent", Identity: i, Allowed: []AuthorizationTarget{environment}}
	createArgs := func() []any {
		return []any{"create", agent, o, w, e, p, "createSecurityAgent", key, int64(0), json.RawMessage(`{}`), json.RawMessage(`{}`), audit, correlation, receipt}
	}
	for name, mutate := range map[string]func([]any){
		"update action":         func(a []any) { a[0] = "update" },
		"nonzero version":       func(a []any) { a[8] = int64(1) },
		"another operation":     func(a []any) { a[6] = "updateSecurityAgent" },
		"missing receipt":       func(a []any) { a[13] = "" },
		"short idempotency":     func(a []any) { a[7] = "short" },
		"invalid audit":         func(a []any) { a[11] = "audit" },
		"untyped version":       func(a []any) { a[8] = 0 },
		"invalid definition":    func(a []any) { a[1] = "agent" },
		"invalid correlation":   func(a []any) { a[12] = "" },
		"browser empty receipt": func(a []any) { a[13] = "" },
	} {
		args := createArgs()
		mutate(args)
		if authorizationStatementAllowed(create, currentSecurityAgentDefinitionMutateSQL, args) {
			t.Fatalf("create admitted %s", name)
		}
	}
	control := RequestAuthorization{OperationID: "setSecurityAgentExecutionControl", Identity: i, Allowed: []AuthorizationTarget{environment}}
	if authorizationStatementAllowed(control, currentSecurityAgentSetExecutionControlSQL, []any{o, w, e, p, key, "action", "delete_everything", true, int64(0), i.FreshAuthExpiresAt, audit, correlation, receipt}) ||
		authorizationStatementAllowed(control, currentSecurityAgentSetExecutionControlSQL, []any{o, w, e, p, key, "global", "*", true, int64(0), i.FreshAuthExpiresAt, audit, correlation, receipt}) ||
		authorizationStatementAllowed(control, currentSecurityAgentSetExecutionControlSQL, []any{o, w, e, p, key, "environment", "*", true, int64(0), i.FreshAuthExpiresAt, audit, audit, receipt}) {
		t.Fatal("execution control admitted an unknown switch or repeated identifiers")
	}

	// The historical statements these writes replace stay refused under a grant.
	for _, statement := range []string{postgresSecurityAgentDefinitionMutateSQL, postgresSecurityAgentDefinitionReplaySQL, postgresSecurityAgentDefinitionValueSQL, postgresSecurityAgentActivateSQL, postgresSecurityAgentRunSQL, postgresSecurityAgentRunV24SQL, postgresSecurityAgentSetExecutionControlSQL, postgresExportSetControlSQL, postgresExportDefinitionMutateSQL,
		`SELECT zasp_temporal78.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, `SELECT zasp_temporal78.resource($1::jsonb)`, `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`} {
		if authorizationStatementAllowed(create, statement, createArgs()) {
			t.Fatalf("historical statement admitted: %s", statement)
		}
	}
}

func TestSecurityAgentFamilyResult(t *testing.T) {
	family, result, err := securityAgentFamilyResult(json.RawMessage(`{"family":"ordered","result":{"contract_version":62,"id":"x"}}`))
	if err != nil || family != "ordered" || string(result) != `{"id":"x"}` {
		t.Fatalf("ordered family=%q result=%s err=%v", family, result, err)
	}
	family, result, err = securityAgentFamilyResult(json.RawMessage(`{"family":"finding","result":{"id":"x"}}`))
	if err != nil || family != "finding" || string(result) != `{"id":"x"}` {
		t.Fatalf("finding family=%q result=%s err=%v", family, result, err)
	}
	for _, envelope := range []string{`{"family":"ordered","result":{"id":"x"}}`, `{"family":"ordered","result":{"contract_version":61}}`, `{"family":"other","result":{}}`, `{"family":"test","result":null}`, `{"family":"test","result":{},"extra":1}`, `{"result":{}}`, `null`} {
		if _, _, err := securityAgentFamilyResult(json.RawMessage(envelope)); err == nil {
			t.Fatalf("envelope admitted: %s", envelope)
		}
	}
}
