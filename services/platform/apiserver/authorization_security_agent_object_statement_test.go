package apiserver

import (
	"encoding/json"
	"testing"
	"time"
)

// Every Security Agent run and approval statement is admitted only for its
// own operation, scope, actor, credential kind, path object and allowed
// target.
func TestSecurityAgentObjectStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Microsecond)
	authenticated := i.FreshAuthExpiresAt.Add(-securityAgentFreshAuthenticationTTL)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const object, other = "pid_20000001-0000-4000-8000-000000000001", "pid_20000002-0000-4000-8000-000000000002"
	const audit, correlation, receipt, run, evidence = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003", "pid_30000004-0000-4000-8000-000000000004", "pid_30000005-0000-4000-8000-000000000005"
	const key = "idempotency-key-0001"
	expires := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)
	type contract struct {
		name, query, operation, kind string
		args                         func() []any
		browserFresh                 bool
		ids                          []int // Positions of the identifiers the request generates.
	}
	contracts := []contract{
		{"run detail", currentSecurityAgentRunDetailSQL, "getSecurityAgentRun", "security_agent_run", func() []any { return []any{o, w, e, object, p} }, false, nil},
		{"cancel", currentSecurityAgentCancelRunSQL, "cancelSecurityAgentRun", "security_agent_run", func() []any { return []any{o, w, e, object, p, key, int64(3), audit, correlation, receipt} }, false, []int{7, 8, 9}},
		{"approval", currentSecurityAgentApprovalSQL, "getSecurityAgentApproval", "security_agent_approval", func() []any { return []any{o, w, e, object, p} }, false, nil},
		{"decide", currentSecurityAgentDecideApprovalSQL, "decideSecurityAgentApproval", "security_agent_approval", func() []any {
			return []any{o, w, e, object, p, key, int64(1), "approved", authenticated, audit, correlation, receipt}
		}, true, []int{9, 10, 11}},
		{"simulate", currentSecurityAgentSimulateSQL, "simulateSecurityAgent", "security_agent", func() []any {
			return []any{o, w, e, object, p, key, int64(3), run, "Check the plan", json.RawMessage(`["` + evidence + `"]`), expires, audit, correlation, receipt, "attested evidence decision"}
		}, false, []int{7, 11, 12, 13}},
		{"close", currentSecurityAgentCloseRunSQL, "closeSecurityAgentRun", "security_agent_run", func() []any {
			return []any{o, w, e, object, p, key, int64(3), "usage_unknown_accepted", nil, audit, correlation, receipt}
		}, false, []int{9, 10, 11}},
		{"manual run", currentSecurityAgentManualRunSQL, "runSecurityAgent", "security_agent", func() []any { return []any{o, w, e, object, p, key, int64(3), run, audit, correlation, receipt} }, false, []int{7, 8, 9, 10}},
	}
	operations := []string{"getSecurityAgentRun", "cancelSecurityAgentRun", "closeSecurityAgentRun", "getSecurityAgentApproval", "decideSecurityAgentApproval", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "listSecurityAgentApprovals", "getSecurityAgent", "activateSecurityAgent", "setSecurityAgentPlannerPricing"}
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			grant := func() RequestAuthorization {
				return RequestAuthorization{OperationID: c.operation, Identity: i, Allowed: []AuthorizationTarget{{Scope: i.Scope, Kind: c.kind, ID: object, Version: 3}}, PathParameters: map[string]string{"id": object}}
			}
			refused := func(reason string, g RequestAuthorization, args []any) {
				t.Helper()
				if authorizationStatementAllowed(g, c.query, args) {
					t.Fatalf("%s was admitted", reason)
				}
			}
			if handled, allowed := securityAgentObjectStatementAllowed(grant(), c.query, c.args()); !handled || !allowed {
				t.Fatalf("own contract handled=%v allowed=%v", handled, allowed)
			}
			if !authorizationStatementAllowed(grant(), c.query, c.args()) {
				t.Fatal("statement allowlist refused the contract")
			}
			for _, operation := range operations {
				if operation != c.operation {
					g := grant()
					g.OperationID = operation
					refused("operation "+operation, g, c.args())
				}
			}
			g := grant()
			g.Collection = true
			refused("a collection request", g, c.args())
			for n, name := range []string{"organization", "workspace", "environment"} {
				args := c.args()
				args[n] = p
				refused("another "+name, grant(), args)
			}
			args := c.args()
			args[4] = o
			refused("another principal", grant(), args)
			args = c.args()
			args[3] = other
			refused("an object other than the path object", grant(), args)
			g = grant()
			g.PathParameters = map[string]string{"id": other}
			refused("a request for another path object", g, c.args())
			g = grant()
			g.PathParameters = nil
			refused("a request without a path object", g, c.args())
			g = grant()
			g.Allowed = nil
			refused("a request without its checked target", g, c.args())
			g = grant()
			g.Allowed[0].Kind = "finding"
			refused("a target of another kind", g, c.args())
			g = grant()
			g.Allowed[0].ID = other
			refused("another allowed target", g, c.args())
			refused("an extra argument", grant(), append(c.args(), "extra"))
			refused("a missing argument", grant(), c.args()[:len(c.args())-1])
			g = grant()
			g.Identity.CredentialKind = CredentialBearerToken
			if got := authorizationStatementAllowed(g, c.query, c.args()); got == c.browserFresh {
				t.Fatalf("API token admitted=%v for browserFresh=%v", got, c.browserFresh)
			}
			g = grant()
			g.Identity.FreshAuthenticated = false
			if got := authorizationStatementAllowed(g, c.query, c.args()); got == c.browserFresh {
				t.Fatalf("stale authentication admitted=%v for browserFresh=%v", got, c.browserFresh)
			}
			for n, position := range c.ids {
				args = c.args()
				args[position] = "not-a-product-id"
				refused("a malformed identifier", grant(), args)
				if n > 0 {
					args = c.args()
					args[position] = args[c.ids[0]]
					refused("a repeated identifier", grant(), args)
				}
			}
			if len(c.ids) > 0 {
				args = c.args()
				args[5] = "short"
				refused("a malformed idempotency key", grant(), args)
				args = c.args()
				args[6] = int64(0)
				refused("version zero", grant(), args)
				args = c.args()
				args[6] = int64(1000001)
				refused("a version above the maximum", grant(), args)
				args = c.args()
				args[6] = "3"
				refused("a version of another type", grant(), args)
			}
		})
	}
	decide := func(mutate func([]any)) []any {
		args := []any{o, w, e, object, p, key, int64(1), "approved", authenticated, audit, correlation, receipt}
		mutate(args)
		return args
	}
	approval := RequestAuthorization{OperationID: "decideSecurityAgentApproval", Identity: i, Allowed: []AuthorizationTarget{{Scope: i.Scope, Kind: "security_agent_approval", ID: object, Version: 1}}, PathParameters: map[string]string{"id": object}}
	for name, args := range map[string][]any{
		"another decision":           decide(func(a []any) { a[7] = "expired" }),
		"another time":               decide(func(a []any) { a[8] = authenticated.Add(time.Second) }),
		"the end of the window":      decide(func(a []any) { a[8] = i.FreshAuthExpiresAt }),
		"a local time":               decide(func(a []any) { a[8] = authenticated.In(time.FixedZone("x", 3600)) }),
		"a time of another type":     decide(func(a []any) { a[8] = authenticated.Format(time.RFC3339Nano) }),
		"a decision of another type": decide(func(a []any) { a[7] = true }),
	} {
		if authorizationStatementAllowed(approval, currentSecurityAgentDecideApprovalSQL, args) {
			t.Fatalf("decision with %s was admitted", name)
		}
	}
	simulate := func(mutate func([]any)) []any {
		args := []any{o, w, e, object, p, key, int64(3), run, "Check the plan", json.RawMessage(`["` + evidence + `"]`), expires, audit, correlation, receipt, "attested evidence decision"}
		mutate(args)
		return args
	}
	agent := RequestAuthorization{OperationID: "simulateSecurityAgent", Identity: i, Allowed: []AuthorizationTarget{{Scope: i.Scope, Kind: "security_agent", ID: object, Version: 3}}, PathParameters: map[string]string{"id": object}}
	for name, args := range map[string][]any{
		"no evidence":          simulate(func(a []any) { a[9] = json.RawMessage(`[]`) }),
		"repeated evidence":    simulate(func(a []any) { a[9] = json.RawMessage(`["` + evidence + `","` + evidence + `"]`) }),
		"malformed evidence":   simulate(func(a []any) { a[9] = json.RawMessage(`["x"]`) }),
		"evidence as a string": simulate(func(a []any) { a[9] = `["` + evidence + `"]` }),
		"an empty goal":        simulate(func(a []any) { a[8] = "" }),
		"no expiry":            simulate(func(a []any) { a[10] = time.Time{} }),
		"a local expiry":       simulate(func(a []any) { a[10] = expires.In(time.FixedZone("x", 3600)) }),
		"no evidence decision": simulate(func(a []any) { a[14] = nil }),
		"an empty decision":    simulate(func(a []any) { a[14] = "" }),
		"a decision as bytes":  simulate(func(a []any) { a[14] = []byte("attested evidence decision") }),
	} {
		if authorizationStatementAllowed(agent, currentSecurityAgentSimulateSQL, args) {
			t.Fatalf("simulation with %s was admitted", name)
		}
	}
	closeRun := func(mutate func([]any)) []any {
		args := []any{o, w, e, object, p, key, int64(3), "no_action_required", "Reviewed by the on-call engineer", audit, correlation, receipt}
		mutate(args)
		return args
	}
	closing := RequestAuthorization{OperationID: "closeSecurityAgentRun", Identity: i, Allowed: []AuthorizationTarget{{Scope: i.Scope, Kind: "security_agent_run", ID: object, Version: 3}}, PathParameters: map[string]string{"id": object}}
	if !authorizationStatementAllowed(closing, currentSecurityAgentCloseRunSQL, closeRun(func([]any) {})) {
		t.Fatal("a closure with a note was refused")
	}
	for name, args := range map[string][]any{
		"an unknown reason":         closeRun(func(a []any) { a[7] = "because" }),
		"a reason of another type":  closeRun(func(a []any) { a[7] = true }),
		"an empty note":             closeRun(func(a []any) { a[8] = "" }),
		"a padded note":             closeRun(func(a []any) { a[8] = " padded " }),
		"a note with a line break":  closeRun(func(a []any) { a[8] = "line\nbreak" }),
		"a note that is too long":   closeRun(func(a []any) { a[8] = string(make([]byte, 501)) }),
		"a note of another type":    closeRun(func(a []any) { a[8] = 7 }),
		"a cancellation's argument": closeRun(func(a []any) { a[7] = audit }),
	} {
		if authorizationStatementAllowed(closing, currentSecurityAgentCloseRunSQL, args) {
			t.Fatalf("closure with %s was admitted", name)
		}
	}
	if handled, _ := securityAgentObjectStatementAllowed(agent, `SELECT zasp_authorization80.security_agent_page($1,$2,$3,NULLIF($4,''),$5)`, nil); handled {
		t.Fatal("an unrelated statement was claimed")
	}
}
