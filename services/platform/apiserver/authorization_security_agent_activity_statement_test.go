package apiserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Every Security Agent activity, audit record and export statement is
// admitted only for its own operation, a browser session, the request's
// scope and actor, the path object and the allowed target.
func TestSecurityAgentActivityStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const run, step, finding, audit, other = "pid_20000001-0000-4000-8000-000000000001", "pid_20000002-0000-4000-8000-000000000002", "pid_20000003-0000-4000-8000-000000000003", "pid_20000004-0000-4000-8000-000000000004", "pid_20000009-0000-4000-8000-000000000009"
	digest := make([]byte, 32)
	digest[0] = 1
	before := time.Now().UTC().Truncate(time.Microsecond)
	target := func(kind, id string) []AuthorizationTarget {
		return []AuthorizationTarget{{Scope: i.Scope, Kind: kind, ID: id, Version: 1}}
	}
	type contract struct {
		name, query, operation string
		path                   map[string]string
		targets                []AuthorizationTarget
		args                   func() []any
		object, actor          int // Positions of the path object and the actor.
	}
	contracts := []contract{
		{"run activity", currentSecurityAgentRunActivitySQL, "listSecurityAgentRunActivity", map[string]string{"id": run, "kind": "audit"}, target("security_agent_run", run),
			func() []any { return []any{o, w, e, run, p, "audit", nil, 50} }, 3, 4},
		{"activity runs", currentSecurityAgentActivityRunsSQL, "listSecurityAgentActivityRuns", map[string]string{"id": finding, "kind": "finding"}, target("finding", finding),
			func() []any { return []any{o, w, e, p, "finding", finding, nil, nil, 50, "attested run decision"} }, 5, 3},
		{"activity runs of an audit record", currentSecurityAgentActivityRunsSQL, "listSecurityAgentActivityRuns", map[string]string{"id": audit, "kind": "audit"}, target("security_agent_run", run),
			func() []any { return []any{o, w, e, p, "audit", audit, before, other, 50, "attested run decision"} }, 5, 3},
		{"audit record", currentSecurityAgentAuditEventSQL, "getSecurityAgentAuditEvent", map[string]string{"id": audit}, target("security_agent_run", run),
			func() []any { return []any{o, w, e, audit, p} }, 3, 4},
		{"export status", currentSecurityAgentExportGetSQL, "getSecurityAgentExport", map[string]string{"id": run, "stepId": step}, target("security_agent_run", run),
			func() []any { return []any{o, w, e, run, step, p, digest, "csrf", "checksum", "fingerprint"} }, 3, 5},
		{"export grant", currentSecurityAgentExportGrantSQL, "createSecurityAgentExportDownloadGrant", map[string]string{"id": run, "stepId": step}, target("security_agent_run", run),
			func() []any {
				return []any{o, w, e, run, step, p, digest, "csrf", "token", "json", "issue", "checksum", "fingerprint"}
			}, 3, 5},
		{"export download", currentSecurityAgentExportGrantSQL, "downloadSecurityAgentExport", map[string]string{"id": run, "stepId": step}, target("security_agent_run", run),
			func() []any {
				return []any{o, w, e, run, step, p, digest, "csrf", "token", "json", "consume", "checksum", "fingerprint"}
			}, 3, 5},
	}
	operations := []string{"listSecurityAgentRunActivity", "listSecurityAgentActivityRuns", "getSecurityAgentAuditEvent", "getSecurityAgentExport", "createSecurityAgentExportDownloadGrant", "downloadSecurityAgentExport", "getSecurityAgentRun", "listSecurityAgentRuns", "cancelSecurityAgentRun"}
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			grant := func() RequestAuthorization {
				path := map[string]string{}
				for k, v := range c.path {
					path[k] = v
				}
				allowed := append([]AuthorizationTarget(nil), c.targets...)
				return RequestAuthorization{OperationID: c.operation, Identity: i, Targets: append([]AuthorizationTarget(nil), c.targets...), Allowed: allowed, PathParameters: path}
			}
			refused := func(reason string, g RequestAuthorization, args []any) {
				t.Helper()
				if authorizationStatementAllowed(g, c.query, args) {
					t.Fatalf("%s was admitted", reason)
				}
			}
			if handled, allowed := securityAgentActivityStatementAllowed(grant(), c.query, c.args()); !handled || !allowed {
				t.Fatalf("own contract handled=%v allowed=%v", handled, allowed)
			}
			if !authorizationStatementAllowed(grant(), c.query, c.args()) {
				t.Fatal("statement allowlist refused the contract")
			}
			for _, operation := range operations {
				// The grant statement serves two operations, each with its own phase.
				if operation != c.operation {
					g := grant()
					g.OperationID = operation
					refused("operation "+operation, g, c.args())
				}
			}
			g := grant()
			g.Identity.CredentialKind = CredentialBearerToken
			refused("an API token", g, c.args())
			g = grant()
			g.Collection = true
			refused("a collection request", g, c.args())
			for n, name := range []string{"organization", "workspace", "environment"} {
				args := c.args()
				args[n] = p
				refused("another "+name, grant(), args)
			}
			args := c.args()
			args[c.actor] = o
			refused("another principal", grant(), args)
			args = c.args()
			args[c.object] = other
			refused("an object other than the path object", grant(), args)
			g = grant()
			g.PathParameters["id"] = other
			refused("a request for another path object", g, c.args())
			g = grant()
			g.Allowed = nil
			refused("a request without its checked target", g, c.args())
			g = grant()
			g.Allowed[0].Kind = "environment"
			refused("a target of another kind", g, c.args())
			refused("an extra argument", grant(), append(c.args(), "extra"))
			refused("a missing argument", grant(), c.args()[:len(c.args())-1])
		})
	}
	activity := RequestAuthorization{OperationID: "listSecurityAgentRunActivity", Identity: i, Allowed: target("security_agent_run", run), PathParameters: map[string]string{"id": run, "kind": "audit"}}
	for name, args := range map[string][]any{
		"another kind than the path": {o, w, e, run, p, "finding", nil, 50},
		"an unknown kind":            {o, w, e, run, p, "agent", nil, 50},
		"no limit":                   {o, w, e, run, p, "audit", nil, 0},
		"a limit above the maximum":  {o, w, e, run, p, "audit", nil, 101},
		"a malformed cursor":         {o, w, e, run, p, "audit", "x", 50},
	} {
		if authorizationStatementAllowed(activity, currentSecurityAgentRunActivitySQL, args) {
			t.Fatalf("run activity with %s was admitted", name)
		}
	}
	related := RequestAuthorization{OperationID: "listSecurityAgentActivityRuns", Identity: i, Targets: target("finding", finding), Allowed: target("finding", finding), PathParameters: map[string]string{"id": finding, "kind": "finding"}}
	for name, args := range map[string][]any{
		"no run decision":            {o, w, e, p, "finding", finding, nil, nil, 50, nil},
		"an empty run decision":      {o, w, e, p, "finding", finding, nil, nil, 50, ""},
		"half a cursor":              {o, w, e, p, "finding", finding, before, nil, 50, "attested run decision"},
		"another kind than the path": {o, w, e, p, "attack_path", finding, nil, nil, 50, "attested run decision"},
		"a limit above the maximum":  {o, w, e, p, "finding", finding, nil, nil, 101, "attested run decision"},
	} {
		if authorizationStatementAllowed(related, currentSecurityAgentActivityRunsSQL, args) {
			t.Fatalf("related runs with %s were admitted", name)
		}
	}
	// A parent-decided record is admitted only when every resolved target is
	// allowed and each is a run of this scope.
	record := RequestAuthorization{OperationID: "getSecurityAgentAuditEvent", Identity: i, Targets: target("security_agent_run", run), PathParameters: map[string]string{"id": audit}}
	if authorizationStatementAllowed(record, currentSecurityAgentAuditEventSQL, []any{o, w, e, audit, p}) {
		t.Fatal("an audit record whose run is not allowed was admitted")
	}
	grant := RequestAuthorization{OperationID: "createSecurityAgentExportDownloadGrant", Identity: i, Allowed: target("security_agent_run", run), PathParameters: map[string]string{"id": run, "stepId": step}}
	for name, args := range map[string][]any{
		"a download phase": {o, w, e, run, step, p, digest, "csrf", "token", "json", "consume", "checksum", "fingerprint"},
		"another step":     {o, w, e, run, other, p, digest, "csrf", "token", "json", "issue", "checksum", "fingerprint"},
		"a short digest":   {o, w, e, run, step, p, digest[:16], "csrf", "token", "json", "issue", "checksum", "fingerprint"},
		"an unknown phase": {o, w, e, run, step, p, digest, "csrf", "token", "json", "other", "checksum", "fingerprint"},
		"a digest as text": {o, w, e, run, step, p, "digest", "csrf", "token", "json", "issue", "checksum", "fingerprint"},
	} {
		if authorizationStatementAllowed(grant, currentSecurityAgentExportGrantSQL, args) {
			t.Fatalf("export grant with %s was admitted", name)
		}
	}
	download := grant
	download.OperationID = "downloadSecurityAgentExport"
	if authorizationStatementAllowed(download, currentSecurityAgentExportGrantSQL, []any{o, w, e, run, step, p, digest, "csrf", "token", "json", "issue", "checksum", "fingerprint"}) {
		t.Fatal("a download that issues a grant was admitted")
	}
	if handled, _ := securityAgentActivityStatementAllowed(activity, currentSecurityAgentRunDetailSQL, nil); handled {
		t.Fatal("an unrelated statement was claimed")
	}
}

// The kind of an activity record in a request path decides which object the
// request is authorized for.
func TestSecurityAgentActivityTargetKind(t *testing.T) {
	for kind, want := range map[string]string{"finding": "finding", "attack_path": "attack_path", "audit": "security_agent_audit"} {
		if got, ok := securityAgentActivityTargetKind(kind, "pid_20000001-0000-4000-8000-000000000001"); !ok || got != want {
			t.Fatalf("%s decided as %q ok=%v, want %q", kind, got, ok, want)
		}
	}
	if got, ok := securityAgentActivityTargetKind("session", "pid_20000001-0000-4000-8000-000000000001"); !ok || got != "session" && got != "product_session" {
		t.Fatalf("session decided as %q ok=%v", got, ok)
	}
	for _, kind := range []string{"", "agent", "run", "security_agent_run"} {
		if _, ok := securityAgentActivityTargetKind(kind, "pid_20000001-0000-4000-8000-000000000001"); ok {
			t.Fatalf("kind %q was accepted", kind)
		}
	}
}

// A closure is decoded only when it answers the request that was sent.
func TestSecurityAgentRunCloseResult(t *testing.T) {
	i := fixtureRequestIdentity(t)
	const run, agent, audit, correlation, receipt = "pid_20000001-0000-4000-8000-000000000001", "pid_20000002-0000-4000-8000-000000000002", "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"
	input := SecurityAgentRunCloseRequest{RunID: run, IdempotencyKey: "idempotency-key-0001", ExpectedVersion: 3, Reason: "usage_unknown_accepted", Note: "Reviewed", AuditID: audit, CorrelationID: correlation, ReceiptID: receipt}
	payload := func(mutate func(map[string]any)) []byte {
		value := map[string]any{"id": run, "agent_id": agent, "state": "needs_human", "definition_version": 2, "version": 3,
			"closure":  map[string]any{"closed_at": "2026-11-13T23:53:11.454205Z", "closed_by": i.PrincipalID.String(), "reason": "usage_unknown_accepted", "note": "Reviewed"},
			"audit_id": audit, "correlation_id": correlation, "receipt_id": receipt, "replayed": false}
		mutate(value)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	result, err := decodeSecurityAgentRunCloseResult(payload(func(map[string]any) {}), i, input)
	if err != nil || result.Closure.Reason != input.Reason || result.Closure.Note != "Reviewed" || result.Version != 3 || result.Replayed {
		t.Fatalf("closure=%+v err=%v", result, err)
	}
	// A replay carries the identifiers of the first answer.
	if _, err := decodeSecurityAgentRunCloseResult(payload(func(v map[string]any) { v["replayed"], v["audit_id"] = true, correlation }), i, input); err != nil {
		t.Fatalf("replay refused: %v", err)
	}
	closure := func(mutate func(map[string]any)) func(map[string]any) {
		return func(v map[string]any) { mutate(v["closure"].(map[string]any)) }
	}
	for name, mutate := range map[string]func(map[string]any){
		"another run":             func(v map[string]any) { v["id"] = agent },
		"another state":           func(v map[string]any) { v["state"] = "cancelled" },
		"a moved version":         func(v map[string]any) { v["version"] = 4 },
		"another audit record":    func(v map[string]any) { v["audit_id"] = correlation },
		"an extra field":          func(v map[string]any) { v["evidence_ids"] = []string{} },
		"a missing closure":       func(v map[string]any) { delete(v, "closure") },
		"another actor":           closure(func(c map[string]any) { c["closed_by"] = agent }),
		"another reason":          closure(func(c map[string]any) { c["reason"] = "no_action_required" }),
		"another note":            closure(func(c map[string]any) { c["note"] = "Other" }),
		"an unknown reason":       closure(func(c map[string]any) { c["reason"] = "because" }),
		"a local time":            closure(func(c map[string]any) { c["closed_at"] = "2026-11-13T23:53:11+01:00" }),
		"an extra closure field":  closure(func(c map[string]any) { c["extra"] = 1 }),
		"a closure without actor": closure(func(c map[string]any) { delete(c, "closed_by") }),
	} {
		if _, err := decodeSecurityAgentRunCloseResult(payload(mutate), i, input); err != ErrRepositoryUnavailable {
			t.Fatalf("closure with %s: err=%v", name, err)
		}
	}
	// Without a checked request there is no proof, so nothing is sent.
	repository := &PostgresRepository{database: &completionJSONFixture{}, securityAgentExecution: true}
	if _, err := repository.CloseSecurityAgentRun(t.Context(), i, input); err != ErrRepositoryAuthorization {
		t.Fatalf("closure without a checked request: err=%v", err)
	}
	for name, mutate := range map[string]func(*SecurityAgentRunCloseRequest){
		"an unknown reason":   func(q *SecurityAgentRunCloseRequest) { q.Reason = "because" },
		"a padded note":       func(q *SecurityAgentRunCloseRequest) { q.Note = " x " },
		"version zero":        func(q *SecurityAgentRunCloseRequest) { q.ExpectedVersion = 0 },
		"a short key":         func(q *SecurityAgentRunCloseRequest) { q.IdempotencyKey = "short" },
		"a repeated identity": func(q *SecurityAgentRunCloseRequest) { q.ReceiptID = q.AuditID },
	} {
		request := input
		mutate(&request)
		if _, err := repository.CloseSecurityAgentRun(t.Context(), i, request); err != ErrRepositoryOperation {
			t.Fatalf("closure request with %s: err=%v", name, err)
		}
	}
}

// Only the statement's own refusal of evidence is a denial of the request.
func TestSecurityAgentStatementRefused(t *testing.T) {
	const message = "current security agent evidence authorization required"
	refusal := classifyPostgresError(&pgconn.PgError{Code: "42501", Message: message})
	if !securityAgentStatementRefused(refusal, message) || !securityAgentStatementRefused(discoveryProviderError(refusal), message) {
		t.Fatal("the statement's refusal was not recognised")
	}
	for name, err := range map[string]error{
		"another message": classifyPostgresError(&pgconn.PgError{Code: "42501", Message: "current security agent authorization required"}),
		"another state":   classifyPostgresError(&pgconn.PgError{Code: "55000", Message: message}),
		"a conflict":      classifyPostgresError(&pgconn.PgError{Code: "40001", Message: message}),
		"an unavailable":  ErrRepositoryUnavailable,
		"no error":        nil,
	} {
		if securityAgentStatementRefused(err, message) {
			t.Fatalf("%s was read as the refusal", name)
		}
	}
}
