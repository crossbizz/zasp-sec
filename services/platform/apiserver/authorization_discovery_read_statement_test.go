package apiserver

import "testing"

// Every integration read is admitted only for its own operation, the scope of
// the checked request, the integration named in the path and an object the
// decision allows.
func TestDiscoveryReadStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	const integrationID, syncID, otherID = "pid_71000001-0000-4000-8000-000000000001", "pid_71000002-0000-4000-8000-000000000002", "pid_71000003-0000-4000-8000-000000000003"
	integration := AuthorizationTarget{Scope: i.Scope, Kind: "integration", ID: integrationID, Version: 1}
	sync := AuthorizationTarget{Scope: i.Scope, Kind: "discovery_sync", ID: syncID, Version: 1}
	var before any
	type contract struct {
		query, operation string
		args             []any
		target           AuthorizationTarget
	}
	contracts := []contract{
		{`SELECT zasp_temporal72.sync_detail($1,$2,$3,$4,$5)`, "getIntegrationSync", []any{o, w, e, integrationID, syncID}, sync},
		{`SELECT zasp_temporal72.sync_history($1,$2,$3,$4,$5,$6,$7)`, "listIntegrationSyncs", []any{o, w, e, integrationID, before, before, 25}, integration},
		{`SELECT zasp_temporal72.schedule_detail($1,$2,$3,$4)`, "getIntegrationSchedule", []any{o, w, e, integrationID}, integration},
		{`SELECT zasp_temporal72.last_good_freshness($1,$2,$3,$4)`, "getIntegrationFreshness", []any{o, w, e, integrationID}, integration},
	}
	for _, c := range contracts {
		t.Run(c.operation, func(t *testing.T) {
			grant := func() RequestAuthorization {
				return RequestAuthorization{OperationID: c.operation, Identity: i, PathParameters: map[string]string{"id": integrationID, "syncId": syncID}, Allowed: []AuthorizationTarget{c.target}}
			}
			arguments := func() []any { return append([]any(nil), c.args...) }
			if handled, allowed := discovery72StatementAllowed(grant(), c.query, arguments()); !handled || !allowed {
				t.Fatalf("own contract handled=%v allowed=%v", handled, allowed)
			}
			if !authorizationStatementAllowed(grant(), c.query, arguments()) {
				t.Fatal("statement allowlist refused the read contract")
			}
			refused := func(name string, g RequestAuthorization, args []any) {
				t.Helper()
				if handled, allowed := discovery72StatementAllowed(g, c.query, args); !handled || allowed {
					t.Fatalf("%s: handled=%v allowed=%v", name, handled, allowed)
				}
				if authorizationStatementAllowed(g, c.query, args) {
					t.Fatalf("%s: statement allowlist admitted it", name)
				}
			}
			for _, other := range contracts {
				if other.operation != c.operation {
					g := grant()
					g.OperationID = other.operation
					refused("operation "+other.operation, g, arguments())
				}
			}
			g := grant()
			g.Collection = true
			refused("collection decision", g, arguments())
			g = grant()
			g.Allowed = nil
			refused("no allowed object", g, arguments())
			g = grant()
			g.Allowed = []AuthorizationTarget{{Scope: i.Scope, Kind: c.target.Kind, ID: otherID, Version: 1}}
			refused("another allowed object", g, arguments())
			g = grant()
			g.Allowed = []AuthorizationTarget{{Scope: i.Scope, Kind: "agent", ID: c.target.ID, Version: 1}}
			refused("allowed object of another kind", g, arguments())
			g = grant()
			g.PathParameters["id"] = otherID
			refused("another integration in the path", g, arguments())
			for position := 0; position < 4; position++ {
				args := arguments()
				args[position] = otherID
				refused("foreign scope or integration argument", grant(), args)
			}
			refused("missing argument", grant(), arguments()[:len(c.args)-1])
			refused("extra argument", grant(), append(arguments(), "extra"))
			if c.operation == "getIntegrationSync" {
				args := arguments()
				args[4] = otherID
				refused("another sync argument", grant(), args)
				g = grant()
				g.PathParameters["syncId"] = otherID
				refused("another sync in the path", g, arguments())
				g = grant()
				g.Allowed = []AuthorizationTarget{integration}
				refused("integration allowed but not the sync", g, arguments())
			}
		})
	}
}
